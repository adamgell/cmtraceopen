use super::canonical_fragment_complete;
use crate as cmtraceopen_parser;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_management_point_fixture, analyze_management_point_from_server_intake,
    assess_server_intake, declared_server_source_catalog, SccmManagementPointBundle,
    SccmManagementPointIntakeError, SccmManagementPointSource, SccmManagementPointTopology,
    SccmServerArtifactPayload,
};
use cmtraceopen_parser::sccm::{
    declared_source_catalog, normalize_ccm_artifact, SccmArtifact, SccmArtifactFamily,
    SccmCoverageState, SccmRole, SccmRotation,
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
        let producer_role = match source.role.as_str() {
            "managementPoint" => SccmRole::ManagementPoint,
            "siteServer" => SccmRole::SiteServer,
            other => panic!("unsupported MP fixture producer role {other}"),
        };
        let artifact = SccmArtifact {
            artifact_id: source.artifact_id,
            display_name: source.original_basename,
            original_path: None,
            host: None,
            role: producer_role,
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

fn load_server_intake_fixture(
    directory: &Path,
) -> cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment {
    let manifest_json = fs::read_to_string(directory.join("manifest.json"))
        .expect("server intake fixture manifest must be readable");
    let manifest = load_json(&directory.join("manifest.json"));
    let payloads = manifest["artifacts"]
        .as_array()
        .expect("canonical MP fixture artifacts")
        .iter()
        .filter_map(|artifact| {
            let relative_path = artifact["relativePath"].as_str()?;
            Some(SccmServerArtifactPayload {
                manifest_artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("server intake fixture artifact ID")
                    .to_owned(),
                bytes: fs::read(directory.join(relative_path))
                    .expect("server intake fixture payload must be readable"),
            })
        })
        .collect::<Vec<_>>();
    assess_server_intake(&manifest_json, &payloads)
        .expect("fixture must satisfy canonical server intake")
}

fn load_canonical_intake(
    scenario: &str,
) -> cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment {
    load_server_intake_fixture(&fixture_directory(scenario))
}

fn load_server_intake_scenario(
    scenario: &str,
) -> cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment {
    load_server_intake_fixture(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sccm/server/intake")
            .join(scenario),
    )
}

fn expected_transaction_projection(expected: &Value) -> Vec<Value> {
    expected["transactions"]
        .as_array()
        .expect("expected transactions")
        .iter()
        .map(|transaction| {
            let next_artifact_logical_ids = transaction["nextArtifact"]["logicalArtifactId"]
                .as_str()
                .map(|_| vec![transaction["nextArtifact"]["logicalArtifactId"].clone()])
                .unwrap_or_default();
            json!({
                "transactionId": transaction["transactionId"],
                "phase": transaction["phase"],
                "state": transaction["state"],
                "lastSuccessfulPhase": transaction["lastSuccessfulPhase"],
                "classification": transaction["classification"],
                "confidence": transaction["confidence"],
                "coverageGapArtifactIds": transaction["coverageGapArtifactIds"],
                "nextArtifactLogicalIds": next_artifact_logical_ids,
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
            let next_artifact_logical_ids = transaction["nextArtifacts"]
                .as_array()
                .map(|requests| {
                    requests
                        .iter()
                        .map(|request| request["logicalArtifactId"].clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            json!({
                "transactionId": transaction["transactionId"],
                "phase": transaction["phase"],
                "state": transaction["state"],
                "lastSuccessfulPhase": transaction["lastSuccessfulPhase"],
                "classification": transaction["classification"],
                "confidence": transaction["confidence"],
                "coverageGapArtifactIds": transaction["coverageGapArtifactIds"],
                "nextArtifactLogicalIds": next_artifact_logical_ids,
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
                    reference_is_within_expected_ranges(
                        reference,
                        std::slice::from_ref(expected_reference),
                    )
                }),
                "{scenario}: {transaction_id} omitted an expected evidence range"
            );
        }

        let observations = actual["observations"]
            .as_array()
            .expect("transaction observations");
        assert_eq!(
            observations.len(),
            expected_transaction["observations"]
                .as_array()
                .expect("expected transaction observations")
                .len(),
            "{scenario}: observation count"
        );
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
            let next_logical_ids = if actual {
                observation["nextArtifacts"]
                    .as_array()
                    .map(|requests| {
                        requests
                            .iter()
                            .map(|request| request["logicalArtifactId"].clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            } else {
                observation["nextArtifact"]["logicalArtifactId"]
                    .as_str()
                    .map(|_| vec![observation["nextArtifact"]["logicalArtifactId"].clone()])
                    .unwrap_or_default()
            };
            json!({
                "observationId": observation["observationId"],
                "phase": observation["phase"],
                "classification": observation["classification"],
                "confidence": observation["confidence"],
                "correlationEligible": observation["correlationEligible"],
                "nextArtifactLogicalIds": next_logical_ids,
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
        let analysis =
            serde_json::to_value(analyze_management_point_fixture(&load_bundle(scenario)))
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
fn canonical_intake_adapter_uses_assessed_mp_evidence_and_rejects_mismatches() {
    let assessment = load_canonical_intake("canonical-intake-policy-scope");
    let assert_unbound =
        |mutated: &cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment| {
            assert!(matches!(
                analyze_management_point_from_server_intake(mutated),
                Err(SccmManagementPointIntakeError::SourceMismatch { artifact_id })
                    if artifact_id == "management-point-intake-projection"
            ));
        };
    let analysis = analyze_management_point_from_server_intake(&assessment)
        .expect("complete canonical MP source must enter the reducer");

    assert!(
        analysis.transactions.is_empty(),
        "one policy-phase record is not a completed transaction"
    );
    assert!(!analysis.cross_side_correlation_performed);
    assert_eq!(analysis.source_local_observations.len(), 1);
    assert!(analysis.source_local_observations[0]
        .evidence
        .iter()
        .all(|reference| reference.artifact_id == "mp-policy-current"));

    let mut supplemental_iis = assessment.clone();
    let mut iis_artifact = supplemental_iis.artifacts[0].clone();
    iis_artifact.artifact_id = "mp-iis-skipped".to_owned();
    iis_artifact.source_id = "server-mp-iis".to_owned();
    iis_artifact.source_kind = "iisW3c".to_owned();
    iis_artifact.state = SccmCoverageState::Skipped;
    iis_artifact.parser_eligible = false;
    iis_artifact.fragment_complete = None;
    iis_artifact.truncated = None;
    supplemental_iis.artifacts.push(iis_artifact);
    assert_unbound(&supplemental_iis);

    let mut missing_role = assessment.clone();
    missing_role
        .topology
        .roles_observed
        .retain(|role| *role != SccmRole::ManagementPoint);
    assert_unbound(&missing_role);

    let mut opaque_site_handle = assessment.clone();
    opaque_site_handle.topology.site_handle = format!("cmtraceopen.site.sha256.v1:{:064x}", 1);
    assert_unbound(&opaque_site_handle);

    let mut wrong_role = assessment.clone();
    wrong_role.artifacts[0].producer_role = SccmRole::SiteServer;
    assert_unbound(&wrong_role);

    let mut wrong_profile = assessment.clone();
    wrong_profile.artifacts[0].source_version = Some("5.00.TEST.9999".to_owned());
    wrong_profile.artifacts[0].profile_eligible = true;
    assert_unbound(&wrong_profile);

    let mut wrong_source = assessment.clone();
    wrong_source.artifacts[0].source_id = "server-sitecomp".to_owned();
    assert_unbound(&wrong_source);

    let mut missing_coverage = assessment.clone();
    missing_coverage.coverage.clear();
    assert_unbound(&missing_coverage);

    let mut capped = assessment.clone();
    capped.artifacts[0].state = SccmCoverageState::Capped;
    capped.artifacts[0].truncated = Some(true);
    capped.artifacts[0].fragment_complete = Some(false);
    assert_unbound(&capped);

    let mut fragment = assessment;
    fragment.artifacts[0].fragment_complete = Some(false);
    assert_unbound(&fragment);
}

#[test]
fn canonical_intake_adapter_admits_its_exact_synthetic_profile_version() {
    let bundle = load_bundle("healthy-policy");
    assert_eq!(
        bundle.sources[0].artifact.configmgr_version.as_deref(),
        Some("5.00.TEST"),
        "the frozen synthetic MP corpus must retain its exact profile version"
    );

    let analysis = analyze_management_point_fixture(&bundle);
    assert_eq!(
        analysis.transactions.len(),
        1,
        "profile-shaped canonical evidence must not be silently filtered by a second version"
    );
}

#[test]
fn canonical_intake_adapter_maps_captured_unspecified_fragment_to_complete() {
    let assessment = load_canonical_intake("canonical-intake-policy-scope");
    let artifact = &assessment.artifacts[0];
    assert_eq!(artifact.state, SccmCoverageState::Captured);
    assert_eq!(artifact.truncated, None);
    assert_eq!(
        artifact.fragment_complete, None,
        "canonical intake represents a full captured artifact without fragment flags"
    );

    assert_eq!(
        canonical_fragment_complete(artifact),
        Some(true),
        "the adapter must project canonical captured completeness for its internal reducer"
    );
    let analysis = analyze_management_point_from_server_intake(&assessment)
        .expect("the canonical captured artifact must enter MP reduction");
    assert_eq!(
        analysis.source_local_observations.len(),
        1,
        "the canonical policy record remains reducer-visible after completeness projection"
    );
}

#[test]
fn canonical_intake_adapter_rejects_self_attested_line_authority() {
    let mut assessment = load_canonical_intake("canonical-intake-policy-scope");
    let evidence = assessment
        .evidence
        .first_mut()
        .expect("canonical fixture evidence");
    evidence.evidence_id = "mp-policy-current:999-999".to_owned();
    evidence.reference.entry_id = "mp-policy-current:999-999".to_owned();
    evidence.reference.line_start = Some(999);
    evidence.reference.line_end = Some(999);

    assert!(
        analyze_management_point_from_server_intake(&assessment).is_err(),
        "caller-submitted line ranges cannot become physical line authority"
    );
}

#[test]
fn canonical_intake_adapter_rejects_forged_evidence_ownership() {
    let assessment = load_canonical_intake("canonical-intake-policy-scope");

    let mut foreign_artifact = assessment.clone();
    foreign_artifact.evidence[0].reference.artifact_id = "mp-policy-forged".to_owned();
    assert!(
        analyze_management_point_from_server_intake(&foreign_artifact).is_err(),
        "evidence cannot be silently reassigned to an undeclared artifact"
    );

    let mut foreign_role = assessment;
    foreign_role.evidence[0].role = SccmRole::SiteServer;
    assert!(
        analyze_management_point_from_server_intake(&foreign_role).is_err(),
        "evidence cannot be silently reassigned to another producer role"
    );
}

#[test]
fn canonical_intake_adapter_rejects_forged_admission_metadata() {
    let mut assessment = load_canonical_intake("canonical-intake-policy-scope");
    assessment.artifacts[0].producer_host_handle =
        Some(format!("cmtraceopen.host.sha256.v1:{:064x}", 1));

    assert!(
        analyze_management_point_from_server_intake(&assessment).is_err(),
        "caller-submitted topology and artifact metadata cannot replace canonical intake authority"
    );
}

#[test]
fn canonical_intake_adapter_accepts_reordered_authoritative_records() {
    let assessment = load_canonical_intake("canonical-intake-policy-scope");
    let expected = analyze_management_point_from_server_intake(&assessment)
        .expect("canonical intake must enter the adapter");

    let mut reordered = assessment;
    reordered.artifacts.reverse();
    reordered.coverage.reverse();
    reordered.evidence.reverse();
    assert_eq!(
        analyze_management_point_from_server_intake(&reordered)
            .expect("record ordering is not intake authority"),
        expected
    );
}

#[test]
fn canonical_intake_adapter_rejects_promoted_capped_profile_ineligible_metadata() {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/intake/capped-sup");
    let mut manifest = load_json(&directory.join("manifest.json"));
    manifest["artifacts"][0]
        .as_object_mut()
        .expect("capped fixture artifact")
        .remove("sourceVersion");
    let manifest_json = serde_json::to_string(&manifest).expect("manifest serializes");
    let payloads = vec![SccmServerArtifactPayload {
        manifest_artifact_id: "sup-sync-capped".to_owned(),
        bytes: fs::read(directory.join(
            "evidence/sccm/server/site-server/server-sup-sync/subject-software-update-point/instance-17eae15500d8968f/root-b11afca548220198/current/wsyncmgr.log",
        ))
        .expect("capped fixture payload"),
    }];
    let assessment = assess_server_intake(&manifest_json, &payloads)
        .expect("capped profile-ineligible intake must be canonical");
    assert_eq!(assessment.artifacts[0].state, SccmCoverageState::Capped);
    assert!(!assessment.artifacts[0].profile_eligible);

    let sealed_evidence = assessment.evidence.clone();
    let mut promoted = assessment;
    promoted.topology.roles_observed = vec![SccmRole::ManagementPoint];
    let artifact = &mut promoted.artifacts[0];
    artifact.producer_role = SccmRole::ManagementPoint;
    artifact.producer_host_handle = Some("synthetic:host:mp-01".to_owned());
    artifact.workflow_subject_role = None;
    artifact.workflow_subject_handle = None;
    artifact.source_id = "server-mp-policy".to_owned();
    artifact.family = SccmArtifactFamily::ManagementPoint;
    artifact.original_basename = Some("MP_GetPolicy.log".to_owned());
    artifact.state = SccmCoverageState::Captured;
    artifact.source_version = Some("5.00.TEST".to_owned());
    artifact.profile_eligible = true;
    artifact.truncated = None;
    artifact.fragment_complete = None;
    promoted.coverage[0].producer_role = SccmRole::ManagementPoint;
    promoted.coverage[0].workflow_subject_role = None;
    promoted.coverage[0].source_id = "server-mp-policy".to_owned();
    promoted.coverage[0].state = SccmCoverageState::Captured;

    assert_eq!(
        promoted.evidence, sealed_evidence,
        "the attempted promotion must not require evidence rewriting"
    );
    assert!(matches!(
        analyze_management_point_from_server_intake(&promoted),
        Err(SccmManagementPointIntakeError::SourceMismatch { .. })
    ));
}

#[test]
fn canonical_intake_adapter_rejects_forged_message_and_timestamp() {
    let assessment = load_canonical_intake("canonical-intake-policy-scope");

    let mut forged_message = assessment.clone();
    forged_message.evidence[0]
        .message
        .push_str(" terminal outcome forged by caller");
    assert!(
        analyze_management_point_from_server_intake(&forged_message).is_err(),
        "caller-submitted messages cannot replace intake-normalized evidence"
    );

    let mut forged_timestamp = assessment;
    forged_timestamp.evidence[0].timestamp.utc_millis = Some(1_785_373_204_000);
    assert!(
        analyze_management_point_from_server_intake(&forged_timestamp).is_err(),
        "caller-submitted timestamps cannot replace intake-normalized provenance"
    );
}

#[test]
fn canonical_intake_adapter_rejects_duplicate_and_colliding_evidence_identities() {
    let assessment = load_canonical_intake("canonical-intake-policy-scope");

    let mut duplicate = assessment.clone();
    duplicate.evidence.push(duplicate.evidence[0].clone());
    assert!(
        analyze_management_point_from_server_intake(&duplicate).is_err(),
        "duplicate canonical evidence identities must fail closed"
    );

    let mut collision = assessment;
    let mut colliding_evidence = collision.evidence[0].clone();
    colliding_evidence.message = "different record with the same evidence identity".to_owned();
    collision.evidence.push(colliding_evidence);
    assert!(
        analyze_management_point_from_server_intake(&collision).is_err(),
        "different evidence cannot collide under one canonical identity"
    );
}

#[test]
fn canonical_intake_adapter_is_deterministic_under_valid_evidence_reordering() {
    let assessment = load_server_intake_scenario("complete-multi-role");
    assert!(
        assessment.evidence.len() > 1,
        "fixture must exercise reordering"
    );
    let expected = analyze_management_point_from_server_intake(&assessment)
        .expect("canonical multi-role intake must be admitted");

    let mut reordered = assessment;
    reordered.evidence.reverse();
    let actual = analyze_management_point_from_server_intake(&reordered)
        .expect("reordering intact canonical evidence must remain valid");

    assert_eq!(actual, expected);
}

#[test]
fn management_point_analysis_is_deterministic_under_bundle_reordering() {
    for scenario in SCENARIOS {
        let bundle = load_bundle(scenario);
        let expected = serde_json::to_string(&analyze_management_point_fixture(&bundle))
            .expect("analysis JSON");

        let mut reordered = bundle.clone();
        reordered.sources.reverse();
        reordered.evidence.reverse();
        let actual = serde_json::to_string(&analyze_management_point_fixture(&reordered))
            .expect("analysis JSON");
        assert_eq!(actual, expected, "{scenario}");
    }
}

#[test]
fn management_point_counterpart_handoff_requires_an_exact_policy_key() {
    for scenario in SCENARIOS {
        let analysis =
            serde_json::to_value(analyze_management_point_fixture(&load_bundle(scenario))).unwrap();
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

    let unrelated = serde_json::to_value(analyze_management_point_fixture(&load_bundle(
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

    let failed = serde_json::to_value(analyze_management_point_fixture(&load_bundle(
        "policy-failure",
    )))
    .expect("policy failure analysis");
    let failed_fact = failed["counterpartReadyFacts"]
        .as_array()
        .expect("counterpart facts")
        .iter()
        .find(|fact| fact["state"] == "failed")
        .expect("failed policy counterpart fact");
    assert_eq!(failed_fact["classification"], "confirmedFailure");
    assert_eq!(failed_fact["confidence"], "high");
    assert_eq!(
        failed_fact["terminalEvidence"], failed_fact["evidence"],
        "a failed handoff must identify its terminal evidence"
    );
}

#[test]
fn failed_counterpart_handoff_cites_the_decided_terminal_failure() {
    let mut bundle = load_bundle("policy-failure");
    let later_outcome = bundle
        .evidence
        .iter_mut()
        .find(|evidence| {
            evidence.reference.artifact_id == "mp-policy-response-current"
                && evidence.reference.line_start == Some(5)
        })
        .expect("later policy evidence");
    later_outcome.message = "Record outcome succeeded RequestId={28555555-5555-5555-5555-555555555555} PolicyId={a8555555-5555-5555-5555-555555555555} ClientHandle={safe:client:mp-policy-primary-05} SiteCode={LAB} MPHandle={safe:mp:lab-mp-01}".to_owned();

    let analysis = analysis_value(&bundle);
    let failed_fact = analysis["counterpartReadyFacts"]
        .as_array()
        .expect("counterpart facts")
        .iter()
        .find(|fact| fact["state"] == "failed")
        .expect("failed policy counterpart fact");

    assert_eq!(failed_fact["phase"], "respond");
    assert_eq!(failed_fact["evidence"]["lineStart"], 2);
    assert_eq!(
        failed_fact["terminalEvidence"], failed_fact["evidence"],
        "a later successful fact cannot masquerade as terminal failure evidence"
    );
}

#[test]
fn management_point_catalog_declares_every_reducer_source() {
    let mp_produced = declared_source_catalog()
        .into_iter()
        .filter(|source| {
            source.role == SccmRole::ManagementPoint
                && source.family == SccmArtifactFamily::ManagementPoint
        })
        .map(|source| (source.basename, source.logical_name))
        .collect::<BTreeSet<_>>();
    let expected_mp_produced = [
        ("MP_CliReg.log", "mpCliReg"),
        ("MP_GetAuth.log", "mpGetAuth"),
        ("MP_GetPolicy.log", "mpGetPolicy"),
        ("MP_Location.log", "mpLocation"),
        ("MP_RegistrationManager.log", "mpRegistrationManager"),
    ]
    .into_iter()
    .map(|(basename, logical_name)| (basename.to_owned(), logical_name.to_owned()))
    .collect::<BTreeSet<_>>();
    assert_eq!(
        mp_produced, expected_mp_produced,
        "the MP-produced reducer sources are exactly the MP_* family"
    );

    let control = declared_source_catalog()
        .into_iter()
        .find(|source| source.basename == "mpcontrol.log")
        .expect("mpcontrol.log stays declared in the shared catalog");
    assert_eq!(
        control.role,
        SccmRole::SiteServer,
        "mpcontrol.log is produced by the site-server MP control workflow"
    );
    assert_eq!(control.family, SccmArtifactFamily::ManagementPoint);

    let subject_row = declared_server_source_catalog()
        .iter()
        .find(|spec| {
            spec.source_id == "server-mp-policy" && spec.producer_role == SccmRole::SiteServer
        })
        .expect("subject-scoped mpcontrol server source row");
    assert_eq!(
        subject_row.workflow_subject_role,
        Some(SccmRole::ManagementPoint),
        "mpcontrol is evidence about the Management Point, not by it"
    );
    assert_eq!(subject_row.logical_names, ["mpcontrol"].as_slice());
}

fn analysis_value(bundle: &SccmManagementPointBundle) -> Value {
    serde_json::to_value(analyze_management_point_fixture(bundle)).expect("analysis JSON")
}

fn assert_no_high_success(value: &Value, context: &str) {
    assert!(
        value["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .all(|transaction| {
                transaction["state"] != "succeeded" || transaction["confidence"] != "high"
            }),
        "{context}: untrusted evidence produced high success"
    );
}

#[test]
fn management_point_terminal_failure_requires_a_nonzero_result_and_an_exact_event_marker() {
    let mut zero_result = load_bundle("auth-failure");
    let failed = zero_result
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Authenticate failed terminal"))
        .expect("auth failure evidence");
    failed.message = failed.message.replace("Result=0x80010001", "Status=0");
    let analysis = analysis_value(&zero_result);
    assert!(
        analysis["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .all(|transaction| transaction["classification"] != "confirmedFailure"),
        "zero status is not a terminal MP failure"
    );

    let mut narrated_success = load_bundle("healthy-policy");
    let response = narrated_success
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Respond succeeded after retry"))
        .expect("response success evidence");
    response.message = response.message.replace(
        "Respond succeeded after retry",
        "Do not treat Respond succeeded after retry text as an outcome",
    );
    assert_no_high_success(
        &analysis_value(&narrated_success),
        "narrated event-marker text",
    );
}

#[test]
fn management_point_exact_keys_reject_embedded_labels_suffixes_nil_ids_and_unsafe_handles() {
    let base = load_bundle("healthy-policy");

    let mut embedded_label = base.clone();
    for evidence in &mut embedded_label.evidence {
        evidence.message = evidence.message.replace("RequestId=", "NotRequestId=");
    }
    assert!(
        analysis_value(&embedded_label)["transactions"]
            .as_array()
            .expect("transactions")
            .is_empty(),
        "an embedded RequestId label is not an exact key"
    );

    let mut suffixed_uuid = base.clone();
    for evidence in &mut suffixed_uuid.evidence {
        evidence.message = evidence.message.replace(
            "RequestId={28111111-1111-1111-1111-111111111111}",
            "RequestId={28111111-1111-1111-1111-111111111111}suffix",
        );
    }
    assert!(
        analysis_value(&suffixed_uuid)["transactions"]
            .as_array()
            .expect("transactions")
            .is_empty(),
        "a UUID with trailing token data is not exact"
    );

    let mut nil_uuid = base.clone();
    for evidence in &mut nil_uuid.evidence {
        evidence.message = evidence.message.replace(
            "28111111-1111-1111-1111-111111111111",
            "00000000-0000-0000-0000-000000000000",
        );
    }
    assert!(
        analysis_value(&nil_uuid)["transactions"]
            .as_array()
            .expect("transactions")
            .is_empty(),
        "the nil UUID is not a usable request key"
    );

    let mut unsafe_handle = base;
    for evidence in &mut unsafe_handle.evidence {
        evidence.message = evidence
            .message
            .replace("safe:client:mp-healthy-01", "safe:client:..private");
    }
    assert!(
        analysis_value(&unsafe_handle)["transactions"]
            .as_array()
            .expect("transactions")
            .is_empty(),
        "an unsafe client handle is not correlation eligible"
    );
}

#[test]
fn management_point_evidence_references_must_fit_the_captured_physical_source() {
    let mut bundle = load_bundle("healthy-policy");
    let outcome = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Record outcome succeeded"))
        .expect("outcome evidence");
    outcome.reference.line_end = Some(999);
    outcome.reference.entry_id = format!("{}:4-999", outcome.reference.artifact_id);
    outcome.evidence_id = outcome.reference.entry_id.clone();

    let analysis = analysis_value(&bundle);
    assert_no_high_success(&analysis, "out-of-bounds physical citation");
    assert!(
        !serde_json::to_string(&analysis)
            .expect("analysis JSON")
            .contains("\"lineEnd\":999"),
        "an out-of-bounds citation reached public output"
    );
}

#[test]
fn management_point_noncaptured_sources_are_coverage_states_not_malformed_evidence() {
    for coverage in [
        SccmCoverageState::AccessDenied,
        SccmCoverageState::Capped,
        SccmCoverageState::Skipped,
        SccmCoverageState::Unsupported,
        SccmCoverageState::ParseFailed,
    ] {
        let mut bundle = load_bundle("healthy-policy");
        let policy_artifact_id = bundle
            .sources
            .iter_mut()
            .find(|source| source.source_group == "server-mp-policy")
            .map(|source| {
                source.artifact.coverage = coverage.clone();
                source.artifact.artifact_id.clone()
            })
            .expect("policy source");
        let analysis = analysis_value(&bundle);

        assert_no_high_success(&analysis, "noncaptured policy source");
        assert!(
            analysis["coverageGaps"]
                .as_array()
                .expect("coverage gaps")
                .iter()
                .any(|gap| {
                    gap["logicalArtifactId"] == "server-mp-policy"
                        && gap["state"] == serde_json::to_value(&coverage).expect("coverage state")
                }),
            "{coverage:?}: exact coverage state must be retained"
        );
        assert!(
            analysis["sourceLocalObservations"]
                .as_array()
                .expect("source-local observations")
                .iter()
                .all(|observation| {
                    observation["classification"] != "lowConfidenceSymptom"
                        || observation["evidence"]
                            .as_array()
                            .expect("observation evidence")
                            .iter()
                            .all(|reference| reference["artifactId"] != policy_artifact_id)
                }),
            "{coverage:?}: noncaptured bytes were misclassified as malformed evidence"
        );
    }
}

#[test]
fn management_point_profile_topology_source_and_time_mutations_fail_closed() {
    let base = load_bundle("healthy-policy");

    for version in [None, Some("5.00.UNKNOWN.0000")] {
        let mut bundle = base.clone();
        for source in &mut bundle.sources {
            source.artifact.configmgr_version = version.map(str::to_owned);
        }
        assert!(
            analysis_value(&bundle)["transactions"]
                .as_array()
                .expect("transactions")
                .is_empty(),
            "{version:?}: unknown profile emitted an exact transaction"
        );
    }

    let mut topology_mismatch = base.clone();
    topology_mismatch.topology.management_point_host_handle =
        "safe:mp:other-management-point".to_owned();
    assert!(
        analysis_value(&topology_mismatch)["transactions"]
            .as_array()
            .expect("transactions")
            .is_empty(),
        "incompatible topology emitted a transaction"
    );

    let mut wrong_source = base.clone();
    let policy_source = wrong_source
        .sources
        .iter_mut()
        .find(|source| source.producer == "MP_GetPolicy")
        .expect("policy source");
    policy_source.producer = "MP_GetAuth".to_owned();
    assert_no_high_success(&analysis_value(&wrong_source), "wrong source ownership");

    let mut invalid_offset = base.clone();
    let response = invalid_offset
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Respond succeeded after retry"))
        .expect("response success");
    response.timestamp.ordering_state =
        cmtraceopen_parser::sccm::SccmTimeOrderingState::OffsetInvalid;
    response.timestamp.utc_millis = None;
    assert_no_high_success(&analysis_value(&invalid_offset), "invalid offset");

    let mut inverted = base;
    let receive_millis = inverted
        .evidence
        .iter()
        .find(|evidence| evidence.message.contains("Receive request succeeded"))
        .and_then(|evidence| evidence.timestamp.utc_millis)
        .expect("receive UTC");
    let outcome = inverted
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Record outcome succeeded"))
        .expect("outcome evidence");
    outcome.timestamp.utc_millis = Some(receive_millis - 1);
    assert_no_high_success(&analysis_value(&inverted), "phase time inversion");
}

#[test]
fn management_point_output_never_exports_input_paths_hosts_or_raw_messages() {
    let mut bundle = load_bundle("healthy-policy");
    for source in &mut bundle.sources {
        source.artifact.original_path =
            Some(r"C:\Users\Adam.Gell\private\MP_GetPolicy.log".to_owned());
        source.artifact.host = Some("LAB-MP01.private.example".to_owned());
    }
    let evidence = bundle.evidence.first_mut().expect("fixture evidence");
    evidence
        .message
        .push_str(" AuthorizationHeader=Bearer private-secret; QueryHandle=SELECT private_object");

    let serialized =
        serde_json::to_string(&analyze_management_point_fixture(&bundle)).expect("analysis JSON");
    for prohibited in [
        "Adam.Gell",
        "LAB-MP01",
        "private.example",
        "private-secret",
        "private_object",
        "AuthorizationHeader",
        "QueryHandle",
    ] {
        assert!(
            !serialized.contains(prohibited),
            "public MP output leaked {prohibited}"
        );
    }
}

#[test]
fn management_point_duplicate_artifact_ids_are_ambiguous_not_order_authoritative() {
    let mut first = load_bundle("healthy-policy");
    let mut duplicate = first
        .sources
        .iter()
        .find(|source| source.producer == "MP_GetPolicy")
        .expect("policy source")
        .clone();
    duplicate.artifact.configmgr_version = Some("5.00.UNKNOWN.0000".to_owned());
    first.sources.push(duplicate);

    let mut second = first.clone();
    second.sources.reverse();
    let first_analysis = analysis_value(&first);
    let second_analysis = analysis_value(&second);
    assert_eq!(
        first_analysis, second_analysis,
        "duplicate artifact handling must not depend on vector order"
    );
    assert_no_high_success(&first_analysis, "duplicate artifact identity");
}

#[test]
fn management_point_site_codes_are_canonicalized_for_counterpart_keys() {
    let mut bundle = load_bundle("healthy-policy");
    bundle.topology.site_code = "lab".to_owned();
    for evidence in &mut bundle.evidence {
        evidence.message = evidence.message.replace("SiteCode={LAB}", "SiteCode={lab}");
    }

    let analysis = analysis_value(&bundle);
    assert_eq!(analysis["transactions"][0]["state"], "succeeded");
    assert_eq!(analysis["transactions"][0]["key"]["siteCode"], "LAB");
    assert_eq!(
        analysis["counterpartReadyFacts"][0]["key"]["siteCode"],
        "LAB"
    );
}

#[test]
fn management_point_missing_captured_phase_is_not_reported_as_an_absent_artifact() {
    let mut bundle = load_bundle("healthy-policy");
    let response = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Respond succeeded after retry"))
        .expect("response success evidence");
    response.message = response.message.replace(
        "Respond succeeded after retry",
        "Respond candidate retained without an outcome",
    );
    let deferred = bundle
        .evidence
        .iter_mut()
        .find(|evidence| {
            evidence
                .message
                .contains("Respond deferred retry scheduled")
        })
        .expect("response deferred evidence");
    deferred.message = deferred.message.replace(
        "Respond deferred retry scheduled",
        "Respond candidate retained without a disposition",
    );

    let analysis = analysis_value(&bundle);
    assert_no_high_success(&analysis, "missing captured response outcome");
    assert!(
        analysis["coverageGaps"]
            .as_array()
            .expect("coverage gaps")
            .iter()
            .any(|gap| {
                gap["logicalArtifactId"] == "server-mp-policy" && gap["state"] == "parseFailed"
            }),
        "captured-but-unusable phase evidence is not an absent artifact"
    );
}

#[test]
fn management_point_conflicting_duplicate_key_labels_fail_closed() {
    let mut accepted = Vec::new();
    for (label, duplicate) in [
        (
            "RequestId",
            "RequestId={28999999-9999-9999-9999-999999999999}",
        ),
        (
            "PolicyId",
            "PolicyId={a8999999-9999-9999-9999-999999999999}",
        ),
        ("ClientHandle", "ClientHandle={safe:client:mp-other-99}"),
        ("SiteCode", "SiteCode={XYZ}"),
        ("MPHandle", "MPHandle={safe:mp:other-mp-99}"),
    ] {
        let mut bundle = load_bundle("healthy-policy");
        for evidence in &mut bundle.evidence {
            evidence.message.push(' ');
            evidence.message.push_str(duplicate);
        }
        let analysis = analysis_value(&bundle);
        if analysis["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .any(|transaction| {
                transaction["state"] == "succeeded" && transaction["confidence"] == "high"
            })
        {
            accepted.push(label);
        }
    }

    let mut failure = load_bundle("auth-failure");
    failure
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Authenticate failed terminal"))
        .expect("terminal authentication failure")
        .message
        .push_str(" Result=0x00000000");
    if analysis_value(&failure)["transactions"]
        .as_array()
        .expect("transactions")
        .iter()
        .any(|transaction| {
            transaction["state"] == "failed"
                && transaction["classification"] == "confirmedFailure"
                && transaction["confidence"] == "high"
        })
    {
        accepted.push("Result");
    }

    assert!(
        accepted.is_empty(),
        "conflicting duplicate exact-profile labels were accepted: {accepted:?}"
    );
}

#[test]
fn management_point_later_deferred_phase_invalidates_earlier_success() {
    let mut bundle = load_bundle("healthy-policy");
    let deferred_index = bundle
        .evidence
        .iter()
        .position(|evidence| {
            evidence
                .message
                .contains("Respond deferred retry scheduled")
        })
        .expect("deferred response");
    let success_index = bundle
        .evidence
        .iter()
        .position(|evidence| evidence.message.contains("Respond succeeded after retry"))
        .expect("later response");
    bundle.evidence[deferred_index].message = bundle.evidence[deferred_index].message.replace(
        "Respond deferred retry scheduled",
        "Respond succeeded after retry",
    );
    bundle.evidence[success_index].message = bundle.evidence[success_index].message.replace(
        "Respond succeeded after retry",
        "Respond deferred retry scheduled",
    );

    assert_no_high_success(
        &analysis_value(&bundle),
        "a later deferred phase observation",
    );
}

#[test]
fn management_point_event_markers_require_an_exact_delimiter() {
    let mut bundle = load_bundle("healthy-policy");
    let outcome = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Record outcome succeeded"))
        .expect("record outcome");
    outcome.message = outcome
        .message
        .replace("Record outcome succeeded", "Record outcome succeededness");

    assert_no_high_success(
        &analysis_value(&bundle),
        "an event marker with an alphanumeric suffix",
    );
}

#[test]
fn management_point_conflicting_evidence_identity_reuse_fails_closed() {
    let mut bundle = load_bundle("healthy-policy");
    let mut conflicting = bundle.evidence.clone();
    for evidence in &mut conflicting {
        evidence.message = evidence
            .message
            .replace(
                "28111111-1111-1111-1111-111111111111",
                "28999999-9999-9999-9999-999999999999",
            )
            .replace(
                "a8111111-1111-1111-1111-111111111111",
                "a8999999-9999-9999-9999-999999999999",
            )
            .replace("safe:client:mp-healthy-01", "safe:client:mp-conflicting-99");
    }
    bundle.evidence.extend(conflicting);

    let first = analysis_value(&bundle);
    let high_successes = first["transactions"]
        .as_array()
        .expect("transactions")
        .iter()
        .filter(|transaction| {
            transaction["state"] == "succeeded" && transaction["confidence"] == "high"
        })
        .count();
    assert_eq!(
        high_successes, 0,
        "one physical evidence identity cannot authorize conflicting exact-key transactions"
    );

    bundle.evidence.reverse();
    assert_eq!(
        analysis_value(&bundle),
        first,
        "ambiguous evidence identities must have deterministic public handling"
    );
}

#[test]
fn management_point_overlapping_physical_ranges_fail_closed_deterministically() {
    let mut bundle = load_bundle("healthy-policy");
    for evidence in &mut bundle.evidence {
        if evidence.reference.artifact_id != "mp-healthy-policy-current" {
            continue;
        }
        match evidence.reference.line_start {
            Some(1) => {
                evidence.reference.line_start = Some(2);
                evidence.reference.line_end = Some(3);
                evidence.reference.entry_id = "mp-review-overlap-a".to_owned();
                evidence.evidence_id = evidence.reference.entry_id.clone();
            }
            Some(2) => {
                evidence.reference.line_start = Some(3);
                evidence.reference.line_end = Some(4);
                evidence.reference.entry_id = "mp-review-overlap-b".to_owned();
                evidence.evidence_id = evidence.reference.entry_id.clone();
            }
            _ => {}
        }
    }

    let first = analysis_value(&bundle);
    assert_no_high_success(&first, "overlapping physical logical records");

    bundle.evidence.reverse();
    assert_eq!(
        analysis_value(&bundle),
        first,
        "overlap quarantine must not depend on bundle order"
    );
}

#[test]
fn management_point_exact_labels_reject_hyphenated_prefixes() {
    let mut accepted = Vec::new();
    for label in [
        "RequestId",
        "PolicyId",
        "ClientHandle",
        "SiteCode",
        "MPHandle",
    ] {
        let mut bundle = load_bundle("healthy-policy");
        for evidence in &mut bundle.evidence {
            evidence.message = evidence
                .message
                .replace(&format!("{label}="), &format!("Not-{label}="));
        }
        if analysis_value(&bundle)["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .any(|transaction| {
                transaction["state"] == "succeeded" && transaction["confidence"] == "high"
            })
        {
            accepted.push(label);
        }
    }

    let mut failure = load_bundle("auth-failure");
    let terminal = failure
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Authenticate failed terminal"))
        .expect("terminal authentication failure");
    terminal.message = terminal.message.replace("Result=", "Not-Result=");
    if analysis_value(&failure)["transactions"]
        .as_array()
        .expect("transactions")
        .iter()
        .any(|transaction| {
            transaction["state"] == "failed"
                && transaction["classification"] == "confirmedFailure"
                && transaction["confidence"] == "high"
        })
    {
        accepted.push("Result");
    }

    assert!(
        accepted.is_empty(),
        "hyphen-prefixed exact-profile labels were accepted: {accepted:?}"
    );
}

#[test]
fn successful_counterpart_handoff_requires_the_decisive_fact_to_prove_the_policy_key() {
    let mut bundle = load_bundle("healthy-policy");
    let deferred = bundle
        .evidence
        .iter_mut()
        .find(|evidence| {
            evidence
                .message
                .contains("Respond deferred retry scheduled")
        })
        .expect("deferred response");
    deferred.message = deferred.message.replace(
        "Respond deferred retry scheduled",
        "Respond succeeded before recovered outcome",
    );

    let earlier_outcome = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Respond succeeded after retry"))
        .expect("earlier response");
    earlier_outcome.message = earlier_outcome.message.replace(
        "Respond succeeded after retry",
        "Record outcome failed terminal Result=0x80004005",
    );

    let decisive_success = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Record outcome succeeded"))
        .expect("decisive successful outcome");
    decisive_success.message = decisive_success
        .message
        .replace(" PolicyId={a8111111-1111-1111-1111-111111111111}", "");

    let analysis = analysis_value(&bundle);
    let transaction = analysis["transactions"]
        .as_array()
        .expect("transactions")
        .iter()
        .find(|transaction| transaction["state"] == "succeeded")
        .expect("recovered successful transaction");
    assert_eq!(transaction["phase"], "recordOutcome");
    assert_eq!(transaction["confidence"], "high");

    assert!(
        analysis["counterpartReadyFacts"]
            .as_array()
            .expect("counterpart facts")
            .is_empty(),
        "a decisive record without PolicyId cannot prove an exact policy counterpart key"
    );

    let baseline = analysis_value(&load_bundle("healthy-policy"));
    let counterpart = baseline["counterpartReadyFacts"]
        .as_array()
        .expect("counterpart facts")
        .iter()
        .find(|fact| fact["state"] == "succeeded")
        .expect("baseline successful counterpart");
    assert_eq!(counterpart["classification"], "success");
    assert_eq!(
        counterpart["evidence"]["lineStart"], 4,
        "the policy-bearing decisive success must remain correlation eligible"
    );
    assert!(
        counterpart["terminalEvidence"].is_null(),
        "successful handoff cannot advertise terminal-failure evidence"
    );
}

#[test]
fn management_point_result_codes_must_match_the_event_outcome() {
    let mut nonzero_success = load_bundle("healthy-policy");
    nonzero_success
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Record outcome succeeded"))
        .expect("successful outcome")
        .message
        .push_str(" Result=0x80004005");
    assert_no_high_success(
        &analysis_value(&nonzero_success),
        "nonzero terminal result on a success marker",
    );

    let mut zero_success = load_bundle("healthy-policy");
    zero_success
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Record outcome succeeded"))
        .expect("successful outcome")
        .message
        .push_str(" Result=0x00000000");
    let zero_success_analysis = analysis_value(&zero_success);
    assert!(
        zero_success_analysis["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .any(|transaction| {
                transaction["state"] == "succeeded" && transaction["confidence"] == "high"
            }),
        "an explicit zero result must remain compatible with success"
    );

    let mut zero_failure = load_bundle("auth-failure");
    let failure = zero_failure
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Authenticate failed terminal"))
        .expect("terminal authentication failure");
    failure.message = failure
        .message
        .replace("Result=0x80010001", "Result=0x00000000");
    assert!(
        analysis_value(&zero_failure)["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .all(|transaction| transaction["classification"] != "confirmedFailure"),
        "an explicit zero result cannot substantiate a terminal failure"
    );
}

#[test]
fn management_point_transaction_citations_do_not_span_rejected_records() {
    let mut bundle = load_bundle("healthy-policy");
    let rejected = bundle
        .evidence
        .iter_mut()
        .find(|evidence| {
            evidence.reference.artifact_id == "mp-healthy-policy-current"
                && evidence.reference.line_start == Some(2)
        })
        .expect("second policy record");
    rejected.message = rejected
        .message
        .replace("RequestId=", "MalformedRequestId=");

    let first = analysis_value(&bundle);
    let transaction = first["transactions"]
        .as_array()
        .expect("transactions")
        .iter()
        .find(|transaction| {
            transaction["state"] == "succeeded" && transaction["confidence"] == "high"
        })
        .expect("remaining exact records still prove success");
    assert!(
        transaction["evidence"]
            .as_array()
            .expect("transaction evidence")
            .iter()
            .filter(|reference| reference["artifactId"] == "mp-healthy-policy-current")
            .all(|reference| {
                let start = reference["lineStart"].as_u64().expect("line start");
                let end = reference["lineEnd"].as_u64().expect("line end");
                !(start <= 2 && 2 <= end)
            }),
        "transaction citation absorbed a rejected logical record"
    );

    bundle.evidence.reverse();
    assert_eq!(
        analysis_value(&bundle),
        first,
        "disjoint exact citations must be stable under bundle reversal"
    );
}

#[test]
fn site_server_mpcontrol_never_shapes_management_point_coverage_states() {
    for control_coverage in [SccmCoverageState::Captured, SccmCoverageState::AccessDenied] {
        let mut bundle = load_bundle("iis-supplemental");
        bundle
            .evidence
            .retain(|evidence| evidence.reference.artifact_id != "mp-iis-policy-current");
        bundle
            .sources
            .retain(|source| source.artifact.artifact_id != "mp-iis-policy-current");
        let control = bundle
            .sources
            .iter_mut()
            .find(|source| source.artifact.artifact_id == "mp-iis-control-current")
            .expect("subject-scoped mpcontrol source");
        assert_eq!(
            control.artifact.role,
            SccmRole::SiteServer,
            "the fixture must model mpcontrol as site-server-produced"
        );
        control.artifact.coverage = control_coverage.clone();

        let analysis = analysis_value(&bundle);
        assert_eq!(
            analysis["coverageGaps"],
            json!([{
                "logicalArtifactId": "server-mp-policy",
                "role": "managementPoint",
                "state": "absent",
            }]),
            "{control_coverage:?}: a site-server mpcontrol capture must not \
             masquerade as MP-produced policy coverage"
        );
    }
}

#[test]
fn mp_produced_mpcontrol_claims_fail_closed_as_rejected_evidence() {
    let mut bundle = load_bundle("iis-supplemental");
    let control = bundle
        .sources
        .iter_mut()
        .find(|source| source.artifact.artifact_id == "mp-iis-control-current")
        .expect("subject-scoped mpcontrol source");
    control.artifact.role = SccmRole::ManagementPoint;
    for evidence in &mut bundle.evidence {
        if evidence.reference.artifact_id == "mp-iis-control-current" {
            evidence.role = SccmRole::ManagementPoint;
        }
    }

    let analysis = analysis_value(&bundle);
    let rejected = analysis["sourceLocalObservations"]
        .as_array()
        .expect("source-local observations")
        .iter()
        .find(|observation| {
            observation["classification"] == "lowConfidenceSymptom"
                && observation["correlationEligible"] == false
                && observation["evidence"]
                    .as_array()
                    .expect("observation evidence")
                    .iter()
                    .any(|reference| reference["artifactId"] == "mp-iis-control-current")
        })
        .expect(
            "an mpcontrol source claiming MP production is a contract violation \
             and must surface as rejected evidence, not silent supplemental input",
        );
    assert_eq!(
        observation_request_groups(rejected),
        vec!["server-mp-policy"],
        "the rejected mpcontrol record belongs to the policy group, so its \
         remediation hint must request the MP-produced policy logs"
    );
}

fn observation_request_groups(observation: &Value) -> Vec<&str> {
    observation["nextArtifacts"]
        .as_array()
        .expect("observation requests")
        .iter()
        .map(|request| {
            request["logicalArtifactId"]
                .as_str()
                .expect("request logical artifact id")
        })
        .collect()
}

#[test]
fn rejected_records_request_their_owning_source_group() {
    let mut bundle = load_bundle("healthy-policy");
    bundle
        .sources
        .iter_mut()
        .find(|source| source.artifact.artifact_id == "mp-healthy-auth-current")
        .expect("auth source")
        .fragment_complete = Some(false);

    let analysis = analysis_value(&bundle);
    let observations = analysis["sourceLocalObservations"]
        .as_array()
        .expect("source-local observations");

    let policy_rejected = observations
        .iter()
        .find(|observation| {
            observation["evidence"]
                .as_array()
                .expect("observation evidence")
                .iter()
                .any(|reference| reference["artifactId"] == "mp-healthy-policy-current")
        })
        .expect("rejected policy-group records must surface");
    assert_eq!(
        observation_request_groups(policy_rejected),
        vec!["server-mp-policy"],
        "a rejected policy-group record must request its own group, \
         not MP_GetAuth.log"
    );

    let auth_rejected = observations
        .iter()
        .find(|observation| {
            observation["evidence"]
                .as_array()
                .expect("observation evidence")
                .iter()
                .any(|reference| reference["artifactId"] == "mp-healthy-registration-current")
        })
        .expect("rejected auth-group records must surface");
    assert_eq!(
        observation_request_groups(auth_rejected),
        vec!["server-mp-auth"],
        "a rejected auth-group record keeps requesting the auth group"
    );
}
