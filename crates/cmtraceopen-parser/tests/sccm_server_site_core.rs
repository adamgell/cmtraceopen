//! Contract tests for the issue #327 site-core and status-system reducer.
//!
//! The merged fixture corpus under `tests/fixtures/sccm/server/site_core` is the
//! specification: every scenario declares the transactions, findings, coverage
//! states and evidence citations `analyze_site_core` must produce. These tests
//! read that corpus and assert the reducer reproduces it exactly.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_site_core, SccmSiteCoreBundle, SccmSiteCoreSource, SccmSiteCoreTopology,
};
use cmtraceopen_parser::sccm::{
    normalize_ccm_artifact, SccmArtifact, SccmCoverageState, SccmEvidence, SccmRole, SccmRotation,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/server/site_core";
const SCENARIOS: &[&str] = &[
    "component-failure",
    "contradictory",
    "healthy",
    "inbox-backlog",
    "incomplete",
    "malformed",
    "recovery",
    "rotation-boundary",
    "status-processing-failure",
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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureArtifact {
    artifact_id: String,
    role: String,
    source_group: String,
    original_basename: String,
    rotation: FixtureRotation,
    rotation_lineage: String,
    capture_state: String,
    capture_limit_bytes: Option<u64>,
    source_version: Option<String>,
    collected_utc: Option<String>,
    encoding: Option<String>,
    relative_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureRotation {
    kind: String,
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
        "loUnderscore" => SccmRotation::LoUnderscore,
        other => panic!("unsupported site-core fixture rotation {other}"),
    }
}

fn load_bundle(scenario: &str) -> SccmSiteCoreBundle {
    let directory = fixture_directory(scenario);
    let manifest: FixtureManifest =
        serde_json::from_value(load_json(&directory.join("manifest.json")))
            .expect("fixture manifest must match its declared contract");

    let mut sources = Vec::new();
    let mut evidence = Vec::new();
    for source in manifest.artifacts {
        let producer_role = match source.role.as_str() {
            "siteServer" => SccmRole::SiteServer,
            other => panic!("unsupported site-core fixture producer role {other}"),
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

        let physical_line_end = source.relative_path.map(|relative_path| {
            let content = fs::read_to_string(directory.join(relative_path))
                .expect("captured site-core evidence must be readable UTF-8");
            let line_count = u32::try_from(content.lines().count())
                .expect("synthetic fixture line count must fit in u32");
            evidence.extend(normalize_ccm_artifact(artifact.clone(), &content));
            line_count.max(1)
        });

        sources.push(SccmSiteCoreSource {
            artifact,
            source_group: source.source_group,
            rotation_lineage: source.rotation_lineage,
            fragment_complete: source.rotation.fragment_complete,
            physical_line_end,
            capture_limit_bytes: source.capture_limit_bytes,
        });
    }

    sources.sort_by(|left, right| left.artifact.artifact_id.cmp(&right.artifact.artifact_id));
    evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    SccmSiteCoreBundle {
        topology: SccmSiteCoreTopology {
            site_code: manifest.topology.site_code,
        },
        sources,
        evidence,
    }
}

fn analysis_value(bundle: &SccmSiteCoreBundle) -> Value {
    serde_json::to_value(analyze_site_core(bundle))
        .expect("site-core analysis must serialize under the shared finding contract")
}

/// The corpus omits `completeLogicalRecord` on the rotation-boundary coverage
/// gap evidence while declaring it on the malformed and capped gaps. The
/// reducer emits the flag uniformly, so gap evidence is compared without it and
/// the stronger uniform invariant is asserted separately.
fn gap_evidence_without_completeness(value: &Value) -> Value {
    let mut object = value
        .as_object()
        .expect("coverage gap evidence must be an object")
        .clone();
    object.remove("completeLogicalRecord");
    Value::Object(object)
}

fn normalized_coverage_gaps(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .expect("coverage gaps must be an array")
        .iter()
        .map(|gap| {
            let mut object = gap
                .as_object()
                .expect("coverage gap must be an object")
                .clone();
            if let Some(evidence) = object.get("evidence") {
                let normalized = gap_evidence_without_completeness(evidence);
                object.insert("evidence".to_owned(), normalized);
            }
            Value::Object(object)
        })
        .collect()
}

fn projected_section(value: &Value, key: &str) -> Value {
    value
        .get(key)
        .cloned()
        .unwrap_or_else(|| panic!("analysis must expose {key}"))
}

fn result_projection(value: &Value) -> Value {
    let entry = value.as_object().expect("result must be an object");
    json!({
        "resultId": entry["resultId"],
        "transactionKey": entry["transactionKey"],
        "state": entry["state"],
        "lastSuccessfulPhase": entry["lastSuccessfulPhase"],
        "findingClass": entry["findingClass"],
        "confidence": entry["confidence"],
        "confidenceCeiling": entry["confidenceCeiling"],
        "evidence": entry["evidence"],
        "coverageGapArtifactIds": entry["coverageGapArtifactIds"],
        "nextArtifacts": entry["nextArtifacts"],
    })
}

fn observation_projection(value: &Value) -> Value {
    let entry = value.as_object().expect("observation must be an object");
    json!({
        "observationId": entry["observationId"],
        "state": entry["state"],
        "lastSuccessfulPhase": entry["lastSuccessfulPhase"],
        "findingClass": entry["findingClass"],
        "confidence": entry["confidence"],
        "confidenceCeiling": entry["confidenceCeiling"],
        "evidence": entry["evidence"],
        "coverageGapArtifactIds": entry["coverageGapArtifactIds"],
        "nextArtifacts": entry["nextArtifacts"],
    })
}

fn project_all(value: &Value, key: &str, projector: fn(&Value) -> Value) -> Vec<Value> {
    projected_section(value, key)
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(projector)
        .collect()
}

fn expected_all(expected: &Value, key: &str, projector: fn(&Value) -> Value) -> Vec<Value> {
    expected[key]
        .as_array()
        .unwrap_or_else(|| panic!("expected {key} must be an array"))
        .iter()
        .map(projector)
        .collect()
}

#[test]
fn site_core_reproduces_every_merged_corpus_scenario() {
    for scenario in SCENARIOS {
        let bundle = load_bundle(scenario);
        let analysis = analysis_value(&bundle);
        let expected = load_json(&fixture_directory(scenario).join("expected.json"));

        assert_eq!(
            projected_section(&analysis, "profile"),
            expected["profile"],
            "{scenario}: analyzer profile"
        );
        assert_eq!(
            projected_section(&analysis, "prohibitedClaims"),
            expected["prohibitedClaims"],
            "{scenario}: prohibited claims"
        );
        assert_eq!(
            project_all(&analysis, "results", result_projection),
            expected_all(&expected, "results", result_projection),
            "{scenario}: results"
        );
        assert_eq!(
            project_all(&analysis, "unlinkedObservations", observation_projection),
            expected_all(&expected, "unlinkedObservations", observation_projection),
            "{scenario}: unlinked observations"
        );
        assert_eq!(
            normalized_coverage_gaps(&projected_section(&analysis, "coverageGaps")),
            normalized_coverage_gaps(&expected["coverageGaps"]),
            "{scenario}: coverage gaps"
        );
        assert_eq!(
            analysis["crossSideCorrelationPerformed"],
            Value::Bool(false),
            "{scenario}: the role-local analyzer must never correlate across sides"
        );
    }
}

#[test]
fn every_coverage_gap_evidence_is_marked_incomplete() {
    for scenario in SCENARIOS {
        let analysis = analysis_value(&load_bundle(scenario));
        for gap in analysis["coverageGaps"]
            .as_array()
            .expect("coverage gaps must be an array")
        {
            let Some(evidence) = gap.get("evidence").filter(|value| !value.is_null()) else {
                continue;
            };
            assert_eq!(
                evidence["completeLogicalRecord"],
                Value::Bool(false),
                "{scenario}: coverage gap evidence must never claim a complete logical record"
            );
        }
    }
}

#[test]
fn evidence_flags_stay_within_the_declared_corpus_vocabulary() {
    let allowed = ["artifactId", "entryId", "lineStart", "lineEnd"]
        .into_iter()
        .chain(["terminal", "recovery", "completeLogicalRecord"])
        .collect::<BTreeSet<_>>();
    for scenario in SCENARIOS {
        let analysis = analysis_value(&load_bundle(scenario));
        let mut queue = vec![analysis];
        while let Some(value) = queue.pop() {
            match value {
                Value::Array(items) => queue.extend(items),
                Value::Object(fields) => {
                    if fields.contains_key("entryId") && fields.contains_key("artifactId") {
                        for key in fields.keys() {
                            assert!(
                                allowed.contains(key.as_str()),
                                "{scenario}: evidence carries undeclared field {key}"
                            );
                        }
                    }
                    queue.extend(fields.into_iter().map(|(_, value)| value));
                }
                _ => {}
            }
        }
    }
}

#[test]
fn declared_adversarial_assertions_hold() {
    for scenario in SCENARIOS {
        let expected = load_json(&fixture_directory(scenario).join("expected.json"));
        let Some(assertions) = expected
            .get("adversarialAssertions")
            .and_then(Value::as_object)
        else {
            continue;
        };
        let analysis = analysis_value(&load_bundle(scenario));
        let results = analysis["results"].as_array().expect("results array");

        for (assertion, value) in assertions {
            match assertion.as_str() {
                "resultCount" => assert_eq!(
                    Value::from(results.len()),
                    *value,
                    "{scenario}: result count"
                ),
                "transactionCount" => assert_eq!(
                    Value::from(results.len()),
                    *value,
                    "{scenario}: transaction count"
                ),
                "sameMinuteMayMerge" | "crossComponentRecovery" | "timeOnlyCausalClaim" => {
                    assert_eq!(*value, Value::Bool(false), "{scenario}: {assertion}");
                    let keys = results
                        .iter()
                        .map(|result| result["transactionKey"].to_string())
                        .collect::<Vec<_>>();
                    let distinct = keys.iter().collect::<BTreeSet<_>>();
                    assert_eq!(
                        keys.len(),
                        distinct.len(),
                        "{scenario}: transactions merged across component keys"
                    );
                }
                "phaseMayAdvance" | "terminalMayBeInferred" | "confirmedFailure"
                | "componentKeyAdmitted" | "crossRotationFragmentJoin" => {
                    assert_eq!(*value, Value::Bool(false), "{scenario}: {assertion}");
                    assert!(results.is_empty(), "{scenario}: {assertion}");
                }
                "highConfidenceCause" => {
                    assert_eq!(*value, Value::Bool(false), "{scenario}: {assertion}");
                    for observation in analysis["unlinkedObservations"]
                        .as_array()
                        .expect("observations array")
                    {
                        assert_ne!(
                            observation["confidence"],
                            Value::String("high".to_owned()),
                            "{scenario}: fragment observation claimed high confidence"
                        );
                    }
                }
                other => panic!("{scenario}: unhandled adversarial assertion {other}"),
            }
        }
    }
}

#[test]
fn every_classified_outcome_carries_a_validated_shared_finding() {
    for scenario in SCENARIOS {
        let analysis = analysis_value(&load_bundle(scenario));
        let findings = analysis["findings"].as_array().expect("findings array");

        for subject in analysis["results"]
            .as_array()
            .expect("results array")
            .iter()
            .map(|result| (result["resultId"].clone(), result["findingClass"].clone()))
            .chain(
                analysis["unlinkedObservations"]
                    .as_array()
                    .expect("observations array")
                    .iter()
                    .map(|observation| {
                        (
                            observation["observationId"].clone(),
                            observation["findingClass"].clone(),
                        )
                    }),
            )
        {
            let (subject_id, finding_class) = subject;
            let matching = findings
                .iter()
                .filter(|finding| finding["subjectId"] == subject_id)
                .collect::<Vec<_>>();
            if finding_class.is_null() {
                assert!(
                    matching.is_empty(),
                    "{scenario}: healthy subject {subject_id} must not raise a finding"
                );
                continue;
            }
            assert_eq!(
                matching.len(),
                1,
                "{scenario}: subject {subject_id} must raise exactly one finding"
            );
            let finding = matching[0];
            assert_eq!(
                finding["class"], finding_class,
                "{scenario}: subject {subject_id} finding class"
            );
            assert_eq!(
                finding["role"],
                Value::String("siteServer".to_owned()),
                "{scenario}: subject {subject_id} finding role"
            );
            assert!(
                !finding["evidence"]
                    .as_array()
                    .expect("finding evidence array")
                    .is_empty()
                    || !finding["coverageGaps"]
                        .as_array()
                        .expect("finding coverage gaps array")
                        .is_empty(),
                "{scenario}: subject {subject_id} finding cites nothing"
            );
        }
    }
}

#[test]
fn analysis_is_independent_of_source_and_evidence_order() {
    for scenario in SCENARIOS {
        let bundle = load_bundle(scenario);
        let mut reversed = load_bundle(scenario);
        reversed.sources.reverse();
        reversed.evidence.reverse();

        assert_eq!(
            serde_json::to_string(&analyze_site_core(&bundle)).expect("analysis serializes"),
            serde_json::to_string(&analyze_site_core(&reversed)).expect("analysis serializes"),
            "{scenario}: analysis depends on input order"
        );
    }
}

#[test]
fn duplicate_artifact_identity_is_rejected_rather_than_selected_by_order() {
    let mut bundle = load_bundle("healthy");
    let duplicate = bundle
        .sources
        .iter()
        .find(|source| source.source_group == "server-sitecomp")
        .expect("healthy bundle declares a sitecomp source")
        .clone();
    bundle.sources.push(duplicate);

    let analysis = analyze_site_core(&bundle);
    assert!(
        analysis.results.is_empty(),
        "a duplicated artifact identity must fail closed instead of selecting by vector order"
    );
}

#[test]
fn colliding_evidence_identity_is_rejected() {
    let mut bundle = load_bundle("healthy");
    let collision = bundle
        .evidence
        .first()
        .cloned()
        .expect("healthy bundle carries evidence");
    bundle.evidence.push(collision);

    let analysis = analyze_site_core(&bundle);
    assert!(
        analysis
            .results
            .iter()
            .all(|result| result.evidence.iter().all(|evidence| evidence.entry_id
                != bundle.evidence[0].reference.entry_id)),
        "a colliding evidence identity must never be admitted as a fact"
    );
}

#[test]
fn evidence_from_another_role_is_never_admitted() {
    let mut bundle = load_bundle("healthy");
    for source in &mut bundle.sources {
        source.artifact.role = SccmRole::ManagementPoint;
    }
    for evidence in &mut bundle.evidence {
        evidence.role = SccmRole::ManagementPoint;
    }

    let analysis = analyze_site_core(&bundle);
    assert!(
        analysis.results.is_empty(),
        "site-core must only reduce site-server produced evidence"
    );
}

#[test]
fn unusable_chronology_downgrades_confidence_instead_of_confirming() {
    let mut bundle = load_bundle("component-failure");
    for evidence in &mut bundle.evidence {
        evidence.timestamp.offset_minutes = None;
        evidence.timestamp.utc_millis = None;
        evidence.timestamp.ordering_state =
            cmtraceopen_parser::sccm::SccmTimeOrderingState::OffsetMissing;
    }

    let analysis = analyze_site_core(&bundle);
    let serialized = serde_json::to_value(&analysis).expect("analysis serializes");
    for result in serialized["results"].as_array().expect("results array") {
        assert_ne!(
            result["confidence"],
            Value::String("high".to_owned()),
            "incomparable chronology must not support high confidence"
        );
    }
}

#[test]
fn synthesized_fragment_references_never_collide_with_parsed_records() {
    for scenario in SCENARIOS {
        let bundle = load_bundle(scenario);
        let parsed = bundle
            .evidence
            .iter()
            .map(|evidence: &SccmEvidence| evidence.reference.entry_id.clone())
            .collect::<BTreeSet<_>>();
        let analysis = analysis_value(&bundle);
        for gap in analysis["coverageGaps"]
            .as_array()
            .expect("coverage gaps array")
        {
            let Some(evidence) = gap.get("evidence").filter(|value| !value.is_null()) else {
                continue;
            };
            let entry_id = evidence["entryId"].as_str().expect("gap evidence entry id");
            assert!(
                !parsed.contains(entry_id),
                "{scenario}: synthesized gap reference {entry_id} collides with a parsed record"
            );
        }
    }
}

#[test]
fn requested_next_artifacts_stay_bounded_and_declared() {
    let declared = ["server-sitecomp", "server-status"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    for scenario in SCENARIOS {
        let analysis = analysis_value(&load_bundle(scenario));
        let requests = analysis["artifactRequests"]
            .as_array()
            .expect("artifact requests array");
        for request in requests {
            let logical_name = request["logicalName"]
                .as_str()
                .expect("request logical name");
            assert!(
                declared.contains(logical_name),
                "{scenario}: request names an undeclared source group {logical_name}"
            );
            assert_eq!(
                request["role"],
                Value::String("siteServer".to_owned()),
                "{scenario}: request role"
            );
            let basenames = request["basenames"].as_array().expect("request basenames");
            let rotations = request["rotations"].as_array().expect("request rotations");
            let max_artifacts = request["maxArtifacts"].as_u64().expect("request bound");
            assert!(
                !basenames.is_empty() && !rotations.is_empty() && max_artifacts > 0,
                "{scenario}: request must be a bounded, concrete bundle"
            );
            assert!(
                max_artifacts <= 4,
                "{scenario}: request must stay the smallest next bundle"
            );
        }
        let scoped = requests
            .iter()
            .map(|request| request["scope"].clone())
            .collect::<Vec<_>>();
        assert!(
            scoped
                .iter()
                .all(|scope| scope.as_object().is_some_and(Map::is_empty).eq(&false)),
            "{scenario}: every request must carry a correlation scope"
        );
    }
}
