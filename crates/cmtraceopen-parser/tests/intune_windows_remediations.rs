//! Fixture matrix for `intune::apps::windows::remediations` (issue #360).
//!
//! Every scenario directory holds the shared Intune fixture envelope -- a
//! `manifest.json` naming its artifacts and their capture states, the artifact
//! bytes themselves, and an `expected.json` -- validated by the shared harness
//! in `tests/support/`. On top of that envelope this file asserts the
//! remediation contract the issue defines: detection and remediation are
//! separate stages with separate exit semantics, the local outcome and the
//! Intune reporting outcome are separate answers, and nothing is synthesized
//! from evidence that was not supplied.
//!
//! Expectations are written out rather than snapshotted so a reviewer can see
//! what each scenario asserts and why.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::apps::windows::remediations::{
    analyze_remediation_bundle, redacted_export_projection, RemediationSnapshot,
    RemediationSourceInput,
};
use cmtraceopen_parser::intune::evidence::{IntuneAccessState, IntuneParseState};
use serde_json::{json, Value};
use support::{corpus_root, load_json, mutated, scenario_names, validate_scenario, Failures};

/// The fixture matrix issue #360 requires, pinned so a scenario cannot be
/// quietly dropped or renamed.
const SCENARIOS: [&str; 17] = [
    "detection-compliant-no-remediation",
    "detection-launch-failure",
    "detection-timeout",
    "execution-complete-report-failed",
    "malformed-embedded-json",
    "missing-agent-executor-log",
    "missing-health-scripts-log",
    "privacy-redaction",
    "remediation-exited-nonzero",
    "remediation-launch-failure",
    "remediation-succeeded-post-compliant",
    "remediation-succeeded-post-noncompliant",
    "remediation-timeout",
    "retry-sequence",
    "rotation-split-logical-record",
    "same-minute-distinct-policies",
    "scheduled-and-on-demand-same-policy",
];

const CORPUS: &str = "apps/windows/remediations";

fn scenario_root(scenario: &str) -> PathBuf {
    corpus_root(CORPUS).join(scenario)
}

fn manifest_and_expected(scenario: &str) -> (Value, Value) {
    let root = scenario_root(scenario);
    (
        load_json(&root.join("manifest.json")),
        load_json(&root.join("expected.json")),
    )
}

fn access_state_for(capture_state: &str) -> IntuneAccessState {
    match capture_state {
        "captured" => IntuneAccessState::Available,
        "capped" => IntuneAccessState::Capped,
        "absent" => IntuneAccessState::Missing,
        "accessDenied" => IntuneAccessState::PermissionDenied,
        "skipped" => IntuneAccessState::Skipped,
        "unsupported" => IntuneAccessState::Unsupported,
        "parseFailed" => IntuneAccessState::Failed,
        other => panic!("unknown captureState {other}"),
    }
}

/// Turn a manifest into the bundle a caller would hand the analyzer.
///
/// The test is the only thing here that touches the filesystem: the crate under
/// test never does.
fn inputs_for(root: &Path, manifest: &Value) -> Vec<RemediationSourceInput> {
    manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts")
        .iter()
        .map(|artifact| {
            let access_state =
                access_state_for(artifact["captureState"].as_str().expect("captureState"));
            let readable = matches!(
                access_state,
                IntuneAccessState::Available | IntuneAccessState::Capped
            );
            let content = artifact["relativePath"]
                .as_str()
                .filter(|_| readable)
                .map(|relative| {
                    fs::read_to_string(root.join(relative))
                        .unwrap_or_else(|error| panic!("{relative} is readable: {error}"))
                });
            RemediationSourceInput {
                artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId")
                    .to_owned(),
                file_name: artifact["originalBasename"]
                    .as_str()
                    .expect("originalBasename")
                    .to_owned(),
                file_path: artifact["sanitizedSourcePath"].as_str().map(str::to_owned),
                captured_at_utc: artifact["capturedUtc"].as_str().map(str::to_owned),
                access_state,
                content,
            }
        })
        .collect()
}

fn analyze(scenario: &str) -> (RemediationSnapshot, Value) {
    let root = scenario_root(scenario);
    let (manifest, expected) = manifest_and_expected(scenario);
    let snapshot = analyze_remediation_bundle(&inputs_for(&root, &manifest));
    (snapshot, expected)
}

/// Render a snapshot into the shape `expected.json` states.
///
/// Comparing one projection rather than dozens of field assertions keeps the
/// mismatch report readable and lets the adversarial test reuse the comparison.
fn projection(snapshot: &RemediationSnapshot) -> Value {
    let value = serde_json::to_value(snapshot).expect("snapshot serializes");

    let runs = value["runs"]
        .as_array()
        .expect("runs")
        .iter()
        .map(|run| {
            json!({
                "policyId": run["key"]["policyId"],
                "runId": run["key"]["runId"],
                "invocation": run["key"]["invocation"],
                "detection": {
                    "outcome": run["detection"]["outcome"],
                    "exitRaw": run["detection"]["exitCode"]["raw"],
                    "attempts": run["detection"]["attempts"],
                    "evidence": evidence_ids(&run["detection"]["evidence"]),
                },
                "remediation": {
                    "outcome": run["remediation"]["outcome"],
                    "exitRaw": run["remediation"]["exitCode"]["raw"],
                    "attempts": run["remediation"]["attempts"],
                    "evidence": evidence_ids(&run["remediation"]["evidence"]),
                },
                "postRemediation": {
                    "state": run["postRemediation"]["state"],
                    "exitRaw": run["postRemediation"]["exitCode"]["raw"],
                    "evidence": evidence_ids(&run["postRemediation"]["evidence"]),
                },
                "reporting": {
                    "state": run["reporting"]["state"],
                    "errorRaw": run["reporting"]["errorCode"]["raw"],
                    "evidence": evidence_ids(&run["reporting"]["evidence"]),
                },
                "lastConfirmedPhase": run["lastConfirmedPhase"],
                "confidence": run["confidence"],
                "nextEvidenceRequest": run["nextEvidenceRequest"],
                "retainedFacts": run["retainedFacts"],
            })
        })
        .collect::<Vec<_>>();

    let findings = value["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|finding| {
            json!({
                "findingId": finding["findingId"],
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "evidence": evidence_ids(&finding["evidence"]),
                "coverageGapIds": finding["coverageGapIds"],
            })
        })
        .collect::<Vec<_>>();

    let artifacts = value["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .map(|artifact| {
            json!({
                "artifactId": artifact["artifactId"],
                "sourceKind": artifact["sourceKind"],
                "framedRecords": artifact["framedRecords"],
                "unframedRecords": artifact["unframedRecords"],
            })
        })
        .collect::<Vec<_>>();

    json!({
        "runs": runs,
        "findings": findings,
        "artifacts": artifacts,
        "unkeyedObservations": value["unkeyedObservations"],
    })
}

fn evidence_ids(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|refs| {
            refs.iter()
                .filter_map(|entry| entry["evidenceId"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Compare a reduction against the contract the scenario states.
fn compare(scenario: &str, snapshot: &RemediationSnapshot, expected: &Value) -> Failures {
    let mut failures = Failures::new();
    let actual = projection(snapshot);

    for key in ["runs", "findings", "artifacts", "unkeyedObservations"] {
        failures.require(actual[key] == expected[key], || {
            format!(
                "{scenario}: {key} mismatch\n      expected: {}\n      actual:   {}",
                serde_json::to_string_pretty(&expected[key]).unwrap_or_default(),
                serde_json::to_string_pretty(&actual[key]).unwrap_or_default(),
            )
        });
    }

    failures
}

// ── Corpus contract ─────────────────────────────────────────────────────────

#[test]
fn the_corpus_is_exactly_the_required_matrix() {
    assert_eq!(
        scenario_names(&corpus_root(CORPUS)),
        SCENARIOS.map(str::to_owned).to_vec(),
        "the fixture matrix issue #360 requires is pinned; add the scenario to SCENARIOS too"
    );
}

#[test]
fn every_scenario_satisfies_the_shared_fixture_contract() {
    let mut failures = Failures::new();
    for scenario in SCENARIOS {
        let (manifest, expected) = manifest_and_expected(scenario);
        failures.absorb(validate_scenario(
            scenario,
            &scenario_root(scenario),
            &manifest,
            &expected,
        ));
    }
    failures.assert_empty("remediation corpus envelope");
}

#[test]
fn every_scenario_reduces_to_its_stated_contract() {
    let mut failures = Failures::new();
    for scenario in SCENARIOS {
        let (snapshot, expected) = analyze(scenario);
        failures.absorb(compare(scenario, &snapshot, &expected));
    }
    failures.assert_empty("remediation reductions");
}

#[test]
fn a_drifted_expectation_is_rejected() {
    // The comparison has to be able to fail, or the whole corpus is decorative.
    let scenario = "remediation-succeeded-post-compliant";
    let (snapshot, expected) = analyze(scenario);
    let drifted = mutated(&expected, "/runs/0/detection/outcome", json!("compliant"));
    assert!(
        !compare(scenario, &snapshot, &drifted).is_empty(),
        "a detection outcome that disagrees with the evidence must be rejected"
    );
}

// ── Contract invariants across the whole corpus ─────────────────────────────

#[test]
fn every_finding_cites_evidence_or_a_coverage_gap() {
    for scenario in SCENARIOS {
        let (snapshot, _) = analyze(scenario);
        for finding in &snapshot.findings {
            assert!(
                finding.is_evidence_backed(),
                "{scenario}: finding {} cites nothing",
                finding.finding_id
            );
        }
    }
}

#[test]
fn detection_and_remediation_evidence_is_never_pooled() {
    // The central acceptance criterion: one record can support exactly one
    // stage. If a record ever appeared under two stages, the two halves of the
    // lifecycle would be sharing an outcome.
    for scenario in SCENARIOS {
        let (snapshot, _) = analyze(scenario);
        for run in &snapshot.runs {
            let mut seen = Vec::new();
            for (stage, refs) in [
                ("detection", &run.detection.evidence),
                ("remediation", &run.remediation.evidence),
                ("postRemediation", &run.post_remediation.evidence),
                ("reporting", &run.reporting.evidence),
            ] {
                for entry in refs {
                    assert!(
                        !seen.iter().any(|(_, id)| *id == &entry.evidence_id),
                        "{scenario}: {} is cited by two stages ({stage} and an earlier one)",
                        entry.evidence_id
                    );
                    seen.push((stage, &entry.evidence_id));
                }
            }
        }
    }
}

#[test]
fn no_run_is_keyed_without_a_policy_identifier() {
    for scenario in SCENARIOS {
        let (snapshot, _) = analyze(scenario);
        for run in &snapshot.runs {
            assert!(
                !run.key.policy_id.is_empty(),
                "{scenario}: a run was keyed without a policy identifier"
            );
            assert!(
                !run.evidence.is_empty(),
                "{scenario}: run {} cites no record at all",
                run.key.policy_id
            );
        }
    }
}

#[test]
fn every_declared_artifact_produces_exactly_one_coverage_entry() {
    for scenario in SCENARIOS {
        let root = scenario_root(scenario);
        let (manifest, _) = manifest_and_expected(scenario);
        let snapshot = analyze_remediation_bundle(&inputs_for(&root, &manifest));
        let declared = manifest["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .filter_map(|artifact| artifact["artifactId"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            snapshot.coverage.len(),
            declared.len(),
            "{scenario}: coverage must name every declared artifact and invent none"
        );
        for artifact_id in declared {
            assert!(
                snapshot
                    .coverage
                    .iter()
                    .any(|entry| entry.artifact_id == artifact_id),
                "{scenario}: no coverage entry for {artifact_id}"
            );
        }
    }
}

#[test]
fn reduction_is_deterministic_for_every_scenario() {
    for scenario in SCENARIOS {
        let root = scenario_root(scenario);
        let (manifest, _) = manifest_and_expected(scenario);
        let inputs = inputs_for(&root, &manifest);
        let first = serde_json::to_string(&analyze_remediation_bundle(&inputs)).expect("serializes");
        let second =
            serde_json::to_string(&analyze_remediation_bundle(&inputs)).expect("serializes");
        assert_eq!(first, second, "{scenario}: reduction is not deterministic");
    }
}

#[test]
fn serialized_field_names_are_camel_case() {
    // Golden guard on the wire shape: every new field must arrive camelCase.
    let (snapshot, _) = analyze("remediation-succeeded-post-compliant");
    let value = serde_json::to_value(&snapshot).expect("serializes");
    let mut offenders = Vec::new();
    collect_snake_case_keys(&value, &mut offenders);
    assert!(
        offenders.is_empty(),
        "these serialized keys are not camelCase: {offenders:?}"
    );
    assert!(value["schemaVersion"].as_u64().is_some());
    assert!(value["runs"][0]["lastConfirmedPhase"].is_string());
    assert!(value["runs"][0]["postRemediation"]["state"].is_string());
}

fn collect_snake_case_keys(value: &Value, offenders: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                // Retained payload fields keep the key the source wrote, so only
                // this module's own field names are checked.
                if key.contains('_') && key != "name" && key != "value" {
                    offenders.push(key.clone());
                }
                if key != "retainedFields" && key != "retainedFacts" {
                    collect_snake_case_keys(child, offenders);
                }
            }
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_snake_case_keys(item, offenders)),
        _ => {}
    }
}

// ── Privacy ─────────────────────────────────────────────────────────────────

#[test]
fn the_redacted_export_masks_everything_the_scenario_declares() {
    let scenario = "privacy-redaction";
    let (snapshot, expected) = analyze(scenario);
    let redacted = redacted_export_projection(&snapshot);
    let text = serde_json::to_string(&redacted).expect("serializes");

    for forbidden in expected["redaction"]["mustNotContain"]
        .as_array()
        .expect("mustNotContain")
    {
        let forbidden = forbidden.as_str().expect("string");
        assert!(
            !text.contains(forbidden),
            "{scenario}: the redacted export still contains {forbidden:?}"
        );
    }
    for required in expected["redaction"]["mustContain"]
        .as_array()
        .expect("mustContain")
    {
        let required = required.as_str().expect("string");
        // The JSON encoding escapes backslashes, so compare against the encoded
        // form of whatever the fixture declared.
        let encoded = serde_json::to_string(required).expect("encodes");
        let encoded = encoded.trim_matches('"');
        assert!(
            text.contains(encoded),
            "{scenario}: the redacted export lost {required:?}, which every correlation needs"
        );
    }
}

#[test]
fn the_redacted_export_is_idempotent_and_stable() {
    let (snapshot, _) = analyze("privacy-redaction");
    let once = redacted_export_projection(&snapshot);
    let twice = redacted_export_projection(&once);
    assert_eq!(
        serde_json::to_string(&once).expect("serializes"),
        serde_json::to_string(&twice).expect("serializes"),
        "masking a masked export must be a no-op"
    );

    // Same input, same token: an operator must still be able to tell that two
    // records named the same user.
    let repeat = redacted_export_projection(&analyze("privacy-redaction").0);
    assert_eq!(
        serde_json::to_string(&once).expect("serializes"),
        serde_json::to_string(&repeat).expect("serializes"),
        "masking must not depend on run-to-run hash state"
    );
}

#[test]
fn redaction_preserves_every_outcome_and_evidence_reference() {
    let (snapshot, _) = analyze("privacy-redaction");
    let redacted = redacted_export_projection(&snapshot);
    assert_eq!(
        snapshot
            .runs
            .iter()
            .map(|run| (run.key.clone(), run.detection.clone(), run.remediation.clone()))
            .collect::<Vec<_>>(),
        redacted
            .runs
            .iter()
            .map(|run| (run.key.clone(), run.detection.clone(), run.remediation.clone()))
            .collect::<Vec<_>>(),
        "masking must not touch a key or an outcome"
    );
    assert_eq!(snapshot.coverage, redacted.coverage);
    assert_eq!(snapshot.findings, redacted.findings);
    assert_eq!(
        snapshot
            .observations
            .iter()
            .map(|observation| observation.context.evidence_ref.clone())
            .collect::<Vec<_>>(),
        redacted
            .observations
            .iter()
            .map(|observation| observation.context.evidence_ref.clone())
            .collect::<Vec<_>>(),
    );
    assert!(
        snapshot
            .observations
            .iter()
            .any(|observation| observation.message.contains("hunter2")),
        "the unredacted snapshot must keep the value an operator consented to see"
    );
}

// ── Scenario-specific contract points ───────────────────────────────────────

#[test]
fn a_malformed_payload_contributes_nothing_and_is_still_visible() {
    let (snapshot, _) = analyze("malformed-embedded-json");
    let malformed = snapshot
        .observations
        .iter()
        .find(|observation| observation.context.parse_state == IntuneParseState::Malformed)
        .expect("the truncated payload is observed");
    assert_eq!(malformed.policy_id, None, "a truncated payload names nothing");
    assert_eq!(malformed.stage, None);
    assert_eq!(malformed.exit_code, None);
    assert!(
        snapshot
            .unkeyed_observations
            .contains(&malformed.observation_id),
        "an unparseable payload must stay visible rather than joining a run"
    );
    assert!(
        snapshot
            .runs
            .iter()
            .all(|run| !run.observations.contains(&malformed.observation_id)),
        "no run may cite a record whose payload could not be read"
    );
}

#[test]
fn unknown_payload_fields_survive_verbatim() {
    let (snapshot, _) = analyze("malformed-embedded-json");
    let retained = snapshot
        .observations
        .iter()
        .find(|observation| !observation.retained_fields.is_empty())
        .expect("the well-formed payload is observed");
    assert_eq!(
        retained
            .retained_fields
            .iter()
            .map(|field| (field.name.as_str(), field.value.as_str()))
            .collect::<Vec<_>>(),
        vec![("FutureField", "preserved"), ("SchemaVersion", "3")],
        "fields this build does not model are kept, sorted, and unedited"
    );
}

#[test]
fn a_record_split_by_a_rotation_is_never_completed_by_the_next_file() {
    let (snapshot, _) = analyze("rotation-split-logical-record");
    let unframed: u32 = snapshot
        .artifacts
        .iter()
        .map(|artifact| artifact.unframed_records)
        .sum();
    assert!(unframed > 0, "the split record must be visible as unframed");
    let run = snapshot.runs.first().expect("one run");
    assert_eq!(
        run.remediation.outcome,
        cmtraceopen_parser::intune::apps::windows::remediations::RemediationOutcome::Launched,
        "the lost completion must not be reconstructed from the two halves"
    );
    assert!(run.remediation.exit_code.is_none());
}

#[test]
fn two_runs_of_one_policy_never_share_a_record() {
    for scenario in ["scheduled-and-on-demand-same-policy", "same-minute-distinct-policies"] {
        let (snapshot, _) = analyze(scenario);
        assert_eq!(snapshot.runs.len(), 2, "{scenario}: expected two runs");
        let first = snapshot.runs[0]
            .observations
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let second = snapshot.runs[1]
            .observations
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            first.intersection(&second).next().is_none(),
            "{scenario}: the two runs share a record"
        );
    }
}

#[test]
fn a_compliant_detection_never_acquires_a_remediation_exit_code() {
    let (snapshot, _) = analyze("detection-compliant-no-remediation");
    let run = snapshot.runs.first().expect("one run");
    assert!(run.remediation.exit_code.is_none());
    assert_eq!(run.remediation.attempts, 0);
    assert!(
        run.remediation.evidence.len() == 1,
        "the skip is proven by exactly the record that stated it"
    );
}
