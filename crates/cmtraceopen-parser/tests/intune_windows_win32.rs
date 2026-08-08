//! Focused fixture matrix for `intune::apps::windows::win32` (issue #357).
//!
//! Each scenario directory holds a `manifest.json` naming its artifacts, the
//! artifact contents under `evidence/`, and an `expected.json` describing the
//! contract the reduction must satisfy. Expectations are written out rather than
//! snapshotted so a reviewer can see what each scenario asserts and why.
//!
//! The shared harness in `tests/support/` owns everything every Intune corpus
//! has in common: the manifest envelope, path safety, byte-count truth,
//! file/manifest closure, the synthetic-fixture marker, the capture-state ↔
//! coverage-status binding, and the privacy scan. This file owns only the
//! Win32-specific semantics: keying, phases, outcomes, findings, and redaction.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::apps::windows::win32::{
    analyze_win32_bundle, derive_findings, redacted_export_projection, Win32Analysis,
    Win32SourceInput,
};
use cmtraceopen_parser::intune::evidence::IntuneAccessState;
use serde_json::{json, Value};
use support::{load_json, mutated, scenario_names, validate_scenario, Failures};

/// The scenario matrix issue #357 requires, pinned so that adding or removing a
/// scenario is a deliberate, compile-visible change rather than a silent drift.
const SCENARIOS: [&str; 20] = [
    "already-installed-detection",
    "complete-success",
    "dependency-failure",
    "enforcement-command-failed",
    "hash-or-staging-failure",
    "incomplete-bundle-missing-appworkload",
    "installed-but-not-detected",
    "installer-known-nonzero-code",
    "installer-unknown-code",
    "insufficient-evidence",
    "no-usable-content",
    "not-applicable",
    "not-targeted",
    "privacy-redaction",
    "reporting-failure-after-local-outcome",
    "requirement-failure",
    "retry-without-terminal-outcome",
    "rotation-split-record",
    "same-minute-unrelated-apps",
    "unkeyed-malformed-record",
];

fn corpus() -> PathBuf {
    support::corpus_root("apps/windows/win32")
}

/// The access state a manifest capture state declares.
///
/// Kept here rather than in the crate because it translates the *fixture*
/// vocabulary into the library's, and the library must never need to know how a
/// fixture spells things.
fn access_state(capture_state: &str) -> IntuneAccessState {
    match capture_state {
        "captured" => IntuneAccessState::Available,
        "capped" => IntuneAccessState::Capped,
        "absent" => IntuneAccessState::Missing,
        "accessDenied" => IntuneAccessState::PermissionDenied,
        "skipped" => IntuneAccessState::Skipped,
        "unsupported" => IntuneAccessState::Unsupported,
        "parseFailed" => IntuneAccessState::Failed,
        other => panic!("unknown captureState {other:?}"),
    }
}

fn inputs_for(scenario_root: &Path, manifest: &Value) -> Vec<Win32SourceInput> {
    manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts must be an array")
        .iter()
        .map(|artifact| {
            let content = artifact["relativePath"]
                .as_str()
                .map(|relative| {
                    std::fs::read_to_string(scenario_root.join(relative))
                        .unwrap_or_else(|error| panic!("{relative} is readable: {error}"))
                })
                .unwrap_or_default();
            Win32SourceInput {
                artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId")
                    .to_owned(),
                file_name: artifact["originalBasename"]
                    .as_str()
                    .expect("originalBasename")
                    .to_owned(),
                file_path: artifact["sanitizedSourcePath"].as_str().map(str::to_owned),
                access_state: access_state(
                    artifact["captureState"].as_str().expect("captureState"),
                ),
                content,
                captured_at_utc: artifact["capturedUtc"].as_str().map(str::to_owned),
            }
        })
        .collect()
}

fn load(scenario: &str) -> (Win32Analysis, Value, Value, PathBuf) {
    let root = corpus().join(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let analysis = analyze_win32_bundle(&inputs_for(&root, &manifest));
    (analysis, manifest, expected, root)
}

/// Compare one scenario's reduction against its stated contract.
///
/// Failures accumulate so a single run reports every mismatch in the scenario
/// instead of turning a corpus fix into a serial guessing game.
fn assert_scenario(scenario: &str) -> Win32Analysis {
    let (analysis, manifest, expected, root) = load(scenario);
    validate_scenario(scenario, &root, &manifest, &expected)
        .assert_empty(&format!("{scenario}: shared fixture contract"));

    let value = serde_json::to_value(&analysis).expect("analysis must serialize");
    let mut failures = Failures::new();

    assert_transactions(scenario, &value, &expected, &mut failures);
    assert_coverage(scenario, &analysis, &expected, &mut failures);
    assert_findings(scenario, &analysis, &expected, &mut failures);
    assert_redaction(scenario, &analysis, &expected, &mut failures);

    failures.assert_empty(&format!("{scenario}: win32 contract"));
    analysis
}

fn assert_transactions(scenario: &str, value: &Value, expected: &Value, failures: &mut Failures) {
    let want = expected["transactions"]
        .as_array()
        .expect("expected.transactions must be an array");
    let actual = value["transactions"]
        .as_array()
        .expect("analysis transactions");

    failures.require(actual.len() == want.len(), || {
        format!(
            "{scenario}: expected {} transaction(s), got {:?}",
            want.len(),
            actual.iter().map(|entry| &entry["key"]).collect::<Vec<_>>()
        )
    });

    for (index, (actual, want)) in actual.iter().zip(want).enumerate() {
        let at = format!("{scenario}[{index}]");
        for (pointer, expected_value, label) in [
            (&actual["key"]["appId"], &want["appId"], "appId"),
            (
                &actual["key"]["deploymentTypeId"],
                &want["deploymentTypeId"],
                "deploymentTypeId",
            ),
            (
                &actual["key"]["executionContext"],
                &want["executionContext"],
                "executionContext",
            ),
            (&actual["outcome"], &want["outcome"], "outcome"),
            (
                &actual["lastConfirmedPhase"],
                &want["lastConfirmedPhase"],
                "lastConfirmedPhase",
            ),
            (&actual["confidence"], &want["confidence"], "confidence"),
            (
                &actual["localOutcome"],
                &want["localOutcome"],
                "localOutcome",
            ),
            (
                &actual["returnCodeKind"],
                &want["returnCodeKind"],
                "returnCodeKind",
            ),
            (
                &actual["rebootRequired"],
                &want["rebootRequired"],
                "rebootRequired",
            ),
            (
                &actual["nextEvidenceRequest"],
                &want["nextEvidenceRequest"],
                "nextEvidenceRequest",
            ),
            (
                &actual["unresolvedDependencies"],
                &want["unresolvedDependencies"],
                "unresolvedDependencies",
            ),
            (
                &actual["failedRequirements"],
                &want["failedRequirements"],
                "failedRequirements",
            ),
            (
                &actual["corroboratingArtifacts"],
                &want["corroboratingArtifacts"],
                "corroboratingArtifacts",
            ),
        ] {
            failures.require(pointer == expected_value, || {
                format!("{at}: {label} is {pointer}, expected {expected_value}")
            });
        }

        // The raw return token is compared separately: `null` and a missing key
        // are the same thing in the expectation file, and only the raw form
        // proves the token survived exactly as the log wrote it.
        let actual_raw = actual["returnCode"]
            .get("raw")
            .cloned()
            .unwrap_or(Value::Null);
        let want_raw = want["returnCodeRaw"].clone();
        failures.require(actual_raw == want_raw, || {
            format!("{at}: returnCode.raw is {actual_raw}, expected {want_raw}")
        });

        // A transaction must cite the records it was built from, and its
        // evidence and observation lists must stay in step.
        let evidence = actual["evidence"].as_array().expect("evidence");
        let observations = actual["observations"].as_array().expect("observations");
        failures.require(!evidence.is_empty(), || {
            format!("{at}: a transaction must cite evidence")
        });
        failures.require(evidence.len() == observations.len(), || {
            format!(
                "{at}: {} evidence refs against {} observations",
                evidence.len(),
                observations.len()
            )
        });
    }
}

fn assert_coverage(
    scenario: &str,
    analysis: &Win32Analysis,
    expected: &Value,
    failures: &mut Failures,
) {
    let want_ids = expected["coverage"]
        .as_array()
        .expect("expected.coverage")
        .iter()
        .filter_map(|entry| entry["artifactId"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let actual_ids = analysis
        .coverage
        .artifacts
        .iter()
        .map(|entry| entry.artifact_id.clone())
        .collect::<BTreeSet<_>>();

    // Exact equality, not containment. A synthesized "expected but never
    // supplied" entry appearing here would mean the fixture stopped declaring an
    // artifact it is supposed to declare.
    failures.require(actual_ids == want_ids, || {
        format!("{scenario}: coverage ids are {actual_ids:?}, expected exactly {want_ids:?}")
    });

    let want_status = expected["coverage"]
        .as_array()
        .expect("expected.coverage")
        .iter()
        .filter_map(|entry| {
            Some((
                entry["artifactId"].as_str()?.to_owned(),
                entry["status"].as_str()?.to_owned(),
            ))
        })
        .collect::<Vec<_>>();
    for (artifact_id, status) in want_status {
        let actual = analysis
            .coverage
            .artifacts
            .iter()
            .find(|entry| entry.artifact_id == artifact_id);
        let actual_status = actual
            .map(|entry| {
                serde_json::to_value(&entry.status)
                    .expect("status serializes")
                    .as_str()
                    .expect("status is a string")
                    .to_owned()
            })
            .unwrap_or_else(|| "<absent>".to_owned());
        failures.require(actual_status == status, || {
            format!("{scenario}/{artifact_id}: coverage status {actual_status}, expected {status}")
        });
    }

    let counters: [(&str, u64); 2] = [
        (
            "unkeyedObservationCount",
            analysis.unkeyed_observations.len() as u64,
        ),
        (
            "fragmentRecords",
            u64::from(analysis.coverage.fragment_records),
        ),
    ];
    for (field, actual) in counters {
        let want = expected[field].as_u64().unwrap_or_default();
        failures.require(actual == want, || {
            format!("{scenario}: {field} is {actual}, expected {want}")
        });
    }

    let want_unknown = expected["unknownVocabularyObserved"]
        .as_bool()
        .unwrap_or_default();
    failures.require(
        analysis.coverage.unknown_vocabulary_observed == want_unknown,
        || {
            format!(
                "{scenario}: unknownVocabularyObserved is {}, expected {want_unknown}",
                analysis.coverage.unknown_vocabulary_observed
            )
        },
    );
}

fn assert_findings(
    scenario: &str,
    analysis: &Win32Analysis,
    expected: &Value,
    failures: &mut Failures,
) {
    let findings = derive_findings(analysis);

    for finding in &findings {
        failures.require(finding.is_evidence_backed(), || {
            format!(
                "{scenario}: finding {} cites neither evidence nor a coverage gap",
                finding.finding_id
            )
        });
    }

    let Some(want) = expected["findings"].as_array() else {
        return;
    };
    for entry in want {
        let id = entry["findingId"].as_str().expect("findingId");
        let Some(actual) = findings.iter().find(|finding| finding.finding_id == id) else {
            failures.push(format!(
                "{scenario}: expected finding {id}, got {:?}",
                findings
                    .iter()
                    .map(|finding| finding.finding_id.as_str())
                    .collect::<Vec<_>>()
            ));
            continue;
        };

        if let Some(severity) = entry["severity"].as_str() {
            let actual_severity = serde_json::to_value(&actual.severity)
                .expect("severity serializes")
                .as_str()
                .expect("severity is a string")
                .to_owned();
            failures.require(actual_severity == severity, || {
                format!("{scenario}/{id}: severity {actual_severity}, expected {severity}")
            });
        }
        if let Some(confidence) = entry["confidence"].as_str() {
            let actual_confidence = serde_json::to_value(&actual.confidence)
                .expect("confidence serializes")
                .as_str()
                .expect("confidence is a string")
                .to_owned();
            failures.require(actual_confidence == confidence, || {
                format!("{scenario}/{id}: confidence {actual_confidence}, expected {confidence}")
            });
        }

        // Expected evidence is a *subset*: naming one representative record keeps
        // the fixture readable while still proving the finding points at real
        // evidence rather than at whatever happened to be nearby.
        for reference in entry["evidence"].as_array().into_iter().flatten() {
            let evidence_id = reference["evidenceId"].as_str().expect("evidenceId");
            failures.require(
                actual
                    .evidence
                    .iter()
                    .any(|cited| cited.evidence_id == evidence_id),
                || {
                    format!(
                        "{scenario}/{id}: does not cite {evidence_id}; cites {:?}",
                        actual
                            .evidence
                            .iter()
                            .map(|cited| cited.evidence_id.as_str())
                            .collect::<Vec<_>>()
                    )
                },
            );
        }
        for gap in entry["coverageGapIds"].as_array().into_iter().flatten() {
            let gap = gap.as_str().expect("coverageGapId");
            failures.require(
                actual.coverage_gap_ids.iter().any(|cited| cited == gap),
                || format!("{scenario}/{id}: does not cite coverage gap {gap}"),
            );
        }
    }
}

fn assert_redaction(
    scenario: &str,
    analysis: &Win32Analysis,
    expected: &Value,
    failures: &mut Failures,
) {
    let redacted = redacted_export_projection(analysis);
    let text = serde_json::to_string(&redacted).expect("redacted analysis serializes");
    // Findings are part of the exported surface and must be as clean as the
    // projection itself: rules splice log-derived free text into summaries,
    // so the scan covers them too (ADR-004).
    let findings =
        serde_json::to_string(&derive_findings(analysis)).expect("findings serialize");

    for needle in expected["redactionMustNotContain"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let needle = needle.as_str().expect("needle");
        failures.require(!text.contains(needle), || {
            format!("{scenario}: redacted export still contains {needle:?}")
        });
        failures.require(!findings.contains(needle), || {
            format!("{scenario}: derived findings still contain {needle:?}")
        });
    }
    for needle in expected["redactionMustContain"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let needle = needle.as_str().expect("needle");
        failures.require(text.contains(needle), || {
            format!("{scenario}: redacted export dropped correlation key {needle:?}")
        });
    }
}

// ── The required fixture matrix ─────────────────────────────────────────────

#[test]
fn the_corpus_contains_exactly_the_required_scenario_matrix() {
    assert_eq!(
        scenario_names(&corpus()),
        SCENARIOS.map(str::to_owned).to_vec(),
        "adding or removing a scenario must be a deliberate change to SCENARIOS"
    );
}

#[test]
fn every_scenario_satisfies_its_stated_contract() {
    for scenario in SCENARIOS {
        assert_scenario(scenario);
    }
}

#[test]
fn complete_success_reaches_the_reporting_phase() {
    let analysis = assert_scenario("complete-success");
    let transaction = &analysis.transactions[0];
    assert!(
        transaction.next_evidence_request.is_none(),
        "a fully evidenced success asks for nothing further"
    );
}

#[test]
fn already_installed_detection_is_not_reported_as_a_skipped_install() {
    assert_scenario("already-installed-detection");
}

#[test]
fn requirement_failure_names_the_rule_that_blocked_it() {
    let analysis = assert_scenario("requirement-failure");
    assert_eq!(
        analysis.transactions[0].failed_requirements,
        vec!["Minimum OS build 22621".to_owned()]
    );
}

#[test]
fn dependency_failure_never_promotes_the_dependency_to_the_app_id() {
    let analysis = assert_scenario("dependency-failure");
    let transaction = &analysis.transactions[0];
    assert_eq!(transaction.unresolved_dependencies.len(), 1);
    assert_ne!(
        transaction.key.app_id, transaction.unresolved_dependencies[0],
        "the dependency GUID must never become the transaction key"
    );
}

#[test]
fn no_usable_content_is_distinct_from_a_delivery_failure() {
    let unavailable = assert_scenario("no-usable-content");
    let failed = assert_scenario("hash-or-staging-failure");
    assert_ne!(
        unavailable.transactions[0].outcome,
        failed.transactions[0].outcome
    );
}

#[test]
fn a_documented_nonzero_return_code_is_not_a_failure() {
    let analysis = assert_scenario("installer-known-nonzero-code");
    let transaction = &analysis.transactions[0];
    assert!(transaction.reboot_required);
    let ids: Vec<String> = derive_findings(&analysis)
        .into_iter()
        .map(|finding| finding.finding_id)
        .collect();
    assert!(
        !ids.iter().any(|id| id.starts_with("win32-unmapped")),
        "a mapped code must not raise the unmapped-code finding: {ids:?}"
    );
}

#[test]
fn an_unknown_return_code_reports_the_failure_without_asserting_a_cause() {
    let analysis = assert_scenario("installer-unknown-code");
    let code = analysis.transactions[0]
        .return_code
        .as_ref()
        .expect("the token must survive");
    assert_eq!(code.raw, "0x80070643");
    assert_eq!(code.hex.as_deref(), Some("0x80070643"));
    assert_eq!(code.decimal, Some(0x8007_0643));
}

#[test]
fn a_zero_return_code_next_to_a_failing_detection_rule_is_not_success() {
    assert_scenario("installed-but-not-detected");
}

#[test]
fn removal_from_targeting_is_a_terminal_answer_not_a_gap() {
    let analysis = assert_scenario("not-targeted");
    let transaction = &analysis.transactions[0];
    assert!(transaction.outcome.is_terminal());
    assert!(
        transaction.next_evidence_request.is_none(),
        "a settled non-deployment asks for nothing further"
    );
}

#[test]
fn not_applicable_is_terminal_and_distinct_from_not_targeted() {
    let not_applicable = assert_scenario("not-applicable");
    let not_targeted = assert_scenario("not-targeted");
    assert!(not_applicable.transactions[0].outcome.is_terminal());
    assert_ne!(
        not_applicable.transactions[0].outcome,
        not_targeted.transactions[0].outcome
    );
}

#[test]
fn a_failed_launch_is_terminal_with_no_return_code_to_interpret() {
    let analysis = assert_scenario("enforcement-command-failed");
    let transaction = &analysis.transactions[0];
    assert!(transaction.outcome.is_terminal());
    assert!(
        transaction.return_code.is_none(),
        "the installer never ran, so no return token may be asserted"
    );
}

#[test]
fn identity_alone_stays_insufficient_evidence_with_a_next_request() {
    let analysis = assert_scenario("insufficient-evidence");
    let transaction = &analysis.transactions[0];
    assert!(!transaction.outcome.is_terminal());
    assert!(
        transaction.next_evidence_request.is_some(),
        "an unresolved reduction must name the artifact that would advance it"
    );
    assert!(transaction.last_confirmed_phase.is_none());
}

#[test]
fn a_reporting_failure_preserves_the_local_outcome() {
    assert_scenario("reporting-failure-after-local-outcome");
}

#[test]
fn a_deferred_deployment_has_no_terminal_outcome() {
    let analysis = assert_scenario("retry-without-terminal-outcome");
    assert!(!analysis.transactions[0].outcome.is_terminal());
}

#[test]
fn an_incomplete_bundle_reports_a_coverage_gap_rather_than_a_verdict() {
    let analysis = assert_scenario("incomplete-bundle-missing-appworkload");
    assert!(!analysis.transactions[0].outcome.is_terminal());
}

#[test]
fn a_rotation_split_record_cannot_terminate_a_deployment() {
    let analysis = assert_scenario("rotation-split-record");
    assert_eq!(analysis.coverage.fragment_records, 2);
    assert!(
        analysis.transactions[0].return_code.is_none(),
        "the 1603 inside the split record must not reach the transaction"
    );
}

#[test]
fn same_minute_apps_stay_separate_because_identifiers_outrank_time() {
    let analysis = assert_scenario("same-minute-unrelated-apps");
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for transaction in &analysis.transactions {
        for observation in &transaction.observations {
            assert!(
                seen.insert(observation.as_str()),
                "observation {observation} was claimed by two transactions"
            );
        }
    }
}

#[test]
fn an_unkeyed_or_malformed_record_merges_into_nothing() {
    let analysis = assert_scenario("unkeyed-malformed-record");
    assert_eq!(analysis.unkeyed_observations.len(), 1);
    assert_eq!(analysis.coverage.fragment_records, 1);
    for transaction in &analysis.transactions {
        assert!(
            transaction.return_code.is_none(),
            "an unkeyed completion must not supply a return code to any transaction"
        );
    }
}

#[test]
fn the_privacy_fixture_redacts_deterministically() {
    let analysis = assert_scenario("privacy-redaction");
    let first = serde_json::to_string(&redacted_export_projection(&analysis)).expect("serialize");
    let second = serde_json::to_string(&redacted_export_projection(&analysis)).expect("serialize");
    assert_eq!(first, second, "the redacted export must be deterministic");
}

// ── Cross-cutting contract ──────────────────────────────────────────────────

#[test]
fn the_redacted_export_projection_is_idempotent() {
    let (analysis, ..) = load("privacy-redaction");
    let once = redacted_export_projection(&analysis);
    let twice = redacted_export_projection(&once);
    assert_eq!(
        serde_json::to_value(&once).expect("serialize"),
        serde_json::to_value(&twice).expect("serialize")
    );
}

/// A record with no embedded offset must not report a UTC value, because the
/// only one available would come from the parsing machine's timezone. Without
/// this rule the corpus would behave differently per developer machine.
#[test]
fn a_record_without_its_own_offset_reports_no_normalized_utc() {
    let content = concat!(
        "<![LOG[SYNTHETIC FIXTURE inline record]LOG]!><time=\"10:00:00.000\" ",
        "date=\"7-31-2026\" component=\"Win32App\" context=\"\" type=\"1\" ",
        "thread=\"12\" file=\"\">",
    );
    let analysis =
        analyze_win32_bundle(&[Win32SourceInput::captured("aw", "AppWorkload.log", content)]);
    let timestamp = analysis.observations[0]
        .context
        .source_timestamp
        .as_ref()
        .expect("the raw timestamp text always survives");
    assert_eq!(timestamp.normalized_utc, None);
    assert_eq!(timestamp.original_offset, None);
    assert!(!timestamp.raw_text.is_empty());
}

#[test]
fn the_serialized_analysis_is_camel_case_and_stable() {
    let (analysis, ..) = load("complete-success");
    let value = serde_json::to_value(&analysis).expect("serialize");
    for key in [
        "schemaVersion",
        "transactions",
        "observations",
        "unkeyedObservations",
        "coverage",
    ] {
        assert!(value.get(key).is_some(), "missing top-level key {key}");
    }
    for key in [
        "key",
        "displayName",
        "contentVersion",
        "intent",
        "observations",
        "lastConfirmedPhase",
        "outcome",
        "localOutcome",
        "returnCode",
        "returnCodeKind",
        "rebootRequired",
        "unresolvedDependencies",
        "failedRequirements",
        "corroboratingArtifacts",
        "confidence",
        "evidence",
        "nextEvidenceRequest",
    ] {
        assert!(
            value["transactions"][0].get(key).is_some(),
            "missing transaction key {key}"
        );
    }
    for key in [
        "evidenceRef",
        "provenance",
        "sourceTimestamp",
        "observedAtUtc",
        "sensitivity",
        "parseState",
        "accessState",
    ] {
        assert!(
            value["observations"][0]["context"].get(key).is_some(),
            "missing observation context key {key}"
        );
    }
}

/// The shared harness must reject a corpus that lies about itself, and this
/// corpus in particular. Proving it on one of *these* fixtures is what keeps the
/// binding meaningful here rather than only in the skeleton's own tests.
/// A privacy probe is only ever an *asserted* leak: the harness must reject a
/// probe that no `redactionMustNotContain` needle covers, because that probe
/// would be sensitive-shaped fixture material nothing proves redacted.
#[test]
fn a_privacy_probe_without_a_redaction_assertion_is_rejected() {
    let root = corpus().join("privacy-redaction");
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let corrupted = mutated(
        &manifest,
        "/privacyProbes/0",
        json!("S-1-5-21-999999999-888888888-777777777-1001"),
    );
    let failures = validate_scenario("privacy-redaction", &root, &corrupted, &expected);
    assert!(
        failures
            .entries()
            .iter()
            .any(|entry| entry.contains("not covered by any")),
        "an unasserted probe must be rejected, got {:?}",
        failures.entries()
    );
}

#[test]
fn a_coverage_status_contradicting_the_capture_state_is_rejected() {
    let root = corpus().join("incomplete-bundle-missing-appworkload");
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let corrupted = mutated(&expected, "/coverage/1/status", json!("available"));
    let failures = validate_scenario(
        "incomplete-bundle-missing-appworkload",
        &root,
        &manifest,
        &corrupted,
    );
    assert!(
        failures
            .entries()
            .iter()
            .any(|entry| entry.contains("requires coverage status")),
        "declaring an absent artifact available must be rejected, got {:?}",
        failures.entries()
    );
}
