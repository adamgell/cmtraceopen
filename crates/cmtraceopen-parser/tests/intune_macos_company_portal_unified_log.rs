//! Fixture matrix for `intune::portal::macos::company_portal::unified_log`
//! (issue #370 of epic #356).
//!
//! Every scenario is a directory holding a `manifest.json` naming its capture
//! artifacts, the artifact bytes themselves, and an `expected.json` stating the
//! contract the reduction must satisfy. Expectations are written out rather than
//! snapshotted so a reviewer can see what each scenario asserts and why.
//!
//! Two layers of checking run over the same corpus:
//!
//! 1. the shared harness in `tests/support/` validates everything every Intune
//!    corpus shares — manifest envelope, byte-count truth, evidence closure, the
//!    synthetic-fixture marker, the capture-state/coverage binding, and the
//!    privacy scan;
//! 2. this file validates what only issue #370 owns: relevance classification,
//!    activity and signpost grouping, correlation keys, timestamp anchoring,
//!    sequence integrity, and the export projection.
//!
//! The corpus contains no real data. In particular the POSIX home-directory
//! redaction rule is exercised by the module's own unit tests, because the
//! shared privacy scanner forbids that literal path prefix in a committed
//! fixture — which is exactly the material the rule exists to mask.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::portal::macos::company_portal::unified_log::{
    analyze_unified_log_bundle, redacted_export_projection, UnifiedLogAnalysis,
    UnifiedLogCaptureState, UnifiedLogCorrelationKey, UnifiedLogSourceInput,
};
use serde_json::{json, Value};
use support::{corpus_root, load_json, mutated, scenario_names, validate_scenario, Failures};

/// The corpus this leaf owns, relative to `tests/fixtures/intune`.
const CORPUS: &str = "portal/macos/company-portal/unified-log";

/// The required fixture matrix, pinned. Adding a scenario directory without
/// adding it here fails, and so does the reverse.
const SCENARIOS: [&str; 15] = [
    "activity-signpost-relationship",
    "all-message-levels",
    "capped-skipped-permission-denied-coverage",
    "capture-window-and-predicate-metadata",
    "deterministic-redacted-export",
    "direct-log-matching-key",
    "duplicate-sequence-ordering",
    "malformed-json-line",
    "missing-timezone-boot-relative",
    "privacy-sensitive-formatted-values",
    "same-time-unrelated-activity",
    "supported-json-document",
    "supported-ndjson-stream",
    "unknown-schema-version",
    "unrelated-process-negative",
];

// ── Loading ─────────────────────────────────────────────────────────────────

fn corpus() -> PathBuf {
    corpus_root(CORPUS)
}

fn scenario_root(scenario: &str) -> PathBuf {
    corpus().join(scenario)
}

fn descriptors(scenario: &str) -> (Value, Value) {
    let root = scenario_root(scenario);
    (
        load_json(&root.join("manifest.json")),
        load_json(&root.join("expected.json")),
    )
}

/// Build analyzer inputs from the manifest, in manifest order.
///
/// Manifest order is load-bearing: coverage entries and the coverage-gap lists
/// inside findings follow it, so a corpus that reorders its artifacts is
/// declaring a different expected output.
fn inputs(root: &Path, manifest: &Value) -> Vec<UnifiedLogSourceInput> {
    manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts must be an array")
        .iter()
        .map(|artifact| {
            let capture_state: UnifiedLogCaptureState =
                serde_json::from_value(artifact["captureState"].clone())
                    .expect("captureState must be one of the analyzer's states");
            let content = artifact["relativePath"].as_str().map(|relative| {
                std::fs::read_to_string(root.join(relative))
                    .unwrap_or_else(|error| panic!("{relative} is readable: {error}"))
            });
            UnifiedLogSourceInput {
                artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId")
                    .to_owned(),
                file_name: artifact["originalBasename"]
                    .as_str()
                    .expect("originalBasename")
                    .to_owned(),
                capture_state,
                content,
            }
        })
        .collect()
}

fn analyze(scenario: &str) -> (UnifiedLogAnalysis, Value) {
    let (manifest, expected) = descriptors(scenario);
    let analysis = analyze_unified_log_bundle(&inputs(&scenario_root(scenario), &manifest));
    (analysis, expected)
}

// ── Shared-harness layer ────────────────────────────────────────────────────

#[test]
fn the_scenario_matrix_is_pinned() {
    assert_eq!(
        scenario_names(&corpus()),
        SCENARIOS.map(str::to_owned).to_vec(),
        "the corpus on disk and the pinned matrix must agree"
    );
}

#[test]
fn every_scenario_satisfies_the_shared_fixture_contract() {
    let mut failures = Failures::new();
    for scenario in SCENARIOS {
        let (manifest, expected) = descriptors(scenario);
        failures.absorb(validate_scenario(
            scenario,
            &scenario_root(scenario),
            &manifest,
            &expected,
        ));
    }
    failures.assert_empty("company portal macOS unified-log corpus");
}

#[test]
fn a_byte_count_that_disagrees_with_the_file_is_rejected() {
    // Proves the shared validator is actually running over this corpus, rather
    // than passing because it was handed something it never inspected.
    let scenario = "supported-ndjson-stream";
    let (manifest, expected) = descriptors(scenario);
    let failures = validate_scenario(
        scenario,
        &scenario_root(scenario),
        &mutated(&manifest, "/artifacts/0/bytesCopied", json!(1)),
        &expected,
    );
    assert!(
        failures
            .entries()
            .iter()
            .any(|entry| entry.contains("bytesCopied")),
        "expected a bytesCopied failure, got {:?}",
        failures.entries()
    );
}

// ── Reduction layer ─────────────────────────────────────────────────────────

/// Expectation key to JSON pointer, relative to a serialized observation.
const OBSERVATION_POINTERS: [(&str, &str); 19] = [
    ("relevance", "/relevance"),
    ("level", "/level"),
    ("activityKind", "/activityKind"),
    ("messageType", "/messageType"),
    ("signpostType", "/signpostType"),
    ("signpostName", "/signpostName"),
    ("correlationKeys", "/correlationKeys"),
    ("bootRelativeOnly", "/bootRelativeOnly"),
    ("appleRedactedValues", "/appleRedactedValues"),
    ("sequence", "/sequence"),
    ("sensitivity", "/context/sensitivity"),
    ("accessState", "/context/accessState"),
    ("lineNumber", "/context/provenance/lineNumber"),
    ("recordNumber", "/context/provenance/recordNumber"),
    ("normalizedUtc", "/context/sourceTimestamp/normalizedUtc"),
    ("originalOffset", "/context/sourceTimestamp/originalOffset"),
    ("timestampKind", "/context/sourceTimestamp/kind"),
    ("rawTimestamp", "/context/sourceTimestamp/rawText"),
    ("errorRaw", "/error/raw"),
];

/// Expectation key to JSON pointer, relative to a serialized capture summary.
const CAPTURE_POINTERS: [(&str, &str); 9] = [
    ("recordsRead", "/recordsRead"),
    ("recordsRelevant", "/recordsRelevant"),
    ("predicateMismatch", "/predicateMismatch"),
    ("captureId", "/captureId"),
    ("hostOsVersion", "/hostOsVersion"),
    ("companyPortalVersion", "/companyPortalVersion"),
    ("declaredPredicateId", "/declaredPredicate/predicateId"),
    ("declaredPredicateVersion", "/declaredPredicate/predicateVersion"),
    ("windowLast", "/window/last"),
];

/// A pointer that traverses a null resolves to `None`; expectations spell that
/// as JSON null, so the two are the same fact.
fn at<'a>(value: &'a Value, pointer: &str) -> &'a Value {
    value.pointer(pointer).unwrap_or(&Value::Null)
}

fn compare(failures: &mut Failures, at_label: &str, actual: &Value, want: &Value) {
    if actual != want {
        failures.push(format!("{at_label}: expected {want}, got {actual}"));
    }
}

#[test]
fn every_scenario_matches_its_expected_reduction() {
    let mut failures = Failures::new();
    for scenario in SCENARIOS {
        let (analysis, expected) = analyze(scenario);
        let value = serde_json::to_value(&analysis).expect("analysis must serialize");
        check_coverage(scenario, &value, &expected, &mut failures);
        check_findings(scenario, &value, &expected, &mut failures);
        check_analysis(scenario, &value, &expected, &mut failures);
    }
    failures.assert_empty("company portal macOS unified-log reduction");
}

/// Coverage must name the manifest's artifacts, in order, with the bound status.
fn check_coverage(scenario: &str, value: &Value, expected: &Value, failures: &mut Failures) {
    let actual = value["coverage"]
        .as_array()
        .expect("coverage")
        .iter()
        .map(|entry| json!({ "artifactId": entry["artifactId"], "status": entry["status"] }))
        .collect::<Vec<_>>();
    compare(
        failures,
        &format!("{scenario}: coverage"),
        &Value::Array(actual),
        &expected["coverage"],
    );
}

/// Findings must match by identity, ranking, and what they cite.
fn check_findings(scenario: &str, value: &Value, expected: &Value, failures: &mut Failures) {
    let actual = value["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|finding| {
            json!({
                "findingId": finding["findingId"],
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "evidence": finding["evidence"],
                "coverageGapIds": finding["coverageGapIds"],
            })
        })
        .collect::<Vec<_>>();
    compare(
        failures,
        &format!("{scenario}: findings"),
        &Value::Array(actual),
        &expected["findings"],
    );
}

fn check_analysis(scenario: &str, value: &Value, expected: &Value, failures: &mut Failures) {
    let want = &expected["analysis"];

    compare(
        failures,
        &format!("{scenario}: observationCount"),
        &json!(value["observations"].as_array().expect("observations").len()),
        &want["observationCount"],
    );

    let relevant = value["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|observation| observation["relevance"] != "unrelated")
        .count();
    compare(
        failures,
        &format!("{scenario}: relevantCount"),
        &json!(relevant),
        &want["relevantCount"],
    );

    for (key, actual) in [
        ("activities", &value["activities"]),
        ("sequenceAnomalies", &value["sequenceAnomalies"]),
    ] {
        if let Some(expected_value) = want.get(key) {
            compare(failures, &format!("{scenario}: {key}"), actual, expected_value);
        }
    }

    for (key, field) in [("sequences", "sequence"), ("sourcePositions", "sourcePosition")] {
        let Some(expected_value) = want.get(key) else {
            continue;
        };
        let actual = value["observations"]
            .as_array()
            .expect("observations")
            .iter()
            .map(|observation| observation[field].clone())
            .collect::<Vec<_>>();
        compare(
            failures,
            &format!("{scenario}: {key}"),
            &Value::Array(actual),
            expected_value,
        );
    }

    check_captures(scenario, value, want, failures);
    check_observations(scenario, value, want, failures);
}

fn check_captures(scenario: &str, value: &Value, want: &Value, failures: &mut Failures) {
    let Some(expected_captures) = want["captures"].as_array() else {
        return;
    };
    let actual_captures = value["captures"].as_array().expect("captures");
    if actual_captures.len() != expected_captures.len() {
        failures.push(format!(
            "{scenario}: expected {} capture summaries, got {}",
            expected_captures.len(),
            actual_captures.len()
        ));
        return;
    }

    for (actual, want) in actual_captures.iter().zip(expected_captures) {
        let id = want["artifactId"].as_str().unwrap_or("<unnamed>");
        compare(
            failures,
            &format!("{scenario}/{id}: artifactId"),
            &actual["artifactId"],
            &want["artifactId"],
        );

        for (key, pointer) in CAPTURE_POINTERS {
            if let Some(expected_value) = want.get(key) {
                compare(
                    failures,
                    &format!("{scenario}/{id}: {key}"),
                    at(actual, pointer),
                    expected_value,
                );
            }
        }

        // `window` is `None` for a capture that never parsed, so start/end are
        // checked through the same null-tolerant pointer as everything else.
        for (key, pointer) in [("windowStart", "/window/start"), ("windowEnd", "/window/end")] {
            if let Some(expected_value) = want.get(key) {
                compare(
                    failures,
                    &format!("{scenario}/{id}: {key}"),
                    at(actual, pointer),
                    expected_value,
                );
            }
        }

        if let Some(expected_value) = want.get("rejectedReasons") {
            let reasons = actual["rejected"]
                .as_array()
                .expect("rejected")
                .iter()
                .map(|rejection| rejection["reason"].clone())
                .collect::<Vec<_>>();
            compare(
                failures,
                &format!("{scenario}/{id}: rejectedReasons"),
                &Value::Array(reasons),
                expected_value,
            );
        }
        if let Some(expected_value) = want.get("rejectedLineNumbers") {
            let lines = actual["rejected"]
                .as_array()
                .expect("rejected")
                .iter()
                .map(|rejection| rejection["lineNumber"].clone())
                .collect::<Vec<_>>();
            compare(
                failures,
                &format!("{scenario}/{id}: rejectedLineNumbers"),
                &Value::Array(lines),
                expected_value,
            );
        }
    }
}

fn check_observations(scenario: &str, value: &Value, want: &Value, failures: &mut Failures) {
    let Some(expectations) = want["observations"].as_object() else {
        return;
    };
    for (observation_id, fields) in expectations {
        let Some(actual) = value["observations"]
            .as_array()
            .expect("observations")
            .iter()
            .find(|observation| observation["observationId"] == json!(observation_id))
        else {
            failures.push(format!("{scenario}: no observation {observation_id}"));
            continue;
        };

        for (key, pointer) in OBSERVATION_POINTERS {
            if let Some(expected_value) = fields.get(key) {
                compare(
                    failures,
                    &format!("{scenario}/{observation_id}: {key}"),
                    at(actual, pointer),
                    expected_value,
                );
            }
        }
        for (key, pointer) in [("errorDecimal", "/error/decimal"), ("errorHex", "/error/hex")] {
            if let Some(expected_value) = fields.get(key) {
                compare(
                    failures,
                    &format!("{scenario}/{observation_id}: {key}"),
                    at(actual, pointer),
                    expected_value,
                );
            }
        }
        if let Some(expected_value) = fields.get("hasSourceTimestamp") {
            compare(
                failures,
                &format!("{scenario}/{observation_id}: hasSourceTimestamp"),
                &json!(!actual["context"]["sourceTimestamp"].is_null()),
                expected_value,
            );
        }
    }
}

// ── Cross-cutting contract ──────────────────────────────────────────────────

#[test]
fn every_finding_in_every_scenario_cites_evidence_or_a_coverage_gap() {
    for scenario in SCENARIOS {
        let (analysis, _) = analyze(scenario);
        for finding in &analysis.findings {
            assert!(
                finding.is_evidence_backed(),
                "{scenario}: finding {} cites neither evidence nor a coverage gap",
                finding.finding_id
            );
        }
    }
}

#[test]
fn every_cited_evidence_reference_resolves_to_an_observation() {
    // A dangling reference would let a finding look substantiated while citing
    // nothing a reader can open.
    for scenario in SCENARIOS {
        let (analysis, _) = analyze(scenario);
        let known = analysis
            .observations
            .iter()
            .map(|observation| observation.context.evidence_ref.clone())
            .collect::<BTreeSet<_>>();
        for finding in &analysis.findings {
            for reference in &finding.evidence {
                assert!(
                    known.contains(reference),
                    "{scenario}: finding {} cites unknown evidence {reference:?}",
                    finding.finding_id
                );
            }
        }
    }
}

#[test]
fn every_cited_coverage_gap_names_a_declared_artifact() {
    for scenario in SCENARIOS {
        let (analysis, _) = analyze(scenario);
        let known = analysis
            .coverage
            .iter()
            .map(|entry| entry.artifact_id.clone())
            .collect::<BTreeSet<_>>();
        for finding in &analysis.findings {
            for gap in &finding.coverage_gap_ids {
                assert!(
                    known.contains(gap),
                    "{scenario}: finding {} cites unknown coverage gap {gap}",
                    finding.finding_id
                );
            }
        }
    }
}

#[test]
fn the_reduction_is_deterministic_across_runs() {
    for scenario in SCENARIOS {
        let (first, _) = analyze(scenario);
        let (second, _) = analyze(scenario);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap(),
            "{scenario}: the same input must reduce to byte-identical output"
        );
    }
}

// ── Scenario-specific semantics ─────────────────────────────────────────────

/// The only sanctioned join: an explicit identifier, never a timestamp.
#[test]
fn a_direct_log_key_selects_exactly_the_records_that_state_it() {
    let (analysis, expected) = analyze("direct-log-matching-key");
    for lookup in expected["matchingKeyLookups"]
        .as_array()
        .expect("matchingKeyLookups")
    {
        let key: UnifiedLogCorrelationKey = serde_json::from_value(json!({
            "kind": lookup["kind"],
            "value": lookup["value"],
        }))
        .expect("lookup key must deserialize");
        let matched = analysis
            .observations_matching_key(&key)
            .into_iter()
            .map(|observation| observation.observation_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            json!(matched),
            lookup["observationIds"],
            "lookup {key:?} selected the wrong records"
        );
    }
}

/// Two operations at the identical instant must stay apart.
#[test]
fn records_sharing_only_an_instant_are_never_merged() {
    let (analysis, expected) = analyze("same-time-unrelated-activity");

    let ids = expected["sameNormalizedUtc"]
        .as_array()
        .expect("sameNormalizedUtc")
        .iter()
        .map(|id| id.as_str().expect("observation id").to_owned())
        .collect::<Vec<_>>();
    let observations = ids
        .iter()
        .map(|id| {
            analysis
                .observations
                .iter()
                .find(|observation| &observation.observation_id == id)
                .unwrap_or_else(|| panic!("no observation {id}"))
        })
        .collect::<Vec<_>>();

    // The premise: they really are the same instant. Without this the negative
    // below would pass for the wrong reason.
    let instants = observations
        .iter()
        .map(|observation| {
            observation
                .context
                .source_timestamp
                .as_ref()
                .and_then(|timestamp| timestamp.normalized_utc.clone())
                .expect("both records must normalize to a real instant")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(instants.len(), 1, "the fixture must share one instant");

    // The contract: sharing it buys nothing.
    let keys = observations
        .iter()
        .map(|observation| observation.correlation_keys.iter().collect::<BTreeSet<_>>())
        .collect::<Vec<_>>();
    assert!(
        keys[0].is_disjoint(&keys[1]),
        "records sharing only a timestamp must share no correlation key"
    );
    assert_eq!(
        analysis.activities.len(),
        2,
        "each record must keep its own activity"
    );
}

/// Records stay in the order the collector wrote them.
#[test]
fn a_duplicate_sequence_reorders_nothing_and_drops_nothing() {
    let (analysis, _) = analyze("duplicate-sequence-ordering");
    let positions = analysis
        .observations
        .iter()
        .map(|observation| observation.source_position)
        .collect::<Vec<_>>();
    assert_eq!(positions, vec![0, 1, 2, 3, 4], "emitted order must survive");
    assert_eq!(
        analysis
            .observations
            .iter()
            .map(|observation| observation.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 2, 5, 4],
        "the collector's declared sequence must be preserved verbatim"
    );
}

/// A signpost interval keeps one identity across its begin and end records.
#[test]
fn a_signpost_interval_stays_one_relationship() {
    let (analysis, _) = analyze("activity-signpost-relationship");
    let parent = analysis
        .activities
        .iter()
        .find(|activity| activity.activity_identifier == 8_402_315)
        .expect("the parent activity");
    assert_eq!(parent.signpost_ids, vec![770_001]);

    let child = analysis
        .activities
        .iter()
        .find(|activity| activity.activity_identifier == 8_402_316)
        .expect("the child activity");
    assert_eq!(child.parent_activity_identifier, Some(8_402_315));
}

/// The export projection is deterministic, idempotent, and correlation-safe.
#[test]
fn the_redacted_export_is_deterministic_and_idempotent() {
    for scenario in ["privacy-sensitive-formatted-values", "deterministic-redacted-export"] {
        let (analysis, expected) = analyze(scenario);

        let once = redacted_export_projection(&analysis);
        let again = redacted_export_projection(&analysis);
        let first = serde_json::to_string(&once).expect("serialize");
        assert_eq!(
            first,
            serde_json::to_string(&again).expect("serialize"),
            "{scenario}: the export must be byte-identical across runs"
        );
        assert_eq!(
            first,
            serde_json::to_string(&redacted_export_projection(&once)).expect("serialize"),
            "{scenario}: re-projecting an export must change nothing"
        );

        for needle in expected["redactionMustNotContain"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let needle = needle.as_str().expect("needle");
            assert!(
                !first.contains(needle),
                "{scenario}: the export still contains {needle:?}"
            );
        }
        for needle in expected["redactionMustContain"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let needle = needle.as_str().expect("needle");
            assert!(
                first.contains(needle),
                "{scenario}: the export dropped {needle:?}"
            );
        }
    }
}

/// One identity must mask to one token, or a reader loses the correlation.
#[test]
fn one_identity_masks_to_one_token_across_records() {
    let (analysis, expected) = analyze("deterministic-redacted-export");
    let occurrences = expected["redactionStableIdentityCount"]
        .as_u64()
        .expect("redactionStableIdentityCount");

    let exported = redacted_export_projection(&analysis);
    let tokens = exported
        .observations
        .iter()
        .filter_map(|observation| observation.message.as_deref())
        .filter_map(|message| {
            let start = message.find("[upn:")?;
            let end = message[start..].find(']')? + start + 1;
            Some(message[start..end].to_owned())
        })
        .collect::<Vec<_>>();

    assert_eq!(
        tokens.len() as u64,
        occurrences,
        "every mention of the identity must be masked"
    );
    assert_eq!(
        tokens.iter().collect::<BTreeSet<_>>().len(),
        1,
        "one identity must yield one token, got {tokens:?}"
    );
}

/// A capture that produced no bytes must still be visible as coverage.
#[test]
fn an_uncollected_capture_is_reported_rather_than_omitted() {
    let (analysis, _) = analyze("capped-skipped-permission-denied-coverage");
    assert_eq!(
        analysis.coverage.len(),
        4,
        "every declared artifact needs a coverage entry, collected or not"
    );
    assert!(
        analysis.captures.iter().all(|capture| capture
            .analyzer_predicate
            .predicate_id
            .eq("companyPortalMacosV1")),
        "every capture summary must report the rule this build implements"
    );
}
