//! Fixture matrix for `intune::portal::macos::company_portal::logs` (issue #368).
//!
//! Each scenario directory holds a `manifest.json` describing what a native
//! adapter collected, the collected bytes under `evidence/`, and an
//! `expected.json` stating the contract the reduction must satisfy. Expectations
//! are written out rather than snapshotted so a reviewer can see what is being
//! asserted and why.
//!
//! The shared harness in `tests/support/` validates everything every Intune
//! corpus has in common — envelope, byte-count truth, path safety, the synthetic
//! marker, capture-state to coverage binding, and the privacy scan. What is
//! specific to this leaf lives here: detection outcomes, record framing, rotation
//! ordering, severity, and the redacted export.

mod support;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use cmtraceopen_parser::intune::evidence::IntuneSensitivity;
use cmtraceopen_parser::intune::portal::macos::company_portal::logs::{
    analyze_company_portal_logs, decode_log_bytes, derive_findings,
    detect_company_portal_log_content, parse_content, redacted_company_portal_log_export,
    CompanyPortalCaptureState, CompanyPortalLogSnapshot, CompanyPortalLogSource,
    CompanyPortalRecordProfile,
};
use serde_json::{json, Value};
use support::{load_json, mutated, scenario_names, validate_scenario, Failures};

/// The required fixture matrix, pinned so a scenario cannot be quietly dropped.
///
/// Order is the on-disk sort order, which is what `scenario_names` returns.
const SCENARIOS: [&str; 11] = [
    "advanced-logging-certificate-network",
    "basic-severity-records",
    "deterministic-privacy-export",
    "encoding-bom-variants",
    "invalid-truncated-record",
    "multiline-exception-payload",
    "negative-saved-diagnostic-report",
    "negative-unified-log-export",
    "rotation-ordering",
    "same-time-distinct-activities",
    "unknown-app-version",
];

const CORPUS: &str = "portal/macos/company-portal/logs";

fn corpus_root() -> PathBuf {
    support::corpus_root(CORPUS)
}

fn scenario_root(scenario: &str) -> PathBuf {
    corpus_root().join(scenario)
}

/// Build the adapter inputs a scenario describes.
///
/// Bytes are decoded with [`decode_log_bytes`], the same call the native adapter
/// makes, so the corpus exercises the real path rather than a test-only shortcut.
fn load_sources(scenario: &str, manifest: &Value) -> Vec<CompanyPortalLogSource> {
    let root = scenario_root(scenario);
    manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts must be an array")
        .iter()
        .map(|artifact| {
            let artifact_id = artifact["artifactId"].as_str().expect("artifactId");
            let capture_state = CompanyPortalCaptureState::from_wire(
                artifact["captureState"].as_str().expect("captureState"),
            )
            .unwrap_or_else(|| panic!("{scenario}/{artifact_id}: unknown captureState"));

            let decoded = artifact["relativePath"].as_str().map(|relative| {
                let bytes = fs::read(root.join(relative)).unwrap_or_else(|error| {
                    panic!("{scenario}/{artifact_id}: {relative} is readable: {error}")
                });
                decode_log_bytes(&bytes)
            });

            CompanyPortalLogSource {
                artifact_id: artifact_id.to_owned(),
                file_name: artifact["originalBasename"]
                    .as_str()
                    .expect("originalBasename")
                    .to_owned(),
                sanitized_file_path: artifact["sanitizedSourcePath"]
                    .as_str()
                    .map(str::to_owned),
                capture_state,
                content: decoded.as_ref().map(|decoded| decoded.text.clone()),
                encoding: decoded.as_ref().map(|decoded| decoded.encoding.clone()),
                captured_at_utc: artifact["capturedUtc"]
                    .as_str()
                    .expect("capturedUtc")
                    .to_owned(),
            }
        })
        .collect()
}

fn load_scenario(scenario: &str) -> (CompanyPortalLogSnapshot, Value, Value) {
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let snapshot = analyze_company_portal_logs(&load_sources(scenario, &manifest));
    (snapshot, manifest, expected)
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().expect("string element").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Every key `expected.json` may declare.
///
/// Several checks below are opt-in per scenario, which means a typo in a key
/// name would silently disable one instead of failing. Pinning the vocabulary
/// turns that mistake back into a test failure.
const EXPECTATION_KEYS: [&str; 18] = [
    // Structural, asserted for every scenario.
    "scenario",
    "workload",
    "coverage",
    "artifactOrder",
    "detection",
    "stats",
    "unknownAppVersions",
    "advancedLoggingObserved",
    "findings",
    "assertions",
    // Opt-in, asserted when present.
    "recordEvidenceIds",
    "recordActivityIds",
    "distinctActivityIds",
    "restrictedRecordIndexes",
    "malformedRecordIndexes",
    "messageMustContain",
    "decoding",
    "repeatedIdentityRecordIndexes",
];

/// Opt-in redaction keys, checked together by [`assert_redaction`].
const REDACTION_KEYS: [&str; 2] = ["redactionMustNotContain", "redactionMustContain"];

/// Assert one scenario against everything its `expected.json` declares.
fn assert_scenario(scenario: &str) -> CompanyPortalLogSnapshot {
    let (snapshot, manifest, expected) = load_scenario(scenario);

    // The shared contract first: if the fixture itself is invalid, every
    // assertion below is meaningless.
    validate_scenario(scenario, &scenario_root(scenario), &manifest, &expected)
        .assert_empty(scenario);

    for key in expected.as_object().expect("expected.json is an object").keys() {
        assert!(
            EXPECTATION_KEYS.contains(&key.as_str()) || REDACTION_KEYS.contains(&key.as_str()),
            "{scenario}: expected.json declares {key:?}, which no assertion reads"
        );
    }

    assert_coverage(scenario, &snapshot, &expected);
    assert_detection(scenario, &snapshot, &expected);

    assert_eq!(
        serde_json::to_value(&snapshot.stats).expect("stats must serialize"),
        expected["stats"],
        "{scenario}: parse statistics"
    );
    assert_eq!(
        snapshot.unknown_app_versions,
        strings(&expected["unknownAppVersions"]),
        "{scenario}: unknown app versions"
    );
    assert_eq!(
        snapshot.advanced_logging_observed,
        expected["advancedLoggingObserved"]
            .as_bool()
            .expect("advancedLoggingObserved"),
        "{scenario}: advanced logging flag"
    );

    assert_optional_record_shape(scenario, &snapshot, &expected);
    assert_decoding(scenario, &manifest, &expected);
    assert_findings(scenario, &snapshot, &expected);
    assert_redaction(scenario, &snapshot, &expected);

    snapshot
}

fn assert_coverage(scenario: &str, snapshot: &CompanyPortalLogSnapshot, expected: &Value) {
    let actual: Vec<(String, String)> = snapshot
        .coverage
        .iter()
        .map(|entry| {
            (
                entry.artifact_id.clone(),
                serde_json::to_value(&entry.status)
                    .expect("status must serialize")
                    .as_str()
                    .expect("status is a string")
                    .to_owned(),
            )
        })
        .collect();

    for want in expected["coverage"].as_array().expect("coverage") {
        let id = want["artifactId"].as_str().expect("artifactId");
        let status = want["status"].as_str().expect("status");
        assert!(
            actual
                .iter()
                .any(|(actual_id, actual_status)| actual_id == id && actual_status == status),
            "{scenario}: coverage for {id} should be {status:?}, got {actual:?}"
        );
    }
    assert_eq!(
        actual.len(),
        expected["coverage"].as_array().expect("coverage").len(),
        "{scenario}: coverage entry count"
    );

    assert_eq!(
        snapshot
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.clone())
            .collect::<Vec<_>>(),
        strings(&expected["artifactOrder"]),
        "{scenario}: artifact order must be oldest rotation first"
    );
}

fn assert_detection(scenario: &str, snapshot: &CompanyPortalLogSnapshot, expected: &Value) {
    for want in expected["detection"].as_array().expect("detection") {
        let id = want["artifactId"].as_str().expect("artifactId");
        let artifact = snapshot
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == id)
            .unwrap_or_else(|| panic!("{scenario}: no artifact {id}"));

        assert_eq!(
            artifact.detection.confirmed,
            want["confirmed"].as_bool().expect("confirmed"),
            "{scenario}/{id}: detection confirmation"
        );
        assert_eq!(
            serde_json::to_value(&artifact.detection.rejection).expect("rejection serializes"),
            want["rejection"],
            "{scenario}/{id}: rejection reason"
        );
    }
}

fn assert_optional_record_shape(
    scenario: &str,
    snapshot: &CompanyPortalLogSnapshot,
    expected: &Value,
) {
    if let Some(want) = expected.get("recordEvidenceIds") {
        assert_eq!(
            snapshot
                .records
                .iter()
                .map(|record| record.context.evidence_ref.evidence_id.clone())
                .collect::<Vec<_>>(),
            strings(want),
            "{scenario}: record order and evidence identity"
        );
    }

    if let Some(want) = expected.get("recordActivityIds") {
        let actual: Vec<Value> = snapshot
            .records
            .iter()
            .map(|record| match &record.activity_id {
                Some(id) => json!(id),
                None => Value::Null,
            })
            .collect();
        assert_eq!(
            &Value::Array(actual),
            want,
            "{scenario}: per-record activity identity"
        );
    }

    if let Some(want) = expected.get("distinctActivityIds") {
        let actual: BTreeSet<String> = snapshot
            .records
            .iter()
            .filter_map(|record| record.activity_id.clone())
            .collect();
        assert_eq!(
            actual.into_iter().collect::<Vec<_>>(),
            strings(want),
            "{scenario}: distinct activity identities"
        );
    }

    if let Some(want) = expected.get("restrictedRecordIndexes") {
        let actual: Vec<u64> = snapshot
            .records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.context.sensitivity == IntuneSensitivity::Restricted)
            .map(|(index, _)| index as u64)
            .collect();
        assert_eq!(
            actual,
            want.as_array()
                .expect("restrictedRecordIndexes")
                .iter()
                .map(|value| value.as_u64().expect("index"))
                .collect::<Vec<_>>(),
            "{scenario}: records classified restricted"
        );
    }

    if let Some(want) = expected.get("malformedRecordIndexes") {
        let actual: Vec<u64> = snapshot
            .records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.profile == CompanyPortalRecordProfile::Unrecognized)
            .map(|(index, _)| index as u64)
            .collect();
        assert_eq!(
            actual,
            want.as_array()
                .expect("malformedRecordIndexes")
                .iter()
                .map(|value| value.as_u64().expect("index"))
                .collect::<Vec<_>>(),
            "{scenario}: records this build could not decompose"
        );
    }

    for rule in expected
        .get("messageMustContain")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let index = rule["recordIndex"].as_u64().expect("recordIndex") as usize;
        let record = snapshot
            .records
            .get(index)
            .unwrap_or_else(|| panic!("{scenario}: no record at index {index}"));
        for text in strings(&rule["texts"]) {
            assert!(
                record.message.value.contains(&text),
                "{scenario}: record {index} lost {text:?}; message is {:?}",
                record.message.value
            );
        }
        // Losslessness: whatever the message claims must also be in the raw text.
        for text in strings(&rule["texts"]) {
            assert!(
                record.raw.value.contains(&text),
                "{scenario}: record {index} raw text lost {text:?}"
            );
        }
    }
}

fn assert_decoding(scenario: &str, manifest: &Value, expected: &Value) {
    let Some(rules) = expected.get("decoding").and_then(Value::as_array) else {
        return;
    };
    let root = scenario_root(scenario);
    for rule in rules {
        let id = rule["artifactId"].as_str().expect("artifactId");
        let relative = manifest["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .find(|artifact| artifact["artifactId"].as_str() == Some(id))
            .and_then(|artifact| artifact["relativePath"].as_str())
            .unwrap_or_else(|| panic!("{scenario}: artifact {id} has no file to decode"));

        let bytes = fs::read(root.join(relative)).expect("evidence is readable");
        let decoded = decode_log_bytes(&bytes);
        assert_eq!(
            decoded.encoding,
            rule["encoding"].as_str().expect("encoding"),
            "{scenario}/{id}: decoded encoding"
        );
        assert_eq!(
            decoded.had_bom,
            rule["hadBom"].as_bool().expect("hadBom"),
            "{scenario}/{id}: byte-order mark"
        );
    }
}

fn assert_findings(scenario: &str, snapshot: &CompanyPortalLogSnapshot, expected: &Value) {
    let actual = derive_findings(snapshot);
    let want = expected["findings"].as_array().expect("findings");

    assert_eq!(
        actual
            .iter()
            .map(|finding| finding.finding_id.as_str())
            .collect::<Vec<_>>(),
        want.iter()
            .map(|finding| finding["findingId"].as_str().expect("findingId"))
            .collect::<Vec<_>>(),
        "{scenario}: findings"
    );

    for (finding, want) in actual.iter().zip(want) {
        let at = format!("{scenario}/{}", finding.finding_id);
        assert_eq!(
            serde_json::to_value(&finding.severity).expect("severity serializes"),
            want["severity"],
            "{at}: severity"
        );
        assert_eq!(
            serde_json::to_value(&finding.confidence).expect("confidence serializes"),
            want["confidence"],
            "{at}: confidence"
        );
        assert_eq!(
            finding
                .evidence
                .iter()
                .map(|reference| reference.evidence_id.clone())
                .collect::<Vec<_>>(),
            strings(&want["evidence"]),
            "{at}: cited evidence"
        );
        assert_eq!(
            finding.coverage_gap_ids,
            strings(&want["coverageGapIds"]),
            "{at}: cited coverage gaps"
        );
        assert!(
            finding.is_evidence_backed(),
            "{at}: a finding must cite evidence or a coverage gap"
        );
    }
}

fn assert_redaction(scenario: &str, snapshot: &CompanyPortalLogSnapshot, expected: &Value) {
    if expected.get("redactionMustNotContain").is_none()
        && expected.get("redactionMustContain").is_none()
    {
        return;
    }

    let redacted = redacted_company_portal_log_export(snapshot);
    let text = serde_json::to_string(&redacted).expect("redacted export must serialize");

    for needle in expected
        .get("redactionMustNotContain")
        .map(strings)
        .unwrap_or_default()
    {
        assert!(
            !text.contains(&needle),
            "{scenario}: redacted export still contains {needle:?}"
        );
    }
    for needle in expected
        .get("redactionMustContain")
        .map(strings)
        .unwrap_or_default()
    {
        assert!(
            text.contains(&needle),
            "{scenario}: redacted export dropped correlation key {needle:?}"
        );
    }
}

// ── Corpus shape ────────────────────────────────────────────────────────────

#[test]
fn the_scenario_matrix_is_pinned() {
    assert_eq!(
        scenario_names(&corpus_root()),
        SCENARIOS.map(str::to_owned).to_vec(),
        "the required fixture matrix of issue #368 must stay complete"
    );
}

// ── The required fixture matrix ─────────────────────────────────────────────

/// 1. Basic information, warning, and error records.
#[test]
fn basic_information_warning_and_error_records() {
    let snapshot = assert_scenario("basic-severity-records");
    // Severity is structural: the error record's own message says nothing about
    // failing, and the info record's message contains no reassuring word either.
    assert_eq!(
        snapshot.records[3].severity_token.as_deref(),
        Some("E"),
        "the raw severity token must be retained alongside the mapped severity"
    );
}

/// 2. Advanced-logging certificate and network record with redaction.
#[test]
fn advanced_logging_certificate_and_network_record_is_redactable() {
    assert_scenario("advanced-logging-certificate-network");
}

/// 3. Multiline exception and payload.
#[test]
fn multiline_exception_and_payload_stay_one_record() {
    let snapshot = assert_scenario("multiline-exception-payload");
    assert_eq!(
        snapshot.records[1].continuation_lines, 7,
        "every continuation line must be attributed to the record above it"
    );
}

/// 4. Rotation ordering.
#[test]
fn rotation_members_are_ordered_oldest_first() {
    assert_scenario("rotation-ordering");
}

/// 5. Same time, distinct activity identities.
#[test]
fn records_sharing_a_timestamp_keep_distinct_activities() {
    let snapshot = assert_scenario("same-time-distinct-activities");
    let stamps: BTreeSet<String> = snapshot.records[1..]
        .iter()
        .filter_map(|record| {
            record
                .context
                .source_timestamp
                .as_ref()
                .map(|timestamp| timestamp.raw_text.clone())
        })
        .collect();
    assert_eq!(
        stamps.len(),
        1,
        "the scenario is only meaningful if all four records share one timestamp"
    );
}

/// 6. Invalid and truncated record.
#[test]
fn a_truncated_record_is_reported_without_being_dropped() {
    let snapshot = assert_scenario("invalid-truncated-record");
    let malformed = &snapshot.records[2];
    assert_eq!(
        malformed.severity, None,
        "a record whose fields could not be read must not be assigned a severity"
    );
    assert_eq!(
        malformed.message.value, malformed.raw.value,
        "an unreadable record's message is its exact source text"
    );
}

/// 7. Encoding and byte-order-mark variants.
#[test]
fn encoding_and_bom_variants_are_decoded() {
    assert_scenario("encoding-bom-variants");
}

/// The Windows-1252 half of the encoding contract.
///
/// It cannot live in the corpus: the shared harness reads every evidence file as
/// UTF-8, so a file that is only valid as Windows-1252 would be rejected as
/// unreadable before any of this leaf's assertions ran. The bytes are therefore
/// supplied inline.
#[test]
fn non_utf8_bytes_fall_back_to_windows_1252() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        "2026-03-12 14:00:00:000-0700 | CompanyPortal | I | 1 | Logging | \
         SYNTHETIC FIXTURE: legacy encoding\n"
            .as_bytes(),
    );
    // 0xE9 is `é` in Windows-1252 and an invalid lone byte in UTF-8.
    bytes.extend_from_slice(
        b"2026-03-12 14:00:01:000-0700 | CompanyPortal | I | 1 | Sync | caf\xE9 sync\n",
    );

    let decoded = decode_log_bytes(&bytes);
    assert_eq!(decoded.encoding, "windows-1252");
    assert!(!decoded.had_bom);

    let snapshot = analyze_company_portal_logs(&[CompanyPortalLogSource::captured(
        "cp-legacy",
        "CompanyPortal.log",
        decoded.text,
        "2026-07-31T00:00:00Z",
    )]);
    assert_eq!(snapshot.stats.total_records, 2);
    assert!(snapshot.records[1].message.value.contains("café sync"));
}

/// 8. Unknown app version.
#[test]
fn an_unknown_app_version_demotes_confidence_without_losing_records() {
    let snapshot = assert_scenario("unknown-app-version");
    assert_eq!(
        snapshot.records[0].app_version.as_deref(),
        Some("9.2601.0"),
        "the declared version must be retained on the record that declared it"
    );
}

/// 9. Direct app log versus saved diagnostic report, negative.
#[test]
fn a_saved_diagnostic_report_is_never_claimed_as_a_direct_app_log() {
    let snapshot = assert_scenario("negative-saved-diagnostic-report");
    assert!(
        snapshot.records.is_empty(),
        "a refused artifact must contribute no records"
    );
}

/// 10. Direct app log versus generic macOS unified-log export, negative.
#[test]
fn a_unified_log_export_is_never_claimed_as_a_direct_app_log() {
    let snapshot = assert_scenario("negative-unified-log-export");
    assert!(snapshot.records.is_empty());
}

/// 11. Deterministic privacy export.
#[test]
fn the_privacy_export_is_deterministic_and_idempotent() {
    let snapshot = assert_scenario("deterministic-privacy-export");

    let once = redacted_company_portal_log_export(&snapshot);
    let again = redacted_company_portal_log_export(&snapshot);
    assert_eq!(
        serde_json::to_string(&once).unwrap(),
        serde_json::to_string(&again).unwrap(),
        "two runs over the same snapshot must be byte identical"
    );

    let twice = redacted_company_portal_log_export(&once);
    assert_eq!(
        serde_json::to_value(&once).unwrap(),
        serde_json::to_value(&twice).unwrap(),
        "redacting an already-redacted snapshot must change nothing"
    );

    // One identity, two records: the pseudonym has to be the same in both or the
    // export has destroyed the correlation it exists to preserve.
    let expected = load_json(&scenario_root("deterministic-privacy-export").join("expected.json"));
    let indexes: Vec<usize> = expected["repeatedIdentityRecordIndexes"]
        .as_array()
        .expect("repeatedIdentityRecordIndexes")
        .iter()
        .map(|value| value.as_u64().expect("index") as usize)
        .collect();
    let pseudonym = once.records[indexes[0]]
        .message
        .value
        .split_whitespace()
        .find(|token| token.starts_with("[redacted-identity-"))
        .expect("the first record must carry an identity pseudonym")
        .to_owned();
    for index in &indexes[1..] {
        assert!(
            once.records[*index].message.value.contains(&pseudonym),
            "record {index} lost the shared identity pseudonym {pseudonym:?}"
        );
    }
}

// ── Detection registration ──────────────────────────────────────────────────

/// Positive corpus: every scenario whose manifest says the artifact is a direct
/// app log must be confirmed from content.
#[test]
fn the_positive_detection_corpus_is_confirmed_from_content() {
    let mut failures = Failures::new();
    for scenario in SCENARIOS {
        let (snapshot, manifest, _) = load_scenario(scenario);
        for artifact in manifest["artifacts"].as_array().expect("artifacts") {
            if artifact["sourceKind"].as_str() != Some("companyPortalAppLog") {
                continue;
            }
            let id = artifact["artifactId"].as_str().expect("artifactId");
            let Some(state) =
                CompanyPortalCaptureState::from_wire(artifact["captureState"].as_str().unwrap())
            else {
                continue;
            };
            // A parseFailed artifact is a direct-app-log *candidate* whose bytes
            // turned out to be unreadable, so it is not part of the positive set.
            if state != CompanyPortalCaptureState::Captured {
                continue;
            }
            let confirmed = snapshot
                .artifacts
                .iter()
                .find(|candidate| candidate.artifact_id == id)
                .is_some_and(|candidate| candidate.detection.confirmed);
            failures.require(confirmed, || {
                format!("{scenario}/{id}: a captured app log must be confirmed from content")
            });
        }
    }
    failures.assert_empty("positive detection corpus");
}

/// Negative corpus: content that is not a direct app log is refused, and the
/// reason names which other source kind it was.
#[test]
fn the_negative_detection_corpus_is_refused_with_a_reason() {
    for (scenario, artifact_id, reason) in [
        (
            "negative-saved-diagnostic-report",
            "cp-report",
            "diagnosticReport",
        ),
        (
            "negative-unified-log-export",
            "cp-unified",
            "unifiedLogExport",
        ),
        ("invalid-truncated-record", "cp-1", "noRecords"),
    ] {
        let (snapshot, _, _) = load_scenario(scenario);
        let artifact = snapshot
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == artifact_id)
            .unwrap_or_else(|| panic!("{scenario}: no artifact {artifact_id}"));
        assert!(!artifact.detection.confirmed, "{scenario}: must be refused");
        assert_eq!(
            serde_json::to_value(&artifact.detection.rejection).unwrap(),
            json!(reason),
            "{scenario}: rejection reason"
        );
    }
}

/// A path hint narrows the search and never confirms on its own.
#[test]
fn the_company_portal_path_hint_alone_never_confirms() {
    let detection = detect_company_portal_log_content(
        "CompanyPortal.log",
        Some("SYNTHETIC://Library/Logs/CompanyPortal/CompanyPortal.log"),
        "nothing in this file resembles a record\nnor does this line\n",
    );
    assert!(detection.path_hint, "the hint must still be reported");
    assert!(
        !detection.confirmed,
        "a path hint is a candidate signal, never proof"
    );
}

/// Adding this leaf must not change how any existing file is classified.
///
/// Detection is registered inside the leaf rather than in `crate::parser::detect`
/// precisely so this holds, and the assertion pins it: a Company Portal log still
/// resolves through the generic fallback until a follow-up change routes it.
#[test]
fn generic_fallback_classification_is_unchanged() {
    let content = fs::read_to_string(
        scenario_root("basic-severity-records")
            .join("evidence/cp-current/current/CompanyPortal.log"),
    )
    .expect("evidence is readable");

    let selection = cmtraceopen_parser::parser::detect::detect_parser(
        "SYNTHETIC://Library/Logs/CompanyPortal/CompanyPortal.log",
        &content,
    );
    assert_eq!(
        selection.parser,
        cmtraceopen_parser::models::log_entry::ParserKind::Timestamped,
        "a Company Portal log must keep resolving through the generic fallback"
    );
}

// ── LogEntry projection ─────────────────────────────────────────────────────

/// The viewer-facing output contract: one entry per logical record, lossless.
#[test]
fn the_log_entry_projection_matches_the_reduced_records() {
    for scenario in ["basic-severity-records", "multiline-exception-payload"] {
        let path = scenario_root(scenario).join("evidence/cp-current/current/CompanyPortal.log");
        let content = fs::read_to_string(&path).expect("evidence is readable");
        let (entries, parse_errors) = parse_content(&content, &path.to_string_lossy());
        let (snapshot, _, _) = load_scenario(scenario);

        assert_eq!(
            entries.len() as u32,
            snapshot.stats.total_records,
            "{scenario}: one entry per logical record"
        );
        assert_eq!(
            parse_errors, snapshot.stats.malformed_records,
            "{scenario}: parse error count"
        );
        for (entry, record) in entries.iter().zip(&snapshot.records) {
            assert_eq!(
                entry.message, record.message.value,
                "{scenario}: entry and record messages must agree"
            );
        }
    }
}

// ── Corpus self-checks ──────────────────────────────────────────────────────

/// Every fixture satisfies the shared contract, checked in one place so a single
/// run reports every corpus problem rather than the first one.
#[test]
fn every_scenario_satisfies_the_shared_fixture_contract() {
    let mut failures = Failures::new();
    for scenario in SCENARIOS {
        let root = scenario_root(scenario);
        failures.absorb(validate_scenario(
            scenario,
            &root,
            &load_json(&root.join("manifest.json")),
            &load_json(&root.join("expected.json")),
        ));
    }
    failures.assert_empty("company portal macOS logs corpus");
}

/// The corpus validator is actually enforcing something on *this* corpus.
///
/// A validator that silently passes everything would make every assertion above
/// vacuous, so one deliberate corruption is checked for rejection.
#[test]
fn a_corrupted_manifest_is_rejected_by_the_shared_validator() {
    let scenario = "basic-severity-records";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));

    let corrupted = mutated(&manifest, "/artifacts/0/bytesCopied", json!(1));
    let failures = validate_scenario(scenario, &root, &corrupted, &expected);
    assert!(
        failures
            .entries()
            .iter()
            .any(|entry| entry.contains("bytesCopied")),
        "a byte count that disagrees with the file must be rejected, got {:?}",
        failures.entries()
    );
}

/// Nothing in the corpus may name a real user home directory.
///
/// The shared privacy scan already forbids the literal, but macOS Company Portal
/// logs are unusually full of home-relative paths, so the corpus is checked for
/// the sanitized replacement being used consistently rather than only for the
/// forbidden form being absent.
#[test]
fn sanitized_paths_are_used_throughout_the_corpus() {
    for scenario in SCENARIOS {
        let manifest = load_json(&scenario_root(scenario).join("manifest.json"));
        for artifact in manifest["artifacts"].as_array().expect("artifacts") {
            let Some(path) = artifact["sanitizedSourcePath"].as_str() else {
                continue;
            };
            assert!(
                path.starts_with("SYNTHETIC://"),
                "{scenario}: sanitizedSourcePath {path:?} must use the synthetic scheme"
            );
        }
    }
}

/// Every confirmed artifact carries the synthetic marker inside a real record.
///
/// The harness requires the marker on the first line of every evidence file. A
/// bare marker line would frame as an orphan record and show up as a parse error
/// in every scenario, so the corpus writes it inside a genuine record. This pins
/// that convention directly rather than inferring it from a total.
#[test]
fn the_synthetic_marker_is_carried_by_a_real_record() {
    for scenario in SCENARIOS {
        let (snapshot, _, _) = load_scenario(scenario);
        for artifact in snapshot
            .artifacts
            .iter()
            .filter(|artifact| artifact.detection.confirmed)
        {
            let first = snapshot
                .records
                .iter()
                .find(|record| record.context.provenance.source_artifact_id == artifact.artifact_id)
                .unwrap_or_else(|| {
                    panic!("{scenario}: confirmed artifact {} has no records", artifact.artifact_id)
                });
            assert_ne!(
                first.profile,
                CompanyPortalRecordProfile::Unrecognized,
                "{scenario}/{}: the marker record must decompose, not read as an orphan",
                artifact.artifact_id
            );
            assert!(
                first.message.value.contains("SYNTHETIC FIXTURE"),
                "{scenario}/{}: the first record must carry the synthetic marker",
                artifact.artifact_id
            );
        }
    }
}
