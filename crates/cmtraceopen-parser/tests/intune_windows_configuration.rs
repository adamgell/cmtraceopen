//! Contract tests for `intune::device::windows::configuration` (issue #363).
//!
//! The corpus under `tests/fixtures/intune/device/windows/configuration/` is the
//! acceptance criteria for the issue's required fixture matrix. Each scenario is
//! run end to end: the manifest is validated by the shared harness, the evidence
//! files are decoded into the shared normalized inputs, the analyzer runs, and
//! its per-setting states, finding vocabulary, and citations are compared with
//! the hand-authored `expected.json`.
//!
//! Scenarios that would need a device to produce (an unsubstantiated conflict,
//! records with no identifier at all) are exercised from synthesized inputs at
//! the bottom of this file rather than by inflating the matrix.

mod support;

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{json, Value};

use cmtraceopen_parser::intune::device::windows::configuration::{
    analyze_configuration, redacted_configuration_snapshot, ConfigurationInput,
    ConfigurationSetting, ConfigurationSnapshot, INTUNE_CONFIGURATION_SCHEMA_VERSION,
};
use cmtraceopen_parser::intune::evidence::{
    IntuneArtifactCoverage, IntuneArtifactStatus, IntuneEvidenceRef, IntuneNamedValue,
    IntuneObservationContext, IntuneParseState, IntuneProvenance, IntuneSensitivity,
    IntuneSourceKind, IntuneTimestamp, IntuneTimestampKind,
};
use cmtraceopen_parser::intune::normalized::{
    NormalizedEventLevel, NormalizedSettingOutcome, NormalizedSettingReport,
    NormalizedWindowsEvent, INTUNE_NORMALIZED_SCHEMA_VERSION,
};
use support::{load_json, mutated, scenario_names, validate_scenario, Failures};

const CORPUS: &str = "device/windows/configuration";

/// The required fixture matrix from issue #363, pinned so a scenario cannot be
/// quietly dropped or renamed.
const SCENARIOS: [&str; 17] = [
    "applied-from-csp-event",
    "cloud-success-local-terminal-error",
    "conflict-between-two-sources",
    "csp-terminal-error",
    "deterministic-redaction",
    "duplicate-display-name-different-csp-paths",
    "event-only-evidence",
    "incomplete-channel-coverage",
    "invalid-offset-and-contradictory-ordering",
    "local-success-cloud-failure",
    "malformed-mdm-report",
    "not-applicable-setting",
    "removal-rollback",
    "report-only-evidence",
    "scope-mismatch-device-and-user",
    "superseded-by-replacement-source",
    "unknown-report-schema",
];

/// Every finding identifier this build is allowed to emit.
///
/// A rule that invents an identifier outside this list has escaped review, and a
/// consumer keying on identifiers would break silently.
const FINDING_VOCABULARY: [&str; 21] = [
    "configuration-applied",
    "configuration-conflict",
    "configuration-conflict-unsubstantiated",
    "configuration-contested-device-evidence",
    "configuration-device-only-evidence",
    "configuration-duplicate-display-name",
    "configuration-local-rejection",
    "configuration-local-service-contradiction",
    "configuration-not-applicable",
    "configuration-removed",
    "configuration-scope-split",
    "configuration-service-only-evidence",
    "configuration-superseded",
    "configuration-superseded-unsubstantiated",
    "configuration-truncated-artifacts",
    "configuration-unassessable-failure",
    "configuration-unattributed-records",
    "configuration-uncollected-artifacts",
    "configuration-uninterpretable-evidence",
    "configuration-unreadable-artifacts",
    "configuration-unusable-ordering",
];

fn corpus_root() -> PathBuf {
    support::corpus_root(CORPUS)
}

fn scenario_root(scenario: &str) -> PathBuf {
    corpus_root().join(scenario)
}

// ── Loading ─────────────────────────────────────────────────────────────────

/// Build the analyzer input from one scenario's manifest and evidence files.
///
/// This is the boundary a native adapter would occupy: it reads bytes and hands
/// the pure crate the shared normalized types. The parser crate itself never
/// touches the filesystem.
fn load_input(scenario: &str) -> ConfigurationInput {
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));

    let mut input = ConfigurationInput {
        generated_at_utc: manifest["generatedAtUtc"]
            .as_str()
            .expect("manifest declares generatedAtUtc")
            .to_owned(),
        ..ConfigurationInput::default()
    };

    for artifact in manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts is an array")
    {
        let artifact_id = artifact["artifactId"]
            .as_str()
            .expect("artifact declares an id");
        input.coverage.push(coverage_entry(artifact));

        let Some(relative) = artifact["relativePath"].as_str() else {
            continue;
        };
        let document = load_json(&root.join(relative));

        match artifact["payload"].as_str() {
            Some("events") => {
                let events: Vec<NormalizedWindowsEvent> =
                    serde_json::from_value(document["events"].clone()).unwrap_or_else(|error| {
                        panic!("{scenario}/{artifact_id}: events decode: {error}")
                    });
                input.events.extend(events);
            }
            Some("reports") => {
                let reports: Vec<NormalizedSettingReport> =
                    serde_json::from_value(document["reports"].clone()).unwrap_or_else(|error| {
                        panic!("{scenario}/{artifact_id}: reports decode: {error}")
                    });
                input.reports.extend(reports);
            }
            other => panic!("{scenario}/{artifact_id}: unknown payload kind {other:?}"),
        }
    }

    input
}

fn coverage_entry(artifact: &Value) -> IntuneArtifactCoverage {
    let capture_state = artifact["captureState"]
        .as_str()
        .expect("artifact declares a captureState");
    IntuneArtifactCoverage {
        artifact_id: artifact["artifactId"]
            .as_str()
            .expect("artifact declares an id")
            .to_owned(),
        family: artifact["family"].as_str().unwrap_or_default().to_owned(),
        status: status_for(capture_state),
        detail: None,
        observed_at_utc: artifact["capturedUtc"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        evidence: Vec::new(),
    }
}

/// The manifest's capture state, mapped onto the shared coverage vocabulary.
///
/// Kept explicit rather than derived from the harness table so a drift in either
/// direction is a compile-visible change here.
fn status_for(capture_state: &str) -> IntuneArtifactStatus {
    match capture_state {
        "captured" => IntuneArtifactStatus::Available,
        "capped" => IntuneArtifactStatus::Capped,
        "absent" => IntuneArtifactStatus::Missing,
        "accessDenied" => IntuneArtifactStatus::PermissionDenied,
        "skipped" => IntuneArtifactStatus::Skipped,
        "unsupported" => IntuneArtifactStatus::Unsupported,
        "parseFailed" => IntuneArtifactStatus::ParseFailed,
        other => panic!("unknown captureState {other:?}"),
    }
}

fn wire<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("shared contract types serialize")
}

/// The semantic projection compared against `expected.json`.
fn project(setting: &ConfigurationSetting) -> Value {
    let source_ids = setting
        .sources
        .iter()
        .filter_map(|statement| statement.source_id.clone())
        .collect::<BTreeSet<_>>();
    let evidence_ids = setting
        .evidence
        .iter()
        .map(|reference| reference.evidence_id.clone())
        .collect::<BTreeSet<_>>();

    json!({
        "key": setting.identity.key,
        "scope": wire(&setting.identity.scope),
        "canonicalUri": setting.identity.canonical_uri,
        "displayName": setting.identity.display_name,
        "receipt": wire(&setting.receipt),
        "local": wire(&setting.local),
        "service": wire(&setting.service),
        "resolution": wire(&setting.resolution),
        "sourceIds": source_ids.into_iter().collect::<Vec<_>>(),
        "localErrorHex": setting.local_error.as_ref().and_then(|code| code.hex.clone()),
        "serviceErrorHex": setting.service_error.as_ref().and_then(|code| code.hex.clone()),
        "appliedValue": setting.applied_value,
        "timeIsReliable": setting.time_is_reliable,
        "orderingIsContradictory": setting.ordering_is_contradictory,
        "hasUninterpretableEvidence": setting.has_uninterpretable_evidence,
        "hasUnassessableFailure": setting.has_unassessable_failure,
        "evidenceIds": evidence_ids.into_iter().collect::<Vec<_>>(),
    })
}

fn finding_ids(snapshot: &ConfigurationSnapshot) -> Vec<String> {
    snapshot
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect()
}

// ── Corpus contract ─────────────────────────────────────────────────────────

#[test]
fn the_corpus_exposes_exactly_the_required_fixture_matrix() {
    assert_eq!(
        scenario_names(&corpus_root()),
        SCENARIOS.map(str::to_owned).to_vec(),
        "the corpus must match the fixture matrix required by issue #363"
    );
}

#[test]
fn every_scenario_satisfies_the_shared_fixture_contract() {
    let mut failures = Failures::new();
    for scenario in SCENARIOS {
        let root = scenario_root(scenario);
        let manifest = load_json(&root.join("manifest.json"));
        let expected = load_json(&root.join("expected.json"));
        failures.absorb(validate_scenario(scenario, &root, &manifest, &expected));
    }
    failures.assert_empty("configuration corpus");
}

#[test]
fn every_evidence_file_is_decodable_and_carries_the_marker() {
    for scenario in SCENARIOS {
        let root = scenario_root(scenario);
        let manifest = load_json(&root.join("manifest.json"));
        for artifact in manifest["artifacts"].as_array().expect("artifacts array") {
            let Some(relative) = artifact["relativePath"].as_str() else {
                continue;
            };
            let document = load_json(&root.join(relative));
            let marker = document["_marker"].as_str().unwrap_or_default();
            assert!(
                marker.contains(support::SYNTHETIC_MARKER),
                "{scenario}: {relative} must carry the synthetic marker as its first key"
            );
        }
    }
}

#[test]
fn a_corrupted_byte_count_is_rejected_for_this_corpus_too() {
    // The shared harness owns this rule; asserting it here proves the corpus is
    // actually wired into the validator rather than merely sitting next to it.
    let scenario = "applied-from-csp-event";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let failures = validate_scenario(
        scenario,
        &root,
        &mutated(&manifest, "/artifacts/0/bytesCopied", json!(1)),
        &expected,
    );
    assert!(
        failures
            .entries()
            .iter()
            .any(|entry| entry.contains("bytesCopied")),
        "a wrong byte count must be rejected, got {:?}",
        failures.entries()
    );
}

// ── Analysis contract ───────────────────────────────────────────────────────

#[test]
fn every_scenario_matches_its_expected_analysis() {
    for scenario in SCENARIOS {
        let expected = load_json(&scenario_root(scenario).join("expected.json"));
        let snapshot = analyze_configuration(&load_input(scenario));

        assert_eq!(
            snapshot.schema_version, INTUNE_CONFIGURATION_SCHEMA_VERSION,
            "{scenario}: snapshot schema version"
        );

        let actual_settings = snapshot.settings.iter().map(project).collect::<Vec<_>>();
        assert_eq!(
            Value::Array(actual_settings),
            expected["settings"],
            "{scenario}: per-setting states"
        );

        assert_eq!(
            json!(finding_ids(&snapshot)),
            expected["findingIds"],
            "{scenario}: finding identifiers, in rule order"
        );

        // Confidence is a claim about how far the evidence reaches, and ADR-001
        // makes it a contract rather than a presentation detail. Pinning only the
        // identifiers let a High-confidence success survive a bundle whose
        // artifacts were capped, denied, and missing.
        let actual_confidence = snapshot
            .findings
            .iter()
            .map(|finding| (finding.finding_id.clone(), wire(&finding.confidence)))
            .collect::<serde_json::Map<_, _>>();
        assert_eq!(
            Value::Object(actual_confidence),
            expected["findingConfidence"],
            "{scenario}: finding confidence"
        );

        let actual_coverage = snapshot
            .coverage
            .iter()
            .map(|entry| json!({"artifactId": entry.artifact_id, "status": wire(&entry.status)}))
            .collect::<Vec<_>>();
        assert_eq!(
            Value::Array(actual_coverage),
            expected["coverage"],
            "{scenario}: coverage"
        );
    }
}

#[test]
fn cited_evidence_matches_the_expectation_where_a_scenario_pins_it() {
    // Conflict, supersedence, and contradiction findings are the ones issue #363
    // requires to cite the competing evidence rather than assert an outcome, so
    // those scenarios pin the exact citation set.
    let mut checked = 0;
    for scenario in SCENARIOS {
        let expected = load_json(&scenario_root(scenario).join("expected.json"));
        let Some(pinned) = expected["findingEvidence"].as_object() else {
            continue;
        };
        let snapshot = analyze_configuration(&load_input(scenario));
        for (finding_id, evidence_ids) in pinned {
            let finding = snapshot
                .findings
                .iter()
                .find(|finding| finding.finding_id == *finding_id)
                .unwrap_or_else(|| panic!("{scenario}: expected finding {finding_id}"));
            let actual = finding
                .evidence
                .iter()
                .map(|reference| reference.evidence_id.clone())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                json!(actual.into_iter().collect::<Vec<_>>()),
                *evidence_ids,
                "{scenario}: {finding_id} must cite exactly the competing evidence"
            );
            checked += 1;
        }
    }
    assert!(checked >= 2, "expected several pinned citation sets");
}

/// `assertions` is prose, and prose is not a test.
///
/// Two of the flagship scenarios claimed "the conflict finding cites the
/// competing rows" while emitting no such finding at all, because nothing ever
/// compared the sentence with the output. A sentence that claims a citation must
/// therefore be backed by a `findingEvidence` block, which
/// `cited_evidence_matches_the_expectation_where_a_scenario_pins_it` does check.
#[test]
fn a_scenario_that_claims_a_citation_in_prose_must_pin_that_citation() {
    for scenario in SCENARIOS {
        let expected = load_json(&scenario_root(scenario).join("expected.json"));
        let assertions = expected["assertions"]
            .as_array()
            .unwrap_or_else(|| panic!("{scenario}: expected.json declares assertions"));
        assert!(
            !assertions.is_empty(),
            "{scenario}: assertions must not be empty"
        );

        let claims_a_citation = assertions.iter().any(|assertion| {
            let text = assertion.as_str().unwrap_or_default();
            text.contains("cites") || text.contains("cited")
        });
        if claims_a_citation {
            assert!(
                expected["findingEvidence"].is_object(),
                "{scenario}: an assertion claims a citation, so the scenario must pin \
                 findingEvidence for it rather than leave the claim unchecked"
            );
        }
    }
}

#[test]
fn every_finding_cites_evidence_or_a_coverage_gap() {
    for scenario in SCENARIOS {
        let snapshot = analyze_configuration(&load_input(scenario));
        for finding in &snapshot.findings {
            assert!(
                finding.is_evidence_backed(),
                "{scenario}: finding {} cites neither evidence nor a coverage gap",
                finding.finding_id
            );
        }
    }
}

#[test]
fn findings_come_only_from_the_documented_vocabulary() {
    let vocabulary = FINDING_VOCABULARY.iter().copied().collect::<BTreeSet<_>>();
    for scenario in SCENARIOS {
        let snapshot = analyze_configuration(&load_input(scenario));
        for finding in &snapshot.findings {
            assert!(
                vocabulary.contains(finding.finding_id.as_str()),
                "{scenario}: undocumented finding id {}",
                finding.finding_id
            );
        }
    }
}

#[test]
fn every_documented_finding_is_reachable_from_the_corpus_or_a_synthesized_case() {
    // A vocabulary entry no fixture can produce is either dead code or an
    // untested rule; both are worth failing over.
    let mut seen = BTreeSet::new();
    for scenario in SCENARIOS {
        let snapshot = analyze_configuration(&load_input(scenario));
        seen.extend(finding_ids(&snapshot));
    }
    for snapshot in [
        analyze_configuration(&unsubstantiated_conflict_input()),
        analyze_configuration(&unsubstantiated_supersedence_input()),
        analyze_configuration(&ordered_conflict_input()),
        analyze_configuration(&ordered_supersedence_input()),
        analyze_configuration(&unattributed_input()),
        analyze_configuration(&contested_device_input()),
        analyze_configuration(&unassessable_failure_input()),
    ] {
        seen.extend(finding_ids(&snapshot));
    }

    let missing = FINDING_VOCABULARY
        .iter()
        .filter(|id| !seen.contains(**id))
        .collect::<Vec<_>>();
    assert!(missing.is_empty(), "unreachable finding rules: {missing:?}");
}

/// The record ordinals in a report snapshot describe the order rows were written
/// into the file. They do not say which policy won an argument, and swapping them
/// used to flip the two headline scenarios between `contested`/Error and
/// `conflicted`/Warning.
#[test]
fn renumbering_the_rows_of_a_correlated_scenario_does_not_change_the_diagnosis() {
    for scenario in [
        "conflict-between-two-sources",
        "superseded-by-replacement-source",
    ] {
        let baseline = analyze_configuration(&load_input(scenario));

        // A consistent alternative history: the same rows, written to the report
        // in the opposite order. Ordinals and timestamps move together, so the
        // bundle stays internally coherent and the only thing that changed is
        // which row the file happens to list first.
        let mut swapped = load_input(scenario);
        let positions = swapped
            .reports
            .iter()
            .map(|report| {
                (
                    report.context.provenance.record_number,
                    report.context.source_timestamp.clone(),
                )
            })
            .rev()
            .collect::<Vec<_>>();
        for (report, (ordinal, timestamp)) in swapped.reports.iter_mut().zip(positions) {
            report.context.provenance.record_number = ordinal;
            report.context.source_timestamp = timestamp;
        }

        let renumbered = analyze_configuration(&swapped);
        assert_eq!(
            baseline
                .settings
                .iter()
                .map(|setting| (wire(&setting.local), wire(&setting.resolution)))
                .collect::<Vec<_>>(),
            renumbered
                .settings
                .iter()
                .map(|setting| (wire(&setting.local), wire(&setting.resolution)))
                .collect::<Vec<_>>(),
            "{scenario}: record numbers must not decide the outcome"
        );
        assert_eq!(
            finding_ids(&baseline),
            finding_ids(&renumbered),
            "{scenario}: record numbers must not decide the findings"
        );
    }
}

#[test]
fn analysis_is_deterministic_across_repeated_runs() {
    for scenario in SCENARIOS {
        let input = load_input(scenario);
        assert_eq!(
            wire(&analyze_configuration(&input)),
            wire(&analyze_configuration(&input)),
            "{scenario}: analysis must be deterministic"
        );
    }
}

#[test]
fn settings_are_ordered_by_canonical_identity_key() {
    for scenario in SCENARIOS {
        let snapshot = analyze_configuration(&load_input(scenario));
        let keys = snapshot
            .settings
            .iter()
            .map(|setting| setting.identity.key.clone())
            .collect::<Vec<_>>();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "{scenario}: settings must be key-ordered");
    }
}

// ── Redaction ───────────────────────────────────────────────────────────────

#[test]
fn the_redaction_scenario_produces_the_pinned_tokens() {
    let scenario = "deterministic-redaction";
    let expected = load_json(&scenario_root(scenario).join("expected.json"));
    let snapshot = analyze_configuration(&load_input(scenario));
    let redacted = redacted_configuration_snapshot(&snapshot);

    assert!(!snapshot.redacted, "the reduced snapshot is not redacted");
    assert!(redacted.redacted, "the export marks itself redacted");

    let actual = redacted
        .settings
        .iter()
        .map(|setting| {
            json!({
                "key": setting.identity.key,
                "canonicalUri": setting.identity.canonical_uri,
                "appliedValue": setting.applied_value,
                "namedData": setting
                    .observations
                    .iter()
                    .flat_map(|observation| observation.named_data.iter())
                    .map(|entry| json!({"name": entry.name, "value": entry.value}))
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    assert_eq!(Value::Array(actual), expected["redactedSettings"]);

    let enrollment = redacted
        .settings
        .iter()
        .flat_map(|setting| setting.observations.iter())
        .find_map(|observation| observation.enrollment_id.clone());
    assert_eq!(
        json!(enrollment),
        expected["redactedEnrollmentId"],
        "an enrollment id is tokenized rather than dropped"
    );
}

#[test]
fn redaction_preserves_the_diagnosis_and_is_deterministic() {
    let snapshot = analyze_configuration(&load_input("deterministic-redaction"));
    let first = redacted_configuration_snapshot(&snapshot);
    let second = redacted_configuration_snapshot(&snapshot);

    assert_eq!(wire(&first), wire(&second), "redaction is deterministic");

    // ADR-004's invariant is that redaction does not alter a *conclusion*. The
    // conclusion is the identifier, severity, confidence, and citation set — not
    // the prose, which is built from setting labels and therefore carries node
    // paths. The previous expectation here compared whole findings and so pinned
    // the leak in place: a node path embedding a SID reached the export through
    // the summary, and any fix to that would have failed this test.
    let conclusion = |findings: &[cmtraceopen_parser::intune::evidence::IntuneFinding]| {
        findings
            .iter()
            .map(|finding| {
                json!({
                    "id": finding.finding_id,
                    "severity": wire(&finding.severity),
                    "confidence": wire(&finding.confidence),
                    "evidence": wire(&finding.evidence),
                    "coverageGapIds": finding.coverage_gap_ids,
                })
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        conclusion(&first.findings),
        conclusion(&snapshot.findings),
        "redaction must not change what a finding concludes or cites"
    );
    assert_eq!(
        first
            .settings
            .iter()
            .map(|setting| wire(&setting.resolution))
            .collect::<Vec<_>>(),
        snapshot
            .settings
            .iter()
            .map(|setting| wire(&setting.resolution))
            .collect::<Vec<_>>(),
        "redaction must not change any resolution"
    );
}

#[test]
fn no_finding_or_coverage_text_carries_an_identity_the_settings_redacted() {
    // The settings and the prose that describes them are one export. A node path
    // scrubbed in `canonicalUri` and quoted verbatim in a finding summary is the
    // same disclosure, reached by a different field.
    for scenario in SCENARIOS {
        let redacted =
            redacted_configuration_snapshot(&analyze_configuration(&load_input(scenario)));
        let mut prose = Vec::new();
        for finding in &redacted.findings {
            prose.push(finding.title.clone());
            prose.push(finding.summary.clone());
            prose.extend(finding.recommended_checks.iter().cloned());
        }
        prose.extend(redacted.coverage.iter().filter_map(|e| e.detail.clone()));

        for text in prose {
            let lowercased = text.to_ascii_lowercase();
            assert!(
                !lowercased.contains("s-1-"),
                "{scenario}: a SID reached exported prose: {text}"
            );
            assert!(
                !lowercased.contains("@example.invalid"),
                "{scenario}: a UPN reached exported prose: {text}"
            );
        }
    }
}

#[test]
fn re_redacting_an_export_returns_it_unchanged() {
    // Callers chain projections; a token that gets hashed a second time silently
    // breaks the equality the first projection was there to preserve.
    for scenario in SCENARIOS {
        let once = redacted_configuration_snapshot(&analyze_configuration(&load_input(scenario)));
        let twice = redacted_configuration_snapshot(&once);
        assert_eq!(
            wire(&once),
            wire(&twice),
            "{scenario}: redaction is idempotent"
        );
    }
}

#[test]
fn redaction_keeps_the_configuration_source_identifiable() {
    let snapshot = analyze_configuration(&load_input("conflict-between-two-sources"));
    let redacted = redacted_configuration_snapshot(&snapshot);
    let sources = redacted
        .settings
        .iter()
        .flat_map(|setting| setting.sources.iter())
        .filter_map(|statement| statement.source_id.clone())
        .collect::<BTreeSet<_>>();
    assert!(
        sources
            .iter()
            .all(|source| !source.starts_with("[redacted")),
        "policy identifiers must survive redaction so the conflict stays actionable"
    );
    assert_eq!(sources.len(), 2);
}

#[test]
fn identical_values_redact_to_identical_tokens_across_settings() {
    let snapshot = analyze_configuration(&load_input("deterministic-redaction"));
    let redacted = redacted_configuration_snapshot(&snapshot);
    let wallpaper_value = redacted
        .settings
        .iter()
        .find_map(|setting| {
            setting
                .identity
                .canonical_uri
                .as_deref()?
                .contains("Personalization")
                .then(|| setting.applied_value.clone())?
        })
        .expect("the personalization setting is present");
    let previous_value = redacted
        .settings
        .iter()
        .flat_map(|setting| setting.observations.iter())
        .flat_map(|observation| observation.named_data.iter())
        .find(|entry| entry.name == "PreviousValue")
        .map(|entry| entry.value.clone())
        .expect("the previous-value pair is present");

    assert_eq!(
        wallpaper_value, previous_value,
        "the same underlying value must produce the same token"
    );
    assert!(wallpaper_value.starts_with("[redacted:"));
}

// ── Synthesized cases outside the fixture matrix ────────────────────────────

fn context(
    evidence_id: &str,
    artifact: &str,
    source_kind: IntuneSourceKind,
    parse_state: IntuneParseState,
) -> IntuneObservationContext {
    IntuneObservationContext {
        evidence_ref: IntuneEvidenceRef {
            evidence_id: evidence_id.to_owned(),
            source_artifact_id: artifact.to_owned(),
        },
        provenance: IntuneProvenance {
            source_kind,
            source_artifact_id: artifact.to_owned(),
            file_path: None,
            line_number: None,
            record_number: None,
            registry: None,
            event: None,
        },
        source_timestamp: Some(IntuneTimestamp {
            raw_text: "2026-07-31T09:00:00Z".to_owned(),
            original_offset: None,
            normalized_utc: Some("2026-07-31T09:00:00Z".to_owned()),
            kind: IntuneTimestampKind::Utc,
        }),
        observed_at_utc: "2026-07-31T10:00:00Z".to_owned(),
        sensitivity: IntuneSensitivity::Public,
        parse_state,
        access_state: cmtraceopen_parser::intune::evidence::IntuneAccessState::Available,
    }
}

fn row(
    evidence_id: &str,
    uri: Option<&str>,
    policy_id: Option<&str>,
    outcome: NormalizedSettingOutcome,
    named: Vec<(&str, &str)>,
) -> NormalizedSettingReport {
    NormalizedSettingReport {
        context: context(
            evidence_id,
            "mdm-diagnostic-report",
            IntuneSourceKind::DiagnosticReport,
            IntuneParseState::Parsed,
        ),
        setting_uri: uri.map(str::to_owned),
        setting_id: None,
        policy_id: policy_id.map(str::to_owned),
        display_name: None,
        outcome,
        value: None,
        error: None,
        named_data: named
            .into_iter()
            .map(|(name, value)| IntuneNamedValue {
                name: name.to_owned(),
                value: value.to_owned(),
            })
            .collect(),
    }
}

fn input_of(reports: Vec<NormalizedSettingReport>) -> ConfigurationInput {
    ConfigurationInput {
        generated_at_utc: "2026-07-31T10:00:00Z".to_owned(),
        events: Vec::new(),
        reports,
        coverage: Vec::new(),
    }
}

const NODE: &str = "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate";
const POLICY_A: &str = "11111111-1111-4111-8111-111111111111";
const POLICY_B: &str = "22222222-2222-4222-8222-222222222222";

fn unsubstantiated_conflict_input() -> ConfigurationInput {
    input_of(vec![row(
        "rpt-lonely-conflict",
        Some(NODE),
        Some(POLICY_A),
        NormalizedSettingOutcome::Conflict,
        Vec::new(),
    )])
}

fn unsubstantiated_supersedence_input() -> ConfigurationInput {
    input_of(vec![row(
        "rpt-lonely-supersedence",
        Some(NODE),
        Some(POLICY_A),
        NormalizedSettingOutcome::Superseded,
        vec![("SupersededBy", POLICY_B)],
    )])
}

fn ordered_conflict_input() -> ConfigurationInput {
    let mut applied = row(
        "ordered-applied",
        Some(NODE),
        Some(POLICY_A),
        NormalizedSettingOutcome::Applied,
        Vec::new(),
    );
    applied.context.provenance.record_number = Some(1);
    let mut conflict = row(
        "ordered-conflict",
        Some(NODE),
        Some(POLICY_B),
        NormalizedSettingOutcome::Conflict,
        Vec::new(),
    );
    conflict.context.provenance.record_number = Some(2);
    input_of(vec![applied, conflict])
}

fn ordered_supersedence_input() -> ConfigurationInput {
    let mut applied = row(
        "ordered-applied",
        Some(NODE),
        Some(POLICY_A),
        NormalizedSettingOutcome::Applied,
        Vec::new(),
    );
    applied.context.provenance.record_number = Some(1);
    let mut superseded = row(
        "ordered-superseded",
        Some(NODE),
        Some(POLICY_A),
        NormalizedSettingOutcome::Superseded,
        vec![("SupersededBy", POLICY_B)],
    );
    superseded.context.provenance.record_number = Some(2);
    let mut replacement = row(
        "ordered-replacement",
        Some(NODE),
        Some(POLICY_B),
        NormalizedSettingOutcome::Applied,
        Vec::new(),
    );
    replacement.context.provenance.record_number = Some(3);
    input_of(vec![applied, superseded, replacement])
}

fn unattributed_input() -> ConfigurationInput {
    input_of(vec![
        row(
            "rpt-nameless-1",
            None,
            Some(POLICY_A),
            NormalizedSettingOutcome::Applied,
            Vec::new(),
        ),
        row(
            "rpt-nameless-2",
            None,
            Some(POLICY_A),
            NormalizedSettingOutcome::Applied,
            Vec::new(),
        ),
    ])
}

/// A 404 command-failure event whose `Result:` token cannot be read.
fn unreadable_failure_event(evidence_id: &str, record_id: u64) -> NormalizedWindowsEvent {
    NormalizedWindowsEvent {
        context: context(
            evidence_id,
            "mdm-admin-channel",
            IntuneSourceKind::EventLog,
            IntuneParseState::Parsed,
        ),
        channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
            .to_owned(),
        provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider".to_owned(),
        event_id: 404,
        event_version: None,
        level: NormalizedEventLevel::Error,
        task: None,
        keywords: None,
        record_id: Some(record_id),
        activity_id: None,
        named_data: vec![IntuneNamedValue {
            name: "NodeUri".to_owned(),
            value: NODE.to_owned(),
        }],
        message: Some(
            "MDM ConfigurationManager: Command failure status. CSP URI: (./Device/Vendor/MSFT/\
             Policy/Config/Update/AllowAutoUpdate), Result: (unreadable)."
                .to_owned(),
        ),
    }
}

fn applied_event(evidence_id: &str, record_id: u64) -> NormalizedWindowsEvent {
    NormalizedWindowsEvent {
        context: context(
            evidence_id,
            "mdm-admin-channel",
            IntuneSourceKind::EventLog,
            IntuneParseState::Parsed,
        ),
        channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
            .to_owned(),
        provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider".to_owned(),
        event_id: 813,
        event_version: None,
        level: NormalizedEventLevel::Information,
        task: None,
        keywords: None,
        record_id: Some(record_id),
        activity_id: None,
        named_data: vec![
            IntuneNamedValue {
                name: "NodeUri".to_owned(),
                value: NODE.to_owned(),
            },
            IntuneNamedValue {
                name: "Value".to_owned(),
                value: "1".to_owned(),
            },
        ],
        message: None,
    }
}

fn unassessable_failure_input() -> ConfigurationInput {
    ConfigurationInput {
        generated_at_utc: "2026-07-31T10:00:00Z".to_owned(),
        events: vec![
            applied_event("evt-applied", 1),
            unreadable_failure_event("evt-unreadable-404", 2),
        ],
        reports: Vec::new(),
        coverage: Vec::new(),
    }
}

fn contested_device_input() -> ConfigurationInput {
    input_of(vec![
        row(
            "rpt-says-applied",
            Some(NODE),
            Some(POLICY_A),
            NormalizedSettingOutcome::Applied,
            Vec::new(),
        ),
        row(
            "rpt-says-failed",
            Some(NODE),
            Some(POLICY_A),
            NormalizedSettingOutcome::Failed,
            Vec::new(),
        ),
    ])
}

#[test]
fn a_conflict_without_an_observed_competing_source_is_not_claimed() {
    let snapshot = analyze_configuration(&unsubstantiated_conflict_input());
    let ids = finding_ids(&snapshot);
    assert!(
        ids.contains(&"configuration-conflict-unsubstantiated".to_owned()),
        "expected the unsubstantiated variant, got {ids:?}"
    );
    assert!(
        !ids.contains(&"configuration-conflict".to_owned()),
        "a conflict must not be asserted without the competing source"
    );
}

#[test]
fn a_supersedence_whose_replacement_was_never_collected_is_not_claimed() {
    let snapshot = analyze_configuration(&unsubstantiated_supersedence_input());
    let ids = finding_ids(&snapshot);
    assert!(
        ids.contains(&"configuration-superseded-unsubstantiated".to_owned()),
        "expected the unsubstantiated variant, got {ids:?}"
    );
    assert!(!ids.contains(&"configuration-superseded".to_owned()));
}

#[test]
fn records_with_no_identifier_are_never_merged_with_one_another() {
    let snapshot = analyze_configuration(&unattributed_input());
    assert!(
        snapshot.settings.is_empty(),
        "an unidentified record must not become a setting transaction"
    );
    assert_eq!(snapshot.unattributed.len(), 2);
    assert!(finding_ids(&snapshot).contains(&"configuration-unattributed-records".to_owned()));
}

/// The Autopilot class: an 813 says the value was written and a 404 for the same
/// node says a command failed, but its status is unreadable. Reporting a clean
/// `configuration-applied` at High confidence with no mention of the failure is
/// what this guards against.
#[test]
fn an_unreadable_failure_blocks_a_terminal_success_for_the_same_node() {
    let snapshot = analyze_configuration(&unassessable_failure_input());
    let setting = snapshot.settings.first().expect("one transaction");
    assert!(
        setting.has_unassessable_failure,
        "the 404 must be recorded as a failure whose detail is unassessable"
    );
    assert_ne!(
        wire(&setting.resolution),
        json!("applied"),
        "a success must not stand beside an unreadable failure for the same node"
    );

    let ids = finding_ids(&snapshot);
    assert!(
        ids.contains(&"configuration-unassessable-failure".to_owned()),
        "the failure record must be reported, got {ids:?}"
    );
    assert!(
        !ids.contains(&"configuration-applied".to_owned()),
        "got {ids:?}"
    );
}

#[test]
fn a_record_the_collector_could_not_fully_read_states_no_outcome() {
    // `access_state` is the collector telling us the fields this analyzer keys on
    // may be the ones it never read.
    let mut input = unassessable_failure_input();
    input.events = vec![applied_event("evt-partial", 1)];
    input.events[0].context.access_state =
        cmtraceopen_parser::intune::evidence::IntuneAccessState::Capped;

    let snapshot = analyze_configuration(&input);
    let setting = snapshot.settings.first().expect("one transaction");
    assert!(setting.has_uninterpretable_evidence);
    assert_eq!(wire(&setting.local), json!("indeterminate"));
    assert!(!finding_ids(&snapshot).contains(&"configuration-applied".to_owned()));
}

/// ADR-001: coverage gaps cannot raise confidence, and a success claim rests
/// partly on not having seen a failure.
#[test]
fn coverage_gaps_stop_a_success_being_stated_at_high_confidence() {
    let snapshot = analyze_configuration(&load_input("incomplete-channel-coverage"));
    let applied = snapshot
        .findings
        .iter()
        .find(|finding| finding.finding_id == "configuration-applied")
        .expect("the applied finding is present");
    assert_eq!(wire(&applied.confidence), json!("medium"));
    assert!(
        !applied.coverage_gap_ids.is_empty(),
        "the finding must name the gaps that cost it confidence"
    );

    let clean = analyze_configuration(&load_input("applied-from-csp-event"));
    let clean_applied = clean
        .findings
        .iter()
        .find(|finding| finding.finding_id == "configuration-applied")
        .expect("the applied finding is present");
    assert_eq!(wire(&clean_applied.confidence), json!("high"));
}

#[test]
fn disagreeing_device_records_do_not_pick_a_winner() {
    let snapshot = analyze_configuration(&contested_device_input());
    let setting = snapshot.settings.first().expect("one transaction");
    assert_eq!(wire(&setting.local), json!("contested"));
    assert_eq!(wire(&setting.resolution), json!("contradicted"));
    assert!(finding_ids(&snapshot).contains(&"configuration-contested-device-evidence".to_owned()));
}

#[test]
fn the_shared_normalized_contract_is_the_one_this_leaf_was_built_against() {
    // A bump here means the shared input shape moved and this leaf's fixtures
    // need re-checking rather than silently decoding into different semantics.
    assert_eq!(INTUNE_NORMALIZED_SCHEMA_VERSION, 1);
    assert_eq!(INTUNE_CONFIGURATION_SCHEMA_VERSION, 1);
}

#[test]
fn an_event_naming_no_resource_contributes_nothing() {
    let input = ConfigurationInput {
        generated_at_utc: "2026-07-31T10:00:00Z".to_owned(),
        events: vec![NormalizedWindowsEvent {
            context: context(
                "evt-unrelated",
                "mdm-admin-channel",
                IntuneSourceKind::EventLog,
                IntuneParseState::Parsed,
            ),
            channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
                .to_owned(),
            provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider"
                .to_owned(),
            event_id: 208,
            event_version: None,
            level: NormalizedEventLevel::Information,
            task: None,
            keywords: None,
            record_id: Some(1),
            activity_id: None,
            named_data: Vec::new(),
            message: Some("MDM Session: OMA-DM session ended.".to_owned()),
        }],
        reports: Vec::new(),
        coverage: Vec::new(),
    };
    let snapshot = analyze_configuration(&input);
    assert!(snapshot.settings.is_empty());
    assert!(
        snapshot.unattributed.is_empty(),
        "an event about no CSP node is not configuration evidence at all"
    );
}

#[test]
fn expected_files_declare_the_workload_they_belong_to() {
    // Cheap guard against a scenario being copied into the wrong corpus.
    for scenario in SCENARIOS {
        let expected = load_json(&scenario_root(scenario).join("expected.json"));
        assert_eq!(
            expected["workload"].as_str(),
            Some(CORPUS),
            "{scenario}: expected.json workload"
        );
    }
}
