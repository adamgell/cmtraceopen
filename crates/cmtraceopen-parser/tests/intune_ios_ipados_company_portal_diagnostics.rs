//! Fixture matrix for `intune::portal::ios_ipados::company_portal::diagnostics`.
//!
//! The input is the plain-text file produced by Microsoft's documented iOS and
//! iPadOS troubleshooting workflow: connect the device to a Mac, capture in the
//! Console app with info and debug messages enabled, reproduce the problem, copy
//! every visible record, and save it as text.
//!
//! Each scenario directory holds a `manifest.json` naming its artifacts and
//! their acquisition state, the exported text itself, and an `expected.json`
//! spelling out the contract the reduction must satisfy. Expectations are
//! written out rather than snapshotted so a reviewer can see what is being
//! asserted and why.
//!
//! Two things the manifest deliberately does *not* tell the parser: whether a
//! file is a supported Console export, and whether it could be read. Those are
//! conclusions the content must support, so `unsupported` and `parseFailed`
//! artifacts are handed over as ordinary available bytes and the derived
//! coverage status is what the shared harness then checks against the manifest.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::evidence::IntuneAccessState;
use cmtraceopen_parser::intune::portal::ios_ipados::company_portal::diagnostics::{
    analyze_console_exports, redacted_export_projection, ConsoleAnalysisOptions,
    ConsoleDiagnosticsSnapshot, ConsoleExportInput, ConsoleLayout, ConsoleLayoutConfidence,
    ConsoleRecord, ConsoleSourceClass,
};
use serde_json::{json, Value};
use support::{corpus_root, load_json, mutated, privacy_problems, scenario_names, Failures};

const CORPUS: &str = "portal/ios-ipados/company-portal/diagnostics";

/// The scenario matrix this leaf owns, pinned so a deletion cannot pass quietly.
const SCENARIOS: [&str; 14] = [
    "arbitrary-plain-log-negative",
    "company-portal-message-levels",
    "deterministic-filtering-and-export",
    "locale-layout-variant",
    "malformed-timestamp-and-columns",
    "missing-timezone",
    "multiline-exception-payload",
    "privacy-redaction",
    "same-timestamp-different-processes",
    "supported-console-export",
    "truncated-first-and-last-record",
    "uncollected-companion-artifacts",
    "unknown-app-and-os-version",
    "unrelated-process-noise",
];

/// Fixed observation time. Nothing in the crate reads a clock, so a golden stays
/// a golden.
const OBSERVED_AT: &str = "2026-07-31T00:00:00Z";

fn scenario_root(scenario: &str) -> PathBuf {
    corpus_root(CORPUS).join(scenario)
}

/// Translate a manifest artifact into what a collector would hand the parser.
///
/// `unsupported` and `parseFailed` are outcomes, not acquisition states: when
/// such an artifact has a file, it is supplied as ordinary available content and
/// the parser has to reach the conclusion itself.
fn acquisition_of(capture_state: &str, has_file: bool) -> IntuneAccessState {
    match (capture_state, has_file) {
        ("capped", true) => IntuneAccessState::Capped,
        (_, true) => IntuneAccessState::Available,
        ("absent", false) => IntuneAccessState::Missing,
        ("accessDenied", false) => IntuneAccessState::PermissionDenied,
        ("skipped", false) => IntuneAccessState::Skipped,
        ("unsupported", false) => IntuneAccessState::Unsupported,
        (other, false) => panic!("capture state {other} requires an evidence file"),
    }
}

fn inputs_of(scenario: &str, manifest: &Value) -> Vec<ConsoleExportInput> {
    let root = scenario_root(scenario);
    manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts must be an array")
        .iter()
        .map(|artifact| {
            let relative = artifact["relativePath"].as_str();
            let content = relative.map(|relative| {
                std::fs::read_to_string(root.join(relative)).unwrap_or_else(|error| {
                    panic!("{scenario}: evidence file {relative} is readable: {error}")
                })
            });
            ConsoleExportInput {
                artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId")
                    .to_owned(),
                file_name: artifact["originalBasename"]
                    .as_str()
                    .expect("originalBasename")
                    .to_owned(),
                file_path: artifact["sanitizedSourcePath"].as_str().map(str::to_owned),
                content,
                acquisition: acquisition_of(
                    artifact["captureState"].as_str().expect("captureState"),
                    relative.is_some(),
                ),
                detail: artifact["detail"].as_str().map(str::to_owned),
            }
        })
        .collect()
}

fn analyze(scenario: &str) -> (ConsoleDiagnosticsSnapshot, Value, Value) {
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let snapshot = analyze_console_exports(
        &inputs_of(scenario, &manifest),
        &ConsoleAnalysisOptions::observed_at(OBSERVED_AT),
    );
    (snapshot, manifest, expected)
}

fn snapshot_of(scenario: &str) -> ConsoleDiagnosticsSnapshot {
    analyze(scenario).0
}

// ── Projections asserted against expected.json ──────────────────────────────

/// The per-record subset the corpus pins.
///
/// Deliberately not the whole serialized record: `observedAtUtc` and the file
/// path repeat identically on every row and would bury the fields a reviewer
/// actually reads.
fn record_projection(record: &ConsoleRecord) -> Value {
    json!({
        "evidenceId": record.context.evidence_ref.evidence_id,
        "lineNumber": record.context.provenance.line_number,
        "recordNumber": record.context.provenance.record_number,
        "timestampRaw": record
            .context
            .source_timestamp
            .as_ref()
            .map(|stamp| stamp.raw_text.clone()),
        "timestampKind": record
            .context
            .source_timestamp
            .as_ref()
            .map(|stamp| serde_json::to_value(&stamp.kind).expect("kind serializes")),
        "normalizedUtc": record
            .context
            .source_timestamp
            .as_ref()
            .and_then(|stamp| stamp.normalized_utc.clone()),
        "parseState": record.context.parse_state,
        "sensitivity": record.context.sensitivity,
        "accessState": record.context.access_state,
        "messageType": record.message_type,
        "process": record.process,
        "processId": record.process_id,
        "activityId": record.activity_id,
        "subsystem": record.subsystem,
        "category": record.category,
        "message": record.message,
        "messageLineCount": record.message_line_count,
        "sourceClass": record.source_class,
        "sourceSignals": record.source_signals,
        "semantic": record.semantic,
        "semanticSource": record.semantic_source,
        "defects": record.defects,
        "truncated": record.truncated,
        "unmodeledColumns": record.unmodeled_columns,
    })
}

fn artifact_projection(snapshot: &ConsoleDiagnosticsSnapshot) -> Value {
    Value::Array(
        snapshot
            .artifacts
            .iter()
            .map(|artifact| {
                json!({
                    "artifactId": artifact.artifact_id,
                    "layout": artifact.layout,
                    "layoutConfidence": artifact.layout_confidence,
                    "layoutRefusal": artifact.layout_refusal,
                    "status": artifact.status,
                    "columns": artifact.columns,
                    "preambleLineCount": artifact.preamble_line_count,
                    "recordCount": artifact.record_count,
                    "companyPortalRecordCount": artifact.company_portal_record_count,
                    "unrelatedRecordCount": artifact.unrelated_record_count,
                    "malformedRecordCount": artifact.malformed_record_count,
                    "truncatedLeadingFragment": artifact.truncated_leading_fragment,
                    "truncatedTrailingRecord": artifact.truncated_trailing_record,
                    "recordCapReached": artifact.record_cap_reached,
                    "reportedAppVersion": artifact.reported_app_version,
                    "reportedOsVersion": artifact.reported_os_version,
                })
            })
            .collect(),
    )
}

fn coverage_projection(snapshot: &ConsoleDiagnosticsSnapshot) -> Value {
    Value::Array(
        snapshot
            .coverage
            .iter()
            .map(|entry| {
                json!({
                    "artifactId": entry.artifact_id,
                    "family": entry.family,
                    "status": entry.status,
                    "detail": entry.detail,
                })
            })
            .collect(),
    )
}

/// Findings are pinned by identity, weight, and what they cite.
///
/// Title and summary are asserted to be present rather than compared verbatim:
/// pinning prose would turn every wording fix into a fourteen-file diff without
/// testing anything a reader relies on.
fn finding_projection(snapshot: &ConsoleDiagnosticsSnapshot) -> Value {
    Value::Array(
        snapshot
            .findings
            .iter()
            .map(|finding| {
                json!({
                    "findingId": finding.finding_id,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "evidence": finding.evidence,
                    "coverageGapIds": finding.coverage_gap_ids,
                })
            })
            .collect(),
    )
}

fn scenario_projection(scenario: &str, snapshot: &ConsoleDiagnosticsSnapshot) -> Value {
    json!({
        "scenario": scenario,
        "workload": CORPUS,
        "coverage": coverage_projection(snapshot),
        "artifacts": artifact_projection(snapshot),
        "totals": serde_json::to_value(&snapshot.totals).expect("totals serialize"),
        "records": Value::Array(snapshot.records.iter().map(record_projection).collect()),
        "findings": finding_projection(snapshot),
    })
}

// ── Corpus-wide contracts ───────────────────────────────────────────────────

#[test]
fn the_corpus_exposes_exactly_the_pinned_scenario_matrix() {
    assert_eq!(
        scenario_names(&corpus_root(CORPUS)),
        SCENARIOS.map(str::to_owned).to_vec(),
    );
}

#[test]
fn every_scenario_satisfies_the_shared_fixture_contract() {
    let mut failures = Failures::new();
    for scenario in SCENARIOS {
        let root = scenario_root(scenario);
        let manifest = load_json(&root.join("manifest.json"));
        let expected = load_json(&root.join("expected.json"));
        failures.absorb(support::validate_scenario(
            scenario, &root, &manifest, &expected,
        ));
    }
    failures.assert_empty("iOS/iPadOS Company Portal Console corpus");
}

#[test]
fn every_scenario_matches_its_expected_reduction() {
    for scenario in SCENARIOS {
        let (snapshot, _, expected) = analyze(scenario);
        let actual = scenario_projection(scenario, &snapshot);
        for field in ["coverage", "artifacts", "totals", "records", "findings"] {
            assert_eq!(
                actual[field], expected[field],
                "{scenario}: {field} does not match expected.json"
            );
        }
    }
}

#[test]
fn every_finding_in_every_scenario_cites_evidence_or_a_coverage_gap() {
    for scenario in SCENARIOS {
        let snapshot = snapshot_of(scenario);
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
fn every_cited_evidence_reference_resolves_to_a_record_in_the_snapshot() {
    for scenario in SCENARIOS {
        let snapshot = snapshot_of(scenario);
        let known: BTreeSet<&str> = snapshot
            .records
            .iter()
            .map(|record| record.context.evidence_ref.evidence_id.as_str())
            .collect();
        let artifacts: BTreeSet<&str> = snapshot
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect();
        for finding in &snapshot.findings {
            for reference in &finding.evidence {
                assert!(
                    known.contains(reference.evidence_id.as_str()),
                    "{scenario}: finding {} cites unknown evidence {}",
                    finding.finding_id,
                    reference.evidence_id
                );
            }
            for gap in &finding.coverage_gap_ids {
                assert!(
                    artifacts.contains(gap.as_str()),
                    "{scenario}: finding {} cites unknown artifact {gap}",
                    finding.finding_id
                );
            }
        }
    }
}

#[test]
fn every_analysis_is_reproducible_byte_for_byte() {
    for scenario in SCENARIOS {
        let first = serde_json::to_string(&snapshot_of(scenario)).expect("snapshot serializes");
        let second = serde_json::to_string(&snapshot_of(scenario)).expect("snapshot serializes");
        assert_eq!(first, second, "{scenario}: analysis is not reproducible");
    }
}

#[test]
fn every_redacted_export_is_free_of_identity_and_secret_material() {
    for scenario in SCENARIOS {
        let export = redacted_export_projection(&snapshot_of(scenario));
        let text = serde_json::to_string_pretty(&export).expect("export serializes");
        privacy_problems(&format!("{scenario}/redacted-export"), &text)
            .assert_empty("redacted export projection");
    }
}

// ── Scenario semantics ──────────────────────────────────────────────────────

#[test]
fn the_supported_export_is_read_from_its_header_row() {
    let snapshot = snapshot_of("supported-console-export");
    let artifact = &snapshot.artifacts[0];
    assert_eq!(artifact.layout, ConsoleLayout::TabularEnUs);
    assert_eq!(
        artifact.layout_confidence,
        ConsoleLayoutConfidence::HeaderDeclared
    );
    // The synthetic-fixture marker line precedes the header and frames nothing.
    assert_eq!(artifact.preamble_line_count, 1);
    assert_eq!(
        snapshot.records[0].context.provenance.line_number,
        Some(3),
        "the first record starts after the marker and the header"
    );
}

#[test]
fn unrelated_processes_are_read_but_never_claimed_as_company_portal() {
    let snapshot = snapshot_of("unrelated-process-noise");
    // A header-less copy is recovered from agreeing rows, not guessed at.
    assert_eq!(
        snapshot.artifacts[0].layout_confidence,
        ConsoleLayoutConfidence::Inferred
    );

    let claimed_by_text = snapshot.records.iter().filter(|record| {
        record.is_company_portal()
            && (record.message.contains("Intune Company Portal")
                || record.message.contains("com.microsoft.CompanyPortal.refresh"))
    });
    assert_eq!(
        claimed_by_text.count(),
        0,
        "a Company Portal identifier in message text is not a source signature"
    );
    assert_eq!(snapshot.totals.company_portal_record_count, 2);
    assert_eq!(snapshot.artifacts[0].unrelated_record_count, 6);
}

#[test]
fn records_sharing_one_instant_stay_separate_and_ordered() {
    let snapshot = snapshot_of("same-timestamp-different-processes");
    let normalized: BTreeSet<Option<String>> = snapshot
        .records
        .iter()
        .map(|record| {
            record
                .context
                .source_timestamp
                .as_ref()
                .and_then(|stamp| stamp.normalized_utc.clone())
        })
        .collect();
    assert_eq!(normalized.len(), 1, "all four records share one instant");
    assert_eq!(snapshot.records.len(), 4);

    let processes: Vec<Option<&str>> = snapshot
        .records
        .iter()
        .map(|record| record.process.as_deref())
        .collect();
    assert_eq!(
        processes,
        vec![
            Some("CompanyPortal"),
            Some("CompanyPortal"),
            Some("SpringBoard"),
            Some("mDNSResponder")
        ],
        "capture order is preserved"
    );
    let activities: Vec<Option<&str>> = snapshot
        .records
        .iter()
        .map(|record| record.activity_id.as_deref())
        .collect();
    assert_eq!(
        activities,
        vec![Some("0x1a2b"), Some("0x3c4d"), Some("0x5e6f"), None],
        "Console writes 0 for no activity, which is absence, not an identity"
    );
}

#[test]
fn a_multiline_payload_stays_one_record_and_ends_at_the_next_timestamp() {
    let snapshot = snapshot_of("multiline-exception-payload");
    assert_eq!(snapshot.records.len(), 3);
    let exception = &snapshot.records[1];
    assert_eq!(exception.message_line_count, 8);
    assert!(exception.message.starts_with("Unhandled exception"));
    assert!(exception.message.contains("NSInvalidArgumentException"));
    assert!(exception.message.contains("\"attempt\": 3"));
    assert!(
        !exception.message.contains("Scene activation"),
        "the message must end where the next record begins"
    );
    assert_eq!(snapshot.records[2].process.as_deref(), Some("SpringBoard"));
}

#[test]
fn a_capture_cut_at_both_ends_keeps_and_flags_both_fragments() {
    let snapshot = snapshot_of("truncated-first-and-last-record");
    let artifact = &snapshot.artifacts[0];
    assert!(artifact.truncated_leading_fragment);
    assert!(artifact.truncated_trailing_record);

    let leading = &snapshot.records[0];
    assert_eq!(
        leading.source_class,
        ConsoleSourceClass::Indeterminate,
        "a fragment is attributed to no process"
    );
    assert!(snapshot.records.last().expect("a record").truncated);
    assert!(snapshot
        .findings
        .iter()
        .any(|finding| finding.finding_id == "console-capture-truncated"));
}

#[test]
fn a_broken_row_is_kept_as_malformed_rather_than_folded_into_the_message_above() {
    let snapshot = snapshot_of("malformed-timestamp-and-columns");
    let mixed = &snapshot.artifacts[0];
    assert_eq!(mixed.malformed_record_count, 2);
    assert_eq!(mixed.record_count, 4);
    assert!(
        !snapshot.records[1]
            .message
            .contains("impossible calendar date"),
        "a malformed row must not be swallowed by the record above it"
    );
}

#[test]
fn a_localized_export_is_read_under_its_own_grammar() {
    let snapshot = snapshot_of("locale-layout-variant");
    assert_eq!(snapshot.artifacts[0].layout, ConsoleLayout::TabularDeDe);
    let first = &snapshot.records[0];
    assert_eq!(
        first
            .context
            .source_timestamp
            .as_ref()
            .and_then(|stamp| stamp.normalized_utc.as_deref()),
        Some("2026-03-12T09:15:22.481293Z"),
        "12.03.2026 is the twelfth of March, not the third of December"
    );
    assert!(snapshot
        .findings
        .iter()
        .any(|finding| finding.finding_id == "console-company-portal-failure"));
}

#[test]
fn timestamps_without_an_offset_are_never_normalized_to_utc() {
    let snapshot = snapshot_of("missing-timezone");
    assert_eq!(snapshot.totals.offsetless_record_count, 3);
    for record in &snapshot.records {
        let stamp = record
            .context
            .source_timestamp
            .as_ref()
            .expect("every record carries a timestamp");
        assert_eq!(stamp.normalized_utc, None);
        assert!(!stamp.raw_text.is_empty(), "the raw text is always retained");
    }
    assert!(snapshot
        .findings
        .iter()
        .any(|finding| finding.finding_id == "console-timestamps-have-no-offset"));
}

#[test]
fn an_unknown_build_is_carried_verbatim_rather_than_rejected() {
    let snapshot = snapshot_of("unknown-app-and-os-version");
    let artifact = &snapshot.artifacts[0];
    assert_eq!(artifact.reported_app_version.as_deref(), Some("99.2031.7"));
    assert_eq!(artifact.reported_os_version.as_deref(), Some("26.0"));
    assert_eq!(artifact.company_portal_record_count, 3);

    let encoded = serde_json::to_value(&snapshot.records[1]).expect("record serializes");
    assert_eq!(
        encoded["messageType"], "Notice",
        "an unmodeled message type round-trips under its own label"
    );
    assert_eq!(
        snapshot.records[1].subsystem.as_deref(),
        Some("com.microsoft.CompanyPortal.FutureWorkload"),
        "an unknown subsystem beneath a known prefix is still Company Portal"
    );
    assert!(
        !snapshot.records[0].unmodeled_columns.is_empty(),
        "a column this build does not model is carried, not dropped"
    );
}

#[test]
fn an_arbitrary_log_is_refused_rather_than_read_with_invented_columns() {
    let snapshot = snapshot_of("arbitrary-plain-log-negative");
    assert!(snapshot.records.is_empty());
    assert_eq!(snapshot.artifacts[0].layout, ConsoleLayout::Unresolved);
    assert!(snapshot
        .findings
        .iter()
        .any(|finding| finding.finding_id == "console-layout-unsupported"));
    assert!(
        !snapshot
            .findings
            .iter()
            .any(|finding| finding.finding_id.contains("company-portal")),
        "nothing may be concluded about Company Portal from a file that was never read"
    );
}

#[test]
fn the_privacy_fixture_masks_every_class_of_identity_and_secret_material() {
    let snapshot = snapshot_of("privacy-redaction");
    let export = redacted_export_projection(&snapshot);
    let text = serde_json::to_string(&export).expect("export serializes");

    for leaked in [
        "synthetic.user@contoso.invalid",
        "11111111-2222-4333-8444-555555555555",
        "00008030-001C2D8A0EF8802E",
        "eyJhbGciOiJIUzI1NiJ9",
        "BEGIN CERTIFICATE",
        "/var/mobile/Containers",
        "tenantId=",
    ] {
        assert!(
            !text.contains(leaked),
            "the redacted export still contains {leaked}"
        );
    }

    for token in [
        "[redacted:upn#1]",
        "[redacted:guid#1]",
        "[redacted:deviceId#1]",
        "[redacted:secret#1]",
        "[redacted:certificate#1]",
        "[redacted:path#1]",
        "[redacted:query#1]",
    ] {
        assert!(text.contains(token), "the export never emitted {token}");
    }

    // The endpoint survives its query: which service was called is diagnostic,
    // the identifiers in the query are not.
    assert!(text.contains("https://example.invalid/deviceManagement/managedDevices"));

    // The same tenant in two records keeps one token, so correlation survives.
    assert_eq!(
        text.matches("[redacted:guid#1]").count(),
        2,
        "a repeated identifier must keep a single stable token"
    );
    assert!(
        !text.contains("[redacted:guid#3]"),
        "only distinct values may consume ordinals"
    );

    let golden = load_json(&scenario_root("privacy-redaction").join("expected-export.json"));
    assert_eq!(export, golden, "the redacted export drifted from its golden");
}

#[test]
fn the_redacted_export_projection_is_idempotent() {
    // Running the projection over already-masked text must not re-mask the
    // tokens themselves, or a re-export would rewrite history.
    let snapshot = snapshot_of("privacy-redaction");
    let once = redacted_export_projection(&snapshot);
    let text = serde_json::to_string(&once).expect("export serializes");
    assert!(!text.contains("[redacted:upn#1]#"));
    assert!(!text.contains("redacted:guid#1]#"));
}

#[test]
fn filtering_and_export_are_deterministic_across_rotations() {
    let snapshot = snapshot_of("deterministic-filtering-and-export");
    assert_eq!(snapshot.artifacts.len(), 2);

    let company_portal: Vec<&str> = snapshot
        .company_portal_records()
        .map(|record| record.context.evidence_ref.evidence_id.as_str())
        .collect();
    assert_eq!(
        company_portal,
        vec![
            "console-rotation-current:r1",
            "console-rotation-current:r3",
            "console-rotation-archive:r1"
        ],
        "the Company Portal subset follows artifact order, then capture order"
    );

    let first = serde_json::to_string(&redacted_export_projection(&snapshot))
        .expect("export serializes");
    let second = serde_json::to_string(&redacted_export_projection(&snapshot_of(
        "deterministic-filtering-and-export",
    )))
    .expect("export serializes");
    assert_eq!(first, second);

    let golden = load_json(
        &scenario_root("deterministic-filtering-and-export").join("expected-export.json"),
    );
    assert_eq!(redacted_export_projection(&snapshot), golden);
}

#[test]
fn an_uncollected_artifact_becomes_a_coverage_gap_rather_than_a_silent_zero() {
    let snapshot = snapshot_of("uncollected-companion-artifacts");
    assert_eq!(snapshot.coverage.len(), 4);
    let finding = snapshot
        .findings
        .iter()
        .find(|finding| finding.finding_id == "console-artifact-not-collected")
        .expect("uncollected artifacts are themselves a finding");
    assert_eq!(
        finding.coverage_gap_ids,
        vec![
            "console-second-window".to_owned(),
            "console-restricted".to_owned(),
            "console-skipped".to_owned()
        ]
    );
}

#[test]
fn the_partial_capture_window_is_reported_wherever_records_were_read() {
    for scenario in SCENARIOS {
        let snapshot = snapshot_of(scenario);
        let reported = snapshot
            .findings
            .iter()
            .any(|finding| finding.finding_id == "console-capture-window-is-partial");
        assert_eq!(
            reported,
            !snapshot.records.is_empty(),
            "{scenario}: the window bound must be stated exactly when records exist"
        );
    }
}

// ── Adversarial: the corpus must not be able to drift ───────────────────────

#[test]
fn a_byte_count_that_disagrees_with_the_export_is_rejected() {
    let scenario = "supported-console-export";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let failures = support::validate_scenario(
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
        "a byte count drifting from the file must be caught, got {:?}",
        failures.entries()
    );
}

#[test]
fn a_coverage_status_contradicting_the_capture_state_is_rejected() {
    // The unsupported scenario is the one where the parser, not the manifest,
    // decides. Claiming the file was read must fail loudly.
    let scenario = "arbitrary-plain-log-negative";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let failures = support::validate_scenario(
        scenario,
        &root,
        &manifest,
        &mutated(&expected, "/coverage/0/status", json!("available")),
    );
    assert!(
        failures
            .entries()
            .iter()
            .any(|entry| entry.contains("requires coverage status")),
        "coverage drifting from the capture state must be caught, got {:?}",
        failures.entries()
    );
}

#[test]
fn every_evidence_file_carries_the_synthetic_marker_on_its_first_line() {
    for scenario in SCENARIOS {
        for file in support::walk_files(&scenario_root(scenario).join("evidence")) {
            let contents = read(&file);
            assert!(
                contents
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .contains(support::SYNTHETIC_MARKER),
                "{}: first line must carry the synthetic marker",
                file.display()
            );
        }
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()))
}
