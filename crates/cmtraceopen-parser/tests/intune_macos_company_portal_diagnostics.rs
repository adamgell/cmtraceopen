//! Fixture matrix for `intune::portal::macos::company_portal::diagnostics`
//! (issue #369 of epic #356).
//!
//! Each scenario models a saved diagnostic report as a directory of
//! already-extracted members: `manifest.json` supplies the import envelope and
//! one artifact per member, `evidence/` holds the decoded member text, and
//! `expected.json` states the contract the analysis must satisfy.
//!
//! No real `.zip` is committed. The pure parser never opens a container, so a
//! real archive would test the fixture loader rather than the parser, and it
//! would smuggle an opaque binary into a corpus whose whole point is that a
//! reviewer can read every byte of it.
//!
//! The shared harness in `tests/support/` validates everything every Intune
//! corpus shares: envelope, path safety, byte-count truth, evidence closure,
//! the synthetic marker, the capture-state-to-coverage binding, and the privacy
//! scan. What is asserted here is only what this leaf owns.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::evidence::{IntuneEvidenceRef, IntuneFinding};
use cmtraceopen_parser::intune::portal::macos::company_portal::diagnostics::{
    analyze_diagnostic_report, check_member_path, redacted_diagnostic_report_export,
    DeclaredProduct, DiagnosticReportEnvelope, DiagnosticReportImport, DiagnosticReportSnapshot,
    DiagnosticsSupportState, ExtractionOutcome, MemberImportState, MemberPathRejection,
    ReportContainerKind, ReportDetection, ReportMemberRole, SuppliedReportMember,
    COMPANY_PORTAL_MACOS_DIAGNOSTICS_SCHEMA_VERSION,
};
use serde_json::Value;
use support::{load_json, mutated, scenario_names, validate_scenario, Failures};

const CORPUS: &str = "portal/macos/company-portal/diagnostics";

/// The fixture matrix issue #369 requires, pinned so a scenario cannot be
/// dropped or silently renamed.
const SCENARIOS: [&str; 14] = [
    "complete-supported-report",
    "deterministic-ordering",
    "direct-log-member-delegated",
    "duplicate-member-names",
    "encrypted-member-unsupported",
    "foreign-archive-negative",
    "malformed-manifest",
    "mixed-encodings",
    "optional-member-missing",
    "oversized-member-capped",
    "privacy-synthetic-identity",
    "traversal-member-path",
    "truncated-during-collection",
    "unknown-report-schema",
];

fn scenario_root(scenario: &str) -> PathBuf {
    support::corpus_root(CORPUS).join(scenario)
}

fn pair(scenario: &str) -> (Value, Value) {
    let root = scenario_root(scenario);
    (
        load_json(&root.join("manifest.json")),
        load_json(&root.join("expected.json")),
    )
}

// ── Fixture → parser input ──────────────────────────────────────────────────

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn from_wire<T: serde::de::DeserializeOwned>(value: &Value, key: &str, context: &str) -> T {
    serde_json::from_value(value.get(key).cloned().unwrap_or(Value::Null))
        .unwrap_or_else(|error| panic!("{context}: field {key} must decode: {error}"))
}

fn build_import(scenario: &str, root: &Path, manifest: &Value) -> DiagnosticReportImport {
    let import = &manifest["import"];
    let report = &import["report"];

    let envelope = DiagnosticReportEnvelope {
        report_id: string_field(report, "reportId").expect("reportId"),
        declared_product: from_wire(report, "declaredProduct", scenario),
        container_kind: from_wire::<ReportContainerKind>(report, "containerKind", scenario),
        declared_report_schema: string_field(report, "declaredReportSchema"),
        declared_app_version: string_field(report, "declaredAppVersion"),
        collected_at: string_field(report, "collectedAt"),
        extraction: from_wire::<ExtractionOutcome>(report, "extraction", scenario),
        extraction_detail: string_field(report, "extractionDetail"),
        sanitized_source_path: string_field(report, "sanitizedSourcePath"),
        observed_at_utc: string_field(report, "observedAtUtc").expect("observedAtUtc"),
    };

    let members = manifest["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .map(|artifact| {
            let member = &artifact["member"];
            // Content reaches the parser exactly when the corpus has bytes for
            // the member. That is what makes "the importer never produced text"
            // a distinct input from "the importer produced empty text".
            let content = artifact["relativePath"].as_str().map(|relative| {
                std::fs::read_to_string(root.join(relative)).unwrap_or_else(|error| {
                    panic!("{scenario}: evidence {relative} is readable: {error}")
                })
            });
            SuppliedReportMember {
                member_id: artifact["artifactId"].as_str().expect("artifactId").to_owned(),
                member_path: member["memberPath"].as_str().expect("memberPath").to_owned(),
                declared_role: from_wire::<Option<ReportMemberRole>>(
                    member,
                    "declaredRole",
                    scenario,
                ),
                declared_bytes: member["declaredBytes"].as_u64().unwrap_or_default(),
                declared_encoding: string_field(member, "declaredEncoding"),
                transcoded_from: string_field(member, "transcodedFrom"),
                import_state: from_wire::<MemberImportState>(member, "importState", scenario),
                import_detail: string_field(member, "importDetail"),
                content,
            }
        })
        .collect();

    DiagnosticReportImport {
        schema_version: import["schemaVersion"].as_u64().unwrap_or_default() as u32,
        report: envelope,
        members,
    }
}

fn analyze(scenario: &str) -> (DiagnosticReportSnapshot, Value) {
    let root = scenario_root(scenario);
    let (manifest, expected) = pair(scenario);
    (
        analyze_diagnostic_report(&build_import(scenario, &root, &manifest)),
        expected,
    )
}

// ── Corpus-level contracts ──────────────────────────────────────────────────

#[test]
fn corpus_holds_exactly_the_required_fixture_matrix() {
    assert_eq!(
        scenario_names(&support::corpus_root(CORPUS)),
        SCENARIOS.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
    );
}

#[test]
fn every_scenario_satisfies_the_shared_fixture_contract() {
    let mut failures = Failures::new();
    for scenario in SCENARIOS {
        let (manifest, expected) = pair(scenario);
        failures.absorb(validate_scenario(
            scenario,
            &scenario_root(scenario),
            &manifest,
            &expected,
        ));
    }
    failures.assert_empty("macOS Company Portal diagnostics corpus");
}

#[test]
fn the_shared_harness_rejects_a_corrupted_scenario() {
    // Proof that the corpus is actually being checked rather than passing
    // vacuously: break one byte count and confirm the validator notices.
    let scenario = "complete-supported-report";
    let (manifest, expected) = pair(scenario);
    let failures = validate_scenario(
        scenario,
        &scenario_root(scenario),
        &mutated(&manifest, "/artifacts/0/bytesCopied", Value::from(1)),
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

// ── Per-scenario contract ───────────────────────────────────────────────────

#[test]
fn every_scenario_matches_its_stated_contract() {
    for scenario in SCENARIOS {
        assert_scenario(scenario);
    }
}

fn assert_scenario(scenario: &str) {
    let (analysis, expected) = analyze(scenario);

    assert_eq!(
        wire(&analysis.envelope_state),
        expected["envelopeState"],
        "{scenario}: envelopeState"
    );
    assert_eq!(
        wire(&analysis.detection),
        expected["detection"],
        "{scenario}: detection"
    );
    assert_eq!(
        wire(&analysis.support_state),
        expected["supportState"],
        "{scenario}: supportState"
    );

    // Report-level coverage names the container, not an artifact inside it, so
    // it is asserted separately from the member coverage the shared harness
    // binds to manifest capture states.
    assert_eq!(
        analysis.report_coverage.artifact_id,
        expected["reportCoverage"]["artifactId"]
            .as_str()
            .unwrap_or_default(),
        "{scenario}: report coverage artifactId"
    );
    assert_eq!(
        wire(&analysis.report_coverage.status),
        expected["reportCoverage"]["status"],
        "{scenario}: report coverage status"
    );

    assert_json_list(
        scenario,
        "coverage",
        &analysis
            .coverage
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "artifactId": entry.artifact_id,
                    "status": wire(&entry.status),
                })
            })
            .collect::<Vec<_>>(),
        &expected["coverage"],
    );

    assert_json_list(
        scenario,
        "members",
        &analysis
            .members
            .iter()
            .map(|member| {
                serde_json::json!({
                    "memberId": member.member_id,
                    "memberPath": member.member_path,
                    "importState": wire(&member.import_state),
                    "contentKind": wire(&member.content_kind),
                    "confirmedRole": wire(&member.confirmed_role),
                    "roleConfirmation": wire(&member.role_confirmation),
                    "rejection": member.rejection.as_ref().map(wire),
                    "delegated": member.delegation.is_some(),
                })
            })
            .collect::<Vec<_>>(),
        &expected["members"],
    );

    assert_json_list(
        scenario,
        "facts",
        &analysis
            .facts
            .iter()
            .map(|fact| {
                serde_json::json!({
                    "name": fact.fact.name,
                    "value": fact.fact.value,
                })
            })
            .collect::<Vec<_>>(),
        &expected["facts"],
    );

    assert_json_list(
        scenario,
        "findings",
        &analysis
            .findings
            .iter()
            .map(|finding| {
                serde_json::json!({
                    "findingId": finding.finding_id,
                    "severity": wire(&finding.severity),
                    "confidence": wire(&finding.confidence),
                    "evidence": finding
                        .evidence
                        .iter()
                        .map(|reference| reference.evidence_id.clone())
                        .collect::<Vec<_>>(),
                    "coverageGapIds": finding.coverage_gap_ids,
                })
            })
            .collect::<Vec<_>>(),
        &expected["findings"],
    );
}

fn assert_json_list(scenario: &str, label: &str, actual: &[Value], expected: &Value) {
    let expected = expected
        .as_array()
        .unwrap_or_else(|| panic!("{scenario}: expected.json needs a {label} array"));
    assert_eq!(
        actual,
        expected.as_slice(),
        "{scenario}: {label} does not match the stated contract"
    );
}

fn wire<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("wire form must serialize")
}

// ── Invariants that hold across the whole matrix ────────────────────────────

#[test]
fn every_member_has_exactly_one_coverage_entry() {
    for scenario in SCENARIOS {
        let (analysis, _) = analyze(scenario);
        let member_ids: BTreeSet<&str> = analysis
            .members
            .iter()
            .map(|member| member.member_id.as_str())
            .collect();
        let coverage_ids: BTreeSet<&str> = analysis
            .coverage
            .iter()
            .map(|entry| entry.artifact_id.as_str())
            .collect();
        assert_eq!(
            member_ids, coverage_ids,
            "{scenario}: every member must have exactly one coverage entry"
        );
        assert_eq!(
            analysis.coverage.len(),
            analysis.members.len(),
            "{scenario}: coverage must not duplicate a member"
        );
    }
}

#[test]
fn every_finding_cites_evidence_or_a_coverage_gap_that_exists() {
    for scenario in SCENARIOS {
        let (analysis, _) = analyze(scenario);
        let known_evidence: BTreeSet<IntuneEvidenceRef> = analysis
            .members
            .iter()
            .map(|member| member.context.evidence_ref.clone())
            .collect();
        let known_coverage: BTreeSet<&str> = analysis
            .coverage_entries()
            .map(|entry| entry.artifact_id.as_str())
            .collect();

        for finding in &analysis.findings {
            assert!(
                IntuneFinding::is_evidence_backed(finding),
                "{scenario}: finding {} cites nothing",
                finding.finding_id
            );
            for reference in &finding.evidence {
                assert!(
                    known_evidence.contains(reference),
                    "{scenario}: finding {} cites unknown evidence {reference:?}",
                    finding.finding_id
                );
            }
            for gap in &finding.coverage_gap_ids {
                assert!(
                    known_coverage.contains(gap.as_str()),
                    "{scenario}: finding {} cites unknown coverage id {gap}",
                    finding.finding_id
                );
            }
        }
    }
}

#[test]
fn no_scenario_produces_a_silent_empty_success() {
    // A report whose contents could not be extracted must produce a coverage
    // gap, never an empty analysis that reads as "nothing was wrong".
    for scenario in SCENARIOS {
        let (analysis, _) = analyze(scenario);
        assert!(
            !analysis.findings.is_empty(),
            "{scenario}: an analysis must always state its own support level"
        );
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.finding_id
                    == "cp-macos-diagnostics-report-schema-not-fixture-backed"),
            "{scenario}: the unfixtured-report-schema caveat must always be reported"
        );
        assert_eq!(
            analysis.support_state,
            DiagnosticsSupportState::SourceContract,
            "{scenario}: no report schema is fixture-backed, so support stays at source-contract"
        );
    }
}

#[test]
fn analysis_round_trips_through_its_own_wire_form() {
    for scenario in SCENARIOS {
        let (analysis, _) = analyze(scenario);
        let encoded = serde_json::to_string(&analysis).expect("analysis serializes");
        let decoded: DiagnosticReportSnapshot =
            serde_json::from_str(&encoded).expect("analysis round-trips");
        assert_eq!(decoded, analysis, "{scenario}: wire round trip");
    }
}

// ── Import security ─────────────────────────────────────────────────────────

#[test]
fn a_traversal_member_is_refused_even_when_the_importer_claims_it_decoded() {
    let (analysis, _) = analyze("traversal-member-path");
    let escaping = analysis
        .members
        .iter()
        .find(|member| member.member_id == "escaping-member")
        .expect("traversal member is present");

    assert_eq!(
        escaping.rejection,
        Some(MemberPathRejection::ParentTraversal)
    );
    assert_eq!(escaping.import_state, MemberImportState::Rejected);
    assert_eq!(
        escaping.member_path, "../../../../etc/passwd",
        "a refused path is preserved verbatim; normalizing it would launder the traversal"
    );
    assert_eq!(
        escaping.line_count, 0,
        "a refused member contributes no content"
    );
    assert!(escaping.delegation.is_none());
}

#[test]
fn duplicate_member_paths_refuse_every_side() {
    let (analysis, _) = analyze("duplicate-member-names");
    assert_eq!(analysis.members.len(), 2);
    for member in &analysis.members {
        assert_eq!(
            member.rejection,
            Some(MemberPathRejection::DuplicatePath),
            "{}: neither side of a collision can be treated as authoritative",
            member.member_id
        );
    }
}

#[test]
fn the_import_guard_rejects_the_documented_unsafe_path_shapes() {
    for (raw, expected) in [
        ("../../etc/passwd", MemberPathRejection::ParentTraversal),
        ("/etc/passwd", MemberPathRejection::AbsolutePath),
        ("C:/Windows", MemberPathRejection::DriveQualifiedPath),
        ("logs\\portal.log", MemberPathRejection::BackslashSeparator),
        ("./portal.log", MemberPathRejection::CurrentDirectorySegment),
        ("", MemberPathRejection::EmptyPath),
    ] {
        assert_eq!(
            check_member_path(raw).rejection,
            Some(expected.clone()),
            "path {raw:?} must be refused as {expected:?}"
        );
    }
}

#[test]
fn an_arbitrary_archive_is_not_detected_as_a_company_portal_report() {
    let (analysis, _) = analyze("foreign-archive-negative");
    assert_eq!(analysis.detection, ReportDetection::Refused);
    assert!(
        analysis.facts.is_empty(),
        "a refused container must yield no facts"
    );
    assert!(
        analysis.members.iter().all(|member| member.delegation.is_none()),
        "a refused container must delegate nothing"
    );
    assert!(
        analysis
            .findings
            .iter()
            .any(|finding| finding.finding_id
                == "cp-macos-diagnostics-not-a-company-portal-report"),
        "the refusal must be reported"
    );
}

#[test]
fn a_newer_envelope_schema_claims_nothing() {
    let (analysis, _) = analyze("unknown-report-schema");
    assert!(analysis.schema_version > COMPANY_PORTAL_MACOS_DIAGNOSTICS_SCHEMA_VERSION);
    assert!(
        analysis.facts.is_empty(),
        "an unreadable envelope must not yield facts"
    );
    assert!(
        analysis.members.iter().all(|member| member.delegation.is_none()),
        "an unreadable envelope must not delegate members"
    );
}

// ── Classification and delegation ───────────────────────────────────────────

#[test]
fn a_log_framed_member_is_delegated_rather_than_parsed_here() {
    let (analysis, _) = analyze("direct-log-member-delegated");
    let delegated: Vec<_> = analysis.delegated_direct_logs().collect();
    assert_eq!(delegated.len(), 1);
    assert_eq!(
        delegated[0].confirmed_role,
        ReportMemberRole::DirectLog
    );
    assert_eq!(
        delegated[0]
            .delegation
            .as_ref()
            .expect("delegation")
            .target,
        "cmtraceopen_parser::intune::portal::macos::company_portal::logs",
        "record-level parsing belongs to issue #368"
    );
}

#[test]
fn no_member_is_promoted_to_a_role_the_report_schema_would_be_needed_for() {
    // The whole point of the source-contract gate: an importer may declare a
    // member as MSAL evidence or a configuration fact, and this build will
    // carry the declaration without ever confirming it.
    for scenario in SCENARIOS {
        let (analysis, _) = analyze(scenario);
        for member in &analysis.members {
            assert!(
                matches!(
                    member.confirmed_role,
                    ReportMemberRole::DirectLog | ReportMemberRole::Unclassified
                ),
                "{scenario}/{}: confirmed role {:?} would require the undocumented report schema",
                member.member_id,
                member.confirmed_role
            );
        }
    }
}

#[test]
fn declared_encodings_are_recorded_as_provenance_and_never_re_decoded() {
    let (analysis, _) = analyze("mixed-encodings");
    let encodings: Vec<(&str, Option<&str>, Option<&str>)> = analysis
        .members
        .iter()
        .map(|member| {
            (
                member.member_id.as_str(),
                member.declared_encoding.as_deref(),
                member.transcoded_from.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        encodings,
        vec![
            ("bom-json", Some("utf-8-bom"), None),
            ("legacy-log", Some("windows-1252"), Some("windows-1252")),
            ("utf8-log", Some("utf-8"), None),
            ("utf16-note", Some("utf-16le"), Some("utf-16le")),
        ]
    );
}

// ── Determinism ─────────────────────────────────────────────────────────────

#[test]
fn member_order_does_not_depend_on_the_order_the_importer_supplied() {
    let scenario = "deterministic-ordering";
    let root = scenario_root(scenario);
    let (manifest, _) = pair(scenario);
    let import = build_import(scenario, &root, &manifest);

    let baseline = serde_json::to_string(&analyze_diagnostic_report(&import))
        .expect("analysis serializes");

    let mut rotated = import.clone();
    rotated.members.rotate_left(1);
    let mut reversed = import.clone();
    reversed.members.reverse();

    for (label, permutation) in [("rotated", rotated), ("reversed", reversed)] {
        assert_eq!(
            serde_json::to_string(&analyze_diagnostic_report(&permutation))
                .expect("analysis serializes"),
            baseline,
            "{label} input must serialize identically"
        );
    }
}

#[test]
fn analysis_is_byte_stable_across_repeated_runs() {
    for scenario in SCENARIOS {
        let root = scenario_root(scenario);
        let (manifest, _) = pair(scenario);
        let import = build_import(scenario, &root, &manifest);
        let first = serde_json::to_string(&analyze_diagnostic_report(&import)).expect("serializes");
        let second =
            serde_json::to_string(&analyze_diagnostic_report(&import)).expect("serializes");
        assert_eq!(first, second, "{scenario}: repeated runs must agree");
    }
}

// ── Privacy ─────────────────────────────────────────────────────────────────

/// Synthetic values planted in the privacy scenario, in the order they appear.
const PLANTED_SENSITIVE_VALUES: [&str; 7] = [
    "synthetic.user@example.invalid",
    "11111111-2222-3333-4444-555555555555",
    "203.0.113.7",
    "https://storage.example.invalid/reports",
    "0123456789abcdef0123456789abcdef01234567",
    "SYNTHSERIALX1",
    "/Library/Application",
];

#[test]
fn the_export_projection_strips_every_planted_sensitive_value() {
    let (analysis, _) = analyze("privacy-synthetic-identity");
    let raw = serde_json::to_string(&analysis).expect("analysis serializes");
    let exported = serde_json::to_string(&redacted_diagnostic_report_export(&analysis))
        .expect("export serializes");

    let mut planted = 0;
    for value in PLANTED_SENSITIVE_VALUES {
        if raw.contains(value) {
            planted += 1;
            assert!(
                !exported.contains(value),
                "{value:?} survived the export projection"
            );
        }
    }
    assert!(
        planted >= 5,
        "the privacy fixture must actually plant sensitive values in the analysis; only \
         {planted} of {} reached it",
        PLANTED_SENSITIVE_VALUES.len()
    );
}

#[test]
fn the_export_projection_never_carries_a_parse_failure_excerpt() {
    // The excerpt is raw member bytes. No pattern set is a strong enough
    // guarantee for those, so the projection drops it outright.
    let (analysis, _) = analyze("privacy-synthetic-identity");
    assert!(
        analysis
            .members
            .iter()
            .any(|member| member.failure_excerpt.is_some()),
        "the fixture must produce an excerpt for the projection to strip"
    );
    let exported = redacted_diagnostic_report_export(&analysis);
    for member in &exported.members {
        if let Some(excerpt) = &member.failure_excerpt {
            assert_eq!(excerpt, "[redacted-excerpt]", "{}", member.member_id);
        }
    }
}

#[test]
fn the_export_projection_is_idempotent() {
    for scenario in SCENARIOS {
        let (analysis, _) = analyze(scenario);
        let once = redacted_diagnostic_report_export(&analysis);
        let twice = redacted_diagnostic_report_export(&once);
        assert_eq!(once, twice, "{scenario}: a second pass must be a no-op");
    }
}

// ── Rules with no fixture of their own ──────────────────────────────────────

#[test]
fn a_declared_report_holding_nothing_readable_is_contradicted() {
    // Not part of the required matrix, and not expressible as a fixture: the
    // shared harness reads every evidence file as UTF-8, so a member whose
    // decoded text still contains NUL bytes cannot be committed to the corpus.
    let analysis = analyze_diagnostic_report(&DiagnosticReportImport {
        schema_version: COMPANY_PORTAL_MACOS_DIAGNOSTICS_SCHEMA_VERSION,
        report: DiagnosticReportEnvelope {
            report_id: "report-contradicted".to_owned(),
            declared_product: Some(DeclaredProduct::CompanyPortalMacos),
            container_kind: ReportContainerKind::Zip,
            declared_report_schema: None,
            declared_app_version: None,
            collected_at: None,
            extraction: ExtractionOutcome::Complete,
            extraction_detail: None,
            sanitized_source_path: None,
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
        },
        members: vec![SuppliedReportMember {
            member_id: "opaque".to_owned(),
            member_path: "misc/opaque.bin".to_owned(),
            declared_role: Some(ReportMemberRole::SystemFact),
            declared_bytes: 4,
            declared_encoding: Some("utf-8".to_owned()),
            transcoded_from: None,
            import_state: MemberImportState::Decoded,
            import_detail: None,
            content: Some("a\0b\0".to_owned()),
        }],
    });

    assert_eq!(analysis.detection, ReportDetection::DeclaredContradicted);
    assert!(
        analysis
            .findings
            .iter()
            .any(|finding| finding.finding_id
                == "cp-macos-diagnostics-declaration-contradicted"),
        "a declaration nothing supports must be reported, got {:?}",
        analysis
            .findings
            .iter()
            .map(|finding| finding.finding_id.as_str())
            .collect::<Vec<_>>()
    );
}
