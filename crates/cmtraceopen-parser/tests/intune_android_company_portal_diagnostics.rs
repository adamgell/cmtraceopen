//! Fixture matrix for `intune::portal::android::company_portal::diagnostics`
//! (issue #371 of epic #356).
//!
//! The corpus is unusual, and deliberately so. Issue #371 forbids exposing a
//! stable parser until a sanitized artifact contract is documented, and no such
//! artifact has been obtained. So no scenario here asserts a parsed record.
//! What every scenario asserts instead is that the module enumerates, records
//! provenance, refuses what it cannot justify, and says so out loud:
//!
//! * `parsedRecordCount` is `0` in every `expected.json`, and
//!   [`no_scenario_claims_a_parsed_record`] pins that as a corpus-wide
//!   invariant rather than thirteen coincidences;
//! * `verifiedContractCount` is `0`, so the day someone adds a verified
//!   contract, this corpus fails loudly and has to be revisited on purpose.
//!
//! Expectations are written out in `expected.json` rather than snapshotted, so
//! a reviewer can see what each scenario claims and why.

mod support;

use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::evidence::{IntuneArtifactStatus, IntuneFinding};
use cmtraceopen_parser::intune::portal::android::company_portal::diagnostics::{
    analyze_android_diagnostic_bundle, redact_text, redacted_export_projection,
    verified_contract_count, AndroidDiagnosticBundleInput, AndroidDiagnosticMemberInput,
    AndroidDiagnosticsSnapshot, AndroidImportLimits, AndroidMemberSafetyFlag,
    AndroidSuppliedCollectionFacts,
};
use serde_json::{json, Value};
use support::{corpus_root, load_json, mutated, scenario_names, validate_scenario, Failures};

const CORPUS: &str = "portal/android/company-portal/diagnostics";

/// The scenario matrix, pinned so a silently deleted scenario fails the build.
///
/// Maps onto issue #371's required fixture matrix:
///
/// | Required | Scenario |
/// |---|---|
/// | Company Portal saved logs | `company-portal-saved-logs` |
/// | Microsoft Intune app logs | `microsoft-intune-app-uploaded-logs` |
/// | work-profile source metadata | `company-portal-saved-logs`, `incident-id-without-upload-confirmation` |
/// | another Android Enterprise mode | `dedicated-device-verbose-logging-off`, `microsoft-intune-app-uploaded-logs`, `admin-center-download-corporate-owned-work-profile` |
/// | verbose and normal logging | `company-portal-saved-logs`, `dedicated-device-verbose-logging-off` |
/// | complete archive/report | `company-portal-saved-logs` |
/// | missing/truncated member | `truncated-and-missing-members` |
/// | unknown schema/app version | `unknown-app-and-schema-token` |
/// | malformed record | `malformed-member-and-missing-collection-time` |
/// | arbitrary ZIP / logcat negative | `arbitrary-archive-negative`, `android-logcat-negative` |
/// | duplicate/traversal/oversized safety | `unsafe-member-import-flags` |
/// | missing/invalid timezone | `malformed-member-and-missing-collection-time`, `invalid-collection-timestamp` |
/// | incident ID without upload success | `incident-id-without-upload-confirmation` |
/// | deterministic redaction | `deterministic-redaction` |
const SCENARIOS: [&str; 13] = [
    "admin-center-download-corporate-owned-work-profile",
    "android-logcat-negative",
    "arbitrary-archive-negative",
    "company-portal-saved-logs",
    "dedicated-device-verbose-logging-off",
    "deterministic-redaction",
    "incident-id-without-upload-confirmation",
    "invalid-collection-timestamp",
    "malformed-member-and-missing-collection-time",
    "microsoft-intune-app-uploaded-logs",
    "truncated-and-missing-members",
    "unknown-app-and-schema-token",
    "unsafe-member-import-flags",
];

fn scenario_root(scenario: &str) -> PathBuf {
    corpus_root(CORPUS).join(scenario)
}

fn scenario_pair(scenario: &str) -> (Value, Value) {
    let root = scenario_root(scenario);
    (
        load_json(&root.join("manifest.json")),
        load_json(&root.join("expected.json")),
    )
}

/// The harness capture state a manifest artifact declares, as the shared import
/// vocabulary.
///
/// This is the same binding `support::CAPTURE_STATE_COVERAGE` enforces between
/// a manifest and its expected coverage, applied on the input side so a fixture
/// cannot describe one thing to the validator and another to the parser.
fn artifact_status(capture_state: &str) -> IntuneArtifactStatus {
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

fn safety_flag(token: &str) -> AndroidMemberSafetyFlag {
    match token {
        "duplicateEntryName" => AndroidMemberSafetyFlag::DuplicateEntryName,
        "pathTraversal" => AndroidMemberSafetyFlag::PathTraversal,
        "absoluteEntryPath" => AndroidMemberSafetyFlag::AbsoluteEntryPath,
        "oversizedEntry" => AndroidMemberSafetyFlag::OversizedEntry,
        "truncatedEntry" => AndroidMemberSafetyFlag::TruncatedEntry,
        "symlinkEntry" => AndroidMemberSafetyFlag::SymlinkEntry,
        "undecodableBytes" => AndroidMemberSafetyFlag::UndecodableBytes,
        other => panic!("unknown safety flag {other:?}"),
    }
}

fn optional_string(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

fn from_wire<T: serde::de::DeserializeOwned>(value: &Value) -> Option<T> {
    if value.is_null() {
        return None;
    }
    Some(serde_json::from_value(value.clone()).expect("manifest vocabulary value decodes"))
}

/// Build the parser input from a scenario's manifest and evidence files.
///
/// This is the desktop importer's job in miniature: the archive is already
/// extracted, so the test reads the member bytes and hands over named entries.
fn bundle_input(scenario: &str, manifest: &Value) -> AndroidDiagnosticBundleInput {
    let root = scenario_root(scenario);
    let supplied = &manifest["supplied"];

    let members = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts is an array")
        .iter()
        .map(|artifact| {
            let text = artifact["relativePath"].as_str().map(|relative| {
                std::fs::read_to_string(root.join(relative))
                    .unwrap_or_else(|error| panic!("{scenario}: {relative} is readable: {error}"))
            });
            AndroidDiagnosticMemberInput {
                artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId")
                    .to_owned(),
                entry_name: artifact["entryName"].as_str().expect("entryName").to_owned(),
                sanitized_entry_path: optional_string(&artifact["sanitizedSourcePath"]),
                status: artifact_status(artifact["captureState"].as_str().expect("captureState")),
                declared_bytes: artifact["bytesCopied"].as_u64().expect("bytesCopied"),
                encoding: optional_string(&artifact["encoding"]),
                rotation: optional_string(&artifact["rotation"]["kind"]),
                text,
                safety_flags: artifact["safetyFlags"]
                    .as_array()
                    .map(|flags| {
                        flags
                            .iter()
                            .map(|flag| safety_flag(flag.as_str().expect("safety flag is a string")))
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();

    AndroidDiagnosticBundleInput {
        bundle_id: manifest["bundleId"].as_str().expect("bundleId").to_owned(),
        observed_at_utc: manifest["observedAtUtc"]
            .as_str()
            .expect("observedAtUtc")
            .to_owned(),
        supplied: AndroidSuppliedCollectionFacts {
            app: from_wire(&supplied["app"]),
            app_version: optional_string(&supplied["appVersion"]),
            management_mode: from_wire(&supplied["managementMode"]),
            collection_flow: from_wire(&supplied["collectionFlow"]),
            verbose_logging: from_wire(&supplied["verboseLogging"]),
            incident_id: optional_string(&supplied["incidentId"]),
            upload_outcome: from_wire(&supplied["uploadOutcome"]),
            collected_at_text: optional_string(&supplied["collectedAtText"]),
            device_time_zone: optional_string(&supplied["deviceTimeZone"]),
            declared_schema_token: optional_string(&supplied["declaredSchemaToken"]),
            container_kind: optional_string(&supplied["containerKind"]),
            extra: Vec::new(),
        },
        members,
        limits: AndroidImportLimits {
            max_member_bytes: manifest["limits"]["maxMemberBytes"].as_u64(),
        },
    }
}

fn analyze(scenario: &str) -> (AndroidDiagnosticsSnapshot, Value, Value) {
    let (manifest, expected) = scenario_pair(scenario);
    let snapshot = analyze_android_diagnostic_bundle(&bundle_input(scenario, &manifest));
    (snapshot, manifest, expected)
}

/// The finding fields a scenario pins, as JSON.
///
/// Title, summary, and recommended checks are deliberately excluded: they are
/// prose that will be reworded, and pinning them would turn every copy edit
/// into a fixture churn. The identity, weight, and citations are what a
/// reviewer needs to see, and those are pinned exactly.
fn finding_projection(finding: &IntuneFinding) -> Value {
    json!({
        "findingId": finding.finding_id,
        "severity": serde_json::to_value(&finding.severity).expect("severity serializes"),
        "confidence": serde_json::to_value(&finding.confidence).expect("confidence serializes"),
        "evidence": serde_json::to_value(&finding.evidence).expect("evidence serializes"),
        "coverageGapIds": finding.coverage_gap_ids,
    })
}

fn wire(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("value serializes")
}

// ── Corpus-wide contract ────────────────────────────────────────────────────

#[test]
fn corpus_contains_exactly_the_pinned_scenario_matrix() {
    assert_eq!(scenario_names(&corpus_root(CORPUS)), SCENARIOS.to_vec());
}

#[test]
fn every_scenario_satisfies_the_shared_fixture_contract() {
    let mut failures = Failures::new();
    for scenario in SCENARIOS {
        let (manifest, expected) = scenario_pair(scenario);
        failures.absorb(validate_scenario(
            scenario,
            &scenario_root(scenario),
            &manifest,
            &expected,
        ));
    }
    failures.assert_empty("android company portal diagnostics corpus");
}

#[test]
fn no_scenario_claims_a_parsed_record() {
    // The load-bearing assertion of this whole leaf. Issue #371 forbids
    // exposing a parser before a sanitized artifact contract is documented, and
    // no such artifact exists. If this ever fails, either a verified contract
    // was added (in which case the corpus must be revisited deliberately) or
    // the module started inventing a grammar.
    assert_eq!(verified_contract_count(), 0);
    for scenario in SCENARIOS {
        let (snapshot, _, expected) = analyze(scenario);
        assert!(
            snapshot.records.is_empty(),
            "{scenario}: claimed {} parsed record(s) with no verified contract",
            snapshot.records.len()
        );
        assert_eq!(expected["parsedRecordCount"].as_u64(), Some(0), "{scenario}");
        assert_eq!(
            expected["verifiedContractCount"].as_u64(),
            Some(verified_contract_count() as u64),
            "{scenario}"
        );
        assert!(
            snapshot.metadata.verified_contract_id.is_none(),
            "{scenario}: named a verified contract that does not exist"
        );
    }
}

#[test]
fn every_member_is_reported_unsupported_or_malformed() {
    use cmtraceopen_parser::intune::evidence::IntuneParseState;
    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);
        for member in &snapshot.members {
            assert!(
                matches!(
                    member.context.parse_state,
                    IntuneParseState::Unsupported | IntuneParseState::Malformed
                ),
                "{scenario}/{}: parse state {:?} claims more than the evidence supports",
                member.artifact_id,
                member.context.parse_state
            );
        }
    }
}

#[test]
fn every_finding_cites_evidence_or_a_coverage_gap() {
    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);
        for finding in &snapshot.findings {
            assert!(
                finding.is_evidence_backed(),
                "{scenario}: finding {} cites neither evidence nor a coverage gap",
                finding.finding_id
            );
        }
        assert!(snapshot.findings_are_evidence_backed(), "{scenario}");
    }
}

#[test]
fn analysis_is_byte_stable_across_runs() {
    for scenario in SCENARIOS {
        let (manifest, _) = scenario_pair(scenario);
        let input = bundle_input(scenario, &manifest);
        let first = serde_json::to_string(&analyze_android_diagnostic_bundle(&input))
            .expect("snapshot serializes");
        let second = serde_json::to_string(&analyze_android_diagnostic_bundle(&input))
            .expect("snapshot serializes");
        assert_eq!(first, second, "{scenario}: analysis is not deterministic");
    }
}

#[test]
fn the_redacted_export_is_byte_stable_and_idempotent() {
    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);
        let once = redacted_export_projection(&snapshot);
        let twice = redacted_export_projection(&once);
        assert_eq!(
            serde_json::to_string(&once).expect("projection serializes"),
            serde_json::to_string(&twice).expect("projection serializes"),
            "{scenario}: redaction is not idempotent"
        );
    }
}

#[test]
fn findings_survive_redaction_unchanged() {
    // Findings are built from counts and vocabulary tokens only, so the export
    // projection passes them through. That is only safe while it stays true.
    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);
        let projected = redacted_export_projection(&snapshot);
        assert_eq!(
            wire(&snapshot.findings),
            wire(&projected.findings),
            "{scenario}: a finding carried text that redaction had to change"
        );
        for finding in &snapshot.findings {
            let text = format!("{} {}", finding.title, finding.summary);
            assert_eq!(
                redact_text(&text),
                text,
                "{scenario}: finding {} contains a shape redaction would mask",
                finding.finding_id
            );
        }
    }
}

// ── Per-scenario expectations ───────────────────────────────────────────────

#[test]
fn each_scenario_matches_its_written_expectations() {
    for scenario in SCENARIOS {
        let (snapshot, _, expected) = analyze(scenario);

        assert_eq!(
            wire(&snapshot.metadata.classification),
            expected["classification"],
            "{scenario}: bundle classification"
        );

        let coverage: Vec<Value> = snapshot
            .coverage
            .iter()
            .map(|entry| {
                json!({ "artifactId": entry.artifact_id, "status": wire(&entry.status) })
            })
            .collect();
        assert_eq!(
            Value::Array(coverage),
            expected["coverage"],
            "{scenario}: coverage"
        );

        for member in &snapshot.members {
            assert_eq!(
                wire(&member.classification),
                expected["memberClassifications"][&member.artifact_id],
                "{scenario}/{}: member classification",
                member.artifact_id
            );
        }

        let findings: Vec<Value> = snapshot.findings.iter().map(finding_projection).collect();
        assert_eq!(
            Value::Array(findings),
            expected["findings"],
            "{scenario}: findings"
        );
    }
}

#[test]
fn the_redaction_scenario_masks_every_sensitive_shape() {
    let scenario = "deterministic-redaction";
    let (snapshot, manifest, expected) = analyze(scenario);
    let redaction = &expected["redaction"];
    let projected = redacted_export_projection(&snapshot);

    assert_eq!(
        projected.metadata.incident_id.as_deref(),
        redaction["incidentId"].as_str(),
        "incident id is replaced with a fixed marker rather than a masked variant of itself"
    );
    assert!(
        snapshot.metadata.incident_id.is_some(),
        "the unredacted snapshot keeps the value for an entitled operator"
    );

    for member in &projected.members {
        assert_eq!(
            Value::String(member.entry_name.clone()),
            redaction["memberEntryName"][&member.artifact_id],
            "{}: entry name", member.artifact_id
        );
        assert_eq!(
            member.sanitized_entry_path.as_deref(),
            redaction["memberSanitizedPath"][&member.artifact_id].as_str(),
            "{}: sanitized path", member.artifact_id
        );
    }

    // The member bytes themselves: the projection never carries them, so the
    // deterministic masking of content is asserted against `redact_text`.
    let root = scenario_root(scenario);
    for artifact in manifest["artifacts"].as_array().expect("artifacts") {
        let artifact_id = artifact["artifactId"].as_str().expect("artifactId");
        let Some(expected_lines) = redaction["memberText"][artifact_id].as_array() else {
            continue;
        };
        let relative = artifact["relativePath"].as_str().expect("relativePath");
        let content = std::fs::read_to_string(root.join(relative)).expect("evidence is readable");
        let actual: Vec<Value> = redact_text(&content)
            .lines()
            .map(|line| Value::String(line.to_owned()))
            .collect();
        assert_eq!(
            &actual,
            expected_lines,
            "{artifact_id}: redacted content"
        );
    }
}

#[test]
fn the_unsafe_scenario_reads_no_flagged_member() {
    use cmtraceopen_parser::intune::portal::android::company_portal::diagnostics::AndroidMemberClassification;

    let (snapshot, _, _) = analyze("unsafe-member-import-flags");
    assert!(!snapshot.members.is_empty());
    for member in &snapshot.members {
        assert!(
            !member.safety_flags.is_empty(),
            "{}: this scenario exists to exercise flagged members",
            member.artifact_id
        );
        assert_eq!(
            member.classification,
            AndroidMemberClassification::RejectedUnsafe,
            "{}: a flagged member must never be classified from its contents",
            member.artifact_id
        );
    }

    // Traversal and absolute names were re-derived here, not reported by the
    // importer, which is what stops a forgetful host from hiding them.
    let traversal = snapshot
        .members
        .iter()
        .find(|member| member.artifact_id == "unsafe-traversal")
        .expect("traversal member");
    assert!(traversal
        .safety_flags
        .contains(&AndroidMemberSafetyFlag::PathTraversal));
    let oversized = snapshot
        .members
        .iter()
        .find(|member| member.artifact_id == "unsafe-oversized")
        .expect("oversized member");
    assert!(oversized
        .safety_flags
        .contains(&AndroidMemberSafetyFlag::OversizedEntry));
}

#[test]
fn a_logcat_bundle_is_refused_even_though_the_importer_nominated_it() {
    let (snapshot, manifest, _) = analyze("android-logcat-negative");
    assert_eq!(
        manifest["supplied"]["app"].as_str(),
        Some("companyPortal"),
        "the scenario is only meaningful if the importer claimed Company Portal"
    );
    assert_eq!(
        wire(&snapshot.metadata.classification),
        json!("notCompanyPortalDiagnostics")
    );
    assert!(snapshot
        .findings
        .iter()
        .any(|finding| finding.finding_id == "android-diagnostics/not-company-portal"));
}

#[test]
fn an_incident_id_is_never_read_as_a_successful_upload() {
    let (attempted, _, _) = analyze("incident-id-without-upload-confirmation");
    assert!(attempted.metadata.incident_id.is_some());
    assert!(attempted.findings.iter().any(|finding| finding.finding_id
        == "android-diagnostics/incident-id-without-upload-confirmation"));

    // The contrast case: an incident ID with a reported outcome. It is the
    // outcome that clears the caveat, never the identifier.
    let (confirmed, _, _) = analyze("microsoft-intune-app-uploaded-logs");
    assert!(confirmed.metadata.incident_id.is_some());
    assert!(!confirmed.findings.iter().any(|finding| finding.finding_id
        == "android-diagnostics/incident-id-without-upload-confirmation"));
}

#[test]
fn work_profile_scope_is_preserved_in_provenance_and_findings() {
    let (snapshot, _, _) = analyze("company-portal-saved-logs");
    assert_eq!(
        wire(&snapshot.metadata.management_mode),
        json!("workProfile")
    );
    assert!(snapshot.findings.iter().any(
        |finding| finding.finding_id == "android-diagnostics/work-profile-collection-scope"
    ));

    // A corporate-owned work profile is a different mode and must not inherit
    // the personal-profile caveat that applies to a work-profile collection.
    let (cope, _, _) = analyze("admin-center-download-corporate-owned-work-profile");
    assert!(!cope.findings.iter().any(
        |finding| finding.finding_id == "android-diagnostics/work-profile-collection-scope"
    ));
}

#[test]
fn an_unknown_app_name_round_trips_verbatim() {
    let (snapshot, _, _) = analyze("unknown-app-and-schema-token");
    assert_eq!(wire(&snapshot.metadata.app), json!("companyPortalNextGen"));
    assert_eq!(
        snapshot.metadata.declared_schema_token.as_deref(),
        Some("androidDiagnostics/v99")
    );
    assert!(snapshot
        .findings
        .iter()
        .any(|finding| finding.finding_id == "android-diagnostics/unknown-app-or-schema"));
}

#[test]
fn an_unreadable_collection_time_keeps_its_original_text() {
    use cmtraceopen_parser::intune::evidence::IntuneTimestampKind;

    let (snapshot, _, _) = analyze("invalid-collection-timestamp");
    let collected = snapshot
        .metadata
        .collected_at
        .as_ref()
        .expect("a collection time was supplied");
    assert_eq!(collected.kind, IntuneTimestampKind::Invalid);
    assert_eq!(collected.raw_text, "31 July 2026, 9:14 am device local");
    assert_eq!(collected.normalized_utc, None);

    // The missing case is a different scenario and must produce the same
    // finding for a different reason.
    let (missing, _, _) = analyze("malformed-member-and-missing-collection-time");
    assert!(missing.metadata.collected_at.is_none());
    for snapshot in [&snapshot, &missing] {
        assert!(snapshot
            .findings
            .iter()
            .any(|finding| finding.finding_id
                == "android-diagnostics/unusable-collection-time"));
    }
}

// ── Adversarial mutations of the corpus itself ──────────────────────────────

fn assert_rejected(scenario: &str, label: &str, manifest: &Value, expected: &Value, needle: &str) {
    let failures = validate_scenario(scenario, &scenario_root(scenario), manifest, expected);
    assert!(
        !failures.is_empty(),
        "{label}: the validator accepted a corpus it should have rejected"
    );
    assert!(
        failures.entries().iter().any(|entry| entry.contains(needle)),
        "{label}: expected a failure mentioning {needle:?}, got {:?}",
        failures.entries()
    );
}

#[test]
fn a_byte_count_that_disagrees_with_the_member_is_rejected() {
    let scenario = "company-portal-saved-logs";
    let (manifest, expected) = scenario_pair(scenario);
    assert_rejected(
        scenario,
        "byte count drift",
        &mutated(&manifest, "/artifacts/0/bytesCopied", json!(1)),
        &expected,
        "bytesCopied",
    );
}

#[test]
fn coverage_contradicting_a_capture_state_is_rejected() {
    // The capped member in this scenario cannot be reported available: doing so
    // would let a truncated source masquerade as complete coverage, and every
    // finding citing it would inherit the overclaim.
    let scenario = "truncated-and-missing-members";
    let (manifest, expected) = scenario_pair(scenario);
    let capped = expected["coverage"]
        .as_array()
        .expect("coverage")
        .iter()
        .position(|entry| entry["status"] == json!("capped"))
        .expect("the scenario has a capped member");
    assert_rejected(
        scenario,
        "coverage status drift",
        &manifest,
        &mutated(
            &expected,
            &format!("/coverage/{capped}/status"),
            json!("available"),
        ),
        "requires coverage status",
    );
}

#[test]
fn a_finding_stripped_of_its_citations_is_rejected() {
    let scenario = "arbitrary-archive-negative";
    let (manifest, expected) = scenario_pair(scenario);
    assert_rejected(
        scenario,
        "uncited finding",
        &manifest,
        &mutated(&expected, "/findings/0/evidence", json!([])),
        "cites neither evidence nor a coverage gap",
    );
}

#[test]
fn a_member_pointing_outside_the_scenario_is_rejected() {
    let scenario = "company-portal-saved-logs";
    let (manifest, expected) = scenario_pair(scenario);
    assert_rejected(
        scenario,
        "path escape",
        &mutated(
            &manifest,
            "/artifacts/0/relativePath",
            json!("../../../../etc/passwd"),
        ),
        &expected,
        "normal components",
    );
}

#[test]
fn every_evidence_file_is_marked_synthetic() {
    // Belt and braces over the shared validator: this is the tripwire against a
    // real user's diagnostics being pasted into the corpus, and it is worth
    // failing on twice.
    for scenario in SCENARIOS {
        let root = scenario_root(scenario);
        for path in support::walk_files(&root.join("evidence")) {
            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
            assert!(
                contents
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .contains(support::SYNTHETIC_MARKER),
                "{}: first line must carry the synthetic marker",
                path.display()
            );
        }
    }
}

#[test]
fn scenario_roots_exist_for_every_pinned_name() {
    for scenario in SCENARIOS {
        let root: &Path = &scenario_root(scenario);
        assert!(root.is_dir(), "{scenario}: missing scenario directory");
        assert!(root.join("manifest.json").is_file(), "{scenario}: manifest");
        assert!(root.join("expected.json").is_file(), "{scenario}: expected");
    }
}
