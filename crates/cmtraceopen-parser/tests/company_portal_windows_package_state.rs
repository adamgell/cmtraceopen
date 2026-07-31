//! Contract tests for `intune::portal::windows::company_portal::package_state`.
//!
//! Fixtures are embedded with `include_str!` because the parser crate performs
//! no filesystem access and must keep compiling for `wasm32-unknown-unknown`.

use std::collections::BTreeSet;
use std::path::Path;

use cmtraceopen_parser::intune::portal::windows::company_portal::package_state::{
    derive_package_state_findings, import_legacy_format_list, malformed_capture_finding,
    parse_package_state_capture, parse_package_state_findings, redacted_package_state_export,
    ExpectedPackageFact, LegacyImportMetadata, LegacyImportOutcome, LegacyRefusalReason,
    PackageArchitecture, PackageCaptureCommandStatus, PackageCaptureSource, PackageInstallState,
    PackageScope, PackageScopeCoverageStatus, PackageSignatureKind, PackageStateCapture,
    PackageStateError, PackageStateFinding, PackageStateFindingConfidence, PackageStateFindingKind,
    PackageStateFindingSeverity, PackageStateSensitivity, PackageStatus, PortalApp,
    COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION,
};

const FIXTURE_ROOT: &str = "tests/fixtures/intune/portal/windows/package_state";

const INSTALLED_COMPANY_PORTAL: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/installed-company-portal/capture.json"
);
const INSTALLED_BOTH: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/installed-company-portal-and-authenticator/capture.json"
);
const ABSENT_AFTER_COMPLETE_CAPTURE: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/absent-after-complete-all-users-capture/capture.json"
);
const PER_USER_ONLY: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/per-user-only-registration/capture.json"
);
const MULTIPLE_REGISTRATIONS: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/multiple-registrations/capture.json"
);
const STATUS_PROBLEM: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/package-status-problem/capture.json"
);
const ACCESS_DENIED: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/access-denied-incomplete-query/capture.json"
);
const COMMAND_FAILURE: &str =
    include_str!("fixtures/intune/portal/windows/package_state/command-failure/capture.json");
const MALFORMED_JSON: &str =
    include_str!("fixtures/intune/portal/windows/package_state/malformed-json/capture.json");
const UNKNOWN_FUTURE_SCHEMA: &str =
    include_str!("fixtures/intune/portal/windows/package_state/unknown-future-schema/capture.json");
const DETERMINISTIC_SERIALIZATION: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/deterministic-serialization/capture.json"
);
const DETERMINISTIC_SERIALIZATION_GOLDEN: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/deterministic-serialization/golden.json"
);
const PRIVACY_PATHS: &str =
    include_str!("fixtures/intune/portal/windows/package_state/privacy-paths/capture.json");
const PRIVACY_PATHS_GOLDEN: &str =
    include_str!("fixtures/intune/portal/windows/package_state/privacy-paths/golden-redacted.json");
const LEGACY_ENGLISH: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/legacy-format-list-english/packages.txt"
);
const LEGACY_WRAPPED: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/legacy-format-list-refused/wrapped.txt"
);
const LEGACY_NON_ENGLISH: &str = include_str!(
    "fixtures/intune/portal/windows/package_state/legacy-format-list-refused/non-english.txt"
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse(json: &str) -> PackageStateCapture {
    parse_package_state_capture(json).expect("fixture must parse")
}

fn kinds(findings: &[PackageStateFinding]) -> Vec<PackageStateFindingKind> {
    findings.iter().map(|finding| finding.kind).collect()
}

fn of_kind(
    findings: &[PackageStateFinding],
    kind: PackageStateFindingKind,
) -> Vec<&PackageStateFinding> {
    findings
        .iter()
        .filter(|finding| finding.kind == kind)
        .collect()
}

fn expects_company_portal(version: &str) -> ExpectedPackageFact {
    ExpectedPackageFact {
        app: PortalApp::CompanyPortal,
        family_name: None,
        expected_version: version.to_string(),
        source: "Intune app assignment".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Fixture 1: installed Company Portal
// ---------------------------------------------------------------------------

#[test]
fn package_state_installed_company_portal_yields_an_installed_fact() {
    let capture = parse(INSTALLED_COMPANY_PORTAL);

    assert_eq!(
        capture.schema_version,
        COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION
    );
    assert_eq!(capture.capture.source, PackageCaptureSource::Json);
    assert_eq!(
        capture.capture.command_status,
        PackageCaptureCommandStatus::Completed
    );
    assert_eq!(capture.packages.len(), 1);

    let row = &capture.packages[0];
    assert_eq!(row.app, PortalApp::CompanyPortal);
    assert_eq!(row.architecture, PackageArchitecture::X64);
    assert_eq!(row.signature_kind, PackageSignatureKind::Store);
    assert_eq!(row.status, PackageStatus::Ok);
    assert_eq!(row.install_state, PackageInstallState::Installed);
    assert_eq!(row.scopes, vec![PackageScope::AllUsers]);
    assert_eq!(row.user_registration_count, Some(2));
    assert_eq!(
        row.install_location.as_ref().map(|l| l.sensitivity.clone()),
        Some(PackageStateSensitivity::Sensitive)
    );

    let findings = derive_package_state_findings(&capture, &[]);
    assert_eq!(
        kinds(&findings),
        vec![PackageStateFindingKind::PackageInstalled]
    );
    assert_eq!(findings[0].severity, PackageStateFindingSeverity::Info);
    assert_eq!(findings[0].confidence, PackageStateFindingConfidence::High);
    assert_eq!(findings[0].evidence[0].package_index, Some(0));
}

// ---------------------------------------------------------------------------
// Fixture 2: Company Portal and Authenticator together
// ---------------------------------------------------------------------------

#[test]
fn package_state_company_portal_and_authenticator_are_separate_rows() {
    let capture = parse(INSTALLED_BOTH);

    assert_eq!(capture.packages.len(), 2);
    assert_eq!(capture.rows_for_app(&PortalApp::CompanyPortal).len(), 1);
    assert_eq!(capture.rows_for_app(&PortalApp::Authenticator).len(), 1);
    assert_eq!(
        capture.packages[1].architecture,
        PackageArchitecture::Neutral
    );

    let findings = derive_package_state_findings(&capture, &[]);
    assert_eq!(
        kinds(&findings),
        vec![
            PackageStateFindingKind::PackageInstalled,
            PackageStateFindingKind::PackageInstalled
        ]
    );
    // Two complete scopes, but distinct family names, so no duplicate finding.
    assert!(of_kind(
        &findings,
        PackageStateFindingKind::MultiplePackageRegistrations
    )
    .is_empty());
}

// ---------------------------------------------------------------------------
// Fixture 3 + 7: the absence rule, both directions
// ---------------------------------------------------------------------------

#[test]
fn package_state_absence_requires_complete_scope_coverage() {
    let capture = parse(ABSENT_AFTER_COMPLETE_CAPTURE);
    assert!(capture.packages.is_empty());

    let findings = derive_package_state_findings(&capture, &[]);
    let absences = of_kind(
        &findings,
        PackageStateFindingKind::PackageAbsentFromCapturedScope,
    );
    assert_eq!(absences.len(), 1, "one complete scope, one absence claim");
    assert_eq!(absences[0].evidence[0].scope, Some(PackageScope::AllUsers));
    assert_eq!(absences[0].confidence, PackageStateFindingConfidence::High);
    assert!(of_kind(&findings, PackageStateFindingKind::IncompleteQuery).is_empty());
}

#[test]
fn package_state_absence_is_not_claimed_when_the_scope_was_denied() {
    let capture = parse(ACCESS_DENIED);
    assert!(capture.packages.is_empty());
    assert_eq!(
        capture.capture.command_status,
        PackageCaptureCommandStatus::AccessDenied
    );

    let findings = derive_package_state_findings(&capture, &[expects_company_portal("11.2.401.0")]);
    assert!(
        of_kind(
            &findings,
            PackageStateFindingKind::PackageAbsentFromCapturedScope
        )
        .is_empty(),
        "a denied scope is coverage, never evidence of absence: {findings:#?}"
    );

    let incomplete = of_kind(&findings, PackageStateFindingKind::IncompleteQuery);
    // One for the command status, one per non-complete scope.
    assert_eq!(incomplete.len(), 3);
    assert!(incomplete
        .iter()
        .any(|finding| finding.id.contains("command/accessDenied")));
    assert!(incomplete
        .iter()
        .any(|finding| finding.id.contains("scope/allUsers/denied")));
    assert!(incomplete
        .iter()
        .any(|finding| finding.id.contains("scope/provisioned/notQueried")));
}

#[test]
fn package_state_absence_is_not_claimed_from_a_scope_that_was_never_queried() {
    // The all-users scope is `notQueried`, so absence is unclaimable there even
    // though the command itself completed and the current-user scope is clean.
    let capture = parse(PER_USER_ONLY);
    let expected = [ExpectedPackageFact {
        app: PortalApp::Authenticator,
        family_name: None,
        expected_version: "6.2408.1".to_string(),
        source: "Intune app assignment".to_string(),
    }];

    let findings = derive_package_state_findings(&capture, &expected);
    let absences = of_kind(
        &findings,
        PackageStateFindingKind::PackageAbsentFromCapturedScope,
    );
    assert_eq!(
        absences.len(),
        1,
        "only the completely enumerated currentUser scope may carry an absence claim"
    );
    assert_eq!(
        absences[0].evidence[0].scope,
        Some(PackageScope::CurrentUser)
    );
    assert!(absences[0].id.contains("authenticator"));
}

// ---------------------------------------------------------------------------
// Fixture 4: per-user registration without a raw username
// ---------------------------------------------------------------------------

#[test]
fn package_state_per_user_registration_carries_no_raw_username() {
    let capture = parse(PER_USER_ONLY);
    let row = &capture.packages[0];

    assert_eq!(row.scopes, vec![PackageScope::CurrentUser]);
    assert_eq!(row.user_registration_count, Some(1));
    assert!(
        row.user_identifier.is_none(),
        "per-user scope must be expressed structurally, not by naming the user"
    );

    let serialized = serde_json::to_string(&capture).expect("capture must serialize");
    assert!(!serialized.contains("userIdentifier\":{"));
    assert!(
        capture
            .capture
            .coverage_for(&PackageScope::AllUsers)
            .map(|coverage| coverage.status.clone())
            == Some(PackageScopeCoverageStatus::NotQueried)
    );
}

// ---------------------------------------------------------------------------
// Fixture 5: multiple registrations
// ---------------------------------------------------------------------------

#[test]
fn package_state_multiple_registrations_of_one_family_are_reported_once() {
    let capture = parse(MULTIPLE_REGISTRATIONS);
    let findings = derive_package_state_findings(&capture, &[]);

    let duplicates = of_kind(
        &findings,
        PackageStateFindingKind::MultiplePackageRegistrations,
    );
    assert_eq!(duplicates.len(), 1);
    assert!(duplicates[0]
        .id
        .ends_with("Microsoft.CompanyPortal_8wekyb3d8bbwe"));
    assert_eq!(duplicates[0].evidence.len(), 2);
    assert!(duplicates[0].message.contains("11.1.317.0"));
    assert!(duplicates[0].message.contains("11.2.401.0"));

    // Only the `installed` row is an installed fact; the staged one is not.
    assert_eq!(
        of_kind(&findings, PackageStateFindingKind::PackageInstalled).len(),
        1
    );
}

// ---------------------------------------------------------------------------
// Fixture 6: package status problem
// ---------------------------------------------------------------------------

#[test]
fn package_state_status_problem_is_an_error_finding() {
    let capture = parse(STATUS_PROBLEM);
    let findings = derive_package_state_findings(&capture, &[]);

    let problems = of_kind(&findings, PackageStateFindingKind::PackageStatusProblem);
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].severity, PackageStateFindingSeverity::Error);
    assert!(problems[0].message.contains("needsRemediation"));
    // Status problems outrank the informational rows in the ordering.
    assert_eq!(
        findings[0].kind,
        PackageStateFindingKind::PackageStatusProblem
    );
}

// ---------------------------------------------------------------------------
// Version mismatch is a supplied fact, never a lookup
// ---------------------------------------------------------------------------

#[test]
fn package_state_version_mismatch_only_comes_from_a_supplied_expected_fact() {
    let capture = parse(INSTALLED_COMPANY_PORTAL);

    let without_expectation = derive_package_state_findings(&capture, &[]);
    assert!(
        of_kind(
            &without_expectation,
            PackageStateFindingKind::VersionMismatch
        )
        .is_empty(),
        "no expectation supplied, so no version claim may be invented"
    );

    let matching = derive_package_state_findings(&capture, &[expects_company_portal("11.2.401.0")]);
    assert!(of_kind(&matching, PackageStateFindingKind::VersionMismatch).is_empty());

    let mismatched = derive_package_state_findings(&capture, &[expects_company_portal("12.0.0.0")]);
    let mismatches = of_kind(&mismatched, PackageStateFindingKind::VersionMismatch);
    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        mismatches[0].confidence,
        PackageStateFindingConfidence::Medium
    );
    assert!(mismatches[0].message.contains("Intune app assignment"));
    assert!(mismatches[0].message.contains("12.0.0.0"));
}

// ---------------------------------------------------------------------------
// Fixture 8: command failure
// ---------------------------------------------------------------------------

#[test]
fn package_state_command_failure_is_coverage_and_blocks_every_package_claim() {
    let capture = parse(COMMAND_FAILURE);
    let findings = derive_package_state_findings(&capture, &[expects_company_portal("11.2.401.0")]);

    assert!(of_kind(
        &findings,
        PackageStateFindingKind::PackageAbsentFromCapturedScope
    )
    .is_empty());
    assert!(of_kind(&findings, PackageStateFindingKind::PackageInstalled).is_empty());

    let incomplete = of_kind(&findings, PackageStateFindingKind::IncompleteQuery);
    assert_eq!(incomplete.len(), 4);
    let command_level = incomplete
        .iter()
        .find(|finding| finding.id.contains("command/failed"))
        .expect("command status finding");
    assert_eq!(command_level.severity, PackageStateFindingSeverity::Error);
    assert!(command_level.message.contains("CommandNotFoundException"));
}

// ---------------------------------------------------------------------------
// Fixture 9: malformed JSON
// ---------------------------------------------------------------------------

#[test]
fn package_state_malformed_json_is_a_typed_error_and_a_finding_not_a_panic() {
    let error = parse_package_state_capture(MALFORMED_JSON).expect_err("fixture must not parse");
    assert!(matches!(error, PackageStateError::InvalidJson(_)));

    let findings = parse_package_state_findings(MALFORMED_JSON, &[]);
    assert_eq!(
        kinds(&findings),
        vec![PackageStateFindingKind::MalformedCapture]
    );
    assert_eq!(findings[0].severity, PackageStateFindingSeverity::Error);
    assert_eq!(findings[0], malformed_capture_finding(&error));
}

#[test]
fn package_state_rejects_documents_without_a_usable_schema_version() {
    assert!(matches!(
        parse_package_state_capture("[]").expect_err("array is not a capture"),
        PackageStateError::NotAnObject(_)
    ));
    assert!(matches!(
        parse_package_state_capture("{\"capture\":{}}").expect_err("no schemaVersion"),
        PackageStateError::MissingSchemaVersion
    ));
    assert!(matches!(
        parse_package_state_capture("{\"schemaVersion\":1,\"packages\":\"nope\"}")
            .expect_err("packages must be an array"),
        PackageStateError::InvalidBody { version: 1, .. }
    ));
}

// ---------------------------------------------------------------------------
// Fixture 10: unknown future schema
// ---------------------------------------------------------------------------

#[test]
fn package_state_unknown_future_schema_preserves_raw_metadata_and_claims_nothing() {
    let capture = parse(UNKNOWN_FUTURE_SCHEMA);

    assert_eq!(capture.schema_version, 4);
    assert!(capture.is_unsupported_schema());
    assert!(
        capture.packages.is_empty(),
        "a schema we cannot read yields no package facts"
    );

    // Provenance a future schema cannot have moved is still readable, and an
    // unrecognized scope value survives as its raw string.
    assert_eq!(capture.capture.locale.as_deref(), Some("en-GB"));
    assert_eq!(
        capture.capture.scope_coverage[1].scope,
        PackageScope::Unknown("containerUser".to_string())
    );

    let raw = capture
        .raw_document
        .as_ref()
        .expect("raw document preserved");
    assert_eq!(
        raw.pointer("/packageGroups/0/members/0/trustTier")
            .and_then(|value| value.as_str()),
        Some("sealedStore")
    );

    let findings = derive_package_state_findings(&capture, &[expects_company_portal("14.0.0.0")]);
    assert_eq!(
        kinds(&findings),
        vec![PackageStateFindingKind::UnsupportedSchema]
    );
    assert!(findings[0].message.contains("schema version 4"));
}

// ---------------------------------------------------------------------------
// Fixture 11: deterministic, field-order-independent serialization
// ---------------------------------------------------------------------------

#[test]
fn package_state_serialization_is_byte_exact_and_field_order_independent() {
    let capture = parse(DETERMINISTIC_SERIALIZATION);
    let golden = DETERMINISTIC_SERIALIZATION_GOLDEN.trim_end_matches('\n');

    let serialized = serde_json::to_string(&capture).expect("capture must serialize");
    assert_eq!(serialized, golden);

    // Input field order does not reach the output.
    let reparsed = parse(&serialized);
    assert_eq!(reparsed, capture);
    assert_eq!(
        serde_json::to_string(&reparsed).expect("round trip must serialize"),
        golden
    );

    // Unknown enum values and unknown adapter fields both survive the trip.
    let row = &capture.packages[0];
    assert_eq!(
        row.signature_kind,
        PackageSignatureKind::Unknown("quantumAttested".to_string())
    );
    let raw = row.raw.as_ref().expect("unknown fields preserved");
    assert_eq!(raw.get("aaaFutureField").and_then(|v| v.as_u64()), Some(42));
    assert_eq!(
        raw.pointer("/zzzFutureField/kind").and_then(|v| v.as_str()),
        Some("sealed")
    );
}

#[test]
fn package_state_finding_order_is_stable_across_input_permutations() {
    let capture = parse(MULTIPLE_REGISTRATIONS);
    let expected = [expects_company_portal("12.0.0.0")];

    let first = derive_package_state_findings(&capture, &expected);
    let second = derive_package_state_findings(&capture, &expected);
    assert_eq!(first, second);

    let mut reversed = capture.clone();
    reversed.packages.reverse();
    let reordered = derive_package_state_findings(&reversed, &expected);

    // Row indices differ, but the finding kinds arrive in the same order.
    assert_eq!(kinds(&first), kinds(&reordered));
    let ranks: Vec<_> = first.iter().map(|finding| finding.kind).collect();
    let mut sorted = ranks.clone();
    sorted.sort();
    assert_eq!(ranks, sorted, "findings must be emitted most-severe first");
}

// ---------------------------------------------------------------------------
// Fixture 12: legacy Format-List English sample imports
// ---------------------------------------------------------------------------

#[test]
fn package_state_legacy_english_format_list_imports_as_low_confidence_evidence() {
    let outcome = import_legacy_format_list(LEGACY_ENGLISH, english_legacy_metadata());
    let capture = outcome
        .imported()
        .expect("English sample must import")
        .clone();

    assert_eq!(
        capture.capture.source,
        PackageCaptureSource::LegacyFormatList
    );
    assert_eq!(capture.packages.len(), 2);

    let portal = &capture.packages[0];
    assert_eq!(portal.name, "Microsoft.CompanyPortal");
    assert_eq!(portal.version, "11.2.401.0");
    assert_eq!(portal.app, PortalApp::CompanyPortal);
    assert_eq!(portal.status, PackageStatus::Ok);
    assert_eq!(portal.signature_kind, PackageSignatureKind::Store);
    // Family name and architecture are recovered from the documented full-name
    // shape rather than guessed.
    assert_eq!(portal.family_name, "Microsoft.CompanyPortal_8wekyb3d8bbwe");
    assert_eq!(portal.architecture, PackageArchitecture::X64);
    // Display text says nothing about install state, so nothing is claimed.
    assert_eq!(
        portal.install_state,
        PackageInstallState::Unknown(String::new())
    );

    let authenticator = &capture.packages[1];
    assert_eq!(authenticator.app, PortalApp::Authenticator);
    assert_eq!(
        authenticator
            .raw
            .as_ref()
            .and_then(|raw| raw.get("IsBundle"))
            .and_then(|value| value.as_str()),
        Some("False"),
        "unrecognized legacy labels are preserved rather than dropped"
    );

    // A legacy import can never be the basis of an absence claim, and every
    // finding it produces is low confidence.
    let findings = derive_package_state_findings(&capture, &[expects_company_portal("12.0.0.0")]);
    assert!(of_kind(
        &findings,
        PackageStateFindingKind::PackageAbsentFromCapturedScope
    )
    .is_empty());
    assert!(findings
        .iter()
        .filter(|finding| finding.kind != PackageStateFindingKind::IncompleteQuery)
        .all(|finding| finding.confidence == PackageStateFindingConfidence::Low));
}

// ---------------------------------------------------------------------------
// Fixture 13: wrapped / non-English legacy samples refuse
// ---------------------------------------------------------------------------

#[test]
fn package_state_legacy_import_refuses_wrapped_or_non_english_samples() {
    let wrapped = import_legacy_format_list(LEGACY_WRAPPED, english_legacy_metadata());
    let refusal = wrapped.refusal().expect("wrapped sample must refuse");
    assert_eq!(refusal.reason, LegacyRefusalReason::AmbiguousRecord);
    assert_eq!(refusal.line_number, Some(5));
    assert!(wrapped.imported().is_none());

    let mut german = english_legacy_metadata();
    german.locale = Some("de-DE".to_string());
    let non_english = import_legacy_format_list(LEGACY_NON_ENGLISH, german);
    assert_eq!(
        non_english.refusal().map(|refusal| refusal.reason),
        Some(LegacyRefusalReason::UnsupportedLocale)
    );

    let mut anonymous = english_legacy_metadata();
    anonymous.locale = None;
    assert_eq!(
        import_legacy_format_list(LEGACY_ENGLISH, anonymous)
            .refusal()
            .map(|refusal| refusal.reason),
        Some(LegacyRefusalReason::MissingLocale)
    );

    // Refusal must be distinguishable from "captured nothing".
    let empty = import_legacy_format_list("   \n\n", english_legacy_metadata());
    assert_eq!(
        empty.refusal().map(|refusal| refusal.reason),
        Some(LegacyRefusalReason::NoRecognizableRecords)
    );
    assert!(
        !matches!(empty, LegacyImportOutcome::Imported(_)),
        "an empty capture must never stand in for a refusal"
    );
}

fn english_legacy_metadata() -> LegacyImportMetadata {
    LegacyImportMetadata {
        locale: Some("en-US".to_string()),
        adapter_version: "cmtraceopen-legacy-format-list/0".to_string(),
        captured_at_utc: "2026-07-14T09:44:00.0000000Z".to_string(),
        windows_build: Some("10.0.26100.0".to_string()),
        power_shell_version: Some("5.1.26100.2161".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Fixture 14: privacy projection
// ---------------------------------------------------------------------------

#[test]
fn package_state_redacted_export_masks_paths_and_user_identifiers_without_mutating_input() {
    let capture = parse(PRIVACY_PATHS);
    let original_json = serde_json::to_string(&capture).expect("capture must serialize");

    let safe = redacted_package_state_export(&capture);
    let golden = PRIVACY_PATHS_GOLDEN.trim_end_matches('\n');
    assert_eq!(
        serde_json::to_string(&safe).expect("projection must serialize"),
        golden
    );

    // Nothing identity-bearing survives.
    let safe_json = serde_json::to_string(&safe).expect("projection must serialize");
    for secret in [
        "jrivera",
        "amorel",
        "CONTOSO",
        "AppData",
        "Failed reading manifest",
    ] {
        assert!(
            !safe_json.contains(secret),
            "redacted export still leaks {secret}: {safe_json}"
        );
    }

    // Pseudonyms are stable and distinguish the two users.
    assert_eq!(
        safe.packages[0]
            .user_identifier
            .as_ref()
            .map(|id| id.value.as_str()),
        Some("[redacted-user-2]")
    );
    assert_eq!(
        safe.packages[1]
            .user_identifier
            .as_ref()
            .map(|id| id.value.as_str()),
        Some("[redacted-user-1]")
    );

    // Diagnostics that carry no identity survive intact.
    assert_eq!(
        safe.packages[0].publisher.as_deref(),
        capture.packages[0].publisher.as_deref()
    );
    assert_eq!(safe.packages[0].version, "11.2.401.0");
    assert_eq!(
        safe.capture.error.as_ref().and_then(|e| e.code.as_deref()),
        Some("AppxPackagingFailure")
    );
    assert_eq!(
        safe.packages[0]
            .raw
            .as_ref()
            .and_then(|raw| raw.get("packageRoot"))
            .and_then(|value| value.as_str()),
        Some("C:\\Program Files\\WindowsApps"),
        "non-identity paths must stay readable"
    );

    // Projection, not mutation, and idempotent.
    assert_eq!(redacted_package_state_export(&capture), safe);
    assert_eq!(
        serde_json::to_string(&capture).expect("input must be unchanged"),
        original_json
    );
    assert_eq!(redacted_package_state_export(&safe), safe);
}

#[test]
fn package_state_redacted_export_stays_idempotent_beyond_nine_identifiers() {
    // Pseudonyms are numbered by sort position, and "[redacted-user-10]" sorts
    // before "[redacted-user-1]" because '0' < ']'. So a second pass must treat
    // an already-redacted value as terminal. Otherwise ten or more identifiers
    // get renumbered and the projection stops being idempotent. Two identifiers
    // cannot catch this: single digits sort the same either way.
    const IDENTIFIER_COUNT: usize = 12;

    let rows: Vec<String> = (0..IDENTIFIER_COUNT)
        .map(|index| {
            format!(
                r#"{{
                    "name": "Microsoft.CompanyPortal",
                    "familyName": "Microsoft.CompanyPortal_8wekyb3d8bbwe",
                    "fullName": "Microsoft.CompanyPortal_11.2.401.0_x64__8wekyb3d8bbwe",
                    "version": "11.2.401.0",
                    "architecture": "x64",
                    "signatureKind": "store",
                    "status": "ok",
                    "installState": "installed",
                    "scopes": ["currentUser"],
                    "userIdentifier": {{
                        "value": "CONTOSO\\user{index:02}",
                        "sensitivity": "restricted"
                    }},
                    "app": "companyPortal"
                }}"#
            )
        })
        .collect();

    let capture = parse(&format!(
        r#"{{
            "schemaVersion": 1,
            "capture": {{
                "capturedAtUtc": "2026-07-14T09:41:07.1000000Z",
                "adapterVersion": "cmtraceopen-collector-appx/1",
                "commandStatus": "completed",
                "source": "json",
                "scopeCoverage": [
                    {{ "scope": "allUsers", "status": "complete", "detail": null }}
                ]
            }},
            "packages": [{}]
        }}"#,
        rows.join(",")
    ));

    let once = redacted_package_state_export(&capture);
    let twice = redacted_package_state_export(&once);
    assert_eq!(
        twice, once,
        "projection must stay idempotent past nine identifiers"
    );

    // Renumbering would still produce distinct labels, so distinctness alone
    // does not prove idempotence. Assert it anyway: collapsing two users onto
    // one pseudonym would be the worse failure.
    let labels: BTreeSet<&str> = once
        .packages
        .iter()
        .filter_map(|row| row.user_identifier.as_ref())
        .map(|identifier| identifier.value.as_str())
        .collect();
    assert_eq!(
        labels.len(),
        IDENTIFIER_COUNT,
        "every identifier must keep a distinct pseudonym"
    );

    let safe_json = serde_json::to_string(&once).expect("projection must serialize");
    assert!(
        !safe_json.contains("CONTOSO"),
        "redacted export still leaks a domain: {safe_json}"
    );
}

// ---------------------------------------------------------------------------
// Fixture layout guard
// ---------------------------------------------------------------------------

#[test]
fn package_state_fixture_matrix_covers_every_required_scenario() {
    // The issue's 14-item matrix maps onto these scenario directories. Asserting
    // the directory listing makes a silently dropped or renamed scenario a test
    // failure rather than a quietly narrower contract.
    let expected: BTreeSet<String> = [
        "absent-after-complete-all-users-capture",
        "access-denied-incomplete-query",
        "command-failure",
        "deterministic-serialization",
        "installed-company-portal",
        "installed-company-portal-and-authenticator",
        "legacy-format-list-english",
        "legacy-format-list-refused",
        "malformed-json",
        "multiple-registrations",
        "package-status-problem",
        "per-user-only-registration",
        "privacy-paths",
        "unknown-future-schema",
    ]
    .iter()
    .map(|name| (*name).to_string())
    .collect();
    assert_eq!(expected.len(), 14);

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_ROOT);
    let actual: BTreeSet<String> = std::fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("fixture root {} must exist: {error}", root.display()))
        .map(|entry| entry.expect("readable fixture entry"))
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();

    assert_eq!(actual, expected);
}
