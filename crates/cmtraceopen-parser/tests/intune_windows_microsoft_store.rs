//! Focused fixture matrix for `intune::apps::windows::microsoft_store` (issue #358).
//!
//! Every scenario directory is validated twice: once against the shared corpus
//! contract in `tests/support/` (manifest envelope, byte-count truth, evidence
//! closure, privacy), and once against this leaf's own semantics — installer
//! family, cross-source joins, terminal state, coverage, and findings.
//!
//! The expectations are written out in `expected.json` rather than snapshotted
//! so a reviewer can see what each scenario asserts and why. One scenario
//! additionally carries `expected-full.json`, a complete golden of the redacted
//! export projection, which is what pins the serialized wire shape.

mod support;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::apps::windows::microsoft_store::{
    analyze_store_bundle, redacted_export_projection, StoreAnalysis, StoreArtifactPayload,
    StoreInstallerFamily, StoreSourceArtifact,
};
use cmtraceopen_parser::intune::evidence::IntuneSourceKind;
use serde_json::{json, Value};
use support::{
    artifact_status_for_capture_state, corpus_root, load_json, mutated, scenario_names,
    validate_scenario, Failures,
};

/// The scenario matrix this leaf commits to.
///
/// Pinned as a constant and asserted against the directory listing so that
/// deleting a fixture fails the build instead of silently shrinking coverage.
const SCENARIOS: [&str; 17] = [
    "acquisition-license-failure",
    "deployment-registration-failure",
    "download-staging-failure",
    "incomplete-event-channel-coverage",
    "intune-intent-without-os-event",
    "malformed-export-and-redaction",
    "negative-store-looking-text",
    "no-interactive-user",
    "os-error-without-intune-intent",
    "provisioned-package-install-success",
    "provisioning-failure",
    "same-display-name-different-package-family",
    "store-win32-handoff-success",
    "uninstall-failure",
    "uninstall-success",
    "unknown-event-version",
    "user-context-uwp-install-success",
];

const CORPUS: &str = "apps/windows/microsoft-store";

fn scenario_root(scenario: &str) -> PathBuf {
    support::scenario_root(CORPUS, scenario)
}

fn payload_for(path: &Path) -> StoreArtifactPayload {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
        serde_json::from_str(&text).unwrap_or_else(|error| {
            panic!(
                "{} is a valid store artifact payload: {error}",
                path.display()
            )
        })
    } else {
        StoreArtifactPayload::ImeText { text }
    }
}

fn load_bundle(scenario: &str, manifest: &Value) -> Vec<StoreSourceArtifact> {
    let root = scenario_root(scenario);
    manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts is an array")
        .iter()
        .map(|artifact| {
            let relative = artifact["relativePath"].as_str();
            StoreSourceArtifact {
                artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId")
                    .to_owned(),
                family: artifact["family"].as_str().expect("family").to_owned(),
                source_kind: serde_json::from_value::<IntuneSourceKind>(
                    artifact["sourceKind"].clone(),
                )
                .expect("sourceKind"),
                status: artifact_status_for_capture_state(
                    artifact["captureState"].as_str().expect("captureState"),
                ),
                detail: artifact["detail"].as_str().map(str::to_owned),
                observed_at_utc: artifact["capturedUtc"]
                    .as_str()
                    .expect("capturedUtc")
                    .to_owned(),
                file_name: artifact["originalBasename"].as_str().map(str::to_owned),
                file_path: artifact["sanitizedSourcePath"].as_str().map(str::to_owned),
                payload: relative.map(|relative| payload_for(&root.join(relative))),
            }
        })
        .collect()
}

fn load_scenario(scenario: &str) -> (StoreAnalysis, Value) {
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    (
        analyze_store_bundle(&load_bundle(scenario, &manifest)),
        expected,
    )
}

/// The evidence ids cited by an array, **in the order the reducer emitted them**.
///
/// Deliberately not `support::sorted_evidence_ids`. This leaf asserts citation
/// order: a transaction's `evidence` is positionally in step with its
/// `observations` (see `assert_transactions`), so sorting here would silently
/// retire that pairing. It also panics rather than defaulting, because a missing
/// `evidenceId` in this corpus is a corpus bug, not an absent citation.
fn evidence_ids(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("evidence array")
        .iter()
        .map(|entry| entry["evidenceId"].as_str().expect("evidenceId").to_owned())
        .collect()
}

fn expected_strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("string array")
        .iter()
        .map(|entry| entry.as_str().expect("string").to_owned())
        .collect()
}

/// Compare one scenario's reduction against its stated contract.
fn assert_scenario(scenario: &str) -> StoreAnalysis {
    let (analysis, expected) = load_scenario(scenario);
    let actual = serde_json::to_value(&analysis).expect("analysis serializes");

    assert_transactions(scenario, &actual, &expected);
    assert_coverage(scenario, &actual, &expected);
    assert_findings(scenario, &actual, &expected);

    assert_eq!(
        actual["unkeyedObservations"].as_array().unwrap().len() as u64,
        expected["unkeyedObservationCount"]
            .as_u64()
            .expect("unkeyedObservationCount"),
        "{scenario}: unkeyed observation count"
    );
    if let Some(count) = expected.get("observationCount").and_then(Value::as_u64) {
        assert_eq!(
            actual["observations"].as_array().unwrap().len() as u64,
            count,
            "{scenario}: observation count"
        );
    }

    if let Some(forbidden) = expected.get("redactionMustNotContain") {
        let text = serde_json::to_string(&redacted_export_projection(&analysis))
            .expect("redacted export serializes");
        for needle in expected_strings(forbidden) {
            assert!(
                !text.contains(&needle),
                "{scenario}: redacted export still contains {needle:?}"
            );
        }
    }
    if let Some(required) = expected.get("redactionMustContain") {
        let text = serde_json::to_string(&redacted_export_projection(&analysis))
            .expect("redacted export serializes");
        for needle in expected_strings(required) {
            assert!(
                text.contains(&needle),
                "{scenario}: redacted export dropped correlation key {needle:?}"
            );
        }
    }

    analysis
}

fn assert_transactions(scenario: &str, actual: &Value, expected: &Value) {
    let want = expected["transactions"].as_array().expect("transactions");
    let got = actual["transactions"].as_array().expect("transactions");
    assert_eq!(
        got.len(),
        want.len(),
        "{scenario}: transaction count; got {:?}",
        got.iter()
            .map(|transaction| &transaction["identity"])
            .collect::<Vec<_>>()
    );

    for (index, (got, want)) in got.iter().zip(want).enumerate() {
        let at = format!("{scenario}[{index}]");
        for key in [
            "transactionId",
            "installerFamily",
            "familyBasis",
            "state",
            "action",
            "executionContext",
            "intent",
            "lastConfirmedPhase",
            "confidence",
            "hasIntuneIntent",
            "hasDeviceEvidence",
            "unknownVersionObserved",
            "levelMismatchObserved",
            "nextEvidenceRequest",
        ] {
            assert_eq!(got[key], want[key], "{at}: {key}");
        }
        for (key, identity_key) in [
            ("storeProductId", "storeProductId"),
            ("packageFamilyName", "packageFamilyName"),
            ("displayName", "displayName"),
        ] {
            assert_eq!(
                got["identity"][identity_key], want[key],
                "{at}: identity.{identity_key}"
            );
        }
        assert_eq!(got["appId"], want["appId"], "{at}: appId");

        match want["errorHex"].as_str() {
            Some(hex) => assert_eq!(
                got["error"]["hex"].as_str(),
                Some(hex),
                "{at}: error hex, got {}",
                got["error"]
            ),
            None => assert!(
                got["error"].is_null(),
                "{at}: expected no error, got {}",
                got["error"]
            ),
        }

        assert_eq!(
            evidence_ids(&got["evidence"]),
            expected_strings(&want["evidence"]),
            "{at}: cited evidence"
        );
        assert_eq!(
            got["observations"].as_array().unwrap().len(),
            got["evidence"].as_array().unwrap().len(),
            "{at}: observations and evidence must stay in step"
        );

        // The rule this whole leaf exists for.
        assert!(
            !got["installerFamily"].is_null(),
            "{at}: every transaction must state an installer family"
        );
    }
}

fn assert_coverage(scenario: &str, actual: &Value, expected: &Value) {
    let want = expected["coverage"].as_array().expect("coverage");
    let got = actual["coverage"].as_array().expect("coverage");
    assert_eq!(got.len(), want.len(), "{scenario}: coverage entry count");
    for (index, (got, want)) in got.iter().zip(want).enumerate() {
        assert_eq!(
            got["artifactId"], want["artifactId"],
            "{scenario}[{index}]: coverage artifactId"
        );
        assert_eq!(
            got["status"], want["status"],
            "{scenario}[{index}]: coverage status"
        );
    }
}

fn assert_findings(scenario: &str, actual: &Value, expected: &Value) {
    let want = expected["findings"].as_array().expect("findings");
    let got = actual["findings"].as_array().expect("findings");
    assert_eq!(
        got.len(),
        want.len(),
        "{scenario}: finding count; got {:?}",
        got.iter()
            .map(|finding| finding["findingId"].as_str().unwrap_or_default())
            .collect::<Vec<_>>()
    );

    for (index, (got, want)) in got.iter().zip(want).enumerate() {
        let at = format!("{scenario}[{index}]");
        for key in ["findingId", "severity", "confidence"] {
            assert_eq!(got[key], want[key], "{at}: {key}");
        }
        assert_eq!(
            evidence_ids(&got["evidence"]),
            expected_strings(&want["evidence"]),
            "{at}: finding evidence"
        );
        assert_eq!(
            expected_strings(&got["coverageGapIds"]),
            expected_strings(&want["coverageGapIds"]),
            "{at}: finding coverage gaps"
        );
        assert!(
            !got["evidence"].as_array().unwrap().is_empty()
                || !got["coverageGapIds"].as_array().unwrap().is_empty(),
            "{at}: finding {} cites neither evidence nor a coverage gap",
            got["findingId"]
        );
    }
}

// ── Corpus contract ─────────────────────────────────────────────────────────

#[test]
fn the_corpus_contains_exactly_the_pinned_scenario_matrix() {
    assert_eq!(scenario_names(&corpus_root(CORPUS)), SCENARIOS.to_vec());
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
    failures.assert_empty("microsoft-store corpus");
}

/// The shared validator must actually reject a corrupted copy of this corpus,
/// otherwise "the corpus passes" means nothing.
#[test]
fn a_byte_count_that_disagrees_with_the_file_is_rejected() {
    let scenario = "user-context-uwp-install-success";
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
        "expected a bytesCopied failure, got {:?}",
        failures.entries()
    );
}

// ── The required fixture matrix ─────────────────────────────────────────────

#[test]
fn successful_user_context_uwp_install() {
    let analysis = assert_scenario("user-context-uwp-install-success");
    assert_eq!(
        analysis.transactions[0].installer_family,
        StoreInstallerFamily::UwpUserContext
    );
}

#[test]
fn successful_system_provisioned_install() {
    let analysis = assert_scenario("provisioned-package-install-success");
    assert_eq!(
        analysis.transactions[0].installer_family,
        StoreInstallerFamily::UwpProvisioned
    );
}

/// A Store-delivered Win32 package is settled by its installer, never by AppX
/// deployment semantics, and a zero exit code is not a transaction error.
#[test]
fn store_win32_handoff_with_matching_installer_outcome() {
    let analysis = assert_scenario("store-win32-handoff-success");
    let transaction = &analysis.transactions[0];
    assert_eq!(
        transaction.installer_family,
        StoreInstallerFamily::StoreWin32
    );
    assert!(transaction.error.is_none());
    let installer_observation = analysis
        .observation("installer-outcome:1")
        .expect("installer observation");
    assert_eq!(
        installer_observation
            .error
            .as_ref()
            .and_then(|code| code.decimal),
        Some(0),
        "the installer's own exit code stays on the observation"
    );
}

#[test]
fn acquisition_and_license_failure() {
    let analysis = assert_scenario("acquisition-license-failure");
    // Nothing was staged, so there is no installer family to establish yet and
    // its absence must not be reported as a gap.
    assert!(!analysis
        .findings
        .iter()
        .any(|finding| finding.finding_id == "store-installer-family-unknown"));
}

#[test]
fn download_and_staging_failure() {
    assert_scenario("download-staging-failure");
}

#[test]
fn deployment_registration_failure() {
    assert_scenario("deployment-registration-failure");
}

#[test]
fn provisioning_failure() {
    assert_scenario("provisioning-failure");
}

#[test]
fn no_interactive_user_for_a_user_context_requirement() {
    assert_scenario("no-interactive-user");
}

#[test]
fn uninstall_success() {
    assert_scenario("uninstall-success");
}

#[test]
fn uninstall_failure() {
    assert_scenario("uninstall-failure");
}

#[test]
fn intune_intent_with_no_matching_os_event() {
    assert_scenario("intune-intent-without-os-event");
}

#[test]
fn os_error_with_no_intune_intent_is_not_blamed_on_intune() {
    let analysis = assert_scenario("os-error-without-intune-intent");
    let attribution = analysis
        .findings
        .iter()
        .find(|finding| finding.finding_id == "store-device-failure-without-intune-intent")
        .expect("attribution finding");
    assert!(attribution
        .summary
        .contains("must not be attributed to Intune"));
}

/// Two packages sharing a display name must stay separate: the display name is
/// deliberately not a correlation key.
#[test]
fn same_display_name_different_package_families_stay_separate() {
    let analysis = assert_scenario("same-display-name-different-package-family");
    assert_eq!(analysis.transactions.len(), 2);

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for transaction in &analysis.transactions {
        for observation in &transaction.observations {
            assert!(
                seen.insert(observation.as_str()),
                "observation {observation} was claimed by two transactions"
            );
        }
    }

    let families = analysis
        .transactions
        .iter()
        .filter_map(|transaction| transaction.identity.effective_package_family_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(families.len(), 2);
}

#[test]
fn incomplete_event_channel_coverage_is_a_gap_not_a_failure() {
    let analysis = assert_scenario("incomplete-event-channel-coverage");
    assert_eq!(
        analysis.transactions[0].installer_family,
        StoreInstallerFamily::Unknown
    );
    assert!(
        !analysis.findings.iter().any(|finding| finding.severity
            == cmtraceopen_parser::intune::evidence::IntuneFindingSeverity::Error),
        "a missing channel must never produce an error-severity finding"
    );
}

#[test]
fn unknown_event_or_provider_version_lowers_confidence() {
    let analysis = assert_scenario("unknown-event-version");
    assert!(analysis.transactions[0].unknown_version_observed);
}

#[test]
fn malformed_export_and_deterministic_redaction() {
    let analysis = assert_scenario("malformed-export-and-redaction");

    let first = serde_json::to_string(&redacted_export_projection(&analysis)).unwrap();
    let second = serde_json::to_string(&redacted_export_projection(&analysis)).unwrap();
    assert_eq!(first, second, "redacted export must be deterministic");

    let once = redacted_export_projection(&analysis);
    let twice = redacted_export_projection(&once);
    assert_eq!(
        serde_json::to_value(&once).unwrap(),
        serde_json::to_value(&twice).unwrap(),
        "redacted export must be idempotent"
    );
}

/// Negative detection: neither AppX-looking plain text nor an unrelated provider
/// writing to a Store-looking channel may become Store evidence.
#[test]
fn store_looking_text_and_foreign_providers_are_not_store_evidence() {
    let analysis = assert_scenario("negative-store-looking-text");
    assert!(analysis.transactions.is_empty());
    assert!(analysis.observations.is_empty());
    assert_eq!(analysis.coverage.len(), 2);
}

// ── Cross-cutting contract ──────────────────────────────────────────────────

#[test]
fn every_transaction_in_every_scenario_states_an_installer_family() {
    for scenario in SCENARIOS {
        let (analysis, _) = load_scenario(scenario);
        for transaction in &analysis.transactions {
            let value = serde_json::to_value(transaction).unwrap();
            assert!(
                value["installerFamily"].is_string(),
                "{scenario}/{}: installer family is not stated",
                transaction.transaction_id
            );
        }
    }
}

#[test]
fn every_finding_in_every_scenario_cites_evidence_or_a_gap() {
    for scenario in SCENARIOS {
        let (analysis, _) = load_scenario(scenario);
        for finding in &analysis.findings {
            assert!(
                finding.is_evidence_backed(),
                "{scenario}: finding {} cites nothing",
                finding.finding_id
            );
        }
    }
}

#[test]
fn every_cited_evidence_reference_names_a_declared_artifact() {
    for scenario in SCENARIOS {
        let (analysis, _) = load_scenario(scenario);
        let declared = analysis
            .coverage
            .iter()
            .map(|entry| entry.artifact_id.as_str())
            .collect::<BTreeSet<_>>();
        for finding in &analysis.findings {
            for reference in &finding.evidence {
                assert!(
                    declared.contains(reference.source_artifact_id.as_str()),
                    "{scenario}: finding {} cites undeclared artifact {}",
                    finding.finding_id,
                    reference.source_artifact_id
                );
            }
            for gap in &finding.coverage_gap_ids {
                assert!(
                    declared.contains(gap.as_str()),
                    "{scenario}: finding {} names undeclared gap {gap}",
                    finding.finding_id
                );
            }
        }
    }
}

#[test]
fn analysis_serialization_is_camel_case_and_stable() {
    let (analysis, _) = load_scenario("user-context-uwp-install-success");
    let value = serde_json::to_value(&analysis).unwrap();
    for key in [
        "schemaVersion",
        "transactions",
        "observations",
        "unkeyedObservations",
        "coverage",
        "findings",
    ] {
        assert!(value.get(key).is_some(), "missing top-level key {key}");
    }
    for key in [
        "transactionId",
        "appId",
        "identity",
        "installerFamily",
        "familyBasis",
        "executionContext",
        "action",
        "intent",
        "lastConfirmedPhase",
        "state",
        "error",
        "confidence",
        "hasIntuneIntent",
        "hasDeviceEvidence",
        "unknownVersionObserved",
        "observations",
        "evidence",
        "nextEvidenceRequest",
    ] {
        assert!(
            value["transactions"][0].get(key).is_some(),
            "missing transaction key {key}"
        );
    }
}

/// A record with no source-stated offset must not report a normalized UTC value,
/// because the only one available would come from the parsing machine's
/// timezone and the golden below would then differ per developer machine.
#[test]
fn ime_timestamps_never_invent_an_offset_the_record_did_not_state() {
    let (analysis, _) = load_scenario("user-context-uwp-install-success");
    for observation in &analysis.observations {
        let Some(timestamp) = &observation.context.source_timestamp else {
            continue;
        };
        assert!(
            !timestamp.raw_text.is_empty(),
            "raw timestamp text must always survive"
        );
        if timestamp.original_offset.is_none() {
            assert!(
                timestamp.normalized_utc.is_none(),
                "{} invented a UTC value from a record with no offset",
                observation.observation_id
            );
        }
    }
}

/// Full golden of the redacted export for one representative scenario.
///
/// Regenerate with `UPDATE_STORE_GOLDEN=1 cargo test --locked -p
/// cmtraceopen-parser --test intune_windows_microsoft_store` and review the diff.
#[test]
fn redacted_export_matches_the_golden() {
    let scenario = "user-context-uwp-install-success";
    let (analysis, _) = load_scenario(scenario);
    let actual = serde_json::to_string_pretty(&redacted_export_projection(&analysis))
        .expect("serialize")
        + "\n";

    let golden = scenario_root(scenario).join("expected-full.json");
    if std::env::var("UPDATE_STORE_GOLDEN").is_ok() {
        fs::write(&golden, &actual).expect("write golden");
        return;
    }
    let expected = fs::read_to_string(&golden).expect("golden must exist; see this test's docs");
    assert_eq!(actual, expected, "redacted export golden drifted");
}
