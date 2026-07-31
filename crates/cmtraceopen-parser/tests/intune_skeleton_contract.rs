//! Contract tests for the Intune parser-family skeleton (epic #356).
//!
//! Two jobs:
//!
//! 1. Prove the shared harness in `tests/support/` actually rejects what it
//!    claims to reject. Fifteen workload leaves will depend on it, so a validator
//!    that silently passes everything would be worse than no validator.
//! 2. Pin the reference corpus layout that those leaves copy.

mod support;

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use support::{
    load_json, mutated, privacy_problems, scenario_names, validate_scenario, Failures,
    SYNTHETIC_MARKER,
};

fn reference_root() -> PathBuf {
    support::corpus_root("_skeleton").join("reference-scenario")
}

fn reference_pair() -> (Value, Value) {
    let root = reference_root();
    (
        load_json(&root.join("manifest.json")),
        load_json(&root.join("expected.json")),
    )
}

fn validate(root: &Path, manifest: &Value, expected: &Value) -> Failures {
    validate_scenario("reference-scenario", root, manifest, expected)
}

#[test]
fn reference_scenario_satisfies_the_shared_contract() {
    let (manifest, expected) = reference_pair();
    validate(&reference_root(), &manifest, &expected).assert_empty("reference scenario");
}

#[test]
fn skeleton_corpus_exposes_exactly_the_reference_scenario() {
    assert_eq!(
        scenario_names(&support::corpus_root("_skeleton")),
        vec!["reference-scenario".to_owned()],
    );
}

// ── Adversarial mutations: each must be rejected ────────────────────────────

fn assert_rejected(mutation: &str, manifest: &Value, expected: &Value, needle: &str) {
    let failures = validate(&reference_root(), manifest, expected);
    assert!(
        !failures.is_empty(),
        "{mutation}: validator accepted a corpus it should have rejected"
    );
    assert!(
        failures.entries().iter().any(|entry| entry.contains(needle)),
        "{mutation}: expected a failure mentioning {needle:?}, got {:?}",
        failures.entries()
    );
}

#[test]
fn wrong_manifest_version_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "manifest version",
        &mutated(&manifest, "/intuneManifestVersion", json!(2)),
        &expected,
        "intuneManifestVersion",
    );
}

#[test]
fn dropping_the_synthetic_fixture_flag_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "synthetic flag",
        &mutated(&manifest, "/syntheticFixture", json!(false)),
        &expected,
        "syntheticFixture",
    );
}

#[test]
fn scenario_name_drift_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "scenario name",
        &mutated(&manifest, "/scenario", json!("something-else")),
        &expected,
        "manifest scenario",
    );
}

#[test]
fn a_byte_count_that_disagrees_with_the_file_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "byte count",
        &mutated(&manifest, "/artifacts/0/bytesCopied", json!(999)),
        &expected,
        "bytesCopied",
    );
}

#[test]
fn an_absent_artifact_claiming_a_file_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "absent artifact with a path",
        &mutated(
            &manifest,
            "/artifacts/1/relativePath",
            json!("evidence/skeleton-ime/current/IntuneManagementExtension.log"),
        ),
        &expected,
        "relativePath null",
    );
}

#[test]
fn a_captured_artifact_pointing_outside_evidence_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
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
fn a_captured_artifact_outside_the_evidence_directory_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "non-evidence root",
        &mutated(&manifest, "/artifacts/0/relativePath", json!("manifest.json")),
        &expected,
        "evidence directory",
    );
}

#[test]
fn a_missing_evidence_file_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "missing file",
        &mutated(
            &manifest,
            "/artifacts/0/relativePath",
            json!("evidence/skeleton-ime/current/NotThere.log"),
        ),
        &expected,
        "does not exist",
    );
}

#[test]
fn an_unknown_capture_state_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "capture state",
        &mutated(&manifest, "/artifacts/0/captureState", json!("probably")),
        &expected,
        "captureState",
    );
}

#[test]
fn a_duplicate_artifact_id_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "duplicate id",
        &mutated(
            &manifest,
            "/artifacts/1/artifactId",
            json!("skeleton-ime-current"),
        ),
        &expected,
        "duplicate artifactId",
    );
}

#[test]
fn coverage_that_omits_a_manifest_artifact_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "coverage omission",
        &manifest,
        &mutated(&expected, "/coverage", json!([])),
        "no coverage entry",
    );
}

#[test]
fn coverage_naming_an_undeclared_artifact_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "coverage overreach",
        &manifest,
        &mutated(
            &expected,
            "/coverage/0/artifactId",
            json!("never-declared"),
        ),
        "which no manifest artifact declares",
    );
}

#[test]
fn a_finding_citing_neither_evidence_nor_a_coverage_gap_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "uncited finding",
        &manifest,
        &mutated(&expected, "/findings/0/coverageGapIds", json!([])),
        "cites neither evidence nor a coverage gap",
    );
}

// ── Privacy scanner ─────────────────────────────────────────────────────────

#[test]
fn privacy_scanner_flags_forbidden_material() {
    for (label, sample) in [
        ("user path", "opened C:\\Users\\adam\\file.log"),
        ("bearer token", "Authorization: Bearer abc.def.ghi"),
        ("client secret", "client_secret=hunter2"),
        ("sid", "owner S-1-5-21-1004336348-1177238915-682003330-512"),
        ("email", "signed in as real.person@contoso.com"),
        ("private key", "-----BEGIN PRIVATE KEY-----"),
    ] {
        assert!(
            !privacy_problems("sample", sample).is_empty(),
            "privacy scanner missed {label}"
        );
    }
}

#[test]
fn privacy_scanner_allows_reserved_synthetic_domains() {
    assert!(
        privacy_problems("sample", "user synthetic.user@example.invalid signed in").is_empty(),
        "reserved .invalid domains are the documented way to write a synthetic identity"
    );
}

#[test]
fn reference_evidence_carries_the_synthetic_marker() {
    let evidence =
        reference_root().join("evidence/skeleton-ime/current/IntuneManagementExtension.log");
    let contents = std::fs::read_to_string(&evidence).expect("reference evidence is readable");
    assert!(
        contents
            .lines()
            .next()
            .unwrap_or_default()
            .contains(SYNTHETIC_MARKER),
        "the first line of every evidence file must contain {SYNTHETIC_MARKER:?}"
    );
}
