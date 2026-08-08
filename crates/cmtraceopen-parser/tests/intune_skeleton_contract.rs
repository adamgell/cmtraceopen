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

#[test]
fn coverage_status_contradicting_the_capture_state_is_rejected() {
    // The manifest declares skeleton-appworkload-absent as absent. Claiming it
    // was available is self-declared contract drift: the corpus would assert
    // coverage it never had, and any finding citing that entry inherits the lie.
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "coverage status drift",
        &manifest,
        &mutated(&expected, "/coverage/1/status", json!("available")),
        "requires coverage status",
    );
}

#[test]
fn a_missing_coverage_status_is_rejected() {
    let (manifest, expected) = reference_pair();
    assert_rejected(
        "absent coverage status",
        &manifest,
        &mutated(&expected, "/coverage/0/status", json!(null)),
        "requires coverage status",
    );
}

#[test]
fn parse_failed_artifacts_may_carry_evidence() {
    // parseFailed means the artifact was collected and could not be interpreted,
    // so the malformed bytes are the point. Epic #356 requires a malformed
    // scenario from every child issue; forcing parseFailed to have no file made
    // that shape inexpressible.
    let (manifest, expected) = reference_pair();
    let manifest = mutated(&manifest, "/artifacts/0/captureState", json!("parseFailed"));
    let expected = mutated(&expected, "/coverage/0/status", json!("parseFailed"));
    validate(&reference_root(), &manifest, &expected)
        .assert_empty("parseFailed artifact with real evidence");
}

#[test]
fn parse_failed_without_evidence_is_still_rejected() {
    let (manifest, expected) = reference_pair();
    let manifest = mutated(&manifest, "/artifacts/1/captureState", json!("parseFailed"));
    let expected = mutated(&expected, "/coverage/1/status", json!("parseFailed"));
    assert_rejected(
        "parseFailed with no file",
        &manifest,
        &expected,
        "requires a relativePath",
    );
}

// ── Privacy scanner ─────────────────────────────────────────────────────────

#[test]
fn privacy_scanner_flags_forbidden_material() {
    for (label, sample) in [
        ("user path", "opened C:\\Users\\adam\\file.log"),
        // JSON-escaped form: this is how a Windows path is necessarily written
        // inside manifest.json, and the literal-only check never matched it.
        (
            "json-escaped user path",
            r#"{"path":"C:\\Users\\adam\\file.log"}"#,
        ),
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
fn privacy_scanner_flags_emails_joined_by_delimiters() {
    // A semicolon-joined recipient list is the shape a pasted mail header has.
    // Splitting only on whitespace made the whole run one token, whose domain
    // then contained `;` and a second `@`, so both real addresses slipped through.
    for sample in [
        "user1@corp.com;user2@corp.com",
        "to:person@corp.com",
        "<person@corp.com>",
        "owner=person@corp.com|next",
        "[person@corp.com]",
    ] {
        assert!(
            !privacy_problems("sample", sample).is_empty(),
            "privacy scanner missed an email in {sample:?}"
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
#[cfg(unix)]
fn a_symlink_escaping_the_scenario_is_rejected() {
    // The component check is lexical, so without target resolution a symlink
    // under evidence/ reads host files and the privacy scan runs against content
    // that is not in the corpus at all.
    use std::os::unix::fs::symlink;

    let temp = std::env::temp_dir().join(format!(
        "cmtrace-symlink-escape-{}",
        std::process::id()
    ));
    let scenario = temp.join("escape");
    let evidence = scenario.join("evidence/skeleton-ime/current");
    std::fs::create_dir_all(&evidence).expect("scratch scenario is creatable");

    let outside = temp.join("outside.log");
    std::fs::write(&outside, "SYNTHETIC FIXTURE outside the corpus\n")
        .expect("outside file is writable");
    let link = evidence.join("IntuneManagementExtension.log");
    let _ = std::fs::remove_file(&link);
    symlink(&outside, &link).expect("symlink is creatable");

    let bytes = std::fs::metadata(&link).expect("link target metadata").len();
    let manifest = json!({
        "intuneManifestVersion": 1,
        "syntheticFixture": true,
        "scenario": "escape",
        "artifacts": [{
            "artifactId": "escaping",
            "captureState": "captured",
            "relativePath": "evidence/skeleton-ime/current/IntuneManagementExtension.log",
            "bytesCopied": bytes,
        }],
    });
    let expected = json!({
        "scenario": "escape",
        "coverage": [{ "artifactId": "escaping", "status": "available" }],
        "findings": [],
    });

    let failures = validate_scenario("escape", &scenario, &manifest, &expected);
    let outside_rejected = failures
        .entries()
        .iter()
        .any(|entry| entry.contains("outside the scenario directory"));

    std::fs::remove_dir_all(&temp).ok();
    assert!(
        outside_rejected,
        "a symlink resolving outside the scenario must be rejected, got {:?}",
        failures.entries()
    );
}

#[test]
fn descriptor_files_are_privacy_scanned() {
    // manifest.json and expected.json are hand written and carry the free-text
    // fields where a real path or identity gets typed by mistake. Scanning only
    // the evidence left the likeliest leak unchecked.
    let scenario = std::env::temp_dir().join(format!(
        "cmtrace-descriptor-privacy-{}/leaky",
        std::process::id()
    ));
    std::fs::create_dir_all(&scenario).expect("scratch scenario is creatable");
    std::fs::write(
        scenario.join("manifest.json"),
        r#"{"sanitizedSourcePath":"C:\\Users\\jsmith\\AppData\\Local\\app.log"}"#,
    )
    .expect("manifest is writable");
    std::fs::write(scenario.join("expected.json"), r#"{"displayName":"ok"}"#)
        .expect("expected is writable");

    let mut failures = Failures::new();
    support::validate_descriptor_privacy("leaky", &scenario, &[], &mut failures);
    let leaked = failures
        .entries()
        .iter()
        .any(|entry| entry.contains("manifest.json") && entry.contains("forbidden fixture material"));

    std::fs::remove_dir_all(scenario.parent().expect("temp parent")).ok();
    assert!(
        leaked,
        "a user path in manifest.json must be caught, got {:?}",
        failures.entries()
    );
}

#[test]
#[should_panic(expected = "is readable")]
fn a_missing_corpus_directory_panics_rather_than_passing_vacuously() {
    // Returning an empty vec made a misspelled corpus path indistinguishable
    // from an empty corpus, so a loop over scenarios validated nothing and
    // still reported success.
    scenario_names(&support::corpus_root("_skeleton/definitely-not-a-corpus"));
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
