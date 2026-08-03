//! Fixture matrix for `intune::enrollment::windows::autopilot` (issue #362).
//!
//! Two layers, deliberately kept apart:
//!
//! 1. The shared harness in `tests/support/` validates everything every Intune
//!    corpus shares: manifest envelope, path safety, byte-count truth, evidence
//!    closure, the synthetic marker, coverage/capture-state binding, and the
//!    privacy scan. That is not re-implemented here.
//! 2. This file owns the Autopilot semantics: which outcome each scenario must
//!    reduce to, how far the phase got, whether ESP linkage was earned by an
//!    explicit key, and what the export may not leak.
//!
//! Expectations live in each scenario's `expected.json` rather than in inline
//! snapshots, so a reviewer reads the contract next to the evidence that
//! produced it. The `findings` array is the one golden section; regenerate it
//! with `UPDATE_AUTOPILOT_FINDINGS=1` and review the diff. The hand-written
//! `findingIds` list is asserted against it, so a careless regeneration cannot
//! quietly change which rules fire.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::enrollment::windows::autopilot::{
    redacted_export_projection, reduce_autopilot_bundle, AutopilotBundleInput,
    AutopilotCaptureMetadata, AutopilotCaptureState, AutopilotSnapshot, AutopilotSourceInput,
};
use serde_json::{json, Value};
use support::{corpus_root, load_json, mutated, scenario_names, validate_scenario, Failures};

/// The corpus this leaf owns.
const CORPUS: &str = "enrollment/windows/autopilot";

/// The required fixture matrix from issue #362, pinned so a scenario cannot be
/// dropped or silently renamed. Asserted against the directory listing below.
const SCENARIOS: [&str; 15] = [
    "completed-without-esp-bundle",
    "conflicting-profile-session-identifiers",
    "deterministic-identity-redaction",
    "identity-registration-mismatch",
    "incomplete-event-channel",
    "invalid-timezone",
    "malformed-report-section",
    "matching-autopilot-and-esp-session",
    "network-retry-without-terminal-proof",
    "no-profile-candidate",
    "profile-application-failure",
    "profile-retrieval-failure",
    "self-deploying-source-contract-not-captured",
    "unknown-windows-schema-version",
    "user-driven-success-through-esp-handoff",
];

fn scenario_root(scenario: &str) -> PathBuf {
    corpus_root(CORPUS).join(scenario)
}

fn capture_state(raw: &str) -> AutopilotCaptureState {
    serde_json::from_value(Value::String(raw.to_owned()))
        .unwrap_or_else(|error| panic!("captureState {raw:?} is a known state: {error}"))
}

fn optional_string(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

/// Build the reducer input from a scenario's manifest and evidence on disk.
///
/// This is the only place the test touches the filesystem: the crate itself is
/// wasm32-clean and never reads a file.
fn bundle(scenario: &str) -> AutopilotBundleInput {
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));

    let capture = &manifest["capture"];
    let sources = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts must be an array")
        .iter()
        .map(|artifact| AutopilotSourceInput {
            artifact_id: artifact["artifactId"]
                .as_str()
                .expect("artifactId")
                .to_owned(),
            family: artifact["family"].as_str().unwrap_or_default().to_owned(),
            capture_state: capture_state(artifact["captureState"].as_str().expect("captureState")),
            original_basename: optional_string(&artifact["originalBasename"]),
            sanitized_source_path: optional_string(&artifact["sanitizedSourcePath"]),
            content: artifact["relativePath"].as_str().map(|relative| {
                std::fs::read_to_string(root.join(relative))
                    .unwrap_or_else(|error| panic!("{relative} is readable: {error}"))
            }),
            ..AutopilotSourceInput::default()
        })
        .collect();

    AutopilotBundleInput {
        generated_at_utc: manifest["generatedAtUtc"]
            .as_str()
            .expect("generatedAtUtc")
            .to_owned(),
        capture: AutopilotCaptureMetadata {
            collected_at_utc: optional_string(&capture["collectedAtUtc"]),
            windows_build: optional_string(&capture["windowsBuild"]),
            autopilot_schema_version: optional_string(&capture["autopilotSchemaVersion"]),
            timezone: optional_string(&capture["timezone"]),
        },
        sources,
        events: Vec::new(),
    }
}

fn reduce(scenario: &str) -> (AutopilotSnapshot, Value) {
    let expected = load_json(&scenario_root(scenario).join("expected.json"));
    (reduce_autopilot_bundle(&bundle(scenario)), expected)
}

fn wire(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("snapshot must serialize")
}

// ── The shared contract ─────────────────────────────────────────────────────

#[test]
fn the_corpus_contains_exactly_the_required_fixture_matrix() {
    assert_eq!(
        scenario_names(&corpus_root(CORPUS)),
        SCENARIOS.map(str::to_owned).to_vec(),
        "issue #362 pins this matrix; adding or dropping a scenario is a contract change"
    );
}

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
    failures.assert_empty("autopilot corpus");
}

/// The harness must actually reject a corrupted copy of this corpus, not merely
/// pass over the clean one.
#[test]
fn a_corrupted_byte_count_in_this_corpus_is_rejected() {
    let scenario = "no-profile-candidate";
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
        "expected a bytesCopied failure, got {:?}",
        failures.entries()
    );
}

// ── Autopilot semantics ─────────────────────────────────────────────────────

/// Assert one scenario's reduction against its stated contract.
fn assert_scenario(scenario: &str) -> AutopilotSnapshot {
    let (snapshot, expected) = reduce(scenario);
    let value = wire(&snapshot);
    let at = scenario;

    for (pointer, key) in [
        ("/outcome", "outcome"),
        ("/phase", "phase"),
        ("/confidence", "confidence"),
        ("/timezoneState", "timezoneState"),
        ("/timeBasis", "timeBasis"),
    ] {
        assert_eq!(
            value.pointer(pointer).unwrap_or(&Value::Null),
            &expected[key],
            "{at}: {key}"
        );
    }
    assert_eq!(
        value["identity"]["registrationState"], expected["registrationState"],
        "{at}: registrationState"
    );
    assert_eq!(
        value["profile"]["candidateState"], expected["profileCandidateState"],
        "{at}: profileCandidateState"
    );
    assert_eq!(
        value["profile"]["retrieved"], expected["profileRetrieved"],
        "{at}: profileRetrieved"
    );
    assert_eq!(
        value["profile"]["applied"], expected["profileApplied"],
        "{at}: profileApplied"
    );

    // ESP stays a sibling: the snapshot records how the two bind and nothing
    // about what ESP itself concluded.
    assert_eq!(
        value["espLinkage"]["state"], expected["espLinkState"],
        "{at}: espLinkState"
    );
    assert_eq!(
        value["espLinkage"]["confidence"], expected["espLinkConfidence"],
        "{at}: espLinkConfidence"
    );
    assert_eq!(
        value["espLinkage"]["espSessionIds"], expected["espSessionIds"],
        "{at}: espSessionIds"
    );
    assert_eq!(
        snapshot
            .esp_linkage
            .matched_keys
            .iter()
            .map(|key| wire(&key.kind))
            .collect::<Value>(),
        expected["matchedKeyKinds"],
        "{at}: matched correlation key kinds"
    );

    assert_eq!(
        snapshot
            .conflicts
            .iter()
            .map(|conflict| Value::String(conflict.conflict_id.clone()))
            .collect::<Value>(),
        expected["conflictIds"],
        "{at}: conflictIds"
    );

    for document in &snapshot.documents {
        let want = &expected["documentParseStates"][&document.artifact_id];
        assert!(
            !want.is_null(),
            "{at}: document {} has no expected parse state",
            document.artifact_id
        );
        assert_eq!(
            wire(&document.parse_state),
            *want,
            "{at}: parse state for {}",
            document.artifact_id
        );
    }
    assert_eq!(
        snapshot.documents.len(),
        expected["documentParseStates"]
            .as_object()
            .expect("documentParseStates")
            .len(),
        "{at}: every expected document must be reported"
    );

    assert_eq!(
        snapshot.unclassified_observation_ids.len() as u64,
        expected["unclassifiedObservationCount"]
            .as_u64()
            .expect("unclassifiedObservationCount"),
        "{at}: unclassified observation count"
    );

    assert_coverage_matches_manifest(at, &snapshot, &expected);
    assert_findings(at, &snapshot, &expected);

    // The invariant every leaf of epic #356 owes: no uncited conclusions.
    assert!(
        snapshot.findings_are_evidence_backed(),
        "{at}: a finding cited neither evidence nor a coverage gap"
    );

    snapshot
}

fn assert_coverage_matches_manifest(at: &str, snapshot: &AutopilotSnapshot, expected: &Value) {
    let actual = snapshot
        .coverage
        .iter()
        .map(|entry| json!({ "artifactId": entry.artifact_id, "status": wire(&entry.status) }))
        .collect::<Value>();
    assert_eq!(actual, expected["coverage"], "{at}: coverage");
}

fn assert_findings(at: &str, snapshot: &AutopilotSnapshot, expected: &Value) {
    let actual_ids = snapshot
        .findings
        .iter()
        .map(|finding| Value::String(finding.finding_id.clone()))
        .collect::<Value>();
    assert_eq!(actual_ids, expected["findingIds"], "{at}: findingIds");

    let golden = expected["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("{at}: expected.json must carry a findings array"));
    assert_eq!(
        golden.len(),
        snapshot.findings.len(),
        "{at}: findings golden is stale; regenerate with UPDATE_AUTOPILOT_FINDINGS=1"
    );
    for (actual, want) in snapshot.findings.iter().zip(golden) {
        assert_eq!(
            wire(actual),
            *want,
            "{at}: finding {} drifted from its golden",
            actual.finding_id
        );
    }
}

// ── The required fixture matrix ─────────────────────────────────────────────

#[test]
fn user_driven_success_reaches_the_esp_handoff_and_links_by_an_explicit_key() {
    let snapshot = assert_scenario("user-driven-success-through-esp-handoff");
    assert_eq!(
        snapshot.oobe.settings.len(),
        1,
        "the OOBE settings override must be retained as a typed fact"
    );
    assert_eq!(
        snapshot.profile.profile_id.as_deref(),
        Some("11111111-2222-3333-4444-555555555555")
    );
}

/// Issue #362 explicitly defers self-deploying and pre-provisioning "only after
/// its actual source contract is captured". Until then the honest reduction is
/// a refusal, not a guess -- so this fixture asserts the refusal.
#[test]
fn a_self_deploying_sample_without_a_captured_source_contract_asserts_nothing_terminal() {
    let snapshot = assert_scenario("self-deploying-source-contract-not-captured");
    assert!(
        snapshot
            .documents
            .iter()
            .any(|document| document.declared_kind.as_deref()
                == Some("autopilot.selfDeployingContract")),
        "the unvalidated document's declared kind must survive verbatim"
    );
}

#[test]
fn no_profile_candidate_outranks_the_transient_lookup_that_preceded_it() {
    assert_scenario("no-profile-candidate");
}

#[test]
fn profile_retrieval_failure_is_distinct_from_having_no_candidate() {
    let snapshot = assert_scenario("profile-retrieval-failure");
    assert_eq!(
        snapshot
            .profile
            .error
            .as_ref()
            .map(|error| error.raw.as_str()),
        Some("0x80072EE2"),
        "the reported code must survive in the form the source wrote it"
    );
}

#[test]
fn profile_application_failure_keeps_retrieval_marked_as_succeeded() {
    assert_scenario("profile-application-failure");
}

#[test]
fn an_identity_mismatch_outranks_every_downstream_profile_symptom() {
    assert_scenario("identity-registration-mismatch");
}

#[test]
fn a_network_symptom_without_a_proven_cause_stays_low_confidence() {
    let snapshot = assert_scenario("network-retry-without-terminal-proof");
    let finding = snapshot
        .findings
        .iter()
        .find(|finding| finding.finding_id == "autopilot-network-symptom-without-cause")
        .expect("the symptom finding must be present");
    assert_eq!(
        wire(&finding.confidence),
        json!("low"),
        "a symptom with no proven cause may never be presented confidently"
    );
}

#[test]
fn reaching_the_handoff_without_esp_evidence_is_not_a_completed_deployment() {
    assert_scenario("completed-without-esp-bundle");
}

#[test]
fn one_explicit_shared_identifier_links_autopilot_to_an_esp_session() {
    let snapshot = assert_scenario("matching-autopilot-and-esp-session");
    assert_eq!(snapshot.esp_linkage.matched_keys.len(), 1);
}

#[test]
fn contradictory_identifiers_suppress_every_terminal_claim() {
    assert_scenario("conflicting-profile-session-identifiers");
}

#[test]
fn a_capped_channel_cannot_support_a_negative_conclusion() {
    assert_scenario("incomplete-event-channel");
}

#[test]
fn a_malformed_report_section_is_a_coverage_gap_not_an_unknown_schema() {
    assert_scenario("malformed-report-section");
}

#[test]
fn an_unvalidated_windows_build_withholds_terminal_semantics_but_keeps_the_phase() {
    assert_scenario("unknown-windows-schema-version");
}

#[test]
fn an_unrecognizable_timezone_downgrades_the_time_basis() {
    assert_scenario("invalid-timezone");
}

#[test]
fn the_redacted_export_removes_identity_while_preserving_correlation() {
    let scenario = "deterministic-identity-redaction";
    let snapshot = assert_scenario(scenario);
    let expected = load_json(&scenario_root(scenario).join("expected.json"));

    let redacted = redacted_export_projection(&snapshot);
    let text = serde_json::to_string(&wire(&redacted)).expect("redacted export must serialize");

    for needle in expected["redactionMustNotContain"]
        .as_array()
        .expect("redactionMustNotContain")
    {
        let needle = needle.as_str().expect("needle");
        assert!(
            !text.contains(needle),
            "{scenario}: redacted export still contains {needle:?}"
        );
    }
    for needle in expected["redactionMustContain"]
        .as_array()
        .expect("redactionMustContain")
    {
        let needle = needle.as_str().expect("needle");
        assert!(
            text.contains(needle),
            "{scenario}: redacted export dropped {needle:?}, which is the only handle back to Intune"
        );
    }

    // The masked correlation key must still equal the masked value it came
    // from; otherwise redaction would destroy the very link it is exported to
    // show.
    let masked_key = &redacted.esp_linkage.matched_keys[0].value;
    assert!(
        masked_key.starts_with('['),
        "the correlation key must be masked, got {masked_key}"
    );
    assert_eq!(
        redacted.esp_linkage.matched_keys,
        redacted_export_projection(&snapshot)
            .esp_linkage
            .matched_keys,
        "masking must be a pure function of the value"
    );
}

// ── Cross-cutting contract ──────────────────────────────────────────────────

#[test]
fn reduction_is_deterministic_across_runs() {
    for scenario in SCENARIOS {
        let first = wire(&reduce_autopilot_bundle(&bundle(scenario)));
        let second = wire(&reduce_autopilot_bundle(&bundle(scenario)));
        assert_eq!(first, second, "{scenario}: reduction must be deterministic");
    }
}

#[test]
fn the_redacted_export_projection_is_idempotent() {
    for scenario in SCENARIOS {
        let snapshot = reduce_autopilot_bundle(&bundle(scenario));
        let once = redacted_export_projection(&snapshot);
        let twice = redacted_export_projection(&once);
        assert_eq!(
            wire(&once),
            wire(&twice),
            "{scenario}: redaction must be idempotent"
        );
    }
}

#[test]
fn the_snapshot_serializes_as_stable_camel_case() {
    let snapshot = reduce_autopilot_bundle(&bundle("user-driven-success-through-esp-handoff"));
    let value = wire(&snapshot);
    for key in [
        "schemaVersion",
        "generatedAtUtc",
        "capture",
        "timezoneState",
        "timeBasis",
        "identity",
        "profile",
        "oobe",
        "handoff",
        "espLinkage",
        "phase",
        "outcome",
        "confidence",
        "nextEvidenceRequests",
        "observations",
        "unclassifiedObservationIds",
        "documents",
        "conflicts",
        "coverage",
        "findings",
    ] {
        assert!(value.get(key).is_some(), "missing top-level key {key}");
    }
}

/// Every finding must name a concrete next artifact, and every scenario that is
/// not already complete must ask for something. A diagnosis that cannot say
/// what to collect next is not actionable.
#[test]
fn every_finding_recommends_at_least_one_concrete_check() {
    for scenario in SCENARIOS {
        let snapshot = reduce_autopilot_bundle(&bundle(scenario));
        for finding in &snapshot.findings {
            assert!(
                !finding.recommended_checks.is_empty(),
                "{scenario}: finding {} recommends nothing",
                finding.finding_id
            );
        }
        if snapshot.outcome != cmtraceopen_parser::intune::enrollment::windows::autopilot::AutopilotOutcome::Completed {
            assert!(
                !snapshot.next_evidence_requests.is_empty(),
                "{scenario}: an incomplete diagnosis must name the next artifact"
            );
        }
    }
}

/// Observation ids must be unique across a bundle, or a finding's citation
/// becomes ambiguous.
#[test]
fn observation_ids_are_unique_within_a_bundle() {
    for scenario in SCENARIOS {
        let snapshot = reduce_autopilot_bundle(&bundle(scenario));
        let mut seen = BTreeSet::new();
        for observation in &snapshot.observations {
            assert!(
                seen.insert(observation.observation_id.as_str()),
                "{scenario}: observation id {} was reused",
                observation.observation_id
            );
        }
    }
}

/// Records from a channel this module does not own must not become Autopilot
/// evidence, however plausible they look. A busy device would otherwise report
/// a worse diagnosis than a quiet one.
#[test]
fn records_from_a_sibling_channel_are_ignored_entirely() {
    let mut input = bundle("no-profile-candidate");
    let intruder = std::fs::read_to_string(
        scenario_root("no-profile-candidate")
            .join("evidence/autopilot-channel/current/autopilot-events.json"),
    )
    .expect("evidence is readable")
    .replace(
        "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot",
        "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService",
    );
    input.sources.push(AutopilotSourceInput {
        artifact_id: "sibling-channel".to_owned(),
        family: "managementService".to_owned(),
        capture_state: AutopilotCaptureState::Captured,
        original_basename: Some("management-service.json".to_owned()),
        sanitized_source_path: None,
        content: Some(intruder),
        ..AutopilotSourceInput::default()
    });

    let snapshot = reduce_autopilot_bundle(&input);
    let baseline = reduce_autopilot_bundle(&bundle("no-profile-candidate"));
    assert_eq!(
        snapshot.observations.len(),
        baseline.observations.len(),
        "a sibling channel's records must not become Autopilot observations"
    );
    assert_eq!(snapshot.outcome, baseline.outcome);
    assert!(
        snapshot.unclassified_observation_ids.is_empty(),
        "an unrelated channel must not even register as unclassified Autopilot evidence"
    );
}

// ── Golden maintenance ──────────────────────────────────────────────────────

/// Rewrite every scenario's `findings` golden from the current reducer output.
///
/// Runs only under `UPDATE_AUTOPILOT_FINDINGS=1`, and is a no-op otherwise so
/// the suite stays read-only in CI. The rewrite touches the `findings` key and
/// nothing else, so the hand-written semantic expectations survive and keep
/// cross-checking the regenerated goldens.
#[test]
fn update_findings_golden() {
    if std::env::var("UPDATE_AUTOPILOT_FINDINGS").is_err() {
        return;
    }
    for scenario in SCENARIOS {
        let snapshot = reduce_autopilot_bundle(&bundle(scenario));
        let path = scenario_root(scenario).join("expected.json");
        let mut expected = load_json(&path);
        // Only `findings` is regenerated. `findingIds` stays hand written on
        // purpose: it is the cross-check that catches a regeneration which
        // quietly changed which rules fire.
        expected["findings"] = wire(&snapshot.findings);
        write_json(&path, &expected);
    }
}

fn write_json(path: &Path, value: &Value) {
    let text = serde_json::to_string_pretty(value).expect("golden must serialize") + "\n";
    std::fs::write(path, text)
        .unwrap_or_else(|error| panic!("{} is writable: {error}", path.display()));
}
