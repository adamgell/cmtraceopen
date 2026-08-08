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
//! alone (never beside the readers of the same files) with
//! `UPDATE_AUTOPILOT_FINDINGS=1 cargo test --test intune_windows_autopilot -- \
//! --ignored update_findings_golden` and review the diff. The hand-written
//! `findingIds` list is asserted against it, so a careless regeneration cannot
//! quietly change which rules fire.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::enrollment::windows::autopilot::{
    redacted_export_projection, reduce_autopilot_bundle, AutopilotBundleInput,
    AutopilotCaptureMetadata, AutopilotCaptureState, AutopilotEspLinkState, AutopilotOutcome,
    AutopilotPhase, AutopilotSnapshot, AutopilotSourceInput,
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

/// The `matched_keys` masking site in `redacted_export_projection` must
/// normalize case on its own, not by riding on `autopilot_keys` happening to
/// lowercase first. Both halves of that contract are pinned here: the reducer
/// hands the projection lowercase key values, and the projection would still
/// mask a mixed-case value to the same token if it ever received one.
#[test]
fn matched_key_masking_normalizes_case_independently_of_the_reducer() {
    let snapshot = reduce_autopilot_bundle(&bundle("matching-autopilot-and-esp-session"));
    let raw = snapshot.esp_linkage.matched_keys[0].value.clone();

    // Contract half 1: reducer-produced key values are already lowercased.
    assert_eq!(
        raw,
        raw.to_ascii_lowercase(),
        "autopilot_keys must lowercase key values before they reach the snapshot"
    );

    let lower_token = redacted_export_projection(&snapshot).esp_linkage.matched_keys[0]
        .value
        .clone();
    assert!(
        lower_token.starts_with("[redacted:"),
        "the matched key must be masked, got {lower_token}"
    );

    // Contract half 2: the masking loop normalizes on its own. Feed it the
    // same key in a casing the reducer never produces and the token must not
    // change -- otherwise the loop is only correct by coincidence.
    let mut mixed = snapshot.clone();
    mixed.esp_linkage.matched_keys[0].value = raw.to_ascii_uppercase();
    let upper_token = redacted_export_projection(&mixed).esp_linkage.matched_keys[0]
        .value
        .clone();
    assert_eq!(
        lower_token, upper_token,
        "the same identifier in two casings must mask to one token at the matched_keys site"
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

// ── Framework hardening: assessability and linkage-conflict gates ───────────
//
// These scenarios are built inline rather than as fixture directories because
// each one isolates a single reducer invariant from ADR-001 or ADR-003; the
// fixture matrix above stays the contract for whole-bundle behavior.

/// One synthetic Autopilot-channel event as a JSON fragment for an
/// `autopilot.events` document. `access_state`/`parse_state` are the
/// observation's own declared context, which is exactly what the assessability
/// gate must consult.
#[allow(clippy::too_many_arguments)]
fn synthetic_event(
    evidence_id: &str,
    artifact_id: &str,
    record: u64,
    event_id: u32,
    access_state: &str,
    parse_state: &str,
    named_data: Value,
    message: &str,
) -> Value {
    json!({
        "context": {
            "evidenceRef": { "evidenceId": evidence_id, "sourceArtifactId": artifact_id },
            "provenance": {
                "sourceKind": "eventLog", "sourceArtifactId": artifact_id,
                "filePath": null, "lineNumber": null, "recordNumber": record,
                "registry": null, "event": null
            },
            "sourceTimestamp": null,
            "observedAtUtc": "2026-07-31T09:30:00Z",
            "sensitivity": "public",
            "parseState": parse_state,
            "accessState": access_state
        },
        "channel": "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot",
        "provider": "Microsoft-Windows-ModernDeployment-Diagnostics-Provider",
        "eventId": event_id,
        "level": "information",
        "task": null, "keywords": null, "recordId": record, "activityId": null,
        "namedData": named_data,
        "message": message
    })
}

fn synthetic_source(artifact_id: &str, family: &str, document: &Value) -> AutopilotSourceInput {
    AutopilotSourceInput {
        artifact_id: artifact_id.to_owned(),
        family: family.to_owned(),
        capture_state: AutopilotCaptureState::Captured,
        original_basename: Some(format!("{artifact_id}.json")),
        sanitized_source_path: None,
        content: Some(document.to_string()),
        ..AutopilotSourceInput::default()
    }
}

fn synthetic_bundle(sources: Vec<AutopilotSourceInput>) -> AutopilotBundleInput {
    AutopilotBundleInput {
        generated_at_utc: "2026-07-31T09:30:00Z".to_owned(),
        capture: AutopilotCaptureMetadata {
            collected_at_utc: Some("2026-07-31T09:30:00Z".to_owned()),
            windows_build: Some("10.0.26100.2314".to_owned()),
            autopilot_schema_version: Some("1".to_owned()),
            timezone: Some("UTC".to_owned()),
        },
        sources,
        events: Vec::new(),
    }
}

/// The espHandoff report section every ADR-001 test below pairs with the
/// success events, so a Completed claim is one gate away if the reducer honors
/// a non-assessable record.
fn esp_handoff_report(artifact_id: &str) -> Value {
    json!({
        "autopilotDocument": "autopilot.mdmDiagnosticsReport",
        "documentVersion": 1,
        "sections": [{
            "context": {
                "evidenceRef": { "evidenceId": "hardening-esp-handoff", "sourceArtifactId": artifact_id },
                "provenance": {
                    "sourceKind": "diagnosticReport", "sourceArtifactId": artifact_id,
                    "filePath": null, "lineNumber": null, "recordNumber": 1,
                    "registry": null, "event": null
                },
                "sourceTimestamp": null,
                "observedAtUtc": "2026-07-31T09:30:00Z",
                "sensitivity": "sensitive",
                "parseState": "parsed",
                "accessState": "available"
            },
            "sectionId": "espHandoff",
            "kind": "espHandoff",
            "outcome": "observed",
            "error": null,
            "values": [],
            "message": "Control passed to the Enrollment Status Page."
        }]
    })
}

/// ADR-001: non-assessable evidence cannot produce a terminal conclusion.
/// A capped success record must not set `retrieved`/`applied`, and must not
/// combine with an observed handoff into `Completed`.
#[test]
fn non_assessable_success_records_cannot_prove_profile_progress() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [
            synthetic_event(
                "gate-e1", "gated-channel", 1, 161, "capped", "parsed",
                json!([]), "AutopilotManager retrieve settings succeeded.",
            ),
            synthetic_event(
                "gate-e2", "gated-channel", 2, 153, "available", "raw",
                json!([]),
                "AutopilotManager reported the state changed from ProfileState_Available to ProfileState_Provisioned.",
            ),
        ]
    });
    let snapshot = reduce_autopilot_bundle(&synthetic_bundle(vec![
        synthetic_source("gated-channel", "autopilotEvents", &events),
        synthetic_source("gated-report", "mdmReport", &esp_handoff_report("gated-report")),
    ]));

    assert!(
        !snapshot.profile.retrieved,
        "a capped record must not prove retrieval"
    );
    assert!(
        !snapshot.profile.applied,
        "an unparsed record must not prove application"
    );
    assert_ne!(
        snapshot.outcome,
        AutopilotOutcome::Completed,
        "non-assessable success evidence must never reach a terminal success"
    );
}

/// One report section as a JSON fragment, with its own declared context.
#[allow(clippy::too_many_arguments)]
fn synthetic_section(
    evidence_id: &str,
    artifact_id: &str,
    section_id: &str,
    kind: &str,
    outcome: &str,
    access_state: &str,
    parse_state: &str,
    message: &str,
) -> Value {
    json!({
        "context": {
            "evidenceRef": { "evidenceId": evidence_id, "sourceArtifactId": artifact_id },
            "provenance": {
                "sourceKind": "diagnosticReport", "sourceArtifactId": artifact_id,
                "filePath": null, "lineNumber": null, "recordNumber": 1,
                "registry": null, "event": null
            },
            "sourceTimestamp": null,
            "observedAtUtc": "2026-07-31T09:30:00Z",
            "sensitivity": "sensitive",
            "parseState": parse_state,
            "accessState": access_state
        },
        "sectionId": section_id,
        "kind": kind,
        "outcome": outcome,
        "error": null,
        "values": [],
        "message": message
    })
}

/// ADR-001, direction-aware: a non-assessable section can never PROVE
/// progress, but one that explicitly RECORDED a failure must still block
/// success. Hiding it entirely would let sibling assessable evidence complete
/// the enrollment at high confidence over a failure that is on record.
///
/// This is the capped-failed-section fixture the corpus lacked: an assessable
/// success path (events 161 + 153, an observed espHandoff section) plus a
/// capped `profileApplication` section whose outcome is `failed`.
#[test]
fn a_recorded_failure_on_a_non_assessable_section_blocks_success() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [
            synthetic_event(
                "blocked-e1", "blocked-channel", 1, 161, "available", "parsed",
                json!([]), "AutopilotManager retrieve settings succeeded.",
            ),
            synthetic_event(
                "blocked-e2", "blocked-channel", 2, 153, "available", "parsed",
                json!([]),
                "AutopilotManager reported the state changed from ProfileState_Available to ProfileState_Provisioned.",
            ),
        ]
    });
    let report = json!({
        "autopilotDocument": "autopilot.mdmDiagnosticsReport",
        "documentVersion": 1,
        "sections": [
            synthetic_section(
                "blocked-handoff", "blocked-report", "espHandoff", "espHandoff",
                "observed", "available", "parsed",
                "Control passed to the Enrollment Status Page.",
            ),
            synthetic_section(
                "blocked-failure", "blocked-report", "profileApplication", "profileApplication",
                "failed", "capped", "parsed",
                "Failed to set the Autopilot profile as available.",
            ),
        ]
    });
    let snapshot = reduce_autopilot_bundle(&synthetic_bundle(vec![
        synthetic_source("blocked-channel", "autopilotEvents", &events),
        synthetic_source("blocked-report", "mdmReport", &report),
    ]));

    assert_ne!(
        snapshot.outcome,
        AutopilotOutcome::Completed,
        "a recorded failure on a capped section must block a completed outcome"
    );
    assert_eq!(
        snapshot.outcome,
        AutopilotOutcome::InsufficientEvidence,
        "non-assessable evidence proves neither the failure nor the success (ADR-001)"
    );
    assert_ne!(
        wire(&snapshot.confidence),
        json!("high"),
        "a success-path bundle carrying a recorded failure may not be presented at high confidence"
    );
    assert!(
        !snapshot.profile.applied || snapshot.outcome != AutopilotOutcome::Completed,
        "assessable progress may survive, but never as a completed enrollment"
    );
    let finding = snapshot
        .findings
        .iter()
        .find(|finding| finding.finding_id == "autopilot-non-assessable-failure-recorded")
        .unwrap_or_else(|| {
            panic!(
                "the recorded-but-unassessable failure must never be silent, got {:?}",
                snapshot
                    .findings
                    .iter()
                    .map(|finding| finding.finding_id.as_str())
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(wire(&finding.confidence), json!("low"));
    assert!(
        finding
            .evidence
            .iter()
            .any(|evidence| evidence.evidence_id == "blocked-failure"),
        "the finding must cite the capped section that recorded the failure"
    );
    assert!(snapshot.findings_are_evidence_backed());
}

/// The same gate must not fire when the failed section is assessable: an
/// assessable failure is the real terminal outcome, not a blocked success.
#[test]
fn an_assessable_failed_section_still_produces_the_terminal_failure() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [synthetic_event(
            "term-e1", "term-channel", 1, 161, "available", "parsed",
            json!([]), "AutopilotManager retrieve settings succeeded.",
        )]
    });
    let report = json!({
        "autopilotDocument": "autopilot.mdmDiagnosticsReport",
        "documentVersion": 1,
        "sections": [synthetic_section(
            "term-failure", "term-report", "profileApplication", "profileApplication",
            "failed", "available", "parsed",
            "Failed to set the Autopilot profile as available.",
        )]
    });
    let snapshot = reduce_autopilot_bundle(&synthetic_bundle(vec![
        synthetic_source("term-channel", "autopilotEvents", &events),
        synthetic_source("term-report", "mdmReport", &report),
    ]));
    assert_eq!(snapshot.outcome, AutopilotOutcome::ProfileApplicationFailure);
    assert!(
        !snapshot
            .findings
            .iter()
            .any(|finding| finding.finding_id == "autopilot-non-assessable-failure-recorded"),
        "an assessable failure is not a non-assessable one"
    );
}

/// ADR-001, same class: a non-assessable record carrying identity keys must
/// not inflate the phase to `IdentityObserved` through the evidence list.
#[test]
fn non_assessable_identity_records_cannot_raise_the_phase() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [synthetic_event(
            "gate-i1", "gated-channel", 1, 161, "capped", "parsed",
            json!([{ "name": "serialNumber", "value": "SYNTH-5CD1234ABC" }]),
            "AutopilotManager retrieve settings succeeded.",
        )]
    });
    let snapshot = reduce_autopilot_bundle(&synthetic_bundle(vec![synthetic_source(
        "gated-channel",
        "autopilotEvents",
        &events,
    )]));

    assert!(
        snapshot.identity.evidence.is_empty(),
        "a non-assessable record may not be cited as identity evidence"
    );
    assert_eq!(
        snapshot.phase,
        AutopilotPhase::NoEvidence,
        "an unreadable record alone must not raise the phase"
    );
}

/// ADR-003: unresolved authoritative contradictions stay conservative. When
/// distinct explicit keys resolve to distinct ESP sessions, the linkage is
/// `Conflicting`; that must surface as `ContradictoryEvidence` with a finding,
/// never as `Completed`.
#[test]
fn a_conflicting_esp_linkage_cannot_report_completed() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [
            synthetic_event(
                "link-e1", "linked-channel", 1, 161, "available", "parsed",
                json!([{ "name": "enrollmentId", "value": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" }]),
                "AutopilotManager retrieve settings succeeded.",
            ),
            synthetic_event(
                "link-e2", "linked-channel", 2, 153, "available", "parsed",
                json!([{ "name": "correlationId", "value": "99999999-8888-7777-6666-555555555555" }]),
                "AutopilotManager reported the state changed from ProfileState_Unknown to ProfileState_Available.",
            ),
        ]
    });
    let sessions = json!({
        "autopilotDocument": "autopilot.espSession",
        "documentVersion": 1,
        "sessions": [
            {
                "sessionId": "esp-session-a",
                "enrollmentId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "correlationId": null, "activityId": null,
                "entraDeviceId": null, "managedDeviceId": null,
                "startedAtUtc": "2026-07-31T09:00:20Z", "phase": "deviceSetup",
                "evidence": { "evidenceId": "esp-a", "sourceArtifactId": "esp-session-facts" }
            },
            {
                "sessionId": "esp-session-b",
                "enrollmentId": null,
                "correlationId": "99999999-8888-7777-6666-555555555555",
                "activityId": null, "entraDeviceId": null, "managedDeviceId": null,
                "startedAtUtc": "2026-07-31T09:00:25Z", "phase": "deviceSetup",
                "evidence": { "evidenceId": "esp-b", "sourceArtifactId": "esp-session-facts" }
            }
        ]
    });
    let snapshot = reduce_autopilot_bundle(&synthetic_bundle(vec![
        synthetic_source("linked-channel", "autopilotEvents", &events),
        synthetic_source("linked-report", "mdmReport", &esp_handoff_report("linked-report")),
        synthetic_source("esp-session-facts", "espSession", &sessions),
    ]));

    assert_eq!(snapshot.esp_linkage.state, AutopilotEspLinkState::Conflicting);
    assert_eq!(
        snapshot.outcome,
        AutopilotOutcome::ContradictoryEvidence,
        "an ambiguous session identity must not be reported as a completed handoff"
    );
    assert!(
        snapshot
            .findings
            .iter()
            .any(|finding| finding.finding_id == "autopilot-esp-link-conflicting"),
        "the conflicting linkage must be explained by a finding, got {:?}",
        snapshot
            .findings
            .iter()
            .map(|finding| finding.finding_id.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        snapshot.findings_are_evidence_backed(),
        "the linkage-conflict finding must cite evidence"
    );
}

/// ADR-003 via ADR-001, the conservative direction for correlation keys: a key
/// carried only by a non-assessable observation must still be USED to DETECT a
/// session-identity conflict. Dropping it can shrink the matched-session set
/// from two to one and collapse Conflicting into Linked into Completed --
/// exactly the silent upgrade the assessability gate exists to prevent.
///
/// This is the capped-key-carrying-observation fixture the corpus lacked: the
/// first ESP session matches an assessable key, the second matches only a key
/// on a capped observation.
#[test]
fn a_key_on_a_capped_observation_still_detects_a_second_esp_session() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [
            synthetic_event(
                "cap-e1", "cap-channel", 1, 161, "available", "parsed",
                json!([{ "name": "enrollmentId", "value": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" }]),
                "AutopilotManager retrieve settings succeeded.",
            ),
            synthetic_event(
                "cap-e2", "cap-channel", 2, 153, "available", "parsed",
                json!([]),
                "AutopilotManager reported the state changed from ProfileState_Available to ProfileState_Provisioned.",
            ),
            synthetic_event(
                "cap-e3", "cap-channel", 3, 161, "capped", "parsed",
                json!([{ "name": "correlationId", "value": "99999999-8888-7777-6666-555555555555" }]),
                "AutopilotManager retrieve settings succeeded.",
            ),
        ]
    });
    let sessions = json!({
        "autopilotDocument": "autopilot.espSession",
        "documentVersion": 1,
        "sessions": [
            {
                "sessionId": "esp-session-a",
                "enrollmentId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "correlationId": null, "activityId": null,
                "entraDeviceId": null, "managedDeviceId": null,
                "startedAtUtc": "2026-07-31T09:00:20Z", "phase": "deviceSetup",
                "evidence": { "evidenceId": "cap-esp-a", "sourceArtifactId": "esp-session-facts" }
            },
            {
                "sessionId": "esp-session-b",
                "enrollmentId": null,
                "correlationId": "99999999-8888-7777-6666-555555555555",
                "activityId": null, "entraDeviceId": null, "managedDeviceId": null,
                "startedAtUtc": "2026-07-31T09:00:25Z", "phase": "deviceSetup",
                "evidence": { "evidenceId": "cap-esp-b", "sourceArtifactId": "esp-session-facts" }
            }
        ]
    });
    let snapshot = reduce_autopilot_bundle(&synthetic_bundle(vec![
        synthetic_source("cap-channel", "autopilotEvents", &events),
        synthetic_source("cap-report", "mdmReport", &esp_handoff_report("cap-report")),
        synthetic_source("esp-session-facts", "espSession", &sessions),
    ]));

    assert_eq!(
        snapshot.esp_linkage.state,
        AutopilotEspLinkState::Conflicting,
        "the capped key's session must still count toward conflict detection"
    );
    assert!(
        snapshot
            .esp_linkage
            .esp_session_ids
            .contains(&"esp-session-b".to_owned()),
        "the session detected through the capped key must be named"
    );
    assert_ne!(
        snapshot.outcome,
        AutopilotOutcome::Completed,
        "dropping the capped key must not collapse Conflicting into Completed"
    );
    assert_eq!(snapshot.outcome, AutopilotOutcome::ContradictoryEvidence);
    assert!(snapshot.findings_are_evidence_backed());
}

/// The other half of the same rule: a linkage whose ONLY explicit key rides a
/// non-assessable observation may not upgrade to a confident Linked. Detection
/// may widen (conservative); proof may not.
#[test]
fn a_non_assessable_only_key_match_cannot_upgrade_to_linked() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [
            synthetic_event(
                "solo-e1", "solo-channel", 1, 161, "available", "parsed",
                json!([]), "AutopilotManager retrieve settings succeeded.",
            ),
            synthetic_event(
                "solo-e2", "solo-channel", 2, 161, "capped", "parsed",
                json!([{ "name": "enrollmentId", "value": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" }]),
                "AutopilotManager retrieve settings succeeded.",
            ),
        ]
    });
    let sessions = json!({
        "autopilotDocument": "autopilot.espSession",
        "documentVersion": 1,
        "sessions": [{
            "sessionId": "esp-session-a",
            "enrollmentId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "correlationId": null, "activityId": null,
            "entraDeviceId": null, "managedDeviceId": null,
            "startedAtUtc": "2026-07-31T09:00:20Z", "phase": "deviceSetup",
            "evidence": { "evidenceId": "solo-esp-a", "sourceArtifactId": "esp-session-facts" }
        }]
    });
    let snapshot = reduce_autopilot_bundle(&synthetic_bundle(vec![
        synthetic_source("solo-channel", "autopilotEvents", &events),
        synthetic_source("esp-session-facts", "espSession", &sessions),
    ]));

    assert_ne!(
        snapshot.esp_linkage.state,
        AutopilotEspLinkState::Linked,
        "a key readable only from a capped record may not prove a link"
    );
}

/// A capture that declares only an unvalidated Autopilot schema version (no
/// Windows build at all) still refuses terminal semantics, and that refusal
/// must be explained by the unknown-schema finding rather than left silent.
#[test]
fn a_schema_version_only_unknown_schema_is_explained_by_a_finding() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [synthetic_event(
            "schema-e1", "schema-channel", 1, 161, "available", "parsed",
            json!([]), "AutopilotManager retrieve settings succeeded.",
        )]
    });
    let mut bundle = synthetic_bundle(vec![synthetic_source(
        "schema-channel",
        "autopilotEvents",
        &events,
    )]);
    bundle.capture.windows_build = None;
    bundle.capture.autopilot_schema_version = Some("3".to_owned());

    let snapshot = reduce_autopilot_bundle(&bundle);
    assert_eq!(snapshot.outcome, AutopilotOutcome::UnknownSchema);
    assert!(
        snapshot
            .findings
            .iter()
            .any(|finding| finding.finding_id == "autopilot-unknown-schema"),
        "withheld terminal semantics must be explained, got {:?}",
        snapshot
            .findings
            .iter()
            .map(|finding| finding.finding_id.as_str())
            .collect::<Vec<_>>()
    );
}

/// A case-only difference between two sightings of the same identifier is not
/// a conflict: serials and GUIDs are case-insensitive identities, and the
/// redacted export already masks the trimmed, lowercased value, so treating
/// casings as distinct produced "2 distinct values" rendered as two identical
/// tokens -- a self-contradictory export (ADR-004: redaction must not change
/// conclusions within one analysis).
#[test]
fn a_case_only_identifier_difference_is_not_a_conflict() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [
            synthetic_event(
                "case-e1", "case-channel", 1, 161, "available", "parsed",
                json!([{ "name": "serialNumber", "value": "SYNTH-5CD1234ABC" }]),
                "AutopilotManager retrieve settings succeeded.",
            ),
            synthetic_event(
                "case-e2", "case-channel", 2, 153, "available", "parsed",
                json!([{ "name": "serialNumber", "value": "synth-5cd1234abc" }]),
                "AutopilotManager reported the state changed from ProfileState_Unknown to ProfileState_Available.",
            ),
        ]
    });
    let snapshot = reduce_autopilot_bundle(&synthetic_bundle(vec![synthetic_source(
        "case-channel",
        "autopilotEvents",
        &events,
    )]));
    assert!(
        snapshot.conflicts.is_empty(),
        "two casings of one serial are one identity, got {:?}",
        snapshot.conflicts
    );
    assert_ne!(snapshot.outcome, AutopilotOutcome::ContradictoryEvidence);
    assert_eq!(
        snapshot.identity.serial_number.as_deref(),
        Some("SYNTH-5CD1234ABC"),
        "the representative casing must be deterministic"
    );
}

/// The control for the test above: genuinely different identifiers still
/// conflict, and the conflict still reports both values.
#[test]
fn genuinely_distinct_identifiers_still_conflict() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [
            synthetic_event(
                "real-e1", "real-channel", 1, 161, "available", "parsed",
                json!([{ "name": "serialNumber", "value": "SYNTH-5CD1234ABC" }]),
                "AutopilotManager retrieve settings succeeded.",
            ),
            synthetic_event(
                "real-e2", "real-channel", 2, 153, "available", "parsed",
                json!([{ "name": "serialNumber", "value": "SYNTH-5CD9999XYZ" }]),
                "AutopilotManager reported the state changed from ProfileState_Unknown to ProfileState_Available.",
            ),
        ]
    });
    let snapshot = reduce_autopilot_bundle(&synthetic_bundle(vec![synthetic_source(
        "real-channel",
        "autopilotEvents",
        &events,
    )]));
    let conflict = snapshot
        .conflicts
        .iter()
        .find(|conflict| conflict.conflict_id == "conflicting-serial-number")
        .expect("two different serials must still conflict");
    assert_eq!(conflict.values.len(), 2);
    assert_eq!(snapshot.outcome, AutopilotOutcome::ContradictoryEvidence);
}

/// When ESP facts exist but share no explicit key, the guidance to go find a
/// shared identifier must survive whatever the time gate concludes. The
/// narrowed (assessable-only) overlap window can turn TimeOnlyCandidate into
/// NotObserved, and losing the next-evidence request with it would hide the
/// one step that advances the diagnosis.
#[test]
fn unlinked_esp_sessions_keep_the_shared_identifier_evidence_request() {
    let events = json!({
        "autopilotDocument": "autopilot.events",
        "documentVersion": 1,
        "events": [synthetic_event(
            "unlinked-e1", "unlinked-channel", 1, 161, "available", "parsed",
            json!([]), "AutopilotManager retrieve settings succeeded.",
        )]
    });
    let sessions = json!({
        "autopilotDocument": "autopilot.espSession",
        "documentVersion": 1,
        "sessions": [{
            "sessionId": "esp-session-a",
            "enrollmentId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "correlationId": null, "activityId": null,
            "entraDeviceId": null, "managedDeviceId": null,
            "startedAtUtc": "2026-07-31T09:00:20Z", "phase": "deviceSetup",
            "evidence": { "evidenceId": "unlinked-esp-a", "sourceArtifactId": "esp-session-facts" }
        }]
    });
    let snapshot = reduce_autopilot_bundle(&synthetic_bundle(vec![
        synthetic_source("unlinked-channel", "autopilotEvents", &events),
        synthetic_source("esp-session-facts", "espSession", &sessions),
    ]));

    assert_eq!(
        snapshot.esp_linkage.state,
        AutopilotEspLinkState::NotObserved,
        "no key and no provable overlap window must stay NotObserved"
    );
    assert!(
        snapshot.next_evidence_requests.iter().any(|request| {
            request.contains("identifier shared by the Autopilot and ESP evidence")
        }),
        "the shared-identifier request must survive the time gate, got {:?}",
        snapshot.next_evidence_requests
    );
}

/// The native-event input path: events supplied directly on the bundle derive
/// their artifact from the event's own provenance and produce observations
/// without any document or source coverage entry.
#[test]
fn native_events_are_absorbed_with_their_provenance_artifact() {
    use cmtraceopen_parser::intune::evidence::{
        IntuneAccessState, IntuneEvidenceRef, IntuneObservationContext, IntuneParseState,
        IntuneProvenance, IntuneSensitivity, IntuneSourceKind,
    };
    use cmtraceopen_parser::intune::normalized::{NormalizedEventLevel, NormalizedWindowsEvent};

    let mut bundle = synthetic_bundle(Vec::new());
    bundle.events.push(NormalizedWindowsEvent {
        context: IntuneObservationContext {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: "native-e1".to_owned(),
                source_artifact_id: "native-adapter".to_owned(),
            },
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::EventLog,
                source_artifact_id: "native-adapter".to_owned(),
                file_path: None,
                line_number: None,
                record_number: Some(1),
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: "2026-07-31T09:30:00Z".to_owned(),
            sensitivity: IntuneSensitivity::Public,
            parse_state: IntuneParseState::Parsed,
            access_state: IntuneAccessState::Available,
        },
        channel: "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot".to_owned(),
        provider: "Microsoft-Windows-ModernDeployment-Diagnostics-Provider".to_owned(),
        event_id: 161,
        level: NormalizedEventLevel::Information,
        task: None,
        keywords: None,
        record_id: Some(1),
        activity_id: None,
        event_version: None,
        named_data: Vec::new(),
        message: Some("AutopilotManager retrieve settings succeeded.".to_owned()),
    });

    let snapshot = reduce_autopilot_bundle(&bundle);
    let observation = snapshot
        .observations
        .iter()
        .find(|observation| observation.observation_id == "native-e1")
        .expect("the native event must become an observation under its own evidence id");
    assert_eq!(
        observation.context.evidence_ref.source_artifact_id,
        "native-adapter",
        "the artifact must come from the event's own provenance"
    );
    assert!(
        snapshot.documents.is_empty(),
        "a native event is not a document"
    );
    assert!(
        snapshot.coverage.is_empty(),
        "coverage entries describe supplied sources; a native event has none"
    );
    assert!(snapshot.profile.retrieved);
}

// ── Golden maintenance ──────────────────────────────────────────────────────

/// Rewrite every scenario's `findings` golden from the current reducer output.
///
/// Marked `#[ignore]` so it never runs beside the readers of the same files:
/// the harness runs tests in parallel threads, and rewriting an
/// `expected.json` while another test reads it would race. Regenerate with
/// `UPDATE_AUTOPILOT_FINDINGS=1 cargo test --test intune_windows_autopilot -- \
/// --ignored update_findings_golden`, then review the diff. The rewrite
/// touches the `findings` key and nothing else, so the hand-written semantic
/// expectations survive and keep cross-checking the regenerated goldens.
#[test]
#[ignore = "rewrites goldens; run alone via -- --ignored update_findings_golden"]
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

/// Write through a temporary file plus rename so no concurrent reader can ever
/// observe a truncated golden. `std::fs::write` truncates before it writes.
fn write_json(path: &Path, value: &Value) {
    let text = serde_json::to_string_pretty(value).expect("golden must serialize") + "\n";
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, text)
        .unwrap_or_else(|error| panic!("{} is writable: {error}", temporary.display()));
    std::fs::rename(&temporary, path)
        .unwrap_or_else(|error| panic!("{} is replaceable: {error}", path.display()));
}
