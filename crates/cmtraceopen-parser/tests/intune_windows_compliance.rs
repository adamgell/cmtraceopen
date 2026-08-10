//! Fixture matrix for `intune::device::windows::compliance` (issue #364).
//!
//! Every scenario states its expected reduction in `expected.json` rather than
//! being snapshotted, so a reviewer can read what each case asserts and why. The
//! shared harness in `tests/support/` validates the parts every Intune corpus
//! has in common (manifest envelope, byte counts, path safety, evidence closure,
//! coverage binding, privacy); this file owns the compliance semantics.
//!
//! The load-bearing tests are the last four in the "invariants" section. They
//! encode the correctness constraint the whole module exists for: a Conditional
//! Access denial, a stale service record, and a missing user evaluation are each
//! distinct from a failed local setting, and none of them may produce one.

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::device::windows::compliance::{
    analyze_compliance, analyze_compliance_bundle, decode_bundle, redacted_export_projection,
    ComplianceAccessDecision, ComplianceAccessFact, ComplianceCustomFact, ComplianceCustomState,
    ComplianceInput, ComplianceServiceFact, ComplianceServiceState, ComplianceSnapshot,
    ComplianceSourceInput,
};
use cmtraceopen_parser::intune::evidence::{
    IntuneAccessState, IntuneEvidenceRef, IntuneNamedValue, IntuneObservationContext,
    IntuneParseState, IntuneProvenance, IntuneSensitivity, IntuneSourceKind, IntuneTimestamp,
    IntuneTimestampKind,
};
use cmtraceopen_parser::intune::normalized::{
    NormalizedEventLevel, NormalizedSettingOutcome, NormalizedSettingReport,
    NormalizedWindowsEvent,
};
use serde_json::{json, Value};
use support::{
    artifact_status_for_capture_state, corpus_root, load_json, mutated, scenario_names,
    sorted_evidence_ids, validate_scenario, wire, Failures,
};

const CORPUS: &str = "device/windows/compliance";

/// The required fixture matrix from issue #364, pinned so a scenario cannot be
/// dropped or silently renamed. Sorted, because `scenario_names` sorts.
const SCENARIOS: [&str; 16] = [
    "access-denied-with-matching-state",
    "access-denied-without-compliance-evidence",
    "contradictory-ids-and-timestamps",
    "custom-compliance-discovery-noncompliant",
    "custom-compliance-script-failure",
    "deterministic-privacy-redaction",
    "evaluation-error",
    "local-compliant-service-compliant",
    "local-compliant-stale-service-noncompliant",
    "local-noncompliant-setting",
    "local-noncompliant-with-later-service-update",
    "malformed-and-unknown-schema",
    "partial-event-and-report-coverage",
    "report-submission-failure",
    "unsupported-not-applicable-setting",
    "user-targeted-policy-not-evaluated",
];

/// Artifact families whose evidence is a device-local observation.
///
/// A finding that claims a local setting failed must cite only these.
const LOCAL_FAMILIES: [&str; 3] = ["mdmEvents", "mdmReport", "customCompliance"];

/// Findings that assert something about a device-local evaluation.
const LOCAL_CLAIM_FINDINGS: [&str; 5] = [
    "compliance-local-setting-noncompliant",
    "compliance-local-evaluation-error",
    "compliance-prerequisite-unmet",
    "compliance-custom-discovery-noncompliant",
    "compliance-custom-script-failed",
];

// ── Loading ─────────────────────────────────────────────────────────────────

fn scenario_root(scenario: &str) -> PathBuf {
    support::scenario_root(CORPUS, scenario)
}

/// Build the analyzer input exactly as a native collector would report it.
fn sources(root: &Path, manifest: &Value) -> Vec<ComplianceSourceInput> {
    manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts is an array")
        .iter()
        .map(|artifact| {
            let content = artifact["relativePath"].as_str().map(|relative| {
                std::fs::read_to_string(root.join(relative))
                    .unwrap_or_else(|error| panic!("{relative} is readable: {error}"))
            });
            ComplianceSourceInput {
                artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId")
                    .to_string(),
                family: artifact["family"].as_str().expect("family").to_string(),
                status: artifact_status_for_capture_state(
                    artifact["captureState"].as_str().expect("captureState"),
                ),
                captured_at_utc: artifact["capturedUtc"]
                    .as_str()
                    .expect("capturedUtc")
                    .to_string(),
                content,
            }
        })
        .collect()
}

struct Loaded {
    manifest: Value,
    expected: Value,
    snapshot: ComplianceSnapshot,
    actual: Value,
}

fn load(scenario: &str) -> Loaded {
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let snapshot = analyze_compliance_bundle(
        &sources(&root, &manifest),
        manifest["generatedAtUtc"].as_str().expect("generatedAtUtc"),
    );
    let actual = serde_json::to_value(&snapshot).expect("snapshot serializes");
    Loaded {
        manifest,
        expected,
        snapshot,
        actual,
    }
}

/// The decoded facts of one scenario, before reduction.
///
/// The permutation, duplication, and irrelevant-evidence tests need to rearrange
/// the analyzer's *input vectors*, which the bundle entry point hides. Decoding
/// once here keeps those tests reading the same corpus every other test does.
fn load_input(scenario: &str) -> ComplianceInput {
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    decode_bundle(
        &sources(&root, &manifest),
        manifest["generatedAtUtc"].as_str().expect("generatedAtUtc"),
    )
}

/// artifactId -> family, for deciding whether cited evidence is local.
fn families(manifest: &Value) -> BTreeMap<String, String> {
    manifest["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .map(|artifact| {
            (
                artifact["artifactId"].as_str().expect("id").to_string(),
                artifact["family"].as_str().expect("family").to_string(),
            )
        })
        .collect()
}

fn artifact_ids(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    item["sourceArtifactId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            let mut values = items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>();
            values.sort();
            values
        })
        .unwrap_or_default()
}

// ── Corpus contract ─────────────────────────────────────────────────────────

#[test]
fn the_corpus_exposes_exactly_the_required_fixture_matrix() {
    assert_eq!(
        scenario_names(&corpus_root(CORPUS)),
        SCENARIOS.map(str::to_owned).to_vec(),
        "the scenario matrix in issue #364 is the acceptance criteria, not a suggestion"
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
    failures.assert_empty("compliance corpus");
}

// ── Reduction contract ──────────────────────────────────────────────────────

#[test]
fn every_scenario_matches_its_expected_reduction() {
    for scenario in SCENARIOS {
        let loaded = load(scenario);
        let (actual, expected) = (&loaded.actual, &loaded.expected);

        assert_eq!(
            actual["deviceContext"]["userEvaluationContext"], expected["userEvaluationContext"],
            "{scenario}: user evaluation context"
        );
        assert_eq!(
            actual["aggregate"]["state"], expected["aggregate"]["state"],
            "{scenario}: aggregate state"
        );
        assert_eq!(
            actual["aggregate"]["rationale"], expected["aggregate"]["rationale"],
            "{scenario}: aggregate rationale"
        );
        for field in ["state", "serviceFreshness", "serviceDisagreesWithLocal"] {
            assert_eq!(
                actual["reporting"][field], expected["reporting"][field],
                "{scenario}: reporting.{field}"
            );
        }

        assert_settings(scenario, actual, expected);
        assert_access(scenario, actual, expected);
        assert_coverage(scenario, actual, expected);
        assert_findings(scenario, actual, expected);
    }
}

fn assert_settings(scenario: &str, actual: &Value, expected: &Value) {
    let actual_settings = actual["localEvaluation"]["settings"]
        .as_array()
        .expect("settings array");
    let expected_settings = expected["settings"].as_array().expect("expected settings");
    assert_eq!(
        actual_settings.len(),
        expected_settings.len(),
        "{scenario}: setting count, got tokens {:?}",
        actual_settings
            .iter()
            .map(|setting| &setting["groupingToken"])
            .collect::<Vec<_>>()
    );
    for (index, (got, want)) in actual_settings.iter().zip(expected_settings).enumerate() {
        for field in [
            "groupingToken",
            "scope",
            "state",
            "timeContradiction",
            "identityContradiction",
        ] {
            assert_eq!(
                got[field], want[field],
                "{scenario}: settings[{index}].{field}"
            );
        }
        assert_eq!(
            sorted_evidence_ids(&got["evidence"]),
            strings(&want["evidence"]),
            "{scenario}: settings[{index}].evidence"
        );
    }
}

fn assert_access(scenario: &str, actual: &Value, expected: &Value) {
    let actual_access = actual["accessImpact"]["decisions"]
        .as_array()
        .expect("decisions array");
    let expected_access = expected["access"].as_array().expect("expected access");
    assert_eq!(
        actual_access.len(),
        expected_access.len(),
        "{scenario}: access decision count"
    );
    for (index, (got, want)) in actual_access.iter().zip(expected_access).enumerate() {
        for field in ["decision", "linkage"] {
            assert_eq!(
                got[field], want[field],
                "{scenario}: access[{index}].{field}"
            );
        }
        assert_eq!(
            sorted_evidence_ids(&got["matchedEvidence"]),
            strings(&want["matchedEvidence"]),
            "{scenario}: access[{index}].matchedEvidence"
        );
    }
}

fn assert_coverage(scenario: &str, actual: &Value, expected: &Value) {
    let actual_coverage = actual["coverage"].as_array().expect("coverage array");
    let expected_coverage = expected["coverage"].as_array().expect("expected coverage");
    assert_eq!(
        actual_coverage.len(),
        expected_coverage.len(),
        "{scenario}: coverage entry count"
    );
    for (index, (got, want)) in actual_coverage.iter().zip(expected_coverage).enumerate() {
        for field in ["artifactId", "status"] {
            assert_eq!(
                got[field], want[field],
                "{scenario}: coverage[{index}].{field}"
            );
        }
    }
}

fn assert_findings(scenario: &str, actual: &Value, expected: &Value) {
    let actual_findings = actual["findings"].as_array().expect("findings array");
    let expected_findings = expected["findings"].as_array().expect("expected findings");
    assert_eq!(
        actual_findings.len(),
        expected_findings.len(),
        "{scenario}: finding count, got {:?}",
        actual_findings
            .iter()
            .map(|finding| &finding["findingId"])
            .collect::<Vec<_>>()
    );
    for (index, (got, want)) in actual_findings.iter().zip(expected_findings).enumerate() {
        for field in ["findingId", "severity", "confidence"] {
            assert_eq!(
                got[field], want[field],
                "{scenario}: findings[{index}].{field}"
            );
        }
        assert_eq!(
            sorted_evidence_ids(&got["evidence"]),
            strings(&want["evidence"]),
            "{scenario}: findings[{index}].evidence"
        );
        assert_eq!(
            strings(&got["coverageGapIds"]),
            strings(&want["coverageGapIds"]),
            "{scenario}: findings[{index}].coverageGapIds"
        );
    }
}

// ── Invariants ──────────────────────────────────────────────────────────────

#[test]
fn every_finding_cites_evidence_or_a_coverage_gap() {
    for scenario in SCENARIOS {
        for finding in load(scenario).snapshot.findings {
            assert!(
                finding.is_evidence_backed(),
                "{scenario}: {} cites neither evidence nor a coverage gap",
                finding.finding_id
            );
        }
    }
}

/// The core constraint: a claim about a *local* setting is only ever made from
/// local evidence. A service record or a sign-in result can never back one.
#[test]
fn a_local_failure_claim_cites_only_local_evaluation_evidence() {
    for scenario in SCENARIOS {
        let loaded = load(scenario);
        let families = families(&loaded.manifest);
        for finding in loaded.actual["findings"].as_array().expect("findings") {
            let id = finding["findingId"].as_str().unwrap_or_default();
            if !LOCAL_CLAIM_FINDINGS.contains(&id) {
                continue;
            }
            let cited = artifact_ids(&finding["evidence"]);
            assert!(
                !cited.is_empty(),
                "{scenario}: {id} claims a local failure while citing nothing"
            );
            for artifact in cited {
                let family = families
                    .get(&artifact)
                    .unwrap_or_else(|| panic!("{scenario}: unknown artifact {artifact}"));
                assert!(
                    LOCAL_FAMILIES.contains(&family.as_str()),
                    "{scenario}: {id} claims a local failure but cites {artifact} of family {family}"
                );
            }
        }
    }
}

/// A finding built only from access evidence must stay Info + Low.
///
/// This is the acceptance criterion "no high-confidence compliance cause is
/// created from a sign-in error alone", enforced across the whole corpus rather
/// than in the one scenario that exercises it.
#[test]
fn a_finding_built_only_from_access_evidence_makes_no_confident_claim() {
    for scenario in SCENARIOS {
        let loaded = load(scenario);
        let families = families(&loaded.manifest);
        for finding in loaded.actual["findings"].as_array().expect("findings") {
            let cited = artifact_ids(&finding["evidence"]);
            if cited.is_empty() {
                continue;
            }
            let access_only = cited
                .iter()
                .all(|artifact| families.get(artifact).map(String::as_str) == Some("accessFacts"));
            if !access_only {
                continue;
            }
            let id = finding["findingId"].as_str().unwrap_or_default();
            assert_eq!(
                finding["confidence"],
                json!("low"),
                "{scenario}: {id} is built only from access evidence and must stay low confidence"
            );
            assert_eq!(
                finding["severity"],
                json!("info"),
                "{scenario}: {id} is built only from access evidence and must stay informational"
            );
        }
    }
}

#[test]
fn an_access_denial_alone_produces_no_local_setting_state() {
    let loaded = load("access-denied-without-compliance-evidence");
    assert!(
        loaded.snapshot.local_evaluation.settings.is_empty(),
        "a sign-in denial must not synthesize a setting evaluation"
    );
    assert_eq!(
        loaded.actual["aggregate"]["state"],
        json!("insufficientEvidence")
    );
    assert_eq!(
        loaded.actual["accessImpact"]["decisions"][0]["linkage"],
        json!("noMatchingComplianceEvidence")
    );
}

#[test]
fn a_stale_service_record_leaves_every_local_setting_compliant() {
    let loaded = load("local-compliant-stale-service-noncompliant");
    assert_eq!(loaded.actual["aggregate"]["state"], json!("compliant"));
    assert_eq!(
        loaded.actual["reporting"]["serviceFreshness"],
        json!("stale")
    );
    assert!(
        loaded.actual["localEvaluation"]["settings"]
            .as_array()
            .expect("settings")
            .iter()
            .all(|setting| setting["state"] == json!("compliant")),
        "a stale cloud record must never rewrite a local setting state"
    );
}

#[test]
fn an_unevaluated_user_setting_is_never_reported_as_a_failure() {
    let loaded = load("user-targeted-policy-not-evaluated");
    let user_setting = loaded.actual["localEvaluation"]["settings"]
        .as_array()
        .expect("settings")
        .iter()
        .find(|setting| setting["scope"] == json!("user"))
        .expect("a user-scoped setting");
    assert_eq!(user_setting["state"], json!("notEvaluated"));
    assert!(
        !loaded
            .snapshot
            .findings
            .iter()
            .any(|finding| finding.finding_id == "compliance-local-setting-noncompliant"),
        "a missing user evaluation must not produce a local-noncompliance finding"
    );
}

#[test]
fn a_custom_script_failure_is_not_a_noncompliant_discovery() {
    let failure = load("custom-compliance-script-failure");
    let discovery = load("custom-compliance-discovery-noncompliant");
    assert_eq!(
        failure.actual["aggregate"]["state"],
        json!("evaluationError")
    );
    assert_eq!(
        discovery.actual["aggregate"]["state"],
        json!("noncompliant")
    );
    assert_ne!(
        failure.actual["aggregate"]["rationale"], discovery.actual["aggregate"]["rationale"],
        "a crashed script and a noncompliant discovery must not share a rationale"
    );
}

#[test]
fn the_reduction_is_deterministic_across_runs() {
    for scenario in SCENARIOS {
        let first = load(scenario).actual;
        let second = load(scenario).actual;
        assert_eq!(
            serde_json::to_string(&first).expect("serializes"),
            serde_json::to_string(&second).expect("serializes"),
            "{scenario}: the same bundle must reduce to byte-identical output"
        );
    }
}

// ── Caller order, duplication, and irrelevant evidence ──────────────────────

/// The inputs the order-invariance tests sweep.
///
/// The 16 corpus scenarios are the regression net, but every one of them is a
/// single-record-per-setting bundle: none carries two observations sharing a
/// grouping token, two report submissions, or two rows describing one policy.
/// Sweeping only the corpus therefore proves nothing about the order-dependent
/// merges — the gate would pass vacuously. [`contended_bundle`] supplies the
/// contended shapes the corpus does not have, so these tests can actually fail.
fn order_invariance_cases() -> Vec<(String, ComplianceInput)> {
    let mut cases = SCENARIOS
        .iter()
        .map(|scenario| ((*scenario).to_owned(), load_input(scenario)))
        .collect::<Vec<_>>();
    cases.push(("contended-bundle".to_owned(), contended_bundle()));
    cases
}

/// Every ordering of one bundle's sibling records must produce the same
/// snapshot, byte for byte.
///
/// ADR-003's executable invariant. `the_reduction_is_deterministic_across_runs`
/// re-runs the *same* vector and so cannot see a first-wins or last-wins field;
/// this permutes the vector instead. No compliance source contract defines
/// caller order as chronology, so any field that reads it is reading the
/// collector's serializer.
#[test]
fn permuting_sibling_records_does_not_change_the_analysis() {
    for (case, input) in order_invariance_cases() {
        let baseline = wire(&analyze_compliance(&input));
        for permutation in permutations_of(input) {
            assert_eq!(
                wire(&analyze_compliance(&permutation)),
                baseline,
                "{case}: input order must not change the analysis"
            );
        }
    }
}

/// Orderings of each input vector, capped so a large bundle stays a test rather
/// than a benchmark.
///
/// The two vectors that feed the setting merge are crossed with each other; the
/// three fact vectors are permuted one at a time against the baseline, because
/// crossing all five is a combinatorial explosion that proves nothing the
/// one-at-a-time sweep plus the all-reversed case does not.
fn permutations_of(input: ComplianceInput) -> Vec<ComplianceInput> {
    fn orderings<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
        if items.len() <= 1 {
            return vec![items.to_vec()];
        }
        if items.len() > 4 {
            let mut reversed = items.to_vec();
            reversed.reverse();
            return vec![items.to_vec(), reversed];
        }
        let mut result = Vec::new();
        for index in 0..items.len() {
            let mut rest = items.to_vec();
            let head = rest.remove(index);
            for mut tail in orderings(&rest) {
                tail.insert(0, head.clone());
                result.push(tail);
            }
        }
        result
    }

    fn reversed<T: Clone>(items: &[T]) -> Vec<T> {
        let mut items = items.to_vec();
        items.reverse();
        items
    }

    let mut permutations = Vec::new();
    for events in orderings(&input.events) {
        for setting_reports in orderings(&input.setting_reports) {
            permutations.push(ComplianceInput {
                events: events.clone(),
                setting_reports,
                ..input.clone()
            });
        }
    }
    for custom_compliance in orderings(&input.custom_compliance) {
        permutations.push(ComplianceInput {
            custom_compliance,
            ..input.clone()
        });
    }
    for service_results in orderings(&input.service_results) {
        permutations.push(ComplianceInput {
            service_results,
            ..input.clone()
        });
    }
    for access_decisions in orderings(&input.access_decisions) {
        permutations.push(ComplianceInput {
            access_decisions,
            ..input.clone()
        });
    }
    permutations.push(ComplianceInput {
        events: reversed(&input.events),
        setting_reports: reversed(&input.setting_reports),
        custom_compliance: reversed(&input.custom_compliance),
        service_results: reversed(&input.service_results),
        access_decisions: reversed(&input.access_decisions),
        ..input
    });
    permutations
}

/// Re-collecting the same records must not change the analysis.
///
/// A collector that reads an event log twice, or a rotation that overlaps, hands
/// the same evidence over more than once. Every local observation is keyed and
/// every evidence list is normalized, so the reduction is idempotent under
/// duplication — unless a field folds by counting or by vector position.
#[test]
fn re_collecting_the_same_records_does_not_change_the_analysis() {
    for (case, input) in order_invariance_cases() {
        let baseline = wire(&analyze_compliance(&input));

        let doubled = ComplianceInput {
            events: [input.events.clone(), input.events.clone()].concat(),
            setting_reports: [
                input.setting_reports.clone(),
                input.setting_reports.clone(),
            ]
            .concat(),
            ..input
        };
        assert_eq!(
            wire(&analyze_compliance(&doubled)),
            baseline,
            "{case}: re-collected records must not change the analysis"
        );
    }
}

/// Evidence that states nothing about compliance must not disturb a conclusion
/// already drawn from evidence that does.
///
/// Such a record is legitimately visible as an unkeyed observation and may raise
/// a coverage finding about itself; what it must never do is move an aggregate,
/// a setting state, a reporting state, or the verdict of a finding that was
/// already there.
#[test]
fn irrelevant_evidence_does_not_change_an_existing_conclusion() {
    for (case, input) in order_invariance_cases() {
        let baseline = conclusions(&analyze_compliance(&input));

        let mut widened = input;
        widened.events.push(evidence_that_says_nothing("irrelevant-1"));
        widened
            .events
            .insert(0, evidence_that_says_nothing("irrelevant-2"));
        let after = conclusions(&analyze_compliance(&widened));

        for (key, value) in baseline.as_object().expect("conclusions is an object") {
            assert_eq!(
                after.get(key),
                Some(value),
                "{case}: unrelated evidence changed {key}"
            );
        }
    }
}

/// The claims a reader would act on, isolated from coverage bookkeeping.
fn conclusions(snapshot: &ComplianceSnapshot) -> Value {
    let value = wire(snapshot);
    json!({
        "aggregate": value["aggregate"]["state"],
        "rationale": value["aggregate"]["rationale"],
        "reportingState": value["reporting"]["state"],
        "serviceFreshness": value["reporting"]["serviceFreshness"],
        "serviceDisagreesWithLocal": value["reporting"]["serviceDisagreesWithLocal"],
        "settings": value["localEvaluation"]["settings"]
            .as_array()
            .expect("settings")
            .iter()
            .map(|setting| json!([setting["groupingToken"], setting["state"], setting["scope"]]))
            .collect::<Vec<_>>(),
        "access": value["accessImpact"]["decisions"]
            .as_array()
            .expect("decisions")
            .iter()
            .map(|decision| json!([decision["decision"], decision["linkage"]]))
            .collect::<Vec<_>>(),
        "findings": value["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .filter(|finding| finding["findingId"] != json!("compliance-unkeyed-observations"))
            .map(|finding| {
                json!([finding["findingId"], finding["severity"], finding["confidence"]])
            })
            .collect::<Vec<_>>(),
    })
}

/// A record that was collected, parsed, and carries no compliance signal at all.
fn evidence_that_says_nothing(evidence_id: &str) -> NormalizedWindowsEvent {
    event(evidence_id, None, Vec::new())
}

fn event(
    evidence_id: &str,
    at: Option<&str>,
    named_data: Vec<(&str, &str)>,
) -> NormalizedWindowsEvent {
    NormalizedWindowsEvent {
        context: IntuneObservationContext {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: evidence_id.to_owned(),
                source_artifact_id: "mdm-events".to_owned(),
            },
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::EventLog,
                source_artifact_id: "mdm-events".to_owned(),
                file_path: None,
                line_number: None,
                record_number: None,
                registry: None,
                event: None,
            },
            source_timestamp: at.map(|value| IntuneTimestamp {
                raw_text: value.to_owned(),
                original_offset: None,
                normalized_utc: Some(value.to_owned()),
                kind: IntuneTimestampKind::Utc,
            }),
            observed_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            sensitivity: IntuneSensitivity::Public,
            parse_state: IntuneParseState::Parsed,
            access_state: IntuneAccessState::Available,
        },
        channel: "DeviceManagement-Enterprise-Diagnostics-Provider/Admin".to_owned(),
        provider: "DeviceManagement-Enterprise-Diagnostics-Provider".to_owned(),
        event_id: 1,
        level: NormalizedEventLevel::Information,
        task: None,
        keywords: None,
        record_id: None,
        activity_id: None,
        event_version: None,
        named_data: named_data
            .into_iter()
            .map(|(name, value)| IntuneNamedValue {
                name: name.to_owned(),
                value: value.to_owned(),
            })
            .collect(),
        message: None,
    }
}

/// One bundle in which every order-sensitive merge is actually contended.
///
/// The corpus has no scenario like this, which is why the order-invariance gates
/// passed over it while the reducer was still reading the caller's vector. Every
/// pair below states one fact two ways with equal authority:
///
/// - two `Submitted` rows straddling the latest local evaluation, which decides
///   `Submitted` against `Stale` — the conclusion-flipping case;
/// - two rows for one setting differing in display name, scope, and error code;
/// - two rows describing one policy with opposite states and scopes;
/// - two rows describing one prerequisite as unmet with different detail;
/// - a report row for the same setting, so the second input vector is contended
///   too;
/// - two custom-compliance results, two service records, and two access
///   decisions, so the three fact vectors carry more than one entry each and the
///   order of the *exported arrays* is exercised.
fn contended_bundle() -> ComplianceInput {
    ComplianceInput {
        generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
        events: vec![
            event(
                "evt-eval-zebra",
                Some("2026-07-31T10:00:00Z"),
                vec![
                    ("SettingUri", "./Device/Vendor/MSFT/Policy/Result/BitLocker"),
                    ("EvaluationResult", "error"),
                    ("DisplayName", "Zebra requires encryption"),
                    ("Scope", "device"),
                    ("ErrorCode", "0x80070005"),
                ],
            ),
            event(
                "evt-eval-alpha",
                Some("2026-07-31T10:05:00Z"),
                vec![
                    ("SettingUri", "./Device/Vendor/MSFT/Policy/Result/BitLocker"),
                    ("EvaluationResult", "error"),
                    ("DisplayName", "Alpha requires encryption"),
                    ("Scope", "user"),
                    ("ErrorCode", "0x80070002"),
                ],
            ),
            event(
                "evt-submit-early",
                Some("2026-07-31T09:00:00Z"),
                vec![("ReportStatus", "submitted"), ("ReportId", "zebra-report")],
            ),
            event(
                "evt-submit-late",
                Some("2026-07-31T11:00:00Z"),
                vec![("ReportStatus", "submitted"), ("ReportId", "alpha-report")],
            ),
            event(
                "evt-policy-received",
                Some("2026-07-31T09:30:00Z"),
                vec![
                    ("PolicyId", "policy-contended"),
                    ("PolicyState", "received"),
                    ("Scope", "device"),
                ],
            ),
            event(
                "evt-policy-missing",
                Some("2026-07-31T09:40:00Z"),
                vec![
                    ("PolicyId", "policy-contended"),
                    ("PolicyState", "missing"),
                    ("Scope", "user"),
                ],
            ),
            event(
                "evt-prereq-zebra",
                Some("2026-07-31T09:50:00Z"),
                vec![
                    ("Prerequisite", "unmet"),
                    ("PrerequisiteName", "TpmReady"),
                    ("PrerequisiteDetail", "Zebra detail"),
                ],
            ),
            event(
                "evt-prereq-alpha",
                Some("2026-07-31T09:55:00Z"),
                vec![
                    ("Prerequisite", "unmet"),
                    ("PrerequisiteName", "TpmReady"),
                    ("PrerequisiteDetail", "Alpha detail"),
                ],
            ),
        ],
        setting_reports: vec![NormalizedSettingReport {
            context: event("rpt-bitlocker", Some("2026-07-31T10:02:00Z"), Vec::new()).context,
            setting_uri: Some("./Device/Vendor/MSFT/Policy/Result/BitLocker".to_owned()),
            setting_id: None,
            policy_id: None,
            display_name: Some("Middle requires encryption".to_owned()),
            outcome: NormalizedSettingOutcome::Failed,
            value: None,
            error: None,
            named_data: Vec::new(),
        }],
        custom_compliance: vec![
            custom_fact("cus-zebra", "ZebraCheck"),
            custom_fact("cus-alpha", "AlphaCheck"),
        ],
        service_results: vec![
            service_fact("svc-zebra", "2026-07-31T11:30:00Z"),
            service_fact("svc-alpha", "2026-07-31T11:40:00Z"),
        ],
        access_decisions: vec![
            access_fact("acc-zebra", "2026-07-31T11:50:00Z"),
            access_fact("acc-alpha", "2026-07-31T11:55:00Z"),
        ],
        ..ComplianceInput::default()
    }
}

fn custom_fact(evidence_id: &str, setting_name: &str) -> ComplianceCustomFact {
    ComplianceCustomFact {
        context: event(evidence_id, None, Vec::new()).context,
        policy_id: Some("policy-contended".to_owned()),
        run_id: Some(evidence_id.to_owned()),
        setting_name: Some(setting_name.to_owned()),
        outcome: ComplianceCustomState::DiscoveryCompliant,
        error: None,
        raw_output: None,
        named_data: Vec::new(),
    }
}

fn service_fact(evidence_id: &str, at: &str) -> ComplianceServiceFact {
    ComplianceServiceFact {
        context: event(evidence_id, None, Vec::new()).context,
        policy_id: Some("policy-contended".to_owned()),
        setting_id: None,
        state: ComplianceServiceState::Compliant,
        reported_at: Some(IntuneTimestamp {
            raw_text: at.to_owned(),
            original_offset: None,
            normalized_utc: Some(at.to_owned()),
            kind: IntuneTimestampKind::Utc,
        }),
        device_key: Some("device-contended".to_owned()),
        user_key: None,
        named_data: Vec::new(),
    }
}

fn access_fact(evidence_id: &str, at: &str) -> ComplianceAccessFact {
    ComplianceAccessFact {
        context: event(evidence_id, None, Vec::new()).context,
        decision: ComplianceAccessDecision::Denied,
        failure_code: None,
        occurred_at: Some(IntuneTimestamp {
            raw_text: at.to_owned(),
            original_offset: None,
            normalized_utc: Some(at.to_owned()),
            kind: IntuneTimestampKind::Utc,
        }),
        device_key: Some("device-contended".to_owned()),
        user_key: None,
        resource: None,
        named_data: Vec::new(),
    }
}

// ── Redaction ───────────────────────────────────────────────────────────────

#[test]
fn the_redacted_projection_matches_its_golden_and_is_idempotent() {
    let loaded = load("deterministic-privacy-redaction");
    let projected = redacted_export_projection(&loaded.snapshot);
    let golden = &loaded.expected["redaction"];
    let value = serde_json::to_value(&projected).expect("projection serializes");

    for (pointer, key) in [
        ("/deviceContext/deviceKey", "deviceKey"),
        ("/deviceContext/tenantKey", "tenantKey"),
        ("/deviceContext/enrollmentId", "enrollmentId"),
        ("/deviceContext/activeUserKey", "activeUserKey"),
        ("/deviceContext/windowsBuild", "windowsBuild"),
        (
            "/localEvaluation/settings/0/displayName",
            "settingDisplayName",
        ),
        (
            "/localEvaluation/customCompliance/0/rawOutput",
            "customRawOutput",
        ),
        ("/accessImpact/decisions/0/resource", "accessResource"),
    ] {
        assert_eq!(
            value.pointer(pointer).unwrap_or(&Value::Null),
            &golden[key],
            "redaction golden mismatch at {pointer}"
        );
    }

    let cache_path = projected.local_evaluation.settings[0]
        .named_data
        .iter()
        .find(|entry| entry.name == "PolicyCachePath")
        .expect("PolicyCachePath survives redaction")
        .value
        .clone();
    assert_eq!(cache_path, golden["policyCachePath"].as_str().unwrap());

    let twice = redacted_export_projection(&projected);
    assert_eq!(
        serde_json::to_value(&twice).expect("serializes"),
        value,
        "the redaction projection must be idempotent"
    );
}

#[test]
fn redaction_preserves_states_coverage_and_evidence() {
    for scenario in SCENARIOS {
        let loaded = load(scenario);
        let projected = redacted_export_projection(&loaded.snapshot);
        assert_eq!(
            projected.aggregate, loaded.snapshot.aggregate,
            "{scenario}: redaction must not touch the aggregate"
        );
        assert_eq!(
            projected.coverage, loaded.snapshot.coverage,
            "{scenario}: redaction must not drop coverage"
        );
        let ids = |snapshot: &ComplianceSnapshot| {
            snapshot
                .findings
                .iter()
                .map(|finding| (finding.finding_id.clone(), finding.evidence.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(&projected),
            ids(&loaded.snapshot),
            "{scenario}: redaction must not change which evidence a finding cites"
        );
    }
}

// ── Adversarial corpus mutations ────────────────────────────────────────────

fn assert_rejected(scenario: &str, label: &str, manifest: &Value, expected: &Value, needle: &str) {
    let failures = validate_scenario(scenario, &scenario_root(scenario), manifest, expected);
    assert!(
        failures
            .entries()
            .iter()
            .any(|entry| entry.contains(needle)),
        "{label}: expected a failure mentioning {needle:?}, got {:?}",
        failures.entries()
    );
}

#[test]
fn a_byte_count_that_disagrees_with_the_evidence_is_rejected() {
    let scenario = "local-noncompliant-setting";
    let loaded = load(scenario);
    assert_rejected(
        scenario,
        "byte count",
        &mutated(&loaded.manifest, "/artifacts/0/bytesCopied", json!(1)),
        &loaded.expected,
        "bytesCopied",
    );
}

#[test]
fn coverage_that_contradicts_the_capture_state_is_rejected() {
    // partial-event-and-report-coverage declares mdm-events absent. Claiming it
    // was available would let the corpus assert coverage it never had.
    let scenario = "partial-event-and-report-coverage";
    let loaded = load(scenario);
    let coverage = loaded.expected["coverage"]
        .as_array()
        .expect("coverage")
        .iter()
        .position(|entry| entry["artifactId"] == json!("mdm-events"))
        .expect("mdm-events coverage entry");
    assert_rejected(
        scenario,
        "coverage drift",
        &loaded.manifest,
        &mutated(
            &loaded.expected,
            &format!("/coverage/{coverage}/status"),
            json!("available"),
        ),
        "requires coverage status",
    );
}

#[test]
fn a_finding_stripped_of_its_only_citation_is_rejected() {
    let scenario = "malformed-and-unknown-schema";
    let loaded = load(scenario);
    assert_rejected(
        scenario,
        "uncited finding",
        &loaded.manifest,
        &mutated(&loaded.expected, "/findings/0/coverageGapIds", json!([])),
        "cites neither evidence nor a coverage gap",
    );
}
