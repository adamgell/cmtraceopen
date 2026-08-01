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
    analyze_compliance_bundle, redacted_export_projection, ComplianceSnapshot,
    ComplianceSourceInput,
};
use cmtraceopen_parser::intune::evidence::IntuneArtifactStatus;
use serde_json::{json, Value};
use support::{corpus_root, load_json, mutated, scenario_names, validate_scenario, Failures};

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
    corpus_root(CORPUS).join(scenario)
}

fn capture_status(capture_state: &str) -> IntuneArtifactStatus {
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
                status: capture_status(artifact["captureState"].as_str().expect("captureState")),
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

fn evidence_ids(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            let mut ids = items
                .iter()
                .map(|item| item["evidenceId"].as_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>();
            ids.sort();
            ids
        })
        .unwrap_or_default()
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
            evidence_ids(&got["evidence"]),
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
            assert_eq!(got[field], want[field], "{scenario}: access[{index}].{field}");
        }
        assert_eq!(
            evidence_ids(&got["matchedEvidence"]),
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
            evidence_ids(&got["evidence"]),
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
            let access_only = cited.iter().all(|artifact| {
                families.get(artifact).map(String::as_str) == Some("accessFacts")
            });
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
    assert_eq!(loaded.actual["aggregate"]["state"], json!("insufficientEvidence"));
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
    assert_eq!(failure.actual["aggregate"]["state"], json!("evaluationError"));
    assert_eq!(discovery.actual["aggregate"]["state"], json!("noncompliant"));
    assert_ne!(
        failure.actual["aggregate"]["rationale"],
        discovery.actual["aggregate"]["rationale"],
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
        ("/localEvaluation/settings/0/displayName", "settingDisplayName"),
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
