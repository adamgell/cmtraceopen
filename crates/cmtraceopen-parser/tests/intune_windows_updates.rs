//! Fixture matrix for `intune::device::windows::updates` (issue #365).
//!
//! Every scenario is a directory holding a `manifest.json` describing which
//! artifacts were captured, an `evidence/` tree, and an `expected.json` stating
//! the contract the reduction must satisfy. The expectations are written out
//! rather than snapshotted so a reviewer can see what each scenario asserts and
//! why.
//!
//! Beyond the per-scenario expectations, three corpus-wide invariants are
//! asserted against every scenario. They are the ones issue #365 exists to
//! protect:
//!
//! 1. **Chain separation.** A finding under `…/update/…` cites only evidence the
//!    Windows Update client produced (or a supplemental line already tied to a
//!    client-backed transaction). A finding under `…/policy/…` cites only policy
//!    evidence. Neither may borrow the other's citations.
//! 2. **Every finding is backed.** Evidence or a coverage gap, never neither.
//! 3. **The default export leaks nothing.** No policy value and no file path
//!    survives redaction, and the projection is byte-stable.
//!
//! The shared harness in `tests/support/` validates everything the corpora of
//! epic #356 have in common: the manifest envelope, byte-count truth,
//! file/manifest closure, the synthetic marker, and the privacy scan.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::device::windows::updates::{
    analyze_update_bundle, redacted_export_projection, SupplementalLogKind, UpdateEvidenceBundle,
    UpdateSnapshot, UpdateSupplementalLog, EVIDENCE_FINDING_PREFIX, POLICY_FINDING_PREFIX,
    REDACTED, UPDATE_FINDING_PREFIX,
};
use cmtraceopen_parser::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneEvidenceRef,
    IntuneObservationContext, IntuneParseState, IntuneProvenance, IntuneSensitivity,
    IntuneSourceKind,
};
use serde_json::Value;
use support::{corpus_root, load_json, mutated, scenario_names, validate_scenario, Failures};

/// The corpus this leaf owns.
const CORPUS: &str = "device/windows/updates";

/// Every scenario the issue's fixture matrix requires, pinned so a deleted or
/// renamed directory fails loudly instead of silently shrinking the matrix.
const SCENARIOS: [&str; 19] = [
    "co-management-workload-not-owned-by-intune",
    "conflicting-policy-sources",
    "csp-policy-delivery-failure",
    "download-failure",
    "effective-wsus-source-when-wufb-expected",
    "event-only-partial-bundle",
    "install-failure-with-servicing-corroboration",
    "invalid-offset-contradictory-order",
    "local-success-stale-service-report",
    "maintenance-deadline-deferral",
    "policy-applied-no-applicable-update",
    "policy-applied-update-installed-reboot-complete",
    "privacy-safe-deterministic-export",
    "reboot-pending",
    "report-only-partial-bundle",
    "rotation-multiline-supplemental-log",
    "same-time-unrelated-kbs-kept-separate",
    "scan-failure",
    "unknown-windows-event-schema",
];

/// Capture states whose bytes are fed to the analyzer.
///
/// `parseFailed` is deliberately excluded: the artifact was collected and could
/// not be interpreted, so feeding it would be claiming a parse the fixture says
/// did not happen. It still contributes a coverage entry.
const FEEDABLE: [&str; 2] = ["captured", "capped"];

fn scenario_root(scenario: &str) -> PathBuf {
    corpus_root(CORPUS).join(scenario)
}

// ── Bundle construction ─────────────────────────────────────────────────────

/// Build the analyzer's input from a scenario's manifest and evidence tree.
///
/// The manifest is the single source of truth for what was captured; nothing is
/// inferred from the file system. Coverage is derived from the declared capture
/// states, which is what makes the harness's capture-state/coverage binding a
/// real check on the analyzer rather than on the fixture alone.
fn build_bundle(scenario: &str, manifest: &Value) -> UpdateEvidenceBundle {
    let root = scenario_root(scenario);
    let mut bundle = UpdateEvidenceBundle {
        generated_at_utc: manifest["generatedAtUtc"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        ..Default::default()
    };

    for artifact in manifest["artifacts"].as_array().expect("artifacts array") {
        let artifact_id = artifact["artifactId"].as_str().expect("artifactId");
        let capture_state = artifact["captureState"].as_str().expect("captureState");

        bundle.coverage.push(IntuneArtifactCoverage {
            artifact_id: artifact_id.to_owned(),
            family: artifact["family"].as_str().unwrap_or_default().to_owned(),
            status: coverage_status(capture_state),
            detail: artifact["detail"].as_str().map(str::to_owned),
            observed_at_utc: artifact["capturedUtc"].as_str().unwrap_or_default().to_owned(),
            evidence: Vec::new(),
        });

        if !FEEDABLE.contains(&capture_state) {
            continue;
        }
        let Some(relative) = artifact["relativePath"].as_str() else {
            continue;
        };
        let Some(payload_kind) = artifact["payloadKind"].as_str() else {
            continue;
        };
        let path = root.join(relative);

        match payload_kind {
            "supplementalLog" => bundle.supplemental_logs.push(supplemental_log(
                artifact,
                artifact_id,
                &path,
                capture_state,
            )),
            "events" => extend(&mut bundle.events, &path, "events"),
            "settingReports" => extend(&mut bundle.setting_reports, &path, "settingReports"),
            "registryFacts" => extend(&mut bundle.registry_facts, &path, "registryFacts"),
            "serviceReports" => extend(&mut bundle.service_reports, &path, "serviceReports"),
            "deviceFacts" => {
                bundle.device = serde_json::from_value(load_json(&path)["device"].clone())
                    .unwrap_or_else(|error| {
                        panic!("{}: device facts do not deserialize: {error}", path.display())
                    });
            }
            other => panic!("{scenario}/{artifact_id}: unknown payloadKind {other:?}"),
        }
    }

    bundle
}

fn extend<T: serde::de::DeserializeOwned>(target: &mut Vec<T>, path: &Path, key: &str) {
    let rows: Vec<T> = serde_json::from_value(load_json(path)[key].clone())
        .unwrap_or_else(|error| panic!("{}: {key} do not deserialize: {error}", path.display()));
    target.extend(rows);
}

/// A supplemental log's observation context is derived from its manifest entry.
///
/// Hand-writing a context per log file would duplicate what the manifest already
/// states, and the two would drift.
fn supplemental_log(
    artifact: &Value,
    artifact_id: &str,
    path: &Path,
    capture_state: &str,
) -> UpdateSupplementalLog {
    let kind: SupplementalLogKind = serde_json::from_value(artifact["supplementalKind"].clone())
        .unwrap_or_else(|error| panic!("{artifact_id}: supplementalKind is required: {error}"));

    UpdateSupplementalLog {
        context: IntuneObservationContext {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: artifact_id.to_owned(),
                source_artifact_id: artifact_id.to_owned(),
            },
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::PlainTextLog,
                source_artifact_id: artifact_id.to_owned(),
                file_path: artifact["sanitizedSourcePath"].as_str().map(str::to_owned),
                line_number: None,
                record_number: None,
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: artifact["capturedUtc"].as_str().unwrap_or_default().to_owned(),
            sensitivity: IntuneSensitivity::Sensitive,
            parse_state: IntuneParseState::Parsed,
            access_state: if capture_state == "capped" {
                IntuneAccessState::Capped
            } else {
                IntuneAccessState::Available
            },
        },
        kind,
        content: std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display())),
    }
}

fn coverage_status(capture_state: &str) -> IntuneArtifactStatus {
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

fn analyze(scenario: &str) -> (UpdateSnapshot, Value, Value) {
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let snapshot = analyze_update_bundle(&build_bundle(scenario, &manifest));
    (snapshot, manifest, expected)
}

// ── Corpus contract ─────────────────────────────────────────────────────────

#[test]
fn the_corpus_holds_exactly_the_required_fixture_matrix() {
    assert_eq!(
        scenario_names(&corpus_root(CORPUS)),
        SCENARIOS.iter().map(|name| (*name).to_owned()).collect::<Vec<_>>(),
        "the fixture matrix of issue #365 is pinned; add or remove a scenario in both places"
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
    failures.assert_empty("intune windows updates corpus");
}

#[test]
fn a_corrupted_byte_count_is_still_rejected_in_this_corpus() {
    // Proof that the shared validator is actually running against this corpus
    // rather than passing vacuously.
    let scenario = "scan-failure";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let expected = load_json(&root.join("expected.json"));
    let failures = validate_scenario(
        scenario,
        &root,
        &mutated(&manifest, "/artifacts/0/bytesCopied", serde_json::json!(1)),
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

// ── Per-scenario expectations ───────────────────────────────────────────────

#[test]
fn every_scenario_reduces_to_its_stated_contract() {
    for scenario in SCENARIOS {
        let (snapshot, _, expected) = analyze(scenario);
        let actual = serde_json::to_value(&snapshot).expect("snapshot serializes");

        assert_policy_chain(scenario, &actual, &expected["policyChain"]);
        assert_update_chain(scenario, &actual, &expected["updateChain"]);

        assert_eq!(
            actual["linkage"]["state"], expected["linkage"]["state"],
            "{scenario}: chain linkage state"
        );
        for field in ["unmappedEventIds", "unknownProviderEvents"] {
            assert_eq!(
                actual["inputCoverage"][field], expected["inputCoverage"][field],
                "{scenario}: inputCoverage.{field}"
            );
        }
        assert_coverage(scenario, &actual, &expected);
        assert_findings(scenario, &actual, &expected);
    }
}

fn assert_policy_chain(scenario: &str, actual: &Value, expected: &Value) {
    let chain = &actual["policyChain"];
    assert_eq!(chain["state"], expected["state"], "{scenario}: policy state");
    assert_eq!(
        chain["workloadOwner"], expected["workloadOwner"],
        "{scenario}: workload owner"
    );
    assert_eq!(
        chain["conflicts"].as_array().expect("conflicts").len() as u64,
        expected["conflictCount"].as_u64().expect("conflictCount"),
        "{scenario}: conflict count"
    );
    for field in ["expected", "configured", "scanned", "matchesExpectation"] {
        // A `None` on the Rust side is skipped in the serialized form, so an
        // absent key and a JSON null both mean "not known".
        let observed = chain["effectiveSource"].get(field).unwrap_or(&Value::Null);
        let want = expected["effectiveSource"].get(field).unwrap_or(&Value::Null);
        assert_eq!(observed, want, "{scenario}: effectiveSource.{field}");
    }
}

fn assert_update_chain(scenario: &str, actual: &Value, expected: &Value) {
    let chain = &actual["updateChain"];
    assert_eq!(chain["state"], expected["state"], "{scenario}: update state");
    assert_eq!(
        chain.get("rebootPending").unwrap_or(&Value::Null),
        expected.get("rebootPending").unwrap_or(&Value::Null),
        "{scenario}: rebootPending"
    );
    assert_eq!(
        chain["unkeyedObservations"].as_array().unwrap().len() as u64,
        expected["unkeyedObservationCount"].as_u64().unwrap(),
        "{scenario}: unkeyed observation count"
    );

    let transactions = chain["transactions"].as_array().expect("transactions");
    let want = expected["transactions"].as_array().expect("transactions");
    assert_eq!(
        transactions.len(),
        want.len(),
        "{scenario}: transaction count, got keys {:?}",
        transactions.iter().map(|t| &t["key"]).collect::<Vec<_>>()
    );

    for (index, (transaction, want)) in transactions.iter().zip(want).enumerate() {
        let at = format!("{scenario}[{index}]");
        assert_eq!(
            transaction_label(transaction),
            want["key"].as_str().unwrap_or_default(),
            "{at}: transaction key"
        );
        assert_eq!(transaction["state"], want["state"], "{at}: state");
        assert_eq!(
            transaction["confidence"], want["confidence"],
            "{at}: confidence"
        );
        assert_eq!(
            transaction["orderContradiction"].as_bool().unwrap_or(false),
            want["orderContradiction"].as_bool().unwrap_or(false),
            "{at}: orderContradiction"
        );
        assert_eq!(
            transaction.get("serviceState").unwrap_or(&Value::Null),
            want.get("serviceState").unwrap_or(&Value::Null),
            "{at}: serviceState"
        );
        let corroborated = transaction
            .get("corroboratingEvidence")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty());
        assert_eq!(
            corroborated,
            want["corroborated"].as_bool().unwrap_or(false),
            "{at}: corroborated"
        );

        // A transaction that reached a terminal state must cite the update
        // client. Only `insufficientEvidence` may have nothing to cite.
        if transaction["state"] != "insufficientEvidence" {
            assert!(
                !transaction["evidence"].as_array().unwrap().is_empty(),
                "{at}: a terminal transaction must cite update-client evidence"
            );
        }
    }
}

/// Rebuild the human label the analyzer uses in finding ids, from the key.
fn transaction_label(transaction: &Value) -> String {
    let key = &transaction["key"];
    let revision = key.get("revision").and_then(Value::as_str);
    let primary = key
        .get("kbArticle")
        .and_then(Value::as_str)
        .or_else(|| key.get("updateId").and_then(Value::as_str));
    match (primary, revision) {
        (Some(id), Some(revision)) => format!("{id}.{revision}"),
        (Some(id), None) => id.to_owned(),
        (None, _) => "unidentified".to_owned(),
    }
}

fn assert_coverage(scenario: &str, actual: &Value, expected: &Value) {
    let observed: Vec<(String, String)> = actual["coverage"]
        .as_array()
        .expect("coverage")
        .iter()
        .map(|entry| {
            (
                entry["artifactId"].as_str().unwrap_or_default().to_owned(),
                entry["status"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let want: Vec<(String, String)> = expected["coverage"]
        .as_array()
        .expect("coverage")
        .iter()
        .map(|entry| {
            (
                entry["artifactId"].as_str().unwrap_or_default().to_owned(),
                entry["status"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let mut want_sorted = want;
    want_sorted.sort();
    assert_eq!(observed, want_sorted, "{scenario}: coverage");
}

fn assert_findings(scenario: &str, actual: &Value, expected: &Value) {
    let findings = actual["findings"].as_array().expect("findings");
    let want = expected["findings"].as_array().expect("findings");

    assert_eq!(
        findings
            .iter()
            .map(|finding| finding["findingId"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        want.iter()
            .map(|finding| finding["findingId"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        "{scenario}: finding ids, in derivation order"
    );

    for (finding, want) in findings.iter().zip(want) {
        let id = finding["findingId"].as_str().unwrap_or_default();
        assert_eq!(
            finding["severity"], want["severity"],
            "{scenario}/{id}: severity"
        );
        assert_eq!(
            finding["confidence"], want["confidence"],
            "{scenario}/{id}: confidence"
        );
        assert_eq!(
            finding["evidence"], want["evidence"],
            "{scenario}/{id}: cited evidence"
        );
        assert_eq!(
            finding["coverageGapIds"], want["coverageGapIds"],
            "{scenario}/{id}: cited coverage gaps"
        );
    }
}

// ── Corpus-wide invariants ──────────────────────────────────────────────────

#[test]
fn no_finding_is_an_uncited_assertion() {
    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);
        for finding in &snapshot.findings {
            assert!(
                finding.is_evidence_backed(),
                "{scenario}: finding {} cites neither evidence nor a coverage gap",
                finding.finding_id
            );
        }
    }
}

/// The central correctness constraint of issue #365.
///
/// An execution claim may cite only what the Windows Update client produced, or
/// a supplemental line that is already attached to a client-backed transaction.
/// A policy record can never appear in that citation list, which is what makes
/// "the update failed" structurally unable to become "Intune failed to deliver".
#[test]
fn update_execution_findings_never_cite_policy_evidence() {
    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);

        let policy_ids: BTreeSet<&str> = snapshot
            .policy_chain
            .observations
            .iter()
            .map(|observation| observation.context.evidence_ref.evidence_id.as_str())
            .collect();
        let update_ids: BTreeSet<&str> = snapshot
            .update_chain
            .evidence
            .iter()
            .map(|reference| reference.evidence_id.as_str())
            .chain(
                snapshot
                    .update_chain
                    .transactions
                    .iter()
                    .flat_map(|transaction| {
                        transaction
                            .corroborating_evidence
                            .iter()
                            .chain(transaction.service_evidence.iter())
                    })
                    .map(|reference| reference.evidence_id.as_str()),
            )
            .collect();

        for finding in &snapshot.findings {
            if !finding.finding_id.starts_with(UPDATE_FINDING_PREFIX) {
                continue;
            }
            assert!(
                !finding.evidence.is_empty(),
                "{scenario}: {} makes an execution claim with no citation",
                finding.finding_id
            );
            for reference in &finding.evidence {
                let id = reference.evidence_id.as_str();
                assert!(
                    update_ids.contains(id),
                    "{scenario}: {} cites {id}, which the update chain never produced",
                    finding.finding_id
                );
                assert!(
                    !policy_ids.contains(id),
                    "{scenario}: {} cites policy evidence {id}",
                    finding.finding_id
                );
            }
        }
    }
}

/// The mirror invariant: a policy claim may not rest on update-client records.
///
/// The single sanctioned exception is the effective-source finding, which is a
/// statement about the one identifier both chains genuinely refer to.
#[test]
fn policy_findings_never_rest_on_update_client_evidence() {
    let source_finding = format!("{POLICY_FINDING_PREFIX}/effective-source-mismatch");

    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);

        let mut policy_ids: BTreeSet<&str> = snapshot
            .policy_chain
            .observations
            .iter()
            .map(|observation| observation.context.evidence_ref.evidence_id.as_str())
            .collect();
        if let Some(context) = snapshot.device.context.as_ref() {
            policy_ids.insert(context.evidence_ref.evidence_id.as_str());
        }

        for finding in &snapshot.findings {
            if !finding.finding_id.starts_with(POLICY_FINDING_PREFIX)
                || finding.finding_id == source_finding
            {
                continue;
            }
            for reference in &finding.evidence {
                assert!(
                    policy_ids.contains(reference.evidence_id.as_str()),
                    "{scenario}: {} cites {}, which is not policy evidence",
                    finding.finding_id,
                    reference.evidence_id
                );
            }
        }
    }
}

#[test]
fn a_terminal_update_state_is_never_read_from_supplemental_evidence_alone() {
    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);
        for transaction in &snapshot.update_chain.transactions {
            if transaction.evidence.is_empty() {
                assert_eq!(
                    serde_json::to_value(transaction.state).unwrap(),
                    Value::String("insufficientEvidence".to_owned()),
                    "{scenario}: {} reached a terminal state on supplemental evidence alone",
                    transaction.key.label()
                );
            }
        }
    }
}

#[test]
fn every_finding_id_uses_a_documented_prefix() {
    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);
        for finding in &snapshot.findings {
            assert!(
                finding.finding_id.starts_with(POLICY_FINDING_PREFIX)
                    || finding.finding_id.starts_with(UPDATE_FINDING_PREFIX)
                    || finding.finding_id.starts_with(EVIDENCE_FINDING_PREFIX),
                "{scenario}: finding id {} uses an undocumented prefix",
                finding.finding_id
            );
        }
    }
}

// ── Serialized shape ────────────────────────────────────────────────────────

#[test]
fn the_serialized_snapshot_keeps_its_documented_camel_case_shape() {
    // Pins the wire contract without a whole-document golden that would churn on
    // every fixture edit. New fields must be additive, so this asserts the
    // documented keys are present, not that no others are.
    let (snapshot, _, _) = analyze("policy-applied-update-installed-reboot-complete");
    let value = serde_json::to_value(&snapshot).expect("snapshot serializes");

    for key in [
        "schemaVersion",
        "generatedAtUtc",
        "device",
        "policyChain",
        "updateChain",
        "linkage",
        "inputCoverage",
        "coverage",
        "findings",
    ] {
        assert!(value.get(key).is_some(), "snapshot is missing key {key:?}");
    }
    for key in ["state", "workloadOwner", "effectiveSource", "observations", "conflicts",
                "evidence", "confidence"] {
        assert!(
            value["policyChain"].get(key).is_some(),
            "policyChain is missing key {key:?}"
        );
    }
    for key in ["state", "transactions", "unkeyedObservations", "evidence"] {
        assert!(
            value["updateChain"].get(key).is_some(),
            "updateChain is missing key {key:?}"
        );
    }
    assert_eq!(value["schemaVersion"], 1);
}

// ── Redacted export ─────────────────────────────────────────────────────────

#[test]
fn the_default_export_carries_no_policy_value_and_no_file_path() {
    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);
        let exported = redacted_export_projection(&snapshot);

        for observation in &exported.policy_chain.observations {
            if let Some(value) = &observation.value {
                assert_eq!(
                    value, REDACTED,
                    "{scenario}: a policy value survived the export"
                );
            }
            assert!(
                observation.context.provenance.file_path.is_none(),
                "{scenario}: a file path survived the export"
            );
        }
        for observation in &exported.update_chain.unkeyed_observations {
            assert!(
                observation.context.provenance.file_path.is_none(),
                "{scenario}: a file path survived the export"
            );
        }
        if let Some(context) = exported.device.context.as_ref() {
            assert!(
                context.provenance.file_path.is_none(),
                "{scenario}: a device-fact file path survived the export"
            );
        }
    }
}

#[test]
fn the_export_removes_the_tenant_shaped_values_the_privacy_scenario_plants() {
    let scenario = "privacy-safe-deterministic-export";
    let (snapshot, _, _) = analyze(scenario);

    let raw = serde_json::to_string(&snapshot).expect("snapshot serializes");
    assert!(
        raw.contains("wsus.example.invalid"),
        "{scenario} must plant a tenant-shaped value for the export to remove"
    );

    let exported = serde_json::to_string(&redacted_export_projection(&snapshot))
        .expect("export serializes");
    assert!(
        !exported.contains("wsus.example.invalid"),
        "{scenario}: the planted value survived the export"
    );
    assert!(
        !exported.contains("Contoso Synthetic"),
        "{scenario}: a tenant display name survived the export"
    );
    // Microsoft-defined identifiers name no one and must survive, or the export
    // stops being diagnosable.
    assert!(
        exported.contains("aaaaaaaa-0000-0000-0000-000000000012"),
        "{scenario}: the update identity must survive the export"
    );
}

#[test]
fn the_export_is_a_pure_function_of_the_snapshot() {
    for scenario in SCENARIOS {
        let (snapshot, _, _) = analyze(scenario);
        let first = serde_json::to_string(&redacted_export_projection(&snapshot)).unwrap();
        let second = serde_json::to_string(&redacted_export_projection(&snapshot)).unwrap();
        assert_eq!(first, second, "{scenario}: export is not deterministic");
    }
}

#[test]
fn re_reducing_the_same_bundle_produces_the_same_snapshot() {
    for scenario in SCENARIOS {
        let root = scenario_root(scenario);
        let manifest = load_json(&root.join("manifest.json"));
        let bundle = build_bundle(scenario, &manifest);
        let first = serde_json::to_string(&analyze_update_bundle(&bundle)).unwrap();
        let second = serde_json::to_string(&analyze_update_bundle(&bundle)).unwrap();
        assert_eq!(first, second, "{scenario}: reduction is not deterministic");
    }
}
