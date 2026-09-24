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
    analyze_update_bundle, redacted_export_projection, PolicyChainState, SupplementalLogKind,
    UpdateChainState, UpdateEvidenceBundle, UpdateSnapshot, UpdateSource, UpdateSupplementalLog,
    EVIDENCE_FINDING_PREFIX, POLICY_FINDING_PREFIX, REDACTED, UPDATE_FINDING_PREFIX,
};
use cmtraceopen_parser::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneEvidenceRef,
    IntuneFindingConfidence, IntuneObservationContext, IntuneParseState, IntuneProvenance,
    IntuneSensitivity, IntuneSourceKind,
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
            observed_at_utc: artifact["capturedUtc"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
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
                        panic!(
                            "{}: device facts do not deserialize: {error}",
                            path.display()
                        )
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
            observed_at_utc: artifact["capturedUtc"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
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
        SCENARIOS
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
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
    assert_eq!(
        chain["state"], expected["state"],
        "{scenario}: policy state"
    );
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
        let want = expected["effectiveSource"]
            .get(field)
            .unwrap_or(&Value::Null);
        assert_eq!(observed, want, "{scenario}: effectiveSource.{field}");
    }
}

fn assert_update_chain(scenario: &str, actual: &Value, expected: &Value) {
    let chain = &actual["updateChain"];
    assert_eq!(
        chain["state"], expected["state"],
        "{scenario}: update state"
    );
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
    for key in [
        "state",
        "workloadOwner",
        "effectiveSource",
        "observations",
        "conflicts",
        "evidence",
        "confidence",
    ] {
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

    let exported =
        serde_json::to_string(&redacted_export_projection(&snapshot)).expect("export serializes");
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

/// A record the adapter could not parse, or read without permission, is a
/// coverage state rather than a reading.
///
/// An earlier revision of this leaf classified such records like any other, so a
/// malformed, access-denied install could establish an `Installed` transaction
/// at High confidence. The excluded records stay visible instead of vanishing:
/// the snapshot counts them under its input coverage.
#[test]
fn a_record_that_could_not_be_read_never_establishes_a_state() {
    let scenario = "policy-applied-update-installed-reboot-complete";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let mut bundle = build_bundle(scenario, &manifest);
    assert!(
        !bundle.events.is_empty(),
        "{scenario}: this test needs client events to exclude"
    );
    for event in &mut bundle.events {
        event.context.parse_state = IntuneParseState::Malformed;
        event.context.access_state = IntuneAccessState::PermissionDenied;
    }

    let snapshot = analyze_update_bundle(&bundle);
    assert_eq!(
        snapshot.update_chain.state,
        UpdateChainState::NotObserved,
        "{scenario}: unreadable records must not establish an update state"
    );
    assert!(
        snapshot.input_coverage.unusable_records > 0,
        "{scenario}: the excluded records must stay visible as coverage"
    );
    assert!(
        snapshot
            .findings
            .iter()
            .any(|finding| finding.finding_id.ends_with("/unusable-records")),
        "{scenario}: excluding records must produce a finding that says so"
    );
}

/// "No restart is pending" is a claim about the device, and a capture that lost
/// or truncated the client's own records cannot support it: the absence of a
/// pending record there is not evidence that the restart completed.
#[test]
fn a_truncated_client_capture_cannot_claim_no_restart_is_pending() {
    let scenario = "policy-applied-update-installed-reboot-complete";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let bundle = build_bundle(scenario, &manifest);
    assert_eq!(
        analyze_update_bundle(&bundle).update_chain.reboot_pending,
        Some(false),
        "{scenario}: the complete capture can support the claim"
    );

    let mut capped = bundle.clone();
    for entry in &mut capped.coverage {
        if entry.family == "windowsUpdateClient" {
            entry.status = IntuneArtifactStatus::Capped;
        }
    }
    assert_eq!(
        analyze_update_bundle(&capped).update_chain.reboot_pending,
        None,
        "{scenario}: a truncated client capture must not claim that no restart is pending"
    );
}

/// An unusable artifact that could never have carried policy does not explain a
/// silent policy chain.
///
/// Pooling every unusable artifact into the policy finding made a missing
/// supplemental servicing log read as the reason no policy record was seen.
#[test]
fn an_unusable_servicing_log_does_not_explain_a_missing_policy_record() {
    let servicing_only = UpdateEvidenceBundle {
        coverage: vec![coverage_entry(
            "cbs-log",
            "servicing",
            IntuneArtifactStatus::Missing,
        )],
        ..Default::default()
    };
    assert!(
        !has_policy_not_observed(&analyze_update_bundle(&servicing_only)),
        "a missing servicing log must not be cited as the reason no policy record was seen"
    );

    let with_policy_gap = UpdateEvidenceBundle {
        coverage: vec![
            coverage_entry("cbs-log", "servicing", IntuneArtifactStatus::Missing),
            coverage_entry(
                "mdm-admin-events",
                "mdmDiagnostics",
                IntuneArtifactStatus::Missing,
            ),
        ],
        ..Default::default()
    };
    assert!(
        has_policy_not_observed(&analyze_update_bundle(&with_policy_gap)),
        "a missing policy-bearing artifact does explain it"
    );
}

fn coverage_entry(
    artifact_id: &str,
    family: &str,
    status: IntuneArtifactStatus,
) -> IntuneArtifactCoverage {
    IntuneArtifactCoverage {
        artifact_id: artifact_id.to_owned(),
        family: family.to_owned(),
        status,
        detail: None,
        observed_at_utc: "2026-07-31T03:00:00Z".to_owned(),
        evidence: Vec::new(),
    }
}

fn has_policy_not_observed(snapshot: &UpdateSnapshot) -> bool {
    snapshot
        .findings
        .iter()
        .any(|finding| finding.finding_id == "intune/windows/updates/policy/not-observed")
}

/// "No restart is pending" is withheld when the capture never described the
/// client channel at all, not only when it described it as truncated.
#[test]
fn an_undescribed_client_capture_cannot_claim_no_restart_is_pending() {
    let scenario = "policy-applied-update-installed-reboot-complete";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let mut undescribed = build_bundle(scenario, &manifest);
    undescribed
        .coverage
        .retain(|entry| entry.family != "windowsUpdateClient");

    assert_eq!(
        analyze_update_bundle(&undescribed)
            .update_chain
            .reboot_pending,
        None,
        "{scenario}: an undescribed client channel is not an empty one"
    );
}

/// A claim that turns on recency is only as good as the readings that make it.
///
/// Deleting the timestamps is the counterexample: with the placeability question
/// asked only of device-level readings, the pending reading has joined a
/// transaction and the question goes unanswered.
#[test]
fn a_pending_restart_no_one_can_place_in_time_is_not_high_confidence() {
    let scenario = "reboot-pending";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let bundle = build_bundle(scenario, &manifest);
    assert_eq!(
        reboot_confidence(&analyze_update_bundle(&bundle)),
        Some(IntuneFindingConfidence::High),
        "{scenario}: a placed capture supports the High-confidence claim"
    );

    let mut unplaced = bundle.clone();
    for event in &mut unplaced.events {
        event.context.source_timestamp = None;
    }
    assert_eq!(
        reboot_confidence(&analyze_update_bundle(&unplaced)),
        Some(IntuneFindingConfidence::Medium),
        "{scenario}: a pending reading nobody can place cannot be High confidence"
    );
}

/// A record nobody could read is not evidence of the workload owner.
#[test]
fn an_unreadable_device_record_is_not_evidence_of_the_workload_owner() {
    let scenario = "co-management-workload-not-owned-by-intune";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let mut bundle = build_bundle(scenario, &manifest);
    let context = bundle
        .device
        .context
        .as_mut()
        .expect("this scenario supplies device facts with a context");
    context.parse_state = IntuneParseState::Malformed;
    context.access_state = IntuneAccessState::PermissionDenied;

    let snapshot = analyze_update_bundle(&bundle);
    assert_ne!(
        snapshot.policy_chain.state,
        PolicyChainState::NotOwnedByIntune,
        "{scenario}: ownership cannot be concluded from a record nobody could read"
    );
    assert_eq!(
        snapshot.input_coverage.unusable_records, 1,
        "{scenario}: the excluded device record stays visible"
    );
}

/// The two evidence findings cite their own records: one is about records that
/// were read and did not map, the other about records that could not be read.
#[test]
fn unreadable_records_and_unmapped_records_are_not_pooled() {
    let scenario = "scan-failure";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let mut bundle = build_bundle(scenario, &manifest);
    assert!(
        !bundle.events.is_empty(),
        "{scenario}: needs a template event"
    );

    let mut unreadable = bundle.events[0].clone();
    unreadable.context.evidence_ref = evidence_ref("denied-1", "denied-artifact");
    unreadable.context.parse_state = IntuneParseState::Malformed;
    unreadable.context.access_state = IntuneAccessState::PermissionDenied;

    let mut unmapped = bundle.events[0].clone();
    unmapped.event_id = 9999;
    unmapped.context.evidence_ref = evidence_ref("unmapped-1", "unmapped-artifact");
    unmapped.context.parse_state = IntuneParseState::Parsed;
    unmapped.context.access_state = IntuneAccessState::Available;

    bundle.events = vec![unreadable, unmapped];
    bundle.setting_reports.clear();
    bundle.registry_facts.clear();
    bundle.supplemental_logs.clear();
    bundle.service_reports.clear();

    let snapshot = analyze_update_bundle(&bundle);
    assert_eq!(
        cited_evidence(&snapshot, "intune/windows/updates/evidence/unknown-schema"),
        vec!["unmapped-1".to_owned()],
        "{scenario}: the unmapped finding cites the record that was read"
    );
    assert_eq!(
        cited_evidence(
            &snapshot,
            "intune/windows/updates/evidence/unusable-records"
        ),
        vec!["denied-1".to_owned()],
        "{scenario}: the unusable finding cites the record that was not"
    );
}

/// No collection times are compared, so the mismatch must not say which reading
/// is current. This is the guard against the sentence that used to claim the
/// local record was the more recent of the two.
#[test]
fn the_reporting_mismatch_does_not_claim_which_reading_is_current() {
    let (snapshot, _, _) = analyze("local-success-stale-service-report");
    let mismatch = snapshot
        .findings
        .iter()
        .find(|finding| finding.finding_id.contains("reporting-mismatch"))
        .expect("this scenario has a device/service disagreement");
    assert!(
        !mismatch.summary.contains("more recent"),
        "the mismatch summary claims recency without comparing timestamps: {}",
        mismatch.summary
    );
}

/// Identity planted in the fields the export keeps for diagnosis is scrubbed
/// there too, not only in the fields this leaf classifies as sensitive.
#[test]
fn identity_in_caller_supplied_text_does_not_survive_the_export() {
    let scenario = "policy-applied-update-installed-reboot-complete";
    let root = scenario_root(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    let mut snapshot = analyze_update_bundle(&build_bundle(scenario, &manifest));
    assert!(
        !snapshot.policy_chain.observations.is_empty()
            && !snapshot.update_chain.transactions.is_empty(),
        "{scenario}: this test needs observations and a transaction"
    );

    let upn = "adam.admin@contoso.example.com";
    let profile = r"C:\Users\adam.admin\AppData\Local\Temp";
    snapshot.policy_chain.observations[0].policy_id = Some(upn.to_owned());
    snapshot.policy_chain.observations[0].source = Some(UpdateSource::Unknown(profile.to_owned()));
    snapshot.update_chain.transactions[0].title = Some(format!("Cumulative update for {upn}"));
    snapshot.findings[0].summary = format!("Reported by {upn} from {profile}");
    snapshot.input_coverage.unknown_providers = vec![format!("Provider mentioning {upn}")];
    snapshot.input_coverage.extraction_profile = Some(format!("profile-for-{upn}"));

    let raw = serde_json::to_string(&snapshot).expect("snapshot serializes");
    assert!(
        raw.contains(upn),
        "the planted identity has to be present before the export can be judged"
    );

    let exported =
        serde_json::to_string(&redacted_export_projection(&snapshot)).expect("export serializes");
    assert!(!exported.contains(upn), "a UPN survived the export");
    assert!(
        !exported.contains("adam.admin"),
        "a user profile name survived the export"
    );
}

fn evidence_ref(evidence_id: &str, artifact_id: &str) -> IntuneEvidenceRef {
    IntuneEvidenceRef {
        evidence_id: evidence_id.to_owned(),
        source_artifact_id: artifact_id.to_owned(),
    }
}

fn cited_evidence(snapshot: &UpdateSnapshot, finding_id: &str) -> Vec<String> {
    snapshot
        .findings
        .iter()
        .find(|finding| finding.finding_id == finding_id)
        .map(|finding| {
            finding
                .evidence
                .iter()
                .map(|evidence| evidence.evidence_id.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn reboot_confidence(snapshot: &UpdateSnapshot) -> Option<IntuneFindingConfidence> {
    snapshot
        .findings
        .iter()
        .find(|finding| finding.finding_id.ends_with("/update/reboot-pending"))
        .map(|finding| finding.confidence.clone())
}

/// The snapshot is a function of the readings, not of the order the caller
/// happened to collect them in.
///
/// `re_reducing_the_same_bundle_produces_the_same_snapshot` pins repeatability
/// over one input order; this pins invariance across orders. The terminal state
/// is the *last* decisive update-client reading, so "last" has to mean last in
/// time -- resolved from the record's own timestamp -- rather than last in the
/// order the artifact happened to be listed. An independent audit of an earlier
/// revision of this leaf reproduced the opposite: reversing the same records
/// moved a transaction from `Installed / contradiction=true` to
/// `InProgress / false` and changed the selected scan source.
#[test]
fn reversal_of_the_same_bundle_produces_the_same_snapshot() {
    for scenario in SCENARIOS {
        let root = scenario_root(scenario);
        let manifest = load_json(&root.join("manifest.json"));
        let forward = build_bundle(scenario, &manifest);
        let mut reversed = forward.clone();
        reversed.events.reverse();
        reversed.setting_reports.reverse();
        reversed.registry_facts.reverse();
        reversed.service_reports.reverse();
        reversed.supplemental_logs.reverse();

        let left = serde_json::to_string(&analyze_update_bundle(&forward)).unwrap();
        let right = serde_json::to_string(&analyze_update_bundle(&reversed)).unwrap();
        assert_eq!(
            left, right,
            "{scenario}: reversing the bundle changed the snapshot"
        );
    }
}
