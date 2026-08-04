use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_software_update_point, assess_server_intake, SccmServerArtifactPayload,
    SccmServerIntakeAssessment,
};
use serde_json::Value;

const SCENARIOS: &[&str] = &[
    "incomplete",
    "metadata-failure",
    "rotation-boundary",
    "sup-setup-failure",
    "supplemental-wsus-skipped",
    "sync-retry",
    "sync-success",
    "unrelated-update-key",
    "wcm-configuration-failure",
    "wsus-health-failure",
];

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/software_update_point")
}

fn load_canonical_intake_scenario(scenario: &str) -> SccmServerIntakeAssessment {
    let scenario_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/intake")
        .join(scenario);
    let manifest_json = std::fs::read_to_string(scenario_root.join("manifest.json"))
        .expect("canonical manifest is readable");
    let manifest: Value =
        serde_json::from_str(&manifest_json).expect("canonical manifest is valid JSON");
    let payloads = manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array")
        .iter()
        .filter_map(|artifact| {
            let relative_path = artifact["relativePath"].as_str()?;
            Some(SccmServerArtifactPayload {
                manifest_artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifact ID is a string")
                    .to_owned(),
                bytes: std::fs::read(scenario_root.join(relative_path))
                    .expect("captured payload is readable"),
            })
        })
        .collect::<Vec<_>>();
    assess_server_intake(&manifest_json, &payloads).expect("canonical intake is accepted")
}

fn load_scenario(scenario: &str) -> (SccmServerIntakeAssessment, Value) {
    let (manifest, payloads) = prepared_scenario(scenario);
    let expected_json = std::fs::read_to_string(corpus_root().join(scenario).join("expected.json"))
        .expect("expected output is readable");
    let expected = serde_json::from_str(&expected_json).expect("expected output is valid JSON");
    (assess_prepared_manifest(manifest, &payloads), expected)
}

fn prepared_scenario(scenario: &str) -> (Value, Vec<SccmServerArtifactPayload>) {
    let (mut manifest, payloads) = raw_scenario(scenario);
    canonicalize_preparation_manifest(&mut manifest);
    (manifest, payloads)
}

fn raw_scenario(scenario: &str) -> (Value, Vec<SccmServerArtifactPayload>) {
    let scenario_root = corpus_root().join(scenario);
    let manifest_json =
        std::fs::read_to_string(scenario_root.join("manifest.json")).expect("manifest is readable");
    let manifest: Value = serde_json::from_str(&manifest_json).expect("manifest is valid JSON");
    let payloads = manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array")
        .iter()
        .filter_map(|artifact| {
            if artifact["producerRole"] == "client" {
                return None;
            }
            let relative_path = artifact["relativePath"].as_str()?;
            Some(SccmServerArtifactPayload {
                manifest_artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifact ID is a string")
                    .to_owned(),
                bytes: std::fs::read(scenario_root.join(relative_path))
                    .expect("captured payload is readable"),
            })
        })
        .collect::<Vec<_>>();
    (manifest, payloads)
}

fn assess_prepared_manifest(
    manifest: Value,
    payloads: &[SccmServerArtifactPayload],
) -> SccmServerIntakeAssessment {
    let canonical_manifest = serde_json::to_string(&manifest).expect("manifest serializes");
    assess_server_intake(&canonical_manifest, payloads).unwrap_or_else(|error| {
        panic!("fixture is accepted by canonical server intake: {error:?}\n{canonical_manifest}")
    })
}

fn canonicalize_preparation_manifest(manifest: &mut Value) {
    // The committed #330 corpus predates the reviewed #335 wire shape. This
    // test-only bridge changes structural capture metadata only; artifact IDs,
    // source versions, workflow-subject handles, and evidence bytes remain the
    // corpus values judged by the production reducer.
    let root = manifest.as_object_mut().expect("manifest is an object");
    root.remove("scenario");
    let bundle = root
        .remove("bundle")
        .expect("preparation manifest has bundle metadata");
    root.insert("bundleRole".to_owned(), bundle["bundleRole"].clone());
    root.insert(
        "privacy".to_owned(),
        serde_json::json!({ "synthetic": true, "rawPaths": "redacted" }),
    );

    let topology = root["topology"]
        .as_object_mut()
        .expect("topology is an object");
    topology.remove("supHandle");
    topology.remove("wsusHandle");
    topology.insert(
        "captureHost".to_owned(),
        Value::String("LAB-CM01".to_owned()),
    );

    root["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        // Canonical server intake is server-only. The client control proves
        // that #330 does not ingest #323 output or perform #333 correlation.
        .retain(|artifact| artifact["producerRole"] != "client");
    let artifacts = root["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array");
    let mut lineages = BTreeMap::<String, String>::new();
    let lineage_slots = ["sitecomp-a", "sitecomp-lab", "sup-sync-cap", "sup-sync-lab"];
    let fingerprint_slots = [
        "synthetic:path:a-mp",
        "synthetic:path:a-site",
        "synthetic:path:site-default",
        "synthetic:path:site-sup-control",
    ];

    for (index, artifact) in artifacts.iter_mut().enumerate() {
        let producer_role = artifact["producerRole"]
            .as_str()
            .expect("producer role is a string")
            .to_owned();
        let producer_host = if producer_role == "wsUs" {
            "synthetic:host:wsus-01"
        } else {
            "synthetic:host:site-01"
        };
        artifact["producerHostHandle"] = Value::String(producer_host.to_owned());

        let subject_role = artifact
            .as_object_mut()
            .expect("artifact is an object")
            .remove("workflowSubjectRole")
            .expect("workflow subject role is present");
        let subject_handle = artifact
            .as_object_mut()
            .expect("artifact is an object")
            .remove("workflowSubjectHandle")
            .expect("workflow subject handle is present");
        artifact["workflowSubject"] = serde_json::json!({
            "role": subject_role,
            "instanceHandle": subject_handle,
        });
        artifact["originalPath"] = Value::String("REDACTED_SUP_SOURCE".to_owned());
        artifact["configuredPathProvenance"] = serde_json::json!({
            "state": "configured",
            "pathFingerprint": fingerprint_slots[index],
        });
        artifact
            .as_object_mut()
            .expect("artifact is an object")
            .remove("sanitizedSourcePath");
        artifact
            .as_object_mut()
            .expect("artifact is an object")
            .remove("pathFingerprint");

        let source_id = artifact["sourceId"]
            .as_str()
            .expect("source ID is a string")
            .to_owned();
        let mut basename = artifact["originalBasename"]
            .as_str()
            .expect("basename is a string")
            .to_owned();
        if artifact["rotation"]["kind"] == "lo_" {
            basename = format!("{}.lo_", basename.trim_end_matches(".log"));
            artifact["originalBasename"] = Value::String(basename.clone());
        }
        let original_lineage = artifact["rotation"]["lineageId"]
            .as_str()
            .expect("lineage is a string")
            .to_owned();
        let rotation_fragment_complete = artifact["rotation"]
            .as_object_mut()
            .expect("rotation is an object")
            .remove("fragmentComplete")
            .and_then(|value| value.as_bool());

        if source_id == "server-sup-wsus" {
            artifact["producerHostHandle"] = Value::String("synthetic:host:wsus-01".to_owned());
            artifact["sourceVersion"] = Value::String("5.00.TEST".to_owned());
            artifact["configuredPathProvenance"]["pathFingerprint"] =
                Value::String("synthetic:path:sup-wsus-health".to_owned());
            artifact["rotation"] = serde_json::json!({
                "kind": "providerDefined",
                "lineageId": "sup-wsus-health",
            });
        } else {
            let next_slot = lineages.len();
            let canonical_lineage = lineages
                .entry(original_lineage)
                .or_insert_with(|| lineage_slots[next_slot].to_owned())
                .clone();
            artifact["rotation"]["lineageId"] = Value::String(canonical_lineage);
            if rotation_fragment_complete == Some(false) {
                artifact["truncated"] = Value::Bool(false);
                artifact["fragmentComplete"] = Value::Bool(false);
            }
        }

        if artifact["bytesCopied"].is_null() {
            artifact["bytesCopied"] = Value::from(0);
        }
        if artifact["relativePath"].is_string() {
            let role_segment = if producer_role == "siteServer" {
                "site-server"
            } else {
                "software-update-point"
            };
            let rotation_segment = if artifact["rotation"]["kind"] == "lo_" {
                "lo_"
            } else {
                "current"
            };
            artifact["relativePath"] = Value::String(format!(
                "evidence/sccm/server/{role_segment}/{source_id}/subject-software-update-point/{rotation_segment}/{basename}"
            ));
        }
    }
}

fn production_projection(mut expected: Value) -> Value {
    let object = expected
        .as_object_mut()
        .expect("expected output is an object");
    object.remove("contractState");
    object.remove("scenario");
    object["coverage"]
        .as_array_mut()
        .expect("coverage is an array")
        .retain(|row| row["artifactId"] != "unrelated-01-client");
    object["sourceLocalObservations"]
        .as_array_mut()
        .expect("source-local observations are an array")
        .retain(|observation| observation["classification"] != "ignoredClientEvidence");
    for request in object["artifactRequests"]
        .as_array_mut()
        .expect("artifact requests are an array")
    {
        request["supHandle"] = Value::String("safe:sup:lab-sup-01".to_owned());
    }
    expected
}

#[test]
fn every_committed_scenario_runs_through_the_exported_production_analyzer() {
    for scenario in SCENARIOS {
        let (intake, expected) = load_scenario(scenario);
        let actual = serde_json::to_value(analyze_software_update_point(&intake))
            .expect("analysis serializes");

        assert_eq!(
            actual,
            production_projection(expected),
            "scenario {scenario}"
        );
    }
}

#[test]
fn sealed_input_order_does_not_change_the_analysis() {
    let (intake, _) = load_scenario("sync-success");
    let mut reordered = intake.clone();
    reordered.artifacts.reverse();
    reordered.coverage.reverse();
    reordered.evidence.reverse();
    reordered.next_artifact_requests.reverse();
    reordered.topology.roles_observed.reverse();

    assert_eq!(
        serde_json::to_vec(&analyze_software_update_point(&intake))
            .expect("original analysis serializes"),
        serde_json::to_vec(&analyze_software_update_point(&reordered))
            .expect("reordered analysis serializes")
    );
}

#[test]
fn tampered_canonical_intake_fails_closed() {
    let (mut intake, _) = load_scenario("sync-success");
    intake.artifacts[0].artifact_id = "forged-artifact".to_owned();

    let serialized = serde_json::to_value(analyze_software_update_point(&intake))
        .expect("fail-closed analysis serializes");

    assert_eq!(serialized["transactions"], serde_json::json!([]));
    assert_eq!(serialized["sourceLocalObservations"], serde_json::json!([]));
    assert_eq!(serialized["artifactRequests"], serde_json::json!([]));
    assert_eq!(serialized["clientCausalClaims"], serde_json::json!([]));
    assert_eq!(serialized["correlationHandoff"]["performed"], false);
}

#[test]
fn an_unregistered_source_profile_cannot_emit_transactions() {
    let intake = load_canonical_intake_scenario("complete-multi-role");

    let serialized =
        serde_json::to_value(analyze_software_update_point(&intake)).expect("analysis serializes");

    assert_eq!(
        serialized["extractionProfile"]["selectionState"],
        "unavailable"
    );
    assert!(serialized["extractionProfile"]["profileId"].is_null());
    assert_eq!(serialized["transactions"], serde_json::json!([]));
}

#[test]
fn required_coverage_gap_overrides_retry_deferred_classification() {
    let (mut manifest, payloads) = raw_scenario("sync-retry");
    let incomplete_manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(corpus_root().join("incomplete/manifest.json"))
            .expect("incomplete manifest is readable"),
    )
    .expect("incomplete manifest is valid JSON");
    let denied = incomplete_manifest["artifacts"][1].clone();
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .push(denied);
    canonicalize_preparation_manifest(&mut manifest);

    let serialized = serde_json::to_value(analyze_software_update_point(
        &assess_prepared_manifest(manifest, &payloads),
    ))
    .expect("analysis serializes");
    let transaction = &serialized["transactions"][0];

    assert_eq!(transaction["state"], "incomplete");
    assert_eq!(transaction["classification"], "insufficientEvidence");
    assert_eq!(transaction["confidence"], "low");
    assert_eq!(
        transaction["coverageGapArtifactIds"],
        serde_json::json!(["incomplete-02-wsync-denied"])
    );
}

#[test]
fn coverage_gaps_and_requests_are_scoped_to_the_exact_sup_subject() {
    let (mut manifest, payloads) = raw_scenario("sync-success");
    let incomplete_manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(corpus_root().join("incomplete/manifest.json"))
            .expect("incomplete manifest is readable"),
    )
    .expect("incomplete manifest is valid JSON");
    let mut foreign_gap = incomplete_manifest["artifacts"][1].clone();
    foreign_gap["workflowSubjectHandle"] = Value::String("synthetic:subject:sup-01".to_owned());
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .push(foreign_gap);
    canonicalize_preparation_manifest(&mut manifest);

    let serialized = serde_json::to_value(analyze_software_update_point(
        &assess_prepared_manifest(manifest, &payloads),
    ))
    .expect("analysis serializes");
    let transaction = &serialized["transactions"][0];

    assert_eq!(transaction["state"], "succeeded");
    assert_eq!(transaction["confidence"], "high");
    assert_eq!(transaction["coverageGapArtifactIds"], serde_json::json!([]));
    assert_eq!(
        serialized["artifactRequests"],
        serde_json::json!([{
            "supHandle": "synthetic:subject:sup-01",
            "sourceId": "server-sup-sync",
            "reasonCode": "coverageAccessDenied",
        }])
    );
}

#[test]
fn captured_uninterpreted_wsus_supplement_keeps_the_confidence_ceiling() {
    let (mut manifest, mut payloads) = prepared_scenario("supplemental-wsus-skipped");
    let supplemental = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "supplemental-04-wsus-health")
        .expect("supplemental artifact exists");
    let supplement_bytes = br#"{}"#.to_vec();
    supplemental["captureState"] = Value::String("captured".to_owned());
    supplemental["rotation"] = serde_json::json!({
        "kind": "current",
        "lineageId": "sup-wsus-health",
    });
    supplemental["encoding"] = Value::String("utf-8".to_owned());
    supplemental["collectionLimit"] =
        serde_json::json!({ "byteLimit": 4096, "limitApplied": false });
    supplemental["bytesCopied"] = Value::from(supplement_bytes.len());
    supplemental["relativePath"] = Value::String(
        "evidence/sccm/server/wsus/server-sup-wsus/subject-software-update-point/current/WsusHealth.json"
            .to_owned(),
    );
    payloads.push(SccmServerArtifactPayload {
        manifest_artifact_id: "supplemental-04-wsus-health".to_owned(),
        bytes: supplement_bytes,
    });

    let serialized = serde_json::to_value(analyze_software_update_point(
        &assess_prepared_manifest(manifest, &payloads),
    ))
    .expect("analysis serializes");

    assert_eq!(serialized["transactions"][0]["state"], "succeeded");
    assert_eq!(serialized["transactions"][0]["confidence"], "medium");
    assert_eq!(serialized["transactions"][0]["confidenceCeiling"], "medium");
}

#[test]
fn tied_or_unusable_timestamps_fail_closed_without_artifact_id_chronology() {
    let (mut manifest, mut tied_payloads) = prepared_scenario("sync-success");
    let wsync = tied_payloads
        .iter_mut()
        .find(|payload| payload.manifest_artifact_id == "sync-success-02-wsync")
        .expect("wsync payload exists");
    let content = String::from_utf8(wsync.bytes.clone()).expect("fixture is UTF-8");
    wsync.bytes = content
        .replacen("14:01:00.000+000", "14:00:00.000+000", 1)
        .into_bytes();
    let tied =
        analyze_software_update_point(&assess_prepared_manifest(manifest.clone(), &tied_payloads));
    assert!(tied.transactions.is_empty());

    let (_, mut unusable_payloads) = prepared_scenario("sync-success");
    let wcm = unusable_payloads
        .iter_mut()
        .find(|payload| payload.manifest_artifact_id == "sync-success-01-wcm")
        .expect("WCM payload exists");
    let content = String::from_utf8(wcm.bytes.clone()).expect("fixture is UTF-8");
    wcm.bytes = content
        .replacen("14:00:00.000+000", "14:00:00.000+9999", 1)
        .into_bytes();
    let wcm_manifest = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "sync-success-01-wcm")
        .expect("WCM manifest artifact exists");
    wcm_manifest["bytesCopied"] = Value::from(wcm.bytes.len());
    let unusable =
        analyze_software_update_point(&assess_prepared_manifest(manifest, &unusable_payloads));
    assert!(unusable.transactions.is_empty());
}

#[test]
fn unusable_later_phase_timestamp_poisons_the_exact_sup_transaction() {
    let (mut manifest, mut payloads) = prepared_scenario("incomplete");
    let later_bytes = b"<![LOG[SYNTHETIC FIXTURE; Phase=synchronize; Disposition=succeeded; Terminal=false; SyncRunId=sync-10; SiteCode=LAB; SupHandle=safe:sup:lab-sup-01; ProfileId=sup-server-5.00.test-v1]LOG]!><time=\"15:31:00.000+9999\" date=\"7-30-2026\" component=\"SMS_WSUS_SYNC_MANAGER\" context=\"\" type=\"1\" thread=\"192\" file=\"wsyncmgr.cpp:1202\">\n".to_vec();
    let later_manifest = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "incomplete-02-wsync-denied")
        .expect("later-phase manifest artifact exists");
    later_manifest["captureState"] = Value::String("captured".to_owned());
    later_manifest["encoding"] = Value::String("utf-8".to_owned());
    later_manifest["collectionLimit"] =
        serde_json::json!({ "byteLimit": 4096, "limitApplied": false });
    later_manifest["bytesCopied"] = Value::from(later_bytes.len());
    later_manifest["relativePath"] = Value::String(
        "evidence/sccm/server/site-server/server-sup-sync/subject-software-update-point/current/wsyncmgr.log"
            .to_owned(),
    );
    payloads.push(SccmServerArtifactPayload {
        manifest_artifact_id: "incomplete-02-wsync-denied".to_owned(),
        bytes: later_bytes,
    });

    let analysis = analyze_software_update_point(&assess_prepared_manifest(manifest, &payloads));

    assert!(
        analysis.transactions.is_empty(),
        "a timestamp-poisoned exact subject cannot retain a correlatable prefix"
    );
}
