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
    let scenario_root = corpus_root().join(scenario);
    let manifest_json =
        std::fs::read_to_string(scenario_root.join("manifest.json")).expect("manifest is readable");
    let mut manifest: Value = serde_json::from_str(&manifest_json).expect("manifest is valid JSON");
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
    let expected_json = std::fs::read_to_string(scenario_root.join("expected.json"))
        .expect("expected output is readable");
    let expected = serde_json::from_str(&expected_json).expect("expected output is valid JSON");
    canonicalize_preparation_manifest(&mut manifest);
    let canonical_manifest = serde_json::to_string(&manifest).expect("manifest serializes");
    let intake = assess_server_intake(&canonical_manifest, &payloads).unwrap_or_else(|error| {
        panic!("fixture is accepted by canonical server intake: {error:?}\n{canonical_manifest}")
    });
    (intake, expected)
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
            artifact["workflowSubject"]["instanceHandle"] =
                Value::String("synthetic:subject:sup-01".to_owned());
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
