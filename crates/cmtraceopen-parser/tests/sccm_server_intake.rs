use cmtraceopen_parser::models::log_entry::Severity;
use cmtraceopen_parser::sccm::server::windows::{
    assess_server_intake, SccmServerArtifactPayload, SccmServerIntakeError,
};
use cmtraceopen_parser::sccm::{
    SccmConfidence, SccmCoverageState, SccmFinding, SccmFindingBuilder, SccmFindingClass,
    SccmFindingCoverageGap, SccmPhase, SccmRole, SccmRotation,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn intake_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/intake")
}

fn load_bundle(scenario: &str) -> (String, Vec<SccmServerArtifactPayload>) {
    let scenario_root = intake_root().join(scenario);
    let manifest_json =
        std::fs::read_to_string(scenario_root.join("manifest.json")).expect("manifest is readable");
    let manifest: Value = serde_json::from_str(&manifest_json).expect("manifest is valid JSON");
    let payloads = manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array")
        .iter()
        .filter_map(|artifact| {
            let relative_path = artifact["relativePath"].as_str()?;
            Some(SccmServerArtifactPayload {
                manifest_artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId is a string")
                    .to_owned(),
                bytes: std::fs::read(scenario_root.join(relative_path))
                    .expect("captured artifact bytes are readable"),
            })
        })
        .collect();
    (manifest_json, payloads)
}

fn manifest_value(manifest_json: &str) -> Value {
    serde_json::from_str(manifest_json).expect("manifest is valid JSON")
}

fn serialize_manifest(manifest: &Value) -> String {
    serde_json::to_string(manifest).expect("manifest serializes")
}

fn manifest_scope_needle(scope: &str) -> &'static str {
    match scope {
        "manifest" => "{",
        "privacy" => "\"privacy\":{",
        "topology" => "\"topology\":{",
        "artifact" => "\"artifacts\":[{",
        "workflowSubject" => "\"workflowSubject\":{",
        "configuredPathProvenance" => "\"configuredPathProvenance\":{",
        "rotation" => "\"rotation\":{",
        "collectionLimit" => "\"collectionLimit\":{",
        _ => panic!("unknown extension scope: {scope}"),
    }
}

fn manifest_with_duplicate_extension(
    manifest_json: &str,
    scope: &str,
    extension_name: &str,
    first_value: &str,
    second_value: &str,
) -> String {
    let needle = manifest_scope_needle(scope);
    let prefix = format!(
        "{needle}\"{extension_name}\":\"{first_value}\",\"{extension_name}\":\"{second_value}\","
    );
    let mutated = manifest_json.replacen(needle, &prefix, 1);
    assert_ne!(mutated, manifest_json, "scope marker must be present");
    mutated
}

fn manifest_with_duplicate_known_field(
    manifest_json: &str,
    scope: &str,
    field_name: &str,
    field_value: &Value,
) -> String {
    let needle = manifest_scope_needle(scope);
    let field_value = serde_json::to_string(field_value).expect("duplicate field value serializes");
    let prefix = format!("{needle}\"{field_name}\":{field_value},");
    let mutated = manifest_json.replacen(needle, &prefix, 1);
    assert_ne!(mutated, manifest_json, "scope marker must be present");
    mutated
}

fn manifest_with_ordered_extensions(
    manifest_json: &str,
    scopes: &[&str],
    extensions: &[(&str, &str)],
) -> String {
    let fields = extensions
        .iter()
        .map(|(name, value)| {
            format!(
                "{}:{},",
                serde_json::to_string(name).expect("extension name serializes"),
                serde_json::to_string(value).expect("extension value serializes")
            )
        })
        .collect::<String>();
    let mut mutated = manifest_json.to_owned();
    for scope in scopes {
        let needle = manifest_scope_needle(scope);
        let replacement = format!("{needle}{fields}");
        let next = mutated.replacen(needle, &replacement, 1);
        assert_ne!(next, mutated, "scope marker must be present: {scope}");
        mutated = next;
    }
    mutated
}

fn load_expected(scenario: &str) -> Value {
    let path = intake_root().join(scenario).join("expected.json");
    let json = std::fs::read_to_string(path).expect("expected intake output is readable");
    serde_json::from_str(&json).expect("expected intake output is valid JSON")
}

fn intake_scenarios() -> Vec<String> {
    let mut scenarios = std::fs::read_dir(intake_root())
        .expect("intake fixture root is readable")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("expected.json").is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    scenarios.sort();
    assert!(
        !scenarios.is_empty(),
        "the intake fixture root must contain committed expected.json oracles"
    );
    scenarios
}

fn opaque_handle(prefix: &str, ordinal: usize) -> String {
    format!("{prefix}{ordinal:064x}")
}

fn bounded_manifest(
    artifact_count: usize,
    byte_limit: u64,
) -> (String, Vec<SccmServerArtifactPayload>) {
    let capture_host = opaque_handle("cmtraceopen.host.sha256.v1:", 1);
    let site_code = opaque_handle("cmtraceopen.site.sha256.v1:", 1);
    let producer_host = opaque_handle("cmtraceopen.host.sha256.v1:", 2);
    let mut artifacts = Vec::with_capacity(artifact_count);
    let mut payloads = Vec::with_capacity(artifact_count);

    for ordinal in 0..artifact_count {
        let artifact_id = opaque_handle("cmtraceopen.artifact.sha256.v1:", ordinal);
        artifacts.push(json!({
            "artifactId": artifact_id.clone(),
            "producerRole": "managementPoint",
            "producerHostHandle": producer_host.clone(),
            "sourceId": "server-mp-policy",
            "sourceKind": "ccmLog",
            "sourceVersion": "5.00.9999.9999",
            "originalPath": "REDACTED",
            "originalBasename": "MP_GetPolicy.log",
            "configuredPathProvenance": {
                "state": "configured",
                "pathFingerprint": opaque_handle("cmtraceopen.path.sha256.v1:", ordinal),
            },
            "rotation": {
                "kind": "current",
                "lineageId": opaque_handle("cmtraceopen.lineage.sha256.v1:", ordinal),
            },
            "captureState": "captured",
            "encoding": "utf-8",
            "collectionLimit": { "byteLimit": byte_limit, "limitApplied": false },
            "collectedUtc": "2026-07-30T00:03:00Z",
            "relativePath": format!(
                "evidence/sccm/server/management-point/server-mp-policy/root-{ordinal:08x}/current/MP_GetPolicy.log"
            ),
            "bytesCopied": 0,
        }));
        payloads.push(SccmServerArtifactPayload {
            manifest_artifact_id: artifact_id,
            bytes: Vec::new(),
        });
    }

    (
        serde_json::to_string(&json!({
            "sccmManifestVersion": 1,
            "syntheticFixture": false,
            "bundleRole": "server",
            "topology": {
                "captureHost": capture_host,
                "siteCode": site_code,
                "rolesObserved": ["managementPoint"],
            },
            "artifacts": artifacts,
        }))
        .expect("bounded manifest serializes"),
        payloads,
    )
}

fn opaque_future_role_manifest(
    capture_state: &str,
    ordinal: usize,
) -> (
    String,
    Vec<SccmServerArtifactPayload>,
    String,
    Option<String>,
) {
    let (manifest_json, _) = bounded_manifest(1, 4_096);
    let mut manifest = manifest_value(&manifest_json);
    let role_digest = format!("{ordinal:064x}");
    let source_digest = format!("{:064x}", ordinal + 1);
    let basename_digest = format!("{:064x}", ordinal + 2);
    let future_role = format!("cmtraceopen.role.sha256.v1:{role_digest}");
    let source_id = format!("cmtraceopen.source.sha256.v1:{source_digest}");
    let source_kind = opaque_handle("cmtraceopen.source-kind.sha256.v1:", ordinal + 3);
    let original_basename = format!("cmtraceopen.basename.sha256.v1:{basename_digest}");
    manifest["topology"]["rolesObserved"] = json!(["managementPoint", future_role]);

    let artifact = &mut manifest["artifacts"][0];
    let artifact_id = artifact["artifactId"]
        .as_str()
        .expect("bounded artifact ID is a string")
        .to_owned();
    artifact["producerRole"] = Value::String(future_role.clone());
    artifact["producerHostHandle"] =
        Value::String(opaque_handle("cmtraceopen.host.sha256.v1:", ordinal + 4));
    artifact["sourceId"] = Value::String(source_id);
    artifact["sourceKind"] = Value::String(source_kind);
    artifact["sourceVersion"] = Value::Null;
    artifact["originalPath"] = Value::String(opaque_handle(
        "cmtraceopen.original-path.sha256.v1:",
        ordinal + 5,
    ));
    artifact["originalBasename"] = Value::String(original_basename);
    artifact["configuredPathProvenance"] = json!({
        "state": "supplied",
        "pathFingerprint": opaque_handle("cmtraceopen.path.sha256.v1:", ordinal + 6),
    });
    artifact["captureState"] = Value::String(capture_state.to_owned());
    artifact["collectionDetail"] = Value::Null;
    artifact["skipReason"] = Value::Null;
    artifact["unsupportedReason"] = Value::Null;
    artifact["truncated"] = Value::Null;
    artifact["fragmentComplete"] = Value::Null;

    let (payloads, relative_path) = if capture_state == "capped" {
        let bytes = vec![b'x'; 16];
        let relative_path = format!(
            "evidence/sccm/server/role-{role_digest}/source-{source_digest}/current/basename-{basename_digest}"
        );
        artifact["rotation"] = json!({
            "kind": "current",
            "lineageId": opaque_handle("cmtraceopen.lineage.sha256.v1:", ordinal + 7),
        });
        artifact["encoding"] = Value::String("utf-8".to_owned());
        artifact["collectionLimit"] = json!({ "byteLimit": 16, "limitApplied": true });
        artifact["bytesCopied"] = Value::from(16);
        artifact["truncated"] = Value::Bool(true);
        artifact["fragmentComplete"] = Value::Bool(false);
        artifact["relativePath"] = Value::String(relative_path.clone());
        (
            vec![SccmServerArtifactPayload {
                manifest_artifact_id: artifact_id,
                bytes,
            }],
            Some(relative_path),
        )
    } else {
        artifact["rotation"] = json!({
            "kind": "none",
            "lineageId": opaque_handle("cmtraceopen.lineage.sha256.v1:", ordinal + 7),
        });
        artifact["encoding"] = Value::Null;
        artifact["collectionLimit"] = Value::Null;
        artifact["bytesCopied"] = Value::from(0);
        artifact["relativePath"] = Value::Null;
        if capture_state == "accessDenied" {
            artifact["collectionDetail"] = Value::String(opaque_handle(
                "cmtraceopen.collection-detail.sha256.v1:",
                ordinal + 8,
            ));
        } else if capture_state == "unsupported" {
            artifact["unsupportedReason"] = Value::String(opaque_handle(
                "cmtraceopen.unsupported-reason.sha256.v1:",
                ordinal + 8,
            ));
        }
        (Vec::new(), None)
    };

    (
        serialize_manifest(&manifest),
        payloads,
        future_role,
        relative_path,
    )
}

fn assert_unsafe_mutation_is_rejected(
    scenario: &str,
    marker: &str,
    mutate: impl FnOnce(&mut Value, &mut Vec<SccmServerArtifactPayload>),
) {
    let (manifest_json, mut payloads) = load_bundle(scenario);
    let mut manifest = manifest_value(&manifest_json);
    mutate(&mut manifest, &mut payloads);

    match assess_server_intake(&serialize_manifest(&manifest), &payloads) {
        Err(_) => {}
        Ok(assessment) => {
            let serialized = serde_json::to_string(&assessment).expect("assessment serializes");
            assert!(
                !serialized
                    .to_ascii_lowercase()
                    .contains(&marker.to_ascii_lowercase()),
                "unsafe marker was projected into public JSON: {serialized}"
            );
            panic!("unsafe manifest mutation was accepted");
        }
    }
}

fn artifact_json<'a>(assessment: &'a Value, artifact_id: &str) -> &'a Value {
    assessment["artifacts"]
        .as_array()
        .expect("assessment artifacts are an array")
        .iter()
        .find(|artifact| artifact["artifactId"] == artifact_id)
        .expect("artifact is present")
}

fn reversed_assessment_json(manifest_json: &str, payloads: &[SccmServerArtifactPayload]) -> Value {
    let mut manifest = manifest_value(manifest_json);
    manifest["artifacts"]
        .as_array_mut()
        .expect("manifest artifacts are an array")
        .reverse();
    let mut reversed_payloads = payloads.to_vec();
    reversed_payloads.reverse();
    let assessment = assess_server_intake(&serialize_manifest(&manifest), &reversed_payloads)
        .expect("reordered manifest remains assessable");
    serde_json::to_value(assessment).expect("reordered assessment serializes")
}

fn assert_unique_public_relative_paths(scenario: &str, actual: &Value) {
    let paths = actual["artifacts"]
        .as_array()
        .expect("assessment artifacts are an array")
        .iter()
        .filter_map(|artifact| artifact["relativePath"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths.iter().copied().collect::<BTreeSet<_>>().len(),
        paths.len(),
        "{scenario}: relative paths are collision-safe"
    );
}

fn assert_collision_contract(scenario: &str, expected: &Value, actual: &Value) {
    let artifacts = actual["artifacts"]
        .as_array()
        .expect("assessment artifacts are an array");
    for (key, value) in expected
        .as_object()
        .expect("collision assertions are an object")
    {
        match key.as_str() {
            "sameBasename" => {
                let expected_basename = value
                    .as_str()
                    .expect("sameBasename expectation is a string");
                let actual_basenames = artifacts
                    .iter()
                    .map(|artifact| artifact["originalBasename"].as_str())
                    .collect::<Vec<_>>();
                assert!(
                    actual_basenames
                        .iter()
                        .all(|basename| *basename == Some(expected_basename)),
                    "{scenario}: expected every basename to be {expected_basename:?}, got {actual_basenames:?}"
                );
            }
            "distinctPathFingerprints" => {
                let fingerprints = artifacts
                    .iter()
                    .map(|artifact| artifact["pathFingerprint"].as_str().expect("fingerprint"))
                    .collect::<BTreeSet<_>>();
                assert_eq!(fingerprints.len(), artifacts.len(), "{scenario}: {key}");
                assert_eq!(value, true, "{scenario}: {key} expectation");
            }
            "distinctOpaqueRootSegments" => {
                assert_eq!(value, true, "{scenario}: {key} expectation");
                let root_segments = artifacts
                    .iter()
                    .map(|artifact| {
                        artifact["relativePath"]
                            .as_str()
                            .expect("relative path")
                            .split('/')
                            .find(|segment| segment.starts_with("root-"))
                            .expect("opaque configured-root segment")
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(root_segments.len(), artifacts.len(), "{scenario}: {key}");
            }
            "notMerged" => {
                assert_eq!(value, true, "{scenario}: {key} expectation");
                let content_digests = artifacts
                    .iter()
                    .map(|artifact| artifact["contentSha256"].as_str().expect("content digest"))
                    .collect::<BTreeSet<_>>();
                assert_eq!(content_digests.len(), artifacts.len(), "{scenario}: {key}");
            }
            "exactReferencesResolve" => {
                assert_eq!(value, true, "{scenario}: {key} expectation");
                let artifact_ids = artifacts
                    .iter()
                    .map(|artifact| artifact["artifactId"].as_str().expect("artifact ID"))
                    .collect::<BTreeSet<_>>();
                for coverage in actual["coverage"].as_array().expect("coverage is an array") {
                    for artifact_id in coverage["artifactIds"]
                        .as_array()
                        .expect("coverage artifact IDs are an array")
                    {
                        assert!(artifact_ids.contains(artifact_id.as_str().expect("artifact ID")));
                    }
                }
                for evidence in actual["evidence"].as_array().expect("evidence is an array") {
                    assert!(artifact_ids.contains(
                        evidence["reference"]["artifactId"]
                            .as_str()
                            .expect("evidence artifact ID")
                    ));
                }
            }
            "normalizedArtifactCount" => assert_eq!(
                artifacts.len() as u64,
                value.as_u64().expect("artifact count is an integer"),
                "{scenario}: {key}"
            ),
            other => panic!("{scenario}: unhandled collision assertion {other}"),
        }
    }
}

fn assert_remaining_expected_contracts(
    scenario: &str,
    expected: &Value,
    manifest_json: &str,
    payloads: &[SccmServerArtifactPayload],
    actual: &Value,
) {
    let manifest = manifest_value(manifest_json);
    let actual_artifacts = actual["artifacts"]
        .as_array()
        .expect("assessment artifacts are an array");
    for (key, value) in expected
        .as_object()
        .expect("expected contract is an object")
    {
        match key.as_str() {
            "pre318ExpectedVersion"
            | "artifactId"
            | "artifactProvenance"
            | "canonicalArtifactIds"
            | "canonicalRotationArtifactIds"
            | "configuredPathProvenance"
            | "coverage"
            | "evidence"
            | "retainedUnclassifiedArtifactIds"
            | "rolesObserved" => {}
            "nonCapturedProvenance" => {
                assert_eq!(value["encoding"], "omitted", "{scenario}: encoding");
                assert_eq!(
                    value["collectionLimit"], "omitted",
                    "{scenario}: collection limit"
                );
                for artifact in manifest["artifacts"]
                    .as_array()
                    .expect("manifest artifacts are an array")
                    .iter()
                    .filter(|artifact| artifact["relativePath"].is_null())
                {
                    assert!(artifact.get("encoding").is_none_or(Value::is_null));
                    assert!(artifact.get("collectionLimit").is_none_or(Value::is_null));
                }
                assert!(actual_artifacts
                    .iter()
                    .filter(|artifact| artifact["relativePath"].is_null())
                    .all(|artifact| artifact["captureProvenance"].is_null()));
            }
            "nextArtifactRequest" => {
                let requests = actual["nextArtifactRequests"]
                    .as_array()
                    .expect("requests are an array");
                assert_eq!(requests.len(), 1, "{scenario}: one bounded request");
                match value.as_str().expect("request expectation is a string") {
                    "read-only capture of server-mp-policy from the observed management point" => {
                        assert_eq!(requests[0]["logicalId"], "mpGetPolicy");
                        assert_eq!(requests[0]["role"], "managementPoint");
                    }
                    "bounded recapture of server-sup-sync with a cap sufficient for complete logical records" => {
                        assert_eq!(requests[0]["logicalId"], "wsyncmgr");
                        assert_eq!(requests[0]["role"], "siteServer");
                    }
                    other => panic!("{scenario}: unhandled request contract {other}"),
                }
            }
            "terminalManagementPointDiagnosis"
            | "terminalSoftwareUpdatePointHealth"
            | "partialPhysicalFragmentCreatesTerminalResult"
            | "requiredSourceFailure" => {
                assert_eq!(value, false, "{scenario}: {key} expectation");
                assert!(actual["findings"]
                    .as_array()
                    .expect("findings are an array")
                    .is_empty());
            }
            "roleHealthFinding" | "databaseOrRoleFinding" => {
                assert_eq!(value, "none", "{scenario}: {key} expectation");
                assert!(actual["findings"]
                    .as_array()
                    .expect("findings are an array")
                    .is_empty());
            }
            "forbiddenConclusion" => {
                let serialized = serde_json::to_string(actual).expect("assessment serializes");
                assert!(!serialized
                    .to_ascii_lowercase()
                    .contains(&value.as_str().expect("forbidden text").to_ascii_lowercase()));
            }
            "privacy" => {
                assert_eq!(value, "synthetic", "{scenario}: privacy declaration");
                assert_eq!(manifest["syntheticFixture"], true);
                assert_eq!(manifest["privacy"]["synthetic"], true);
                assert_eq!(manifest["privacy"]["rawPaths"], "redacted");
                let serialized = serde_json::to_string(actual).expect("assessment serializes");
                assert!(!serialized.contains("REDACTED"));
            }
            "defaultCandidateInterpretation" => {
                assert_eq!(value, "candidateAbsentOnly");
                assert_eq!(
                    manifest["artifacts"][0]["defaultCandidateState"],
                    "absentCandidateOnly"
                );
            }
            "roleInference" => {
                assert_eq!(
                    value,
                    "managementPoint is observed from topology, not from default path"
                );
                assert!(actual["topology"]["rolesObserved"]
                    .as_array()
                    .expect("roles are an array")
                    .contains(&Value::String("managementPoint".to_owned())));
            }
            "lineageId" => assert!(actual_artifacts
                .iter()
                .all(|artifact| { artifact["rotationLineageHandle"] == *value })),
            "totalRotationSort" => {
                assert_eq!(value, true);
                let ids = actual_artifacts
                    .iter()
                    .map(|artifact| artifact["artifactId"].clone())
                    .collect::<Value>();
                assert_eq!(ids, expected["canonicalRotationArtifactIds"]);
            }
            "serializationOrderIsChronology" => {
                assert_eq!(value, false);
                let instants = actual_artifacts
                    .iter()
                    .map(|artifact| artifact["collectedAtUtc"].as_str().expect("timestamp"))
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    instants.len(),
                    1,
                    "{scenario}: chronology cannot choose order"
                );
            }
            "uniqueRelativePaths" | "collisionSafe" => {
                assert_eq!(value, true, "{scenario}: {key} expectation");
                assert_unique_public_relative_paths(scenario, actual);
            }
            "collisionAssertions" => assert_collision_contract(scenario, value, actual),
            "normalizedOutputByteIdenticalWhenReordered"
            | "artifactIdDerivationIgnoresDiscoveryOrder" => {
                assert_eq!(value, true, "{scenario}: {key} expectation");
                assert_eq!(
                    reversed_assessment_json(manifest_json, payloads),
                    *actual,
                    "{scenario}: {key}"
                );
            }
            "artifactIdUniquenessScope" => {
                assert_eq!(value, "manifest");
                let ids = actual_artifacts
                    .iter()
                    .map(|artifact| artifact["artifactId"].as_str().expect("artifact ID"))
                    .collect::<BTreeSet<_>>();
                assert_eq!(ids.len(), actual_artifacts.len());
            }
            "crossBundleArtifactIdReuseAllowed" => {
                assert_eq!(value, true);
                let mut second_manifest = manifest_value(manifest_json);
                second_manifest["topology"]["captureHost"] =
                    if second_manifest["syntheticFixture"] == true {
                        let current_host = second_manifest["topology"]["captureHost"]
                            .as_str()
                            .expect("synthetic capture host is a string");
                        Value::String(
                            if current_host == "LAB-MP01" {
                                "LAB-CM01"
                            } else {
                                "LAB-MP01"
                            }
                            .to_owned(),
                        )
                    } else {
                        Value::String(opaque_handle("cmtraceopen.host.sha256.v1:", 999))
                    };
                let repeated =
                    assess_server_intake(&serialize_manifest(&second_manifest), payloads)
                        .expect("a distinct bundle may reuse manifest-scoped IDs");
                let repeated = serde_json::to_value(repeated).expect("repeat serializes");
                assert_eq!(
                    repeated["artifacts"]
                        .as_array()
                        .expect("repeat artifacts are an array")
                        .iter()
                        .map(|artifact| artifact["artifactId"].clone())
                        .collect::<Vec<_>>(),
                    actual_artifacts
                        .iter()
                        .map(|artifact| artifact["artifactId"].clone())
                        .collect::<Vec<_>>(),
                    "{scenario}: distinct bundles may reuse manifest-scoped IDs"
                );
                assert_ne!(repeated["topology"], actual["topology"]);
            }
            "deterministicEvidenceIds" => {
                assert_eq!(value, true);
                assert_eq!(
                    reversed_assessment_json(manifest_json, payloads)["evidence"],
                    actual["evidence"]
                );
            }
            "rawByteCountedBeforeDecoding" => {
                assert_eq!(value, true);
                for payload in payloads {
                    let artifact = artifact_json(actual, &payload.manifest_artifact_id);
                    assert_eq!(artifact["bytesCopied"], payload.bytes.len() as u64);
                }
            }
            "completeCcmRecordCount" => assert_eq!(
                actual["evidence"]
                    .as_array()
                    .expect("evidence is an array")
                    .len() as u64,
                value.as_u64().expect("record count is an integer")
            ),
            "logicalRecordParseable" => {
                assert_eq!(value, false);
                assert!(actual["evidence"]
                    .as_array()
                    .expect("evidence is an array")
                    .is_empty());
            }
            "eligibleForRoleReducer" => {
                assert_eq!(value, false);
                assert!(actual_artifacts
                    .iter()
                    .all(|artifact| artifact["parserEligible"] == false));
            }
            other => panic!("{scenario}: unhandled expected contract key {other}"),
        }
    }
}

fn assert_request_passes_finding_boundaries(
    scenario: &str,
    assessment: &cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment,
) {
    let request = assessment
        .next_artifact_requests
        .first()
        .unwrap_or_else(|| panic!("{scenario} emits one bounded request"));
    let artifact = assessment
        .artifacts
        .first()
        .unwrap_or_else(|| panic!("{scenario} retains its coverage artifact"));
    let finding = SccmFindingBuilder::new(format!("server-intake-{scenario}"))
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Unknown("serverIntake".to_owned()))
        .role(request.role.clone())
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .coverage_gap(SccmFindingCoverageGap {
            artifact_id: artifact.artifact_id.clone(),
            role: request.role.clone(),
            coverage: artifact.state.clone(),
        })
        .next_artifact(request.clone())
        .build()
        .unwrap_or_else(|error| panic!("{scenario} request must validate: {error:?}"));

    let serialized = serde_json::to_value(&finding)
        .unwrap_or_else(|error| panic!("{scenario} finding must serialize: {error}"));
    let deserialized = serde_json::from_value::<SccmFinding>(serialized)
        .unwrap_or_else(|error| panic!("{scenario} finding must deserialize: {error}"));
    assert_eq!(
        deserialized, finding,
        "{scenario} request and coverage data must survive the JSON boundary"
    );
}

#[test]
fn server_intake_normalizes_role_coverage_and_logical_records() {
    let (complete_manifest, complete_payloads) = load_bundle("complete-multi-role");
    let complete =
        assess_server_intake(&complete_manifest, &complete_payloads).expect("bundle is assessed");

    assert_eq!(complete.schema_version, 1);
    assert_eq!(
        complete
            .coverage
            .iter()
            .map(|row| (
                row.producer_role.clone(),
                row.workflow_subject_role.clone(),
                row.source_id.as_str(),
                row.state.clone(),
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                SccmRole::ManagementPoint,
                None,
                "server-mp-policy",
                SccmCoverageState::Captured,
            ),
            (
                SccmRole::SiteServer,
                Some(SccmRole::DistributionPoint),
                "server-dp-distribution",
                SccmCoverageState::Captured,
            ),
            (
                SccmRole::SiteServer,
                None,
                "server-sitecomp",
                SccmCoverageState::Captured,
            ),
            (
                SccmRole::SiteServer,
                Some(SccmRole::SoftwareUpdatePoint),
                "server-sup-sync",
                SccmCoverageState::Captured,
            ),
        ]
    );
    assert_eq!(complete.evidence.len(), 4);
    assert!(complete.findings.is_empty());

    let (multiline_manifest, multiline_payloads) = load_bundle("multiline");
    let multiline =
        assess_server_intake(&multiline_manifest, &multiline_payloads).expect("bundle is assessed");
    assert_eq!(multiline.evidence.len(), 1);
    assert_eq!(multiline.evidence[0].reference.line_start, Some(1));
    assert_eq!(multiline.evidence[0].reference.line_end, Some(2));

    let (absent_manifest, absent_payloads) = load_bundle("absent-dp");
    let absent =
        assess_server_intake(&absent_manifest, &absent_payloads).expect("bundle is assessed");
    assert_eq!(absent.coverage.len(), 1);
    assert_eq!(absent.coverage[0].state, SccmCoverageState::Absent);
    assert!(absent.evidence.is_empty());
    assert!(absent.findings.is_empty());
    assert_eq!(absent.next_artifact_requests.len(), 1);
    assert_eq!(absent.next_artifact_requests[0].logical_id, "distmgr");

    let (unsorted_manifest, unsorted_payloads) = load_bundle("unsorted-manifest");
    let unsorted =
        assess_server_intake(&unsorted_manifest, &unsorted_payloads).expect("bundle is assessed");
    let mut reordered_manifest: Value =
        serde_json::from_str(&unsorted_manifest).expect("manifest is valid JSON");
    reordered_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .reverse();
    let reordered = assess_server_intake(
        &serde_json::to_string(&reordered_manifest).expect("manifest serializes"),
        &unsorted_payloads,
    )
    .expect("reordered bundle is assessed");
    assert_eq!(
        serde_json::to_vec(&unsorted).expect("assessment serializes"),
        serde_json::to_vec(&reordered).expect("assessment serializes"),
        "manifest order must not affect normalized output"
    );
}

#[test]
fn server_intake_gap_requests_use_exact_shared_catalog_artifacts() {
    let cases = [
        (
            "absent-dp",
            "distmgr",
            SccmRole::SiteServer,
            "Collect the complete distmgr.log file.",
        ),
        (
            "access-denied-mp",
            "mpGetPolicy",
            SccmRole::ManagementPoint,
            "Collect the complete MP_GetPolicy.log file.",
        ),
        (
            "capped-sup",
            "wsyncmgr",
            SccmRole::SiteServer,
            "Collect the complete wsyncmgr.log file.",
        ),
    ];

    for (scenario, logical_id, role, reason) in cases {
        let (manifest, payloads) = load_bundle(scenario);
        let assessment = assess_server_intake(&manifest, &payloads)
            .unwrap_or_else(|error| panic!("{scenario} should be assessed: {error}"));

        assert_request_passes_finding_boundaries(scenario, &assessment);
        assert_eq!(assessment.next_artifact_requests.len(), 1, "{scenario}");
        let request = &assessment.next_artifact_requests[0];
        assert_eq!(request.logical_id, logical_id, "{scenario}");
        assert_eq!(request.role, role, "{scenario}");
        assert_eq!(request.reason, reason, "{scenario}");
    }
}

#[test]
fn server_intake_does_not_request_unknown_or_non_ccm_sources() {
    let (iis_manifest, iis_payloads) = load_bundle("skipped-iis");
    let mut denied_iis = manifest_value(&iis_manifest);
    denied_iis["artifacts"][0]["captureState"] = Value::String("accessDenied".to_owned());
    denied_iis["artifacts"][0]["skipReason"] = Value::Null;
    let iis = assess_server_intake(&serialize_manifest(&denied_iis), &iis_payloads)
        .expect("non-CCM coverage remains assessable");
    assert!(
        iis.next_artifact_requests.is_empty(),
        "a non-CCM group has no shared catalog artifact request"
    );

    let (unknown_manifest, unknown_payloads) = load_bundle("unsupported-db-supplement");
    let unknown = assess_server_intake(&unknown_manifest, &unknown_payloads)
        .expect("unknown coverage remains assessable");
    assert!(
        unknown.next_artifact_requests.is_empty(),
        "an unknown source has no shared catalog artifact request"
    );
}

#[test]
fn server_intake_rejects_identity_bearing_public_inputs() {
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][0]["relativePath"] = Value::String(
            "evidence/sccm/server/site-server/server-sitecomp/current/RealUsersitecomp.log"
                .to_owned(),
        );
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][0]["relativePath"] = Value::String(
            "evidence/sccm/server/site-server/realuser/current/sitecomp.log".to_owned(),
        );
    });
    assert_unsafe_mutation_is_rejected(
        "complete-multi-role",
        "realuser.example.test",
        |manifest, _payloads| {
            manifest["artifacts"][0]["sourceVersion"] =
                Value::String("realuser.example.test".to_owned());
        },
    );
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, payloads| {
        manifest["artifacts"][0]["artifactId"] = Value::String("realuser".to_owned());
        payloads[0].manifest_artifact_id = "realuser".to_owned();
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][0]["producerHostHandle"] =
            Value::String("synthetic:host:realuser".to_owned());
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][2]["workflowSubject"]["instanceHandle"] =
            Value::String("synthetic:subject:realuser".to_owned());
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][0]["configuredPathProvenance"]["pathFingerprint"] =
            Value::String("synthetic:path:realuser".to_owned());
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][0]["rotation"]["lineageId"] = Value::String("realuser".to_owned());
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["topology"]["captureHost"] = Value::String("LAB-REALUSER".to_owned());
    });
}

#[test]
fn server_intake_reserves_windows_equivalent_paths_and_fingerprints() {
    let (manifest_json, payloads) = load_bundle("collision-same-basename-configured-roots");
    let accepted =
        assess_server_intake(&manifest_json, &payloads).expect("distinct roots are valid");
    assert_eq!(accepted.artifacts.len(), 2);

    let mut case_collision = manifest_value(&manifest_json);
    case_collision["artifacts"][1]["relativePath"] = Value::String(
        "evidence/sccm/server/management-point/server-mp-policy/root-7D4A9C2E/current/MP_GetPolicy.log"
            .to_owned(),
    );
    assert!(
        assess_server_intake(&serialize_manifest(&case_collision), &payloads).is_err(),
        "Windows-equivalent destination paths must collide"
    );

    let mut fingerprint_collision = manifest_value(&manifest_json);
    fingerprint_collision["artifacts"][1]["configuredPathProvenance"]["pathFingerprint"] =
        fingerprint_collision["artifacts"][0]["configuredPathProvenance"]["pathFingerprint"]
            .clone();
    assert!(
        assess_server_intake(&serialize_manifest(&fingerprint_collision), &payloads).is_err(),
        "two physical candidates must not share one path fingerprint"
    );

    let mut exact_collision = manifest_value(&manifest_json);
    exact_collision["artifacts"][1]["relativePath"] =
        exact_collision["artifacts"][0]["relativePath"].clone();
    assert!(
        assess_server_intake(&serialize_manifest(&exact_collision), &payloads).is_err(),
        "exact destination paths must collide"
    );
}

#[test]
fn server_intake_rejects_mp_produced_mpcontrol_without_workflow_subject() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "mp-policy-current")
        .expect("MP policy artifact is present");
    artifact["originalBasename"] = Value::String("mpcontrol.log".to_owned());
    artifact["relativePath"] = Value::String(
        "evidence/sccm/server/management-point/server-mp-policy/current/mpcontrol.log".to_owned(),
    );

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
        "mpcontrol is not physically produced by the Management Point role"
    );
}

#[test]
fn server_intake_accepts_site_server_mpcontrol_with_management_point_subject() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "mp-policy-current")
        .expect("MP policy artifact is present");
    artifact["producerRole"] = Value::String("siteServer".to_owned());
    artifact["producerHostHandle"] = Value::String("synthetic:host:site-01".to_owned());
    artifact["workflowSubject"] = json!({ "role": "managementPoint" });
    artifact["originalBasename"] = Value::String("mpcontrol.log".to_owned());
    artifact["relativePath"] = Value::String(
        "evidence/sccm/server/site-server/server-mp-policy/subject-management-point/current/mpcontrol.log"
            .to_owned(),
    );

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("site-server-produced MP control evidence is assessed");
    let mpcontrol = assessment
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_id == "mp-policy-current")
        .expect("MP control artifact is retained");
    assert_eq!(mpcontrol.producer_role, SccmRole::SiteServer);
    assert_eq!(
        mpcontrol.workflow_subject_role,
        Some(SccmRole::ManagementPoint)
    );
    assert_eq!(mpcontrol.source_id, "server-mp-policy");
}

#[test]
fn server_intake_rejects_relabelled_duplicate_canonical_artifact_identity() {
    let (manifest_json, payloads) = load_bundle("collision-same-basename-configured-roots");
    let mut manifest = manifest_value(&manifest_json);
    let fingerprint =
        manifest["artifacts"][0]["configuredPathProvenance"]["pathFingerprint"].clone();
    let lineage = manifest["artifacts"][0]["rotation"]["lineageId"].clone();
    manifest["artifacts"][1]["configuredPathProvenance"]["pathFingerprint"] = fingerprint;
    manifest["artifacts"][1]["rotation"]["lineageId"] = lineage;

    assert_eq!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads),
        Err(SccmServerIntakeError::DuplicateArtifact),
        "caller-chosen artifact and root labels must not duplicate one canonical identity",
    );
}

#[test]
fn server_intake_scopes_canonical_identity_to_producer_host() {
    let (manifest_json, payloads) = load_bundle("collision-same-basename-configured-roots");
    let mut manifest = manifest_value(&manifest_json);
    let fingerprint =
        manifest["artifacts"][0]["configuredPathProvenance"]["pathFingerprint"].clone();
    let lineage = manifest["artifacts"][0]["rotation"]["lineageId"].clone();
    manifest["artifacts"][0]["producerHostHandle"] =
        Value::String("synthetic:host:site-01".to_owned());
    manifest["artifacts"][1]["producerHostHandle"] =
        Value::String("synthetic:host:mp-01".to_owned());
    manifest["artifacts"][1]["configuredPathProvenance"]["pathFingerprint"] = fingerprint;
    manifest["artifacts"][1]["rotation"]["lineageId"] = lineage;

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("the same artifact identity on a distinct producer host is independent");
    assert_eq!(assessment.artifacts.len(), 2);
    assert_eq!(
        assessment
            .artifacts
            .iter()
            .map(|artifact| artifact.producer_host_handle.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("synthetic:host:mp-01"), Some("synthetic:host:site-01"),],
        "producer-host provenance orders otherwise-equal artifacts before caller ids",
    );

    let mut reordered_manifest = manifest.clone();
    reordered_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .reverse();
    let reordered = assess_server_intake(&serialize_manifest(&reordered_manifest), &payloads)
        .expect("reordered distinct-host artifacts are assessed");
    assert_eq!(
        serde_json::to_vec(&assessment).expect("assessment serializes"),
        serde_json::to_vec(&reordered).expect("reordered assessment serializes"),
        "distinct-host output is independent of manifest order",
    );
}

#[test]
fn server_intake_scopes_path_fingerprint_lineage_to_producer_host() {
    let (manifest_json, payloads) = load_bundle("collision-same-basename-configured-roots");
    let mut manifest = manifest_value(&manifest_json);
    let fingerprint =
        manifest["artifacts"][0]["configuredPathProvenance"]["pathFingerprint"].clone();
    manifest["artifacts"][1]["producerHostHandle"] =
        Value::String("synthetic:host:site-01".to_owned());
    manifest["artifacts"][1]["configuredPathProvenance"]["pathFingerprint"] = fingerprint;

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("path fingerprints are scoped to their producer host");
    assert_eq!(assessment.artifacts.len(), 2);
}

fn configure_second_artifact_as_dp_identity(
    manifest: &mut Value,
    subject_handle: &str,
    share_lineage: bool,
) {
    let fingerprint =
        manifest["artifacts"][2]["configuredPathProvenance"]["pathFingerprint"].clone();
    let lineage = manifest["artifacts"][2]["rotation"]["lineageId"].clone();
    let artifact = &mut manifest["artifacts"][3];
    artifact["workflowSubject"] = json!({
        "role": "distributionPoint",
        "instanceHandle": subject_handle,
    });
    artifact["sourceId"] = Value::String("server-dp-distribution".to_owned());
    artifact["originalPath"] = Value::String("REDACTED_SITE_DP_CONTROL_ROOT_COPY".to_owned());
    artifact["originalBasename"] = Value::String("distmgr.log".to_owned());
    artifact["configuredPathProvenance"]["pathFingerprint"] = fingerprint;
    if share_lineage {
        artifact["rotation"]["lineageId"] = lineage;
    }
    artifact["relativePath"] = Value::String(
        "evidence/sccm/server/site-server/server-dp-distribution/subject-distribution-point/instance-bbbbbbbb/current/distmgr.log"
            .to_owned(),
    );
}

#[test]
fn server_intake_scopes_canonical_identity_to_workflow_subject() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][2]["workflowSubject"]["instanceHandle"] =
        Value::String("synthetic:subject:dp-02".to_owned());
    configure_second_artifact_as_dp_identity(&mut manifest, "synthetic:subject:dp-01", true);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("the same artifact identity for a distinct workflow subject is independent");
    assert_eq!(assessment.artifacts.len(), 4);
    assert_eq!(
        assessment
            .artifacts
            .iter()
            .filter(|artifact| artifact.source_id == "server-dp-distribution")
            .map(|artifact| artifact.workflow_subject_handle.as_deref())
            .collect::<Vec<_>>(),
        vec![
            Some("synthetic:subject:dp-01"),
            Some("synthetic:subject:dp-02"),
        ],
        "workflow-subject provenance orders otherwise-equal artifacts before caller ids",
    );

    let mut reordered_manifest = manifest.clone();
    reordered_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .reverse();
    let reordered = assess_server_intake(&serialize_manifest(&reordered_manifest), &payloads)
        .expect("reordered distinct-subject artifacts are assessed");
    assert_eq!(
        serde_json::to_vec(&assessment).expect("assessment serializes"),
        serde_json::to_vec(&reordered).expect("reordered assessment serializes"),
        "distinct-subject output is independent of manifest order",
    );
}

#[test]
fn server_intake_scopes_path_fingerprint_lineage_to_workflow_subject() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    configure_second_artifact_as_dp_identity(&mut manifest, "synthetic:subject:dp-02", false);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("path fingerprints are scoped to their workflow subject");
    assert_eq!(assessment.artifacts.len(), 4);
}

#[test]
fn server_intake_rejects_relabelled_duplicate_for_same_workflow_subject() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    configure_second_artifact_as_dp_identity(&mut manifest, "synthetic:subject:dp-01", true);

    assert_eq!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads),
        Err(SccmServerIntakeError::DuplicateArtifact),
        "caller labels cannot split one host-and-subject artifact identity",
    );
}

#[test]
fn server_intake_preserves_physical_parse_failure_provenance() {
    let (manifest_json, payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["captureState"] = Value::String("parseFailed".to_owned());

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("physical parse failure remains assessable");
    assert_eq!(
        assessment.artifacts[0].state,
        SccmCoverageState::ParseFailed
    );
    assert!(assessment.evidence.is_empty());
    assert!(assessment.findings.is_empty());
    assert_eq!(assessment.next_artifact_requests.len(), 1);

    let serialized = serde_json::to_value(&assessment).expect("assessment serializes");
    let artifact = artifact_json(&serialized, "mp-policy-multiline");
    assert_eq!(artifact["bytesCopied"], 207);
    assert_eq!(artifact["captureProvenance"]["schemaVersion"], 1);
    assert_eq!(artifact["captureProvenance"]["encoding"], "utf-8");
    assert_eq!(artifact["captureProvenance"]["byteLimit"], 4096);
    assert_eq!(artifact["captureProvenance"]["limitApplied"], false);
    assert_eq!(
        artifact["relativePath"],
        "evidence/sccm/server/management-point/server-mp-policy/current/MP_GetPolicy.log"
    );
}

#[test]
fn server_intake_converts_malformed_captured_ccm_to_parse_failed() {
    let (manifest_json, mut payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    payloads[0].bytes = b"not a complete CCM logical record".to_vec();
    manifest["artifacts"][0]["bytesCopied"] = Value::from(payloads[0].bytes.len() as u64);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("malformed collected bytes retain explicit partial coverage");
    assert_eq!(
        assessment.artifacts[0].state,
        SccmCoverageState::ParseFailed
    );
    assert!(assessment.evidence.is_empty());
    assert!(assessment.findings.is_empty());
    assert_eq!(assessment.next_artifact_requests.len(), 1);

    let serialized = serde_json::to_value(&assessment).expect("assessment serializes");
    let artifact = artifact_json(&serialized, "mp-policy-multiline");
    assert_eq!(artifact["captureProvenance"]["encoding"], "utf-8");
    assert_eq!(artifact["captureProvenance"]["byteLimit"], 4096);
    assert_eq!(artifact["captureProvenance"]["limitApplied"], false);
}

#[test]
fn server_intake_projects_versioned_capture_provenance() {
    let (captured_manifest, captured_payloads) = load_bundle("configured-nondefault-path");
    let captured = assess_server_intake(&captured_manifest, &captured_payloads)
        .expect("captured bundle is assessed");
    let captured_json = serde_json::to_value(&captured).expect("assessment serializes");
    let captured_artifact = artifact_json(&captured_json, "mp-policy-configured");
    assert_eq!(captured_artifact["captureProvenance"]["schemaVersion"], 1);
    assert_eq!(captured_artifact["captureProvenance"]["encoding"], "utf-8");
    assert_eq!(captured_artifact["captureProvenance"]["byteLimit"], 4096);
    assert_eq!(
        captured_artifact["captureProvenance"]["limitApplied"],
        false
    );

    let (capped_manifest, capped_payloads) = load_bundle("capped-sup");
    let capped = assess_server_intake(&capped_manifest, &capped_payloads)
        .expect("capped bundle is assessed");
    let capped_json = serde_json::to_value(&capped).expect("assessment serializes");
    let capped_artifact = artifact_json(&capped_json, "sup-sync-capped");
    assert_eq!(capped_artifact["captureProvenance"]["schemaVersion"], 1);
    assert_eq!(capped_artifact["captureProvenance"]["encoding"], "utf-8");
    assert_eq!(capped_artifact["captureProvenance"]["byteLimit"], 64);
    assert_eq!(capped_artifact["captureProvenance"]["limitApplied"], true);
}

#[test]
fn server_intake_suppresses_absent_default_request_when_configured_source_is_usable() {
    let (configured_manifest, configured_payloads) = load_bundle("configured-nondefault-path");
    let mut combined = manifest_value(&configured_manifest);
    let (absent_manifest, _absent_payloads) = load_bundle("access-denied-mp");
    let mut absent = manifest_value(&absent_manifest)["artifacts"][0].clone();
    absent["captureState"] = Value::String("absent".to_owned());
    absent["collectionDetail"] = Value::Null;
    absent["configuredPathProvenance"]["state"] = Value::String("defaultCandidate".to_owned());
    combined["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .push(absent);

    let assessment = assess_server_intake(&serialize_manifest(&combined), &configured_payloads)
        .expect("compatible configured and default candidates are assessed together");
    assert_eq!(assessment.coverage.len(), 2);
    assert!(assessment
        .coverage
        .iter()
        .any(|row| row.state == SccmCoverageState::Captured));
    assert!(assessment
        .coverage
        .iter()
        .any(|row| row.state == SccmCoverageState::Absent));
    assert!(
        assessment.next_artifact_requests.is_empty(),
        "a usable configured candidate satisfies the logical source request"
    );
}

#[test]
fn server_intake_does_not_suppress_default_request_across_producer_hosts() {
    let (configured_manifest, configured_payloads) = load_bundle("configured-nondefault-path");
    let mut combined = manifest_value(&configured_manifest);
    let (absent_manifest, _absent_payloads) = load_bundle("access-denied-mp");
    let mut absent = manifest_value(&absent_manifest)["artifacts"][0].clone();
    absent["producerHostHandle"] = Value::String("synthetic:host:site-01".to_owned());
    absent["captureState"] = Value::String("absent".to_owned());
    absent["collectionDetail"] = Value::Null;
    absent["configuredPathProvenance"]["state"] = Value::String("defaultCandidate".to_owned());
    combined["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .push(absent);

    let assessment = assess_server_intake(&serialize_manifest(&combined), &configured_payloads)
        .expect("distinct-host configured and default candidates are assessed together");
    assert_eq!(assessment.next_artifact_requests.len(), 1);
    assert_eq!(
        assessment.next_artifact_requests[0].logical_id,
        "mpGetPolicy"
    );
}

#[test]
fn server_intake_does_not_suppress_default_request_across_workflow_subjects() {
    let (captured_manifest, captured_payloads) = load_bundle("complete-multi-role");
    let mut combined = manifest_value(&captured_manifest);
    let (absent_manifest, _absent_payloads) = load_bundle("absent-dp");
    let mut absent = manifest_value(&absent_manifest)["artifacts"][0].clone();
    absent["workflowSubject"] = json!({
        "role": "distributionPoint",
        "instanceHandle": "synthetic:subject:dp-02",
    });
    combined["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .push(absent);

    let assessment = assess_server_intake(&serialize_manifest(&combined), &captured_payloads)
        .expect("distinct-subject configured and default candidates are assessed together");
    assert_eq!(assessment.next_artifact_requests.len(), 1);
    assert_eq!(assessment.next_artifact_requests[0].logical_id, "distmgr");
}

#[test]
fn server_intake_exercises_role_state_rotation_and_privacy_matrix() {
    let cases = [
        (
            "configured-nondefault-path",
            SccmCoverageState::Captured,
            1,
            0,
        ),
        ("absent-dp", SccmCoverageState::Absent, 0, 1),
        ("access-denied-mp", SccmCoverageState::AccessDenied, 0, 1),
        ("capped-sup", SccmCoverageState::Capped, 0, 1),
        ("skipped-iis", SccmCoverageState::Skipped, 0, 0),
        (
            "unsupported-db-supplement",
            SccmCoverageState::Unsupported,
            0,
            0,
        ),
    ];
    for (scenario, state, evidence_count, request_count) in cases {
        let (manifest, payloads) = load_bundle(scenario);
        let assessment = assess_server_intake(&manifest, &payloads)
            .unwrap_or_else(|error| panic!("{scenario} should be assessed: {error}"));
        assert_eq!(assessment.coverage[0].state, state, "{scenario}");
        assert_eq!(assessment.evidence.len(), evidence_count, "{scenario}");
        assert_eq!(
            assessment.next_artifact_requests.len(),
            request_count,
            "{scenario}"
        );
        assert!(assessment.findings.is_empty(), "{scenario}");
        let public_json = serde_json::to_string(&assessment).expect("assessment serializes");
        assert!(!public_json.contains("REDACTED_"), "{scenario}");
        assert!(!public_json.contains("LAB-"), "{scenario}");
    }

    let (rotations_manifest, rotations_payloads) = load_bundle("rotations");
    let rotations = assess_server_intake(&rotations_manifest, &rotations_payloads)
        .expect("declared rotations are assessed");
    assert_eq!(
        rotations
            .artifacts
            .iter()
            .map(|artifact| artifact.rotation.clone())
            .collect::<Vec<_>>(),
        vec![
            Some(SccmRotation::Timestamped("20260729-235700".to_owned())),
            Some(SccmRotation::Numbered(2)),
            Some(SccmRotation::LoUnderscore),
            Some(SccmRotation::Current),
        ]
    );

    let mut unknown_rotation = manifest_value(&rotations_manifest);
    unknown_rotation["artifacts"][0]["rotation"]["kind"] = Value::String("unknown".to_owned());
    unknown_rotation["artifacts"][0]["rotation"]["value"] = Value::Null;
    assert!(
        assess_server_intake(&serialize_manifest(&unknown_rotation), &rotations_payloads).is_err(),
        "unknown rotations fail closed"
    );

    let (complete_manifest, complete_payloads) = load_bundle("complete-multi-role");
    let complete = assess_server_intake(&complete_manifest, &complete_payloads)
        .expect("role-aware bundle is assessed");
    assert_eq!(
        complete.topology.capture_host_handle,
        "synthetic:host:lab-cm01"
    );
    assert_eq!(
        complete.topology.roles_observed,
        vec![
            SccmRole::DistributionPoint,
            SccmRole::ManagementPoint,
            SccmRole::SiteServer,
            SccmRole::SoftwareUpdatePoint,
        ]
    );
}

#[test]
fn server_intake_marks_an_incomplete_tail_as_a_parse_gap_even_after_valid_evidence() {
    let (manifest_json, mut payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    payloads[0]
        .bytes
        .extend_from_slice(b"\n<![LOG[SYNTHETIC FIXTURE incomplete rotation tail");
    manifest["artifacts"][0]["bytesCopied"] = Value::from(payloads[0].bytes.len() as u64);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("complete evidence plus a partial tail remains assessable");

    assert_eq!(
        assessment.evidence.len(),
        1,
        "the complete record is retained"
    );
    assert_eq!(
        assessment.artifacts[0].state,
        SccmCoverageState::ParseFailed,
        "the unmatched tail is an explicit parse gap"
    );
    assert_eq!(assessment.next_artifact_requests.len(), 1);
}

#[test]
fn server_intake_keeps_a_zero_byte_capture_distinct_from_parse_failure() {
    let (manifest_json, mut payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    payloads[0].bytes.clear();
    manifest["artifacts"][0]["bytesCopied"] = Value::from(0);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("a bounded zero-byte capture remains valid capture provenance");

    assert_eq!(assessment.artifacts[0].state, SccmCoverageState::Captured);
    assert_eq!(assessment.coverage[0].state, SccmCoverageState::Captured);
    assert!(assessment.evidence.is_empty());
    assert!(assessment.next_artifact_requests.is_empty());
}

#[test]
fn server_intake_decodes_declared_utf16le_ccm_payloads() {
    let (manifest_json, mut payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    let content = String::from_utf8(payloads[0].bytes.clone()).expect("fixture is UTF-8");
    let mut utf16le = vec![0xff, 0xfe];
    for unit in content.encode_utf16() {
        utf16le.extend_from_slice(&unit.to_le_bytes());
    }
    payloads[0].bytes = utf16le;
    manifest["artifacts"][0]["encoding"] = Value::String("utf-16le".to_owned());
    manifest["artifacts"][0]["bytesCopied"] = Value::from(payloads[0].bytes.len() as u64);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("the declared UTF-16LE contract is decoded");

    assert_eq!(assessment.artifacts[0].state, SccmCoverageState::Captured);
    assert_eq!(assessment.evidence.len(), 1);
    assert!(assessment.evidence[0].message.contains("SYNTHETIC FIXTURE"));
}

#[test]
fn server_intake_decodes_declared_windows_1252_ccm_payloads() {
    let (manifest_json, mut payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    let marker = b"SYNTHETIC FIXTURE";
    let marker_start = payloads[0]
        .bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("fixture contains its synthetic marker");
    let marker_end = marker_start + marker.len();
    let mut windows_1252 = payloads[0].bytes[..marker_end].to_vec();
    windows_1252.extend_from_slice(b" caf");
    windows_1252.push(0xe9);
    windows_1252.push(b' ');
    windows_1252.push(0x80);
    windows_1252.extend_from_slice(&payloads[0].bytes[marker_end..]);
    payloads[0].bytes = windows_1252;
    manifest["artifacts"][0]["encoding"] = Value::String("windows-1252".to_owned());
    manifest["artifacts"][0]["bytesCopied"] = Value::from(payloads[0].bytes.len() as u64);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("the declared Windows-1252 contract is decoded");

    assert_eq!(assessment.artifacts[0].state, SccmCoverageState::Captured);
    assert_eq!(assessment.evidence.len(), 1);
    assert!(assessment.evidence[0].message.contains("café €"));
}

#[test]
fn server_intake_keeps_unknown_encoding_as_unsupported_coverage() {
    let (manifest_json, payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["encoding"] = Value::String("unknown".to_owned());

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("unknown encoding is retained without guessing a decoder");

    assert_eq!(
        assessment.artifacts[0].state,
        SccmCoverageState::Unsupported
    );
    assert!(!assessment.artifacts[0].parser_eligible);
    assert!(assessment.evidence.is_empty());
    assert_eq!(assessment.next_artifact_requests.len(), 1);
    let serialized = serde_json::to_value(&assessment).expect("assessment serializes");
    assert_eq!(
        serialized["artifacts"][0]["captureProvenance"]["encoding"],
        "unknown"
    );
}

#[test]
fn server_intake_retains_unsupported_source_provenance() {
    let (manifest_json, payloads) = load_bundle("unsupported-db-supplement");
    let assessment = assess_server_intake(&manifest_json, &payloads)
        .expect("unsupported source remains assessable");
    let serialized = serde_json::to_value(&assessment).expect("assessment serializes");
    let artifact = artifact_json(&serialized, "unknown-db-export");

    assert_eq!(artifact["sourceId"], "unknown-db-supplement");
    assert_eq!(artifact["sourceKind"], "unknown");
    assert_eq!(artifact["family"], "unknown-db-supplement");
    assert_eq!(artifact["originalBasename"], "synthetic-db-export.txt");
    assert_eq!(artifact["rotationLineageHandle"], "unknown-db-export");
    assert_eq!(
        serialized["coverage"][0]["sourceId"],
        "unknown-db-supplement"
    );
}

#[test]
fn server_intake_rejects_unversioned_future_unsupported_source_labels() {
    let (manifest_json, payloads) = load_bundle("unsupported-db-supplement");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["sourceId"] = Value::String("future-server-supplement".to_owned());
    manifest["artifacts"][0]["sourceKind"] = Value::String("futureSupplement".to_owned());

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
        "future provenance needs a versioned opaque handle, not an arbitrary public label"
    );
}

#[test]
fn server_intake_rejects_identity_bearing_unsupported_public_provenance() {
    for (field, marker) in [
        ("sourceId", "realuser-example"),
        ("sourceKind", "RealUser"),
        ("originalBasename", "RealUser.log"),
    ] {
        assert_unsafe_mutation_is_rejected("unsupported-db-supplement", marker, |manifest, _| {
            manifest["artifacts"][0][field] = Value::String(marker.to_owned());
        });
    }
}

#[test]
fn server_intake_accepts_only_opaque_future_unsupported_provenance() {
    let (manifest_json, _) = bounded_manifest(1, 4_096);
    let mut manifest = manifest_value(&manifest_json);
    let source_id = opaque_handle("cmtraceopen.source.sha256.v1:", 1);
    let source_kind = opaque_handle("cmtraceopen.source-kind.sha256.v1:", 2);
    let basename = opaque_handle("cmtraceopen.basename.sha256.v1:", 3);
    let artifact = &mut manifest["artifacts"][0];
    artifact["producerRole"] = Value::String("unclassified".to_owned());
    artifact["producerHostHandle"] = Value::Null;
    artifact["sourceId"] = Value::String(source_id.clone());
    artifact["sourceKind"] = Value::String(source_kind.clone());
    artifact["originalBasename"] = Value::String(basename.clone());
    artifact["rotation"] = json!({
        "kind": "none",
        "lineageId": opaque_handle("cmtraceopen.lineage.sha256.v1:", 4),
    });
    artifact["captureState"] = Value::String("unsupported".to_owned());
    artifact["encoding"] = Value::Null;
    artifact["collectionLimit"] = Value::Null;
    artifact["relativePath"] = Value::Null;
    artifact["bytesCopied"] = Value::from(0);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &[])
        .expect("opaque future unsupported provenance remains retainable");
    let public = serde_json::to_value(&assessment).expect("assessment serializes");
    assert_eq!(public["artifacts"][0]["sourceId"], source_id);
    assert_eq!(public["artifacts"][0]["sourceKind"], source_kind);
    assert_eq!(public["artifacts"][0]["originalBasename"], basename);
}

#[test]
fn server_manifest_v1_retains_only_versioned_opaque_extensions_deterministically() {
    let (manifest_json, payloads) = bounded_manifest(1, 4_096);
    let extension_name_a = "x-cmtraceopen-opaque-v1-alpha";
    let extension_name_b = "x-cmtraceopen-opaque-v1-beta";
    let extension_value_a = opaque_handle("cmtraceopen.extension.sha256.v1:", 1);
    let extension_value_b = opaque_handle("cmtraceopen.extension.sha256.v1:", 2);
    let scopes = ["manifest", "topology", "artifact"];
    let beta_then_alpha = manifest_with_ordered_extensions(
        &manifest_json,
        &scopes,
        &[
            (extension_name_b, extension_value_b.as_str()),
            (extension_name_a, extension_value_a.as_str()),
        ],
    );
    let alpha_then_beta = manifest_with_ordered_extensions(
        &manifest_json,
        &scopes,
        &[
            (extension_name_a, extension_value_a.as_str()),
            (extension_name_b, extension_value_b.as_str()),
        ],
    );
    assert_ne!(
        beta_then_alpha, alpha_then_beta,
        "the test inputs must preserve genuinely different extension arrival orders"
    );
    assert!(
        beta_then_alpha
            .find(extension_name_b)
            .expect("beta extension is present")
            < beta_then_alpha
                .find(extension_name_a)
                .expect("alpha extension is present"),
        "the first raw manifest must place beta before alpha"
    );
    assert!(
        alpha_then_beta
            .find(extension_name_a)
            .expect("alpha extension is present")
            < alpha_then_beta
                .find(extension_name_b)
                .expect("beta extension is present"),
        "the reordered raw manifest must place alpha before beta"
    );

    let assessment = assess_server_intake(&beta_then_alpha, &payloads)
        .expect("versioned opaque extensions are retained");
    let public = serde_json::to_value(&assessment).expect("assessment serializes");
    let expected = json!([
        { "schemaVersion": 1, "name": extension_name_a, "value": extension_value_a },
        { "schemaVersion": 1, "name": extension_name_b, "value": extension_value_b },
    ]);
    assert_eq!(public["extensions"], expected);
    assert_eq!(public["topology"]["extensions"], expected);
    assert_eq!(public["artifacts"][0]["extensions"], expected);

    let reordered_assessment = assess_server_intake(&alpha_then_beta, &payloads)
        .expect("extension arrival order does not change normalized output");
    assert_eq!(assessment, reordered_assessment);
}

#[test]
fn server_manifest_version_gate_precedes_v1_extension_validation() {
    let (manifest_json, payloads) = bounded_manifest(1, 4_096);
    let mut manifest = manifest_value(&manifest_json);
    manifest["sccmManifestVersion"] = Value::from(2);
    manifest["futureManifestField"] = json!({ "shape": "belongs-to-v2" });

    assert_eq!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads),
        Err(SccmServerIntakeError::UnsupportedManifestVersion),
        "unsupported versions are rejected by the version gate before applying the v1 extension grammar"
    );
}

#[test]
fn server_manifest_known_metadata_errors_route_to_manifest_scope() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut wrong_results = Vec::new();

    for case in [
        "missingPrivacy",
        "invalidPrivacySynthetic",
        "invalidPrivacyRawPaths",
        "missingProposalOnly",
        "invalidProposalOnly",
        "invalidInputOrderDeclaration",
    ] {
        let mut manifest = manifest_value(&manifest_json);
        match case {
            "missingPrivacy" => {
                manifest
                    .as_object_mut()
                    .expect("manifest is an object")
                    .remove("privacy");
            }
            "invalidPrivacySynthetic" => manifest["privacy"]["synthetic"] = Value::Bool(false),
            "invalidPrivacyRawPaths" => {
                manifest["privacy"]["rawPaths"] = Value::String("raw".to_owned());
            }
            "missingProposalOnly" => {
                manifest
                    .as_object_mut()
                    .expect("manifest is an object")
                    .remove("proposalOnly");
            }
            "invalidProposalOnly" => manifest["proposalOnly"] = Value::Bool(false),
            "invalidInputOrderDeclaration" => {
                manifest["inputOrderIsDeliberatelyUnsorted"] = Value::Bool(false);
            }
            _ => unreachable!(),
        }
        let actual = assess_server_intake(&serialize_manifest(&manifest), &payloads);
        if actual != Err(SccmServerIntakeError::MalformedManifest) {
            wrong_results.push((case, actual));
        }
    }

    assert!(
        wrong_results.is_empty(),
        "manifest/privacy known-field errors must stay in manifest scope: {wrong_results:?}"
    );
}

#[test]
fn server_manifest_v1_rejects_unversioned_or_nonopaque_unknown_fields() {
    let (manifest_json, payloads) = bounded_manifest(1, 4_096);

    for path in ["manifest", "topology", "artifact"] {
        for (name, value) in [
            ("unexpectedEvidence", Value::Bool(true)),
            (
                "x-cmtraceopen-opaque-v1-arbitrary",
                Value::String("identity-bearing text".to_owned()),
            ),
        ] {
            let mut manifest = manifest_value(&manifest_json);
            match path {
                "manifest" => manifest[name] = value,
                "topology" => manifest["topology"][name] = value,
                "artifact" => manifest["artifacts"][0][name] = value,
                _ => unreachable!(),
            }
            let expected = match path {
                "manifest" => SccmServerIntakeError::MalformedManifest,
                "topology" => SccmServerIntakeError::InvalidTopology,
                "artifact" => SccmServerIntakeError::InvalidArtifact,
                _ => unreachable!(),
            };
            assert_eq!(
                assess_server_intake(&serialize_manifest(&manifest), &payloads),
                Err(expected),
                "{path} must reject arbitrary extension {name} in its own scope"
            );
        }
    }
}

#[test]
fn server_manifest_v1_rejects_duplicate_opaque_fields_in_every_scope() {
    let (production_json, production_payloads) = bounded_manifest(1, 4_096);
    let (synthetic_json, synthetic_payloads) = load_bundle("complete-multi-role");
    let synthetic_json = serialize_manifest(&manifest_value(&synthetic_json));
    let extension_name = "x-cmtraceopen-opaque-v1-duplicate";
    let first_value = opaque_handle("cmtraceopen.extension.sha256.v1:", 31);
    let second_value = opaque_handle("cmtraceopen.extension.sha256.v1:", 32);
    let mut wrong_results = Vec::new();

    for (scope, manifest_json, payloads, expected) in [
        (
            "manifest",
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::MalformedManifest,
        ),
        (
            "privacy",
            synthetic_json.as_str(),
            synthetic_payloads.as_slice(),
            SccmServerIntakeError::MalformedManifest,
        ),
        (
            "topology",
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::InvalidTopology,
        ),
        (
            "artifact",
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::InvalidArtifact,
        ),
        (
            "workflowSubject",
            synthetic_json.as_str(),
            synthetic_payloads.as_slice(),
            SccmServerIntakeError::InvalidArtifact,
        ),
        (
            "configuredPathProvenance",
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::InvalidArtifact,
        ),
        (
            "rotation",
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::InvalidArtifact,
        ),
        (
            "collectionLimit",
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::InvalidArtifact,
        ),
    ] {
        let manifest = manifest_with_duplicate_extension(
            manifest_json,
            scope,
            extension_name,
            &first_value,
            &second_value,
        );
        let actual = assess_server_intake(&manifest, payloads);
        if actual != Err(expected.clone()) {
            wrong_results.push((scope, actual, expected));
        }
    }

    assert!(
        wrong_results.is_empty(),
        "duplicate extension results must be scope exact: {wrong_results:?}"
    );
}

#[test]
fn server_manifest_v1_rejects_duplicate_known_fields_in_every_extension_scope() {
    let (production_json, production_payloads) = bounded_manifest(1, 4_096);
    let (synthetic_json, synthetic_payloads) = load_bundle("complete-multi-role");
    let synthetic_json = serialize_manifest(&manifest_value(&synthetic_json));
    let mut wrong_results = Vec::new();

    for (scope, field, value, manifest_json, payloads, expected) in [
        (
            "manifest",
            "sccmManifestVersion",
            json!(1),
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::MalformedManifest,
        ),
        (
            "privacy",
            "synthetic",
            json!(true),
            synthetic_json.as_str(),
            synthetic_payloads.as_slice(),
            SccmServerIntakeError::MalformedManifest,
        ),
        (
            "topology",
            "captureHost",
            json!("duplicate-host"),
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::InvalidTopology,
        ),
        (
            "artifact",
            "sourceId",
            json!("server-mp-policy"),
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::InvalidArtifact,
        ),
        (
            "workflowSubject",
            "role",
            json!("distributionPoint"),
            synthetic_json.as_str(),
            synthetic_payloads.as_slice(),
            SccmServerIntakeError::InvalidArtifact,
        ),
        (
            "configuredPathProvenance",
            "state",
            json!("configured"),
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::InvalidArtifact,
        ),
        (
            "rotation",
            "kind",
            json!("current"),
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::InvalidArtifact,
        ),
        (
            "collectionLimit",
            "byteLimit",
            json!(4_096),
            production_json.as_str(),
            production_payloads.as_slice(),
            SccmServerIntakeError::InvalidArtifact,
        ),
    ] {
        let manifest = manifest_with_duplicate_known_field(manifest_json, scope, field, &value);
        let actual = assess_server_intake(&manifest, payloads);
        if actual != Err(expected.clone()) {
            wrong_results.push((scope, actual, expected));
        }
    }

    assert!(
        wrong_results.is_empty(),
        "duplicate known-field results must be scope exact: {wrong_results:?}"
    );
}

#[test]
fn server_manifest_v1_retains_safe_nested_extensions_without_interpreting_them() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    let extension_name = "x-cmtraceopen-opaque-v1-nested";
    let extension_value = opaque_handle("cmtraceopen.extension.sha256.v1:", 41);
    manifest["privacy"][extension_name] = Value::String(extension_value.clone());
    let artifact = &mut manifest["artifacts"][2];
    artifact["workflowSubject"][extension_name] = Value::String(extension_value.clone());
    artifact["configuredPathProvenance"][extension_name] = Value::String(extension_value.clone());
    artifact["rotation"][extension_name] = Value::String(extension_value.clone());
    artifact["collectionLimit"][extension_name] = Value::String(extension_value.clone());

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("safe nested extensions are retained as inert provenance");
    let public = serde_json::to_value(&assessment).expect("assessment serializes");
    let expected = json!([{
        "schemaVersion": 1,
        "name": extension_name,
        "value": extension_value,
    }]);
    assert_eq!(public["privacyExtensions"], expected);
    let artifact = artifact_json(&public, "dp-dist-current");
    assert_eq!(artifact["workflowSubjectExtensions"], expected);
    assert_eq!(artifact["configuredPathProvenanceExtensions"], expected);
    assert_eq!(artifact["rotationExtensions"], expected);
    assert_eq!(artifact["collectionLimitExtensions"], expected);
    assert!(assessment.evidence.iter().all(|evidence| {
        !evidence.message.contains(extension_name) && !evidence.message.contains(&extension_value)
    }));
    assert!(assessment.findings.is_empty());
}

#[test]
fn server_manifest_v1_rejects_unsafe_nested_extensions_in_their_scope() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let extension_name = "x-cmtraceopen-opaque-v1-nested-unsafe";
    let mut wrong_results = Vec::new();

    for (scope, expected) in [
        ("privacy", SccmServerIntakeError::MalformedManifest),
        ("workflowSubject", SccmServerIntakeError::InvalidArtifact),
        (
            "configuredPathProvenance",
            SccmServerIntakeError::InvalidArtifact,
        ),
        ("rotation", SccmServerIntakeError::InvalidArtifact),
        ("collectionLimit", SccmServerIntakeError::InvalidArtifact),
    ] {
        let mut manifest = manifest_value(&manifest_json);
        match scope {
            "privacy" => manifest["privacy"][extension_name] = json!({ "identity": "real-user" }),
            "workflowSubject" => {
                manifest["artifacts"][2]["workflowSubject"][extension_name] =
                    json!({ "identity": "real-user" });
            }
            "configuredPathProvenance" => {
                manifest["artifacts"][2]["configuredPathProvenance"][extension_name] =
                    json!({ "identity": "real-user" });
            }
            "rotation" => {
                manifest["artifacts"][2]["rotation"][extension_name] =
                    json!({ "identity": "real-user" });
            }
            "collectionLimit" => {
                manifest["artifacts"][2]["collectionLimit"][extension_name] =
                    json!({ "identity": "real-user" });
            }
            _ => unreachable!(),
        }
        let actual = assess_server_intake(&serialize_manifest(&manifest), &payloads);
        if actual != Err(expected.clone()) {
            wrong_results.push((scope, actual, expected));
        }
    }

    assert!(
        wrong_results.is_empty(),
        "unsafe nested extension results must be scope exact: {wrong_results:?}"
    );
}

#[test]
fn server_intake_retains_only_opaque_future_roles_as_unsupported_coverage() {
    let (manifest_json, _) = bounded_manifest(1, 4_096);
    let mut manifest = manifest_value(&manifest_json);
    let future_role = opaque_handle("cmtraceopen.role.sha256.v1:", 9);
    manifest["topology"]["rolesObserved"] = json!(["managementPoint", future_role]);
    let artifact = &mut manifest["artifacts"][0];
    artifact["producerRole"] = Value::String(future_role.clone());
    artifact["producerHostHandle"] = Value::Null;
    artifact["sourceId"] = Value::String(opaque_handle("cmtraceopen.source.sha256.v1:", 1));
    artifact["sourceKind"] = Value::String(opaque_handle("cmtraceopen.source-kind.sha256.v1:", 2));
    artifact["originalBasename"] =
        Value::String(opaque_handle("cmtraceopen.basename.sha256.v1:", 3));
    artifact["originalPath"] =
        Value::String(opaque_handle("cmtraceopen.original-path.sha256.v1:", 4));
    artifact["rotation"] = json!({
        "kind": "none",
        "lineageId": opaque_handle("cmtraceopen.lineage.sha256.v1:", 5),
    });
    artifact["captureState"] = Value::String("unsupported".to_owned());
    artifact["encoding"] = Value::Null;
    artifact["collectionLimit"] = Value::Null;
    artifact["relativePath"] = Value::Null;
    artifact["bytesCopied"] = Value::from(0);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &[])
        .expect("opaque future role is retained as unsupported provenance");
    let public = serde_json::to_value(&assessment).expect("assessment serializes");
    assert!(public["topology"]["rolesObserved"]
        .as_array()
        .expect("roles observed is an array")
        .contains(&Value::String(future_role.clone())));
    assert_eq!(public["artifacts"][0]["producerRole"], future_role);
    assert_eq!(public["coverage"][0]["state"], "unsupported");
    assert!(!assessment.artifacts[0].parser_eligible);
    assert!(assessment.evidence.is_empty());
    assert!(assessment.findings.is_empty());
    assert!(assessment.next_artifact_requests.is_empty());
}

#[test]
fn server_intake_retains_opaque_future_roles_across_conservative_coverage_states() {
    let mut failures = Vec::new();

    for (wire_state, expected_state, ordinal) in [
        ("absent", SccmCoverageState::Absent, 101),
        ("accessDenied", SccmCoverageState::AccessDenied, 102),
        ("capped", SccmCoverageState::Capped, 103),
        ("unsupported", SccmCoverageState::Unsupported, 104),
    ] {
        let (manifest_json, payloads, future_role, expected_relative_path) =
            opaque_future_role_manifest(wire_state, ordinal);
        let result = (|| -> Result<(), String> {
            let assessment = assess_server_intake(&manifest_json, &payloads)
                .map_err(|error| format!("intake rejected the state: {error:?}"))?;
            let expected_role = SccmRole::Unknown(future_role.clone());
            if !assessment.topology.roles_observed.contains(&expected_role) {
                return Err("future role was not retained in topology".to_owned());
            }
            let artifact = assessment
                .artifacts
                .iter()
                .find(|artifact| artifact.producer_role == expected_role)
                .ok_or_else(|| "future-role artifact was not retained".to_owned())?;
            if artifact.state != expected_state {
                return Err(format!(
                    "coverage changed from {expected_state:?} to {:?}",
                    artifact.state
                ));
            }
            if artifact.parser_eligible {
                return Err("future-role artifact became parser eligible".to_owned());
            }
            if artifact.relative_path != expected_relative_path {
                return Err(format!(
                    "relative path mismatch: {:?}",
                    artifact.relative_path
                ));
            }
            if expected_state == SccmCoverageState::Capped {
                let provenance = artifact
                    .capture_provenance
                    .as_ref()
                    .ok_or_else(|| "capped artifact lost capture provenance".to_owned())?;
                if provenance.schema_version != 1
                    || provenance.encoding != "utf-8"
                    || provenance.byte_limit != 16
                    || !provenance.limit_applied
                    || artifact.bytes_copied != 16
                    || artifact.truncated != Some(true)
                    || artifact.fragment_complete != Some(false)
                    || artifact.content_sha256.is_none()
                {
                    return Err(format!("capped provenance was incoherent: {artifact:?}"));
                }
            } else if artifact.capture_provenance.is_some()
                || artifact.content_sha256.is_some()
                || artifact.bytes_copied != 0
            {
                return Err(format!(
                    "nonphysical state retained physical provenance: {artifact:?}"
                ));
            }
            if assessment.coverage.len() != 1
                || assessment.coverage[0].state != expected_state
                || !assessment.evidence.is_empty()
                || !assessment.findings.is_empty()
                || !assessment.next_artifact_requests.is_empty()
            {
                return Err(format!(
                    "future-role state influenced diagnostics: {assessment:?}"
                ));
            }
            Ok(())
        })();
        if let Err(error) = result {
            failures.push((wire_state, error));
        }
    }

    assert!(
        failures.is_empty(),
        "future-role coverage states must remain inert and exact: {failures:?}"
    );
}

#[test]
fn server_intake_rejects_identity_bearing_future_roles() {
    let (manifest_json, _) = bounded_manifest(1, 4_096);
    let mut manifest = manifest_value(&manifest_json);
    manifest["topology"]["rolesObserved"] = json!(["managementPoint", "real-server-role"]);
    let artifact = &mut manifest["artifacts"][0];
    artifact["producerRole"] = Value::String("real-server-role".to_owned());
    artifact["producerHostHandle"] = Value::Null;
    artifact["captureState"] = Value::String("unsupported".to_owned());
    artifact["encoding"] = Value::Null;
    artifact["collectionLimit"] = Value::Null;
    artifact["relativePath"] = Value::Null;
    artifact["bytesCopied"] = Value::from(0);

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &[]).is_err(),
        "identity-bearing future roles are not public provenance"
    );
}

#[test]
fn server_intake_rejects_future_topology_roles_without_a_matching_artifact() {
    let (manifest_json, payloads) = bounded_manifest(1, 4_096);
    let mut manifest = manifest_value(&manifest_json);
    manifest["topology"]["rolesObserved"] = json!([
        "managementPoint",
        opaque_handle("cmtraceopen.role.sha256.v1:", 10),
    ]);

    assert_eq!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads),
        Err(SccmServerIntakeError::InvalidTopology),
        "every future topology role must have retained artifact provenance"
    );
}

#[test]
fn server_intake_rejects_future_role_artifacts_missing_from_topology() {
    let (manifest_json, payloads, _, _) = opaque_future_role_manifest("unsupported", 105);
    let mut manifest = manifest_value(&manifest_json);
    manifest["topology"]["rolesObserved"] = json!(["managementPoint"]);

    assert_eq!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads),
        Err(SccmServerIntakeError::InvalidArtifact),
        "future producer provenance must be declared by topology"
    );
}

#[test]
fn server_intake_rejects_hashed_future_roles_in_synthetic_fixtures() {
    let (manifest_json, _) = load_bundle("unsupported-db-supplement");
    let mut manifest = manifest_value(&manifest_json);
    let future_role = opaque_handle("cmtraceopen.role.sha256.v1:", 42);
    manifest["topology"]["rolesObserved"] = json!(["managementPoint", future_role]);
    manifest["artifacts"][0]["producerRole"] = Value::String(future_role);

    assert_eq!(
        assess_server_intake(&serialize_manifest(&manifest), &[]),
        Err(SccmServerIntakeError::InvalidTopology),
        "synthetic fixtures keep the finite committed role vocabulary"
    );
}

#[test]
fn server_intake_production_original_path_must_be_redacted_or_opaque() {
    let (manifest_json, payloads) = bounded_manifest(1, 4_096);
    let mut arbitrary = manifest_value(&manifest_json);
    arbitrary["artifacts"][0]["originalPath"] =
        Value::String("C:/Users/real-user/SMS_CCM/Logs/MP_GetPolicy.log".to_owned());
    assert!(
        assess_server_intake(&serialize_manifest(&arbitrary), &payloads).is_err(),
        "production originalPath cannot contradict the redacted privacy declaration"
    );

    let mut opaque = manifest_value(&manifest_json);
    let path_handle = opaque_handle("cmtraceopen.original-path.sha256.v1:", 6);
    opaque["artifacts"][0]["originalPath"] = Value::String(path_handle.clone());
    let assessment = assess_server_intake(&serialize_manifest(&opaque), &payloads)
        .expect("an opaque production originalPath marker is safe");
    let serialized = serde_json::to_string(&assessment).expect("assessment serializes");
    assert!(!serialized.contains(&path_handle));
}

#[test]
fn server_intake_expected_oracle_has_no_unhandled_contract_keys() {
    let currently_asserted = [
        "artifactId",
        "artifactIdDerivationIgnoresDiscoveryOrder",
        "artifactIdUniquenessScope",
        "artifactProvenance",
        "canonicalArtifactIds",
        "canonicalRotationArtifactIds",
        "collisionAssertions",
        "collisionSafe",
        "completeCcmRecordCount",
        "configuredPathProvenance",
        "coverage",
        "crossBundleArtifactIdReuseAllowed",
        "databaseOrRoleFinding",
        "defaultCandidateInterpretation",
        "deterministicEvidenceIds",
        "eligibleForRoleReducer",
        "evidence",
        "forbiddenConclusion",
        "lineageId",
        "logicalRecordParseable",
        "nextArtifactRequest",
        "nonCapturedProvenance",
        "normalizedOutputByteIdenticalWhenReordered",
        "partialPhysicalFragmentCreatesTerminalResult",
        "pre318ExpectedVersion",
        "privacy",
        "rawByteCountedBeforeDecoding",
        "requiredSourceFailure",
        "retainedUnclassifiedArtifactIds",
        "roleHealthFinding",
        "roleInference",
        "rolesObserved",
        "serializationOrderIsChronology",
        "terminalManagementPointDiagnosis",
        "terminalSoftwareUpdatePointHealth",
        "totalRotationSort",
        "uniqueRelativePaths",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let all_expected = intake_scenarios()
        .into_iter()
        .flat_map(|scenario| {
            load_expected(&scenario)
                .as_object()
                .expect("expected contract is an object")
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        currently_asserted, all_expected,
        "every committed expected.json key must drive an assertion"
    );
}

#[test]
fn server_intake_expected_oracles_do_not_claim_native_collection_acceptance() {
    let forbidden_native_claims = BTreeSet::from([
        "atomicCreateNoOverwrite",
        "destinationsPrecomputed",
        "neitherOverwritten",
    ]);

    for scenario in intake_scenarios() {
        let expected = load_expected(&scenario);
        let asserted_collision_keys = expected["collisionAssertions"]
            .as_object()
            .map(|assertions| assertions.keys().map(String::as_str).collect())
            .unwrap_or_default();
        assert!(
            forbidden_native_claims.is_disjoint(&asserted_collision_keys),
            "{scenario}: pure parser oracles cannot claim native collection acceptance"
        );
    }
}

#[test]
fn server_intake_rejects_ambiguous_retained_unknown_rotations() {
    for (kind, value) in [
        ("future", Value::Null),
        ("current", Value::String("unexpected".to_owned())),
        ("none", Value::String("unexpected".to_owned())),
        ("timestamped", Value::String("not-a-timestamp".to_owned())),
    ] {
        let (manifest_json, payloads) = load_bundle("unsupported-db-supplement");
        let mut manifest = manifest_value(&manifest_json);
        manifest["artifacts"][0]["rotation"]["kind"] = Value::String(kind.to_owned());
        manifest["artifacts"][0]["rotation"]["value"] = value;

        assert_eq!(
            assess_server_intake(&serialize_manifest(&manifest), &payloads),
            Err(SccmServerIntakeError::InvalidArtifact),
            "retained unknown evidence needs an unambiguous rotation identity"
        );
    }
}

#[test]
fn server_intake_bounds_each_declared_artifact_limit() {
    let (manifest_json, payloads) = bounded_manifest(1, 268_435_457);

    assert_eq!(
        assess_server_intake(&manifest_json, &payloads),
        Err(SccmServerIntakeError::ManifestLimitExceeded),
        "a single artifact may not declare more than 256 MiB"
    );
}

#[test]
fn server_intake_accepts_a_manifest_within_all_resource_limits() {
    let (manifest_json, payloads) = bounded_manifest(1, 4_096);

    assert!(
        assess_server_intake(&manifest_json, &payloads).is_ok(),
        "the bounded-manifest helper must represent a valid baseline"
    );
}

#[test]
fn server_intake_bounds_manifest_artifact_count() {
    let (manifest_json, payloads) = bounded_manifest(513, 4_096);

    assert_eq!(
        assess_server_intake(&manifest_json, &payloads),
        Err(SccmServerIntakeError::ManifestLimitExceeded),
        "a manifest may not force unbounded per-artifact work"
    );
}

#[test]
fn server_intake_artifact_count_limit_precedes_per_artifact_extension_work() {
    let (manifest_json, payloads) = bounded_manifest(513, 4_096);
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["unsafeIdentityField"] =
        Value::String("Real User <real.user@example.com>".to_owned());

    assert_eq!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads),
        Err(SccmServerIntakeError::ManifestLimitExceeded),
        "the artifact-count gate must stop nested preflight work before artifact validation"
    );
}

#[test]
fn server_intake_bounds_aggregate_declared_bytes() {
    let (manifest_json, payloads) = bounded_manifest(5, 268_435_456);

    assert_eq!(
        assess_server_intake(&manifest_json, &payloads),
        Err(SccmServerIntakeError::ManifestLimitExceeded),
        "aggregate declared collection work may not exceed 1 GiB"
    );
}

#[test]
fn server_intake_bounds_aggregate_bytes_copied_without_collection_limits() {
    let (manifest_json, payloads) = bounded_manifest(5, 1);
    let mut manifest = manifest_value(&manifest_json);
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
    {
        artifact["bytesCopied"] = Value::from(268_435_456_u64);
        artifact["collectionLimit"] = Value::Null;
    }

    assert_eq!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads),
        Err(SccmServerIntakeError::ManifestLimitExceeded),
        "aggregate copied-byte claims stay bounded even before payload validation"
    );
}

#[test]
fn server_intake_rejects_evidence_later_than_collection_time() {
    let (manifest_json, payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["collectedUtc"] = Value::String("2026-07-30T00:02:58Z".to_owned());

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
        "a comparable record instant cannot be later than collection"
    );
}

#[test]
fn server_intake_rejects_incoherent_configured_path_class() {
    let (manifest_json, payloads) = load_bundle("absent-dp");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["configuredPathProvenance"]["pathClass"] =
        Value::String("nonDefault".to_owned());

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
        "a default candidate cannot claim non-default configured provenance"
    );
}

#[test]
fn server_intake_requires_producer_host_for_declared_sources() {
    let (manifest_json, payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["producerHostHandle"] = Value::Null;

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
        "declared server evidence must retain its producer-host provenance"
    );
}

#[test]
fn server_intake_exercises_committed_expected_contracts() {
    for scenario in intake_scenarios() {
        let expected = load_expected(&scenario);
        let (manifest_json, payloads) = load_bundle(&scenario);
        let assessment = assess_server_intake(&manifest_json, &payloads)
            .unwrap_or_else(|error| panic!("{scenario} should be assessed: {error}"));
        let actual = serde_json::to_value(&assessment).expect("assessment serializes");

        assert_eq!(
            actual["schemaVersion"], expected["pre318ExpectedVersion"],
            "{scenario}: expected contract version"
        );

        let actual_artifacts = actual["artifacts"]
            .as_array()
            .expect("assessment artifacts are an array");
        if let Some(expected_ids) = expected.get("canonicalArtifactIds") {
            let actual_ids = Value::Array(
                actual_artifacts
                    .iter()
                    .map(|artifact| artifact["artifactId"].clone())
                    .collect(),
            );
            assert_eq!(
                actual_ids, *expected_ids,
                "{scenario}: canonicalArtifactIds"
            );
        }
        if let Some(expected_ids) = expected.get("canonicalRotationArtifactIds") {
            let actual_ids = Value::Array(
                actual_artifacts
                    .iter()
                    .filter(|artifact| !artifact["rotation"].is_null())
                    .map(|artifact| artifact["artifactId"].clone())
                    .collect(),
            );
            assert_eq!(
                actual_ids, *expected_ids,
                "{scenario}: canonicalRotationArtifactIds"
            );
        }
        if let Some(expected_ids) = expected.get("retainedUnclassifiedArtifactIds") {
            let actual_ids = Value::Array(
                actual_artifacts
                    .iter()
                    .filter(|artifact| artifact["producerRole"] == "unclassified")
                    .map(|artifact| artifact["artifactId"].clone())
                    .collect(),
            );
            assert_eq!(
                actual_ids, *expected_ids,
                "{scenario}: retainedUnclassifiedArtifactIds"
            );
        }

        let expected_coverage = expected["coverage"]
            .as_array()
            .expect("expected coverage is an array");
        let actual_coverage = actual["coverage"]
            .as_array()
            .expect("assessment coverage is an array");
        assert_eq!(
            actual_coverage.len(),
            expected_coverage.len(),
            "{scenario}: coverage row count"
        );
        for (actual_row, expected_row) in actual_coverage.iter().zip(expected_coverage) {
            for (key, expected_value) in expected_row
                .as_object()
                .expect("expected coverage row is an object")
            {
                match key.as_str() {
                    "producerRole" | "workflowSubjectRole" | "sourceId" | "state" => {
                        assert_eq!(
                            &actual_row[key], expected_value,
                            "{scenario}: coverage {key}"
                        );
                    }
                    "gap" => {
                        assert_eq!(expected_value, "candidate absent only");
                        assert_eq!(actual_row["state"], "absent");
                        let artifact = artifact_json(
                            &actual,
                            actual_row["artifactIds"][0]
                                .as_str()
                                .expect("coverage artifact ID"),
                        );
                        assert_eq!(artifact["configuredPathState"], "defaultCandidate");
                    }
                    "configuredRootInstances" => assert_eq!(
                        actual_row["artifactIds"]
                            .as_array()
                            .expect("coverage artifact IDs")
                            .len() as u64,
                        expected_value.as_u64().expect("root count is an integer")
                    ),
                    "truncated" => {
                        assert_eq!(expected_value, true);
                        let artifact = artifact_json(
                            &actual,
                            actual_row["artifactIds"][0]
                                .as_str()
                                .expect("coverage artifact ID"),
                        );
                        assert_eq!(artifact["truncated"], true);
                    }
                    "requiredness" => {
                        assert_eq!(expected_value, "optionalSupplemental");
                        assert!(actual["nextArtifactRequests"]
                            .as_array()
                            .expect("requests are an array")
                            .is_empty());
                    }
                    other => panic!("{scenario}: unhandled coverage key {other}"),
                }
            }
        }

        if let Some(expected_provenance) = expected.get("artifactProvenance") {
            for expected_artifact in expected_provenance
                .as_array()
                .expect("artifact provenance is an array")
            {
                let artifact_id = expected_artifact["artifactId"]
                    .as_str()
                    .expect("expected artifactId is a string");
                let actual_artifact = artifact_json(&actual, artifact_id);
                for (expected_key, expected_value) in expected_artifact
                    .as_object()
                    .expect("expected provenance is an object")
                {
                    let actual_value = match expected_key.as_str() {
                        "artifactId" => &actual_artifact["artifactId"],
                        "encoding" => &actual_artifact["captureProvenance"]["encoding"],
                        "byteLimit" => &actual_artifact["captureProvenance"]["byteLimit"],
                        "limitApplied" => &actual_artifact["captureProvenance"]["limitApplied"],
                        "bytesCopied" => &actual_artifact["bytesCopied"],
                        "relativePath" => &actual_artifact["relativePath"],
                        "fragmentComplete" => &actual_artifact["fragmentComplete"],
                        "sha256" => &actual_artifact["contentSha256"],
                        other => panic!("{scenario}: unhandled provenance key {other}"),
                    };
                    if expected_key != "artifactId" {
                        assert_eq!(
                            actual_value, expected_value,
                            "{scenario}: {artifact_id} {expected_key}"
                        );
                    }
                }
            }
        }

        if let Some(expected_evidence) = expected.get("evidence") {
            for expected_row in expected_evidence
                .as_array()
                .expect("expected evidence is an array")
            {
                let artifact_id = expected_row["artifactId"]
                    .as_str()
                    .expect("expected evidence artifactId is a string");
                let records = actual["evidence"]
                    .as_array()
                    .expect("assessment evidence is an array")
                    .iter()
                    .filter(|row| row["reference"]["artifactId"] == artifact_id)
                    .collect::<Vec<_>>();
                assert_eq!(
                    records.len() as u64,
                    expected_row["logicalRecordCount"]
                        .as_u64()
                        .expect("logicalRecordCount is an integer"),
                    "{scenario}: logical record count"
                );
                let line_range = &expected_row["lineRange"];
                let first = records.first().unwrap_or_else(|| {
                    panic!("{scenario}: {artifact_id} has no evidence record for lineRange")
                });
                assert_eq!(
                    first["reference"]["lineStart"], line_range["start"],
                    "{scenario}: {artifact_id} line start"
                );
                assert_eq!(
                    first["reference"]["lineEnd"], line_range["end"],
                    "{scenario}: {artifact_id} line end"
                );
                let keys = expected_row
                    .as_object()
                    .expect("expected evidence row is an object")
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    keys,
                    BTreeSet::from(["artifactId", "lineRange", "logicalRecordCount"]),
                    "{scenario}: every evidence expectation is asserted"
                );
            }
        }

        if let Some(expected_path) = expected.get("configuredPathProvenance") {
            let artifact_id = expected["artifactId"]
                .as_str()
                .expect("configured-path expected artifactId is a string");
            let actual_artifact = artifact_json(&actual, artifact_id);
            assert_eq!(
                actual_artifact["configuredPathState"],
                expected_path["state"]
            );
            assert_eq!(
                actual_artifact["configuredPathClass"],
                expected_path["pathClass"]
            );
            assert_eq!(
                actual_artifact["pathFingerprint"],
                expected_path["pathFingerprint"]
            );
        }

        if let Some(expected_roles) = expected.get("rolesObserved") {
            assert_eq!(actual["topology"]["rolesObserved"], *expected_roles);
        }

        assert_remaining_expected_contracts(
            &scenario,
            &expected,
            &manifest_json,
            &payloads,
            &actual,
        );
    }
}
