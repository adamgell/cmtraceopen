use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{classify_artifact_name, SccmArtifactFamily, SccmRole};
use serde_json::{Map, Value};

const SCENARIOS: [&str; 20] = [
    "admin-service-access-denied",
    "admin-service-auth-failure",
    "admin-service-backend-failure",
    "admin-service-parse-failed",
    "admin-service-skipped",
    "admin-service-success",
    "blocked-deferred",
    "contradictory-evidence",
    "iis-supplemental",
    "incomplete",
    "privacy-redaction",
    "provider-authz-denied",
    "provider-query-failure",
    "provider-retry",
    "provider-source-absent",
    "provider-source-capped",
    "provider-source-unsupported",
    "provider-success",
    "provider-timeout",
    "rotation-boundary",
];

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/provider_and_admin_service")
}

fn read_json(scenario: &str, filename: &str) -> Value {
    let path = corpus_root().join(scenario).join(filename);
    serde_json::from_str(&fs::read_to_string(&path).expect("fixture file is readable"))
        .unwrap_or_else(|error| panic!("{} is valid JSON: {error}", path.display()))
}

fn actual_scenarios() -> BTreeSet<String> {
    fs::read_dir(corpus_root())
        .expect("corpus root is readable")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            path.is_dir().then(|| {
                path.file_name()
                    .expect("scenario directory name")
                    .to_string_lossy()
                    .into_owned()
            })
        })
        .collect()
}

fn assert_allowed_keys(object: &Map<String, Value>, allowed: &[&str], context: &str) {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    for key in object.keys() {
        assert!(
            allowed.contains(key.as_str()),
            "{context}: unknown field {key}"
        );
    }
}

fn physical_state(state: &str) -> bool {
    matches!(state, "captured" | "capped" | "parseFailed")
}

fn private_payload_tokens(scenario: &str, manifest: &Value) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    for artifact in manifest["artifacts"].as_array().expect("artifact array") {
        let Some(relative) = artifact["relativePath"].as_str() else {
            continue;
        };
        let content = fs::read_to_string(corpus_root().join(scenario).join(relative))
            .expect("synthetic CCM payload is UTF-8");
        for line in content.lines() {
            let Some(message) = line
                .strip_prefix("<![LOG[SYNTHETIC FIXTURE; ")
                .and_then(|line| line.split_once("]LOG]!>").map(|pair| pair.0))
            else {
                continue;
            };
            for field in message.split(';').map(str::trim) {
                let Some((name, value)) = field.split_once('=') else {
                    continue;
                };
                if matches!(
                    name,
                    "RequestId"
                        | "OperationHandle"
                        | "EndpointId"
                        | "CallerHandle"
                        | "Authorization"
                        | "QueryHandle"
                ) {
                    tokens.insert(value.to_owned());
                }
            }
        }
    }
    tokens
}

#[test]
fn corpus_has_the_exact_reviewed_scenario_matrix() {
    assert_eq!(
        actual_scenarios(),
        SCENARIOS.into_iter().map(str::to_owned).collect()
    );
}

#[test]
fn manifests_use_closed_schemas_and_exact_topology_authority() {
    let mut corpus_artifact_ids = BTreeSet::new();
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json");
        let top = manifest.as_object().expect("manifest object");
        assert_eq!(
            top.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            [
                "artifacts",
                "bundleRole",
                "privacy",
                "proposalOnly",
                "sccmManifestVersion",
                "syntheticFixture",
                "topology",
            ]
            .into_iter()
            .collect(),
            "{scenario}: exact top-level fields"
        );
        assert_eq!(manifest["sccmManifestVersion"], 1, "{scenario}");
        assert_eq!(manifest["syntheticFixture"], true, "{scenario}");
        assert_eq!(manifest["proposalOnly"], true, "{scenario}");
        assert_eq!(manifest["bundleRole"], "server", "{scenario}");
        assert_eq!(manifest["privacy"]["synthetic"], true, "{scenario}");
        assert_eq!(manifest["privacy"]["rawPaths"], "redacted", "{scenario}");
        assert_eq!(
            manifest["privacy"]
                .as_object()
                .expect("privacy object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["rawPaths", "synthetic"].into_iter().collect(),
            "{scenario}: exact privacy fields"
        );
        let topology = manifest["topology"].as_object().expect("topology object");
        assert_eq!(
            topology.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            ["captureHost", "rolesObserved", "siteCode"]
                .into_iter()
                .collect(),
            "{scenario}: exact topology fields"
        );
        assert_eq!(topology["captureHost"], "LAB-CM01", "{scenario}");
        assert_eq!(topology["siteCode"], "LAB", "{scenario}");
        let roles = topology["rolesObserved"].as_array().expect("roles array");
        assert!(!roles.is_empty(), "{scenario}");
        assert!(roles
            .iter()
            .all(|role| matches!(role.as_str(), Some("provider" | "adminService"))));

        let mut scenario_paths = BTreeSet::new();
        for artifact in manifest["artifacts"].as_array().expect("artifact array") {
            let object = artifact.as_object().expect("artifact object");
            assert_allowed_keys(
                object,
                &[
                    "artifactId",
                    "bytesCopied",
                    "captureState",
                    "collectedUtc",
                    "collectionDetail",
                    "collectionLimit",
                    "configuredPathProvenance",
                    "encoding",
                    "fragmentComplete",
                    "originalBasename",
                    "originalPath",
                    "producerHostHandle",
                    "producerRole",
                    "relativePath",
                    "rotation",
                    "skipReason",
                    "sourceId",
                    "sourceKind",
                    "sourceVersion",
                    "truncated",
                    "unsupportedReason",
                    "workflowSubject",
                ],
                scenario,
            );
            for required in [
                "artifactId",
                "producerRole",
                "producerHostHandle",
                "workflowSubject",
                "sourceId",
                "sourceKind",
                "originalPath",
                "originalBasename",
                "configuredPathProvenance",
                "rotation",
                "captureState",
                "collectedUtc",
                "bytesCopied",
            ] {
                assert!(
                    object.contains_key(required),
                    "{scenario}: missing {required}"
                );
            }
            assert_allowed_keys(
                artifact["workflowSubject"]
                    .as_object()
                    .expect("workflow subject"),
                &["instanceHandle", "role"],
                scenario,
            );
            assert_allowed_keys(
                artifact["configuredPathProvenance"]
                    .as_object()
                    .expect("configured path"),
                &["pathFingerprint", "state"],
                scenario,
            );
            assert_allowed_keys(
                artifact["rotation"].as_object().expect("rotation"),
                &["kind", "lineageId"],
                scenario,
            );
            if let Some(limit) = artifact.get("collectionLimit") {
                assert_allowed_keys(
                    limit.as_object().expect("collection limit"),
                    &["byteLimit", "limitApplied"],
                    scenario,
                );
            }

            let artifact_id = artifact["artifactId"].as_str().expect("artifact id");
            assert!(
                corpus_artifact_ids.insert(artifact_id.to_owned()),
                "duplicate {artifact_id}"
            );
            let source_id = artifact["sourceId"].as_str().expect("source id");
            let (role, host, subject, profile) = match source_id {
                "server-provider" => (
                    "provider",
                    "synthetic:host:provider-01",
                    "synthetic:subject:provider-01",
                    "provider-server-5.00.test-v1",
                ),
                "server-admin-service" | "server-admin-service-iis" => (
                    "adminService",
                    "synthetic:host:admin-service-01",
                    "synthetic:subject:admin-service-01",
                    "admin-service-server-5.00.test-v1",
                ),
                _ => panic!("{scenario}: undeclared source {source_id}"),
            };
            assert_eq!(artifact["producerRole"], role, "{scenario}");
            assert_eq!(artifact["producerHostHandle"], host, "{scenario}");
            assert_eq!(artifact["workflowSubject"]["role"], role, "{scenario}");
            assert_eq!(
                artifact["workflowSubject"]["instanceHandle"], subject,
                "{scenario}"
            );
            let basename = artifact["originalBasename"].as_str().expect("basename");
            assert!(
                matches!(
                    (source_id, basename),
                    ("server-provider", "Smsprov.log" | "Smsprov.lo_")
                        | ("server-admin-service", "AdminService.log")
                        | ("server-admin-service-iis", "u_ex_synthetic.log")
                ),
                "{scenario}: source/basename tuple"
            );
            assert!(artifact["originalPath"]
                .as_str()
                .is_some_and(|path| path.starts_with("REDACTED_")));

            let state = artifact["captureState"].as_str().expect("capture state");
            if physical_state(state) {
                if scenario != "rotation-boundary" {
                    assert_eq!(artifact["sourceVersion"], "5.00.TEST", "{scenario}");
                }
                let relative = artifact["relativePath"].as_str().expect("relative path");
                assert!(relative.starts_with("evidence/sccm/server/"), "{scenario}");
                assert!(relative.ends_with(basename), "{scenario}");
                assert!(
                    scenario_paths.insert(relative.to_owned()),
                    "{scenario}: duplicate path"
                );
                let payload = corpus_root().join(scenario).join(Path::new(relative));
                let content = fs::read_to_string(&payload)
                    .unwrap_or_else(|error| panic!("{}: {error}", payload.display()));
                assert_eq!(
                    artifact["bytesCopied"].as_u64(),
                    Some(content.len() as u64),
                    "{scenario}"
                );
                assert!(artifact["collectionLimit"].is_object(), "{scenario}");
                if source_id != "server-admin-service-iis"
                    && state != "parseFailed"
                    && scenario != "rotation-boundary"
                {
                    for line in content.lines() {
                        assert!(line.starts_with("<![LOG[SYNTHETIC FIXTURE; "), "{scenario}");
                        assert!(line.contains(&format!("Layer={role}")), "{scenario}");
                        assert!(line.contains(&format!("ProfileId={profile}")), "{scenario}");
                        assert!(line.contains("RequestId="), "{scenario}");
                        assert!(
                            line.contains("OperationHandle=safe-operation-"),
                            "{scenario}"
                        );
                        assert!(line.contains("Terminal="), "{scenario}");
                        assert_eq!(
                            line.contains("+99999"),
                            scenario == "provider-timeout",
                            "{scenario}: timestamp provenance"
                        );
                    }
                }
            } else {
                assert!(artifact.get("relativePath").is_none(), "{scenario}");
                assert_eq!(artifact["bytesCopied"], 0, "{scenario}");
                assert!(artifact.get("encoding").is_none(), "{scenario}");
                assert!(artifact.get("collectionLimit").is_none(), "{scenario}");
            }
        }
    }
}

#[test]
fn complete_oracles_are_privacy_safe_and_cover_every_public_collection() {
    let expected_keys = [
        "artifactRequests",
        "coverage",
        "crossSideCausalClaims",
        "findings",
        "profiles",
        "sourceLocalObservations",
        "supportState",
        "transactions",
        "workflow",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json");
        let expected = read_json(scenario, "expected.json");
        assert_eq!(
            expected
                .as_object()
                .expect("oracle object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected_keys,
            "{scenario}: complete public oracle fields"
        );
        assert_eq!(
            expected["workflow"], "providerAndAdminService",
            "{scenario}"
        );
        assert_eq!(
            expected["supportState"], "syntheticProfileOnly",
            "{scenario}"
        );
        for collection in [
            "profiles",
            "coverage",
            "transactions",
            "findings",
            "sourceLocalObservations",
            "artifactRequests",
            "crossSideCausalClaims",
        ] {
            assert!(expected[collection].is_array(), "{scenario}: {collection}");
        }
        let rendered = serde_json::to_string(&expected).expect("oracle renders");
        for private in private_payload_tokens(scenario, &manifest) {
            assert!(
                !rendered.contains(&private),
                "{scenario}: private payload token escaped: {private}"
            );
        }
        for transaction in expected["transactions"].as_array().expect("transactions") {
            assert_eq!(transaction["key"]["confidence"], "low", "{scenario}");
            assert_eq!(
                transaction["key"]["extractionProfile"]["maturity"], "experimental",
                "{scenario}"
            );
            assert_eq!(transaction["correlationEligible"], false, "{scenario}");
        }
        for finding in expected["findings"].as_array().expect("findings") {
            assert!(finding["finding"]["class"].is_string(), "{scenario}");
            assert!(finding["finding"]["severity"].is_string(), "{scenario}");
            assert!(finding["producerHostHandle"].is_string(), "{scenario}");
            assert!(finding["workflowSubjectHandle"].is_string(), "{scenario}");
        }
    }
}

#[test]
fn phase_disposition_terminal_and_rotation_edges_are_adversarially_present() {
    let retry = fs::read_to_string(corpus_root().join("provider-retry/evidence/sccm/server/provider/server-provider/subject-provider/current/Smsprov.log"))
        .expect("retry fixture");
    assert!(retry.contains("Disposition=retryableFailure; Terminal=false"));
    assert!(retry.contains("Disposition=succeeded; Terminal=true"));

    let contradiction = fs::read_to_string(corpus_root().join("contradictory-evidence/evidence/sccm/server/provider/server-provider/subject-provider/current/Smsprov.log"))
        .expect("contradiction fixture");
    assert!(contradiction.contains("Disposition=failed; Terminal=true"));
    assert!(contradiction.contains("Disposition=succeeded; Terminal=true"));

    let rotation = read_json("rotation-boundary", "manifest.json");
    let artifacts = rotation["artifacts"]
        .as_array()
        .expect("rotation artifacts");
    assert_eq!(artifacts.len(), 2);
    assert_eq!(artifacts[0]["rotation"]["kind"], "current");
    assert_eq!(artifacts[1]["rotation"]["kind"], "lo_");
    assert_ne!(artifacts[0]["artifactId"], artifacts[1]["artifactId"]);
    assert_ne!(artifacts[0]["relativePath"], artifacts[1]["relativePath"]);
}

#[test]
fn source_catalog_distinguishes_provider_and_admin_service() {
    let provider = classify_artifact_name("Smsprov.log", SccmRole::Provider);
    assert!(provider.supported_for_diagnosis);
    assert_eq!(provider.family, SccmArtifactFamily::Provider);
    assert_eq!(provider.role, SccmRole::Provider);

    let admin = classify_artifact_name("AdminService.log", SccmRole::AdminService);
    assert!(admin.supported_for_diagnosis);
    assert_eq!(admin.family, SccmArtifactFamily::AdminService);
    assert_eq!(admin.role, SccmRole::AdminService);

    for wrong_role in [
        SccmRole::SiteServer,
        SccmRole::ManagementPoint,
        SccmRole::DistributionPoint,
        SccmRole::SoftwareUpdatePoint,
        SccmRole::WsUs,
        SccmRole::Provider,
    ] {
        let wrong = classify_artifact_name("AdminService.log", wrong_role);
        assert!(!wrong.supported_for_diagnosis);
    }
}
