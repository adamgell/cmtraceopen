use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{classify_artifact_name, SccmArtifactFamily, SccmRole};
use serde_json::Value;

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

fn private_shape(value: &Value) -> bool {
    match value {
        Value::String(value) => {
            let lowercase = value.to_ascii_lowercase();
            lowercase.contains("bearer ")
                || lowercase.contains("select ")
                || lowercase.contains("@example")
                || lowercase.contains("requestid")
                || lowercase.contains("operationhandle")
                || lowercase.contains("endpointid")
                || lowercase.contains("preparationonly")
                || value.contains("99999999-9999-9999-9999-999999999999")
        }
        Value::Array(values) => values.iter().any(private_shape),
        Value::Object(values) => values.iter().any(|(name, value)| {
            private_shape(&Value::String(name.clone())) || private_shape(value)
        }),
        _ => false,
    }
}

#[test]
fn corpus_has_the_exact_reviewed_scenario_matrix() {
    assert_eq!(
        actual_scenarios(),
        SCENARIOS.into_iter().map(str::to_owned).collect()
    );
}

#[test]
fn manifests_are_canonical_server_intake_inputs_with_sealed_roles_and_paths() {
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json");
        assert_eq!(manifest["sccmManifestVersion"], 1, "{scenario}");
        assert_eq!(manifest["syntheticFixture"], true, "{scenario}");
        assert_eq!(manifest["proposalOnly"], true, "{scenario}");
        assert_eq!(manifest["bundleRole"], "server", "{scenario}");
        assert_eq!(manifest["privacy"]["rawPaths"], "redacted", "{scenario}");
        assert!(manifest.get("scenario").is_none(), "{scenario}");
        assert!(manifest.get("bundle").is_none(), "{scenario}");

        for artifact in manifest["artifacts"].as_array().expect("artifact array") {
            let source_id = artifact["sourceId"].as_str().expect("source id");
            let role = artifact["producerRole"].as_str().expect("producer role");
            let expected_role = if source_id == "server-provider" {
                "provider"
            } else {
                "adminService"
            };
            assert_eq!(role, expected_role, "{scenario}: {source_id}");
            assert_eq!(
                artifact["workflowSubject"]["role"], expected_role,
                "{scenario}"
            );
            assert!(
                artifact["originalPath"]
                    .as_str()
                    .is_some_and(|path| path.starts_with("REDACTED_")),
                "{scenario}"
            );
            for obsolete in [
                "layer",
                "endpointId",
                "diagnosticUse",
                "sanitizedSourcePath",
                "pathFingerprint",
            ] {
                assert!(
                    artifact.get(obsolete).is_none(),
                    "{scenario}: obsolete {obsolete}"
                );
            }

            let state = artifact["captureState"].as_str().expect("coverage state");
            if matches!(state, "captured" | "capped" | "parseFailed") {
                let relative = artifact["relativePath"].as_str().expect("relative path");
                let payload = corpus_root().join(scenario).join(Path::new(relative));
                let size = fs::metadata(&payload)
                    .unwrap_or_else(|error| panic!("{}: {error}", payload.display()))
                    .len();
                assert_eq!(artifact["bytesCopied"].as_u64(), Some(size), "{scenario}");
            } else {
                assert!(artifact.get("relativePath").is_none(), "{scenario}");
                assert_eq!(artifact["bytesCopied"], 0, "{scenario}");
            }
        }
    }
}

#[test]
fn expected_contracts_are_final_privacy_safe_semantic_oracles() {
    for scenario in SCENARIOS {
        let expected = read_json(scenario, "expected.json");
        assert_eq!(expected["fixtureContractVersion"], 1, "{scenario}");
        assert_eq!(
            expected["workflow"], "providerAndAdminService",
            "{scenario}"
        );
        assert_eq!(expected["scenario"], scenario, "{scenario}");
        assert!(
            !private_shape(&expected),
            "{scenario}: private or obsolete expected shape"
        );
        assert!(expected["expectedCoverage"].is_array(), "{scenario}");
        assert!(expected["expectedTransactions"].is_array(), "{scenario}");
        assert!(
            expected["expectedSourceLocalKinds"].is_array(),
            "{scenario}"
        );
    }
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
