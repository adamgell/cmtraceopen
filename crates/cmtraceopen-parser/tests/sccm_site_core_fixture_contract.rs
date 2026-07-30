use serde_json::Value;

fn site_core_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/site_core")
}

fn site_core_manifests() -> Vec<(String, Value)> {
    let mut scenario_dirs = std::fs::read_dir(site_core_root())
        .expect("site-core fixture root is readable")
        .map(|entry| entry.expect("site-core directory entry is readable").path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    scenario_dirs.sort();

    scenario_dirs
        .into_iter()
        .map(|scenario_dir| {
            let scenario = scenario_dir
                .file_name()
                .expect("scenario directory has a name")
                .to_string_lossy()
                .into_owned();
            let contents = std::fs::read_to_string(scenario_dir.join("manifest.json"))
                .expect("scenario manifest is readable");
            let manifest =
                serde_json::from_str(&contents).expect("scenario manifest contains valid JSON");
            (scenario, manifest)
        })
        .collect()
}

fn coverage_contract_failures(artifact: &Value) -> Vec<String> {
    let state = artifact["captureState"].as_str().unwrap_or_default();
    if matches!(
        state,
        "absent" | "accessDenied" | "capped" | "skipped" | "unsupported" | "parseFailed"
    ) && artifact["rotation"]["fragmentComplete"] == true
    {
        vec![format!(
            "{state} artifact {} cannot be a complete fragment",
            artifact["artifactId"].as_str().unwrap_or("<missing>")
        )]
    } else {
        Vec::new()
    }
}

fn artifact_storage_failures(scenario_dir: &std::path::Path, artifact: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    let artifact_id = artifact["artifactId"].as_str().unwrap_or("<missing>");
    let state = artifact["captureState"].as_str().unwrap_or_default();

    if matches!(state, "captured" | "capped") {
        let Some(relative_path) = artifact["relativePath"].as_str() else {
            return vec![format!(
                "{state} artifact {artifact_id} must have a relativePath"
            )];
        };
        let relative = std::path::Path::new(relative_path);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            failures.push(format!(
                "{state} artifact {artifact_id} has an unsafe relativePath {relative_path}"
            ));
            return failures;
        }

        let fixture_path = scenario_dir.join(relative);
        if !fixture_path.is_file() {
            failures.push(format!(
                "{state} artifact {artifact_id} path does not resolve to a fixture: {}",
                fixture_path.display()
            ));
            return failures;
        }

        let Some(bytes_copied) = artifact["bytesCopied"].as_u64() else {
            failures.push(format!(
                "{state} artifact {artifact_id} must record bytesCopied"
            ));
            return failures;
        };
        let actual_bytes = std::fs::metadata(&fixture_path)
            .expect("validated fixture metadata is readable")
            .len();
        if bytes_copied != actual_bytes {
            failures.push(format!(
                "{state} artifact {artifact_id} bytesCopied {bytes_copied} does not match fixture length {actual_bytes}"
            ));
        }
    } else if matches!(
        state,
        "absent" | "accessDenied" | "skipped" | "unsupported" | "parseFailed"
    ) {
        if !artifact["relativePath"].is_null() {
            failures.push(format!(
                "{state} artifact {artifact_id} cannot have a relativePath"
            ));
        }
        if artifact["bytesCopied"].as_u64() != Some(0) {
            failures.push(format!(
                "{state} artifact {artifact_id} must record zero bytesCopied"
            ));
        }
    } else {
        failures.push(format!(
            "artifact {artifact_id} has missing or unknown captureState {state:?}"
        ));
    }

    failures
}

#[test]
fn site_core_uses_canonical_rotation_and_coverage_contracts() {
    let manifests = site_core_manifests();
    assert_eq!(manifests.len(), 9, "site-core scenario matrix changed");

    let mut failures = Vec::new();
    let mut artifacts_seen = 0;
    let mut physical_artifacts = 0;
    for (scenario, manifest) in &manifests {
        let site_code = manifest["topology"]["siteCode"]
            .as_str()
            .expect("site-core topology has a site code");
        if site_code.len() != 3
            || !site_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            failures.push(format!(
                "{scenario}: siteCode must match ^[A-Z0-9]{{3}}$, got {site_code}"
            ));
        }

        for artifact in manifest["artifacts"]
            .as_array()
            .expect("site-core artifacts are an array")
        {
            artifacts_seen += 1;
            if matches!(
                artifact["captureState"].as_str(),
                Some("captured" | "capped")
            ) {
                physical_artifacts += 1;
            }
            failures.extend(
                coverage_contract_failures(artifact)
                    .into_iter()
                    .map(|failure| format!("{scenario}: {failure}")),
            );
            failures.extend(
                artifact_storage_failures(&site_core_root().join(scenario), artifact)
                    .into_iter()
                    .map(|failure| format!("{scenario}: {failure}")),
            );
        }
    }
    assert_eq!(artifacts_seen, 18, "site-core artifact matrix changed");
    assert_eq!(
        physical_artifacts, 14,
        "site-core physical artifact matrix changed"
    );

    let rotations = manifests
        .iter()
        .find(|(scenario, _)| scenario == "rotation-boundary")
        .map(|(_, manifest)| manifest)
        .expect("site-core has a rotation-boundary scenario");
    let rollover = rotations["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array")
        .iter()
        .find(|artifact| artifact["rotation"]["kind"] == "loUnderscore")
        .expect("rotation corpus has a .lo_ artifact");

    let basename = rollover["originalBasename"]
        .as_str()
        .expect("rollover artifact has an original basename");
    if basename != "sitecomp.lo_" {
        failures.push(format!(
            "rotation-boundary: standard ConfigMgr rollover basename must be sitecomp.lo_, got {basename}"
        ));
    }
    let relative_path = rollover["relativePath"]
        .as_str()
        .expect("captured rollover has a relative path");
    if !relative_path.ends_with("/sitecomp.lo_") {
        failures.push(format!(
            "rotation-boundary: rollover relativePath must end in /sitecomp.lo_, got {relative_path}"
        ));
    }
    let expected: Value = serde_json::from_str(include_str!(
        "fixtures/sccm/server/site_core/rotation-boundary/expected.json"
    ))
    .expect("rotation expected output is JSON");
    let requested_basenames = expected["unlinkedObservations"][0]["nextArtifacts"][0]["basenames"]
        .as_array()
        .expect("rotation request has basenames");
    if requested_basenames
        .iter()
        .any(|value| value.as_str() == Some("sitecomp.log.lo_"))
        || !requested_basenames
            .iter()
            .any(|value| value.as_str() == Some("sitecomp.lo_"))
    {
        failures.push(format!(
            "rotation-boundary: expected request must use sitecomp.lo_, got {requested_basenames:?}"
        ));
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn capped_artifact_cannot_claim_a_complete_fragment() {
    let artifact = serde_json::json!({
        "artifactId": "capped-probe",
        "captureState": "capped",
        "rotation": {"kind": "current", "fragmentComplete": true}
    });

    assert_eq!(coverage_contract_failures(&artifact).len(), 1);
}

#[test]
fn artifact_storage_contract_rejects_missing_mismatched_and_unsafe_paths() {
    let scenario_dir = site_core_root().join("healthy");
    let wrong_size = serde_json::json!({
        "artifactId": "wrong-size",
        "captureState": "captured",
        "relativePath": "evidence/sccm/server/site-core/sitecomp/current/sitecomp.log",
        "bytesCopied": 1
    });
    let missing = serde_json::json!({
        "artifactId": "missing",
        "captureState": "captured",
        "relativePath": "evidence/sccm/server/site-core/sitecomp/current/missing.log",
        "bytesCopied": 1
    });
    let unsafe_path = serde_json::json!({
        "artifactId": "unsafe",
        "captureState": "captured",
        "relativePath": "../outside.log",
        "bytesCopied": 1
    });
    let missing_bytes = serde_json::json!({
        "artifactId": "missing-bytes",
        "captureState": "captured",
        "relativePath": "evidence/sccm/server/site-core/sitecomp/current/sitecomp.log"
    });
    assert_eq!(
        artifact_storage_failures(&scenario_dir, &wrong_size).len(),
        1
    );
    assert_eq!(artifact_storage_failures(&scenario_dir, &missing).len(), 1);
    assert_eq!(
        artifact_storage_failures(&scenario_dir, &unsafe_path).len(),
        1
    );
    assert_eq!(
        artifact_storage_failures(&scenario_dir, &missing_bytes).len(),
        1
    );
}

#[test]
fn nonphysical_states_cannot_claim_files_or_complete_fragments() {
    let scenario_dir = site_core_root().join("healthy");
    for state in [
        "absent",
        "accessDenied",
        "skipped",
        "unsupported",
        "parseFailed",
    ] {
        let artifact = serde_json::json!({
            "artifactId": format!("{state}-with-file"),
            "captureState": state,
            "relativePath": "evidence/placeholder.log",
            "bytesCopied": 1,
            "rotation": {"kind": "current", "fragmentComplete": true}
        });

        assert_eq!(
            coverage_contract_failures(&artifact).len(),
            1,
            "{state} completeness"
        );
        assert_eq!(
            artifact_storage_failures(&scenario_dir, &artifact).len(),
            2,
            "{state} physical storage"
        );
    }
}

#[test]
fn missing_and_unknown_capture_states_fail_closed() {
    let scenario_dir = site_core_root().join("healthy");
    for artifact in [
        serde_json::json!({
            "artifactId": "missing-state",
            "relativePath": null,
            "bytesCopied": 0
        }),
        serde_json::json!({
            "artifactId": "misspelled-state",
            "captureState": "caputred",
            "relativePath": null,
            "bytesCopied": 0
        }),
    ] {
        assert_eq!(artifact_storage_failures(&scenario_dir, &artifact).len(), 1);
    }
}
