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
        "absent" | "accessDenied" | "capped" | "skipped" | "unsupported"
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

#[test]
fn site_core_uses_canonical_rotation_and_coverage_contracts() {
    let manifests = site_core_manifests();
    assert_eq!(manifests.len(), 9, "site-core scenario matrix changed");

    let mut failures = Vec::new();
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
            failures.extend(
                coverage_contract_failures(artifact)
                    .into_iter()
                    .map(|failure| format!("{scenario}: {failure}")),
            );
        }
    }

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
    let fixture_path = site_core_root()
        .join("rotation-boundary")
        .join(relative_path);
    if !fixture_path.is_file() {
        failures.push(format!(
            "rotation-boundary: manifest path does not resolve to a fixture: {}",
            fixture_path.display()
        ));
    } else {
        let bytes_copied = rollover["bytesCopied"]
            .as_u64()
            .expect("captured rollover records bytesCopied");
        let actual_bytes = std::fs::metadata(&fixture_path)
            .expect("rollover fixture metadata is readable")
            .len();
        if bytes_copied != actual_bytes {
            failures.push(format!(
                "rotation-boundary: bytesCopied {bytes_copied} does not match fixture length {actual_bytes}"
            ));
        }
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
