use serde_json::Value;

fn server_intake_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/intake")
}

fn server_intake_manifests() -> Vec<(String, Value)> {
    let mut scenario_dirs = std::fs::read_dir(server_intake_root())
        .expect("server intake fixture root is readable")
        .map(|entry| {
            entry
                .expect("server intake directory entry is readable")
                .path()
        })
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
                .unwrap_or_else(|error| panic!("{scenario}: manifest is readable: {error}"));
            let manifest = serde_json::from_str(&contents).unwrap_or_else(|error| {
                panic!("{scenario}: manifest contains valid JSON: {error}")
            });
            (scenario, manifest)
        })
        .collect()
}

#[test]
fn server_intake_uses_canonical_site_and_rotation_contracts() {
    let manifests = server_intake_manifests();
    assert_eq!(manifests.len(), 11, "server intake scenario matrix changed");

    let mut failures = Vec::new();
    for (scenario, manifest) in &manifests {
        let site_code = manifest["topology"]["siteCode"]
            .as_str()
            .expect("server intake topology has a site code");
        if site_code.len() != 3
            || !site_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            failures.push(format!(
                "{scenario}: siteCode must match ^[A-Z0-9]{{3}}$, got {site_code}"
            ));
        }
    }

    let rotations = manifests
        .iter()
        .find(|(scenario, _)| scenario == "rotations")
        .map(|(_, manifest)| manifest)
        .expect("server intake has a rotations scenario");
    let rollover = rotations["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array")
        .iter()
        .find(|artifact| artifact["rotation"]["kind"] == "lo_")
        .expect("rotation corpus has a .lo_ artifact");

    let basename = rollover["originalBasename"]
        .as_str()
        .expect("rollover artifact has an original basename");
    if basename != "MP_GetPolicy.lo_" {
        failures.push(format!(
            "rotations: standard ConfigMgr rollover basename must be MP_GetPolicy.lo_, got {basename}"
        ));
    }

    let relative_path = rollover["relativePath"]
        .as_str()
        .expect("captured rollover has a relative path");
    if !relative_path.ends_with("/MP_GetPolicy.lo_") {
        failures.push(format!(
            "rotations: rollover relativePath must end in /MP_GetPolicy.lo_, got {relative_path}"
        ));
    }
    let fixture_path = server_intake_root().join("rotations").join(relative_path);
    if !fixture_path.is_file() {
        failures.push(format!(
            "rotations: manifest relativePath does not resolve to a fixture: {}",
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
                "rotations: bytesCopied {bytes_copied} does not match fixture length {actual_bytes}"
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
