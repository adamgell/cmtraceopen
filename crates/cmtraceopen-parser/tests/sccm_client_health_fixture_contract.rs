use serde_json::Value;

fn client_health_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/client/health")
}

fn client_health_manifests() -> Vec<(String, Value)> {
    let mut scenario_dirs = std::fs::read_dir(client_health_root())
        .expect("client health fixture root is readable")
        .map(|entry| {
            entry
                .expect("client health directory entry is readable")
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
                .expect("scenario manifest is readable");
            let manifest =
                serde_json::from_str(&contents).expect("scenario manifest contains valid JSON");
            (scenario, manifest)
        })
        .collect()
}

fn is_exact_site_code(value: &str) -> bool {
    value.len() == 3
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

#[test]
fn client_health_uses_canonical_site_and_rotation_contracts() {
    let manifests = client_health_manifests();
    assert_eq!(manifests.len(), 9, "client health scenario matrix changed");

    let mut failures = Vec::new();
    for (scenario, manifest) in &manifests {
        let site_code = manifest["bundle"]["siteCode"]
            .as_str()
            .expect("client health bundle has a site code");
        if !is_exact_site_code(site_code) {
            failures.push(format!(
                "{scenario}: siteCode must match ^[A-Z0-9]{{3}}$, got {site_code}"
            ));
        }
    }

    let rotations = manifests
        .iter()
        .find(|(scenario, _)| scenario == "rotation-boundary")
        .map(|(_, manifest)| manifest)
        .expect("client health has a rotation-boundary scenario");
    let rollover = rotations["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array")
        .iter()
        .find(|artifact| artifact["rotation"]["kind"] == "lo")
        .expect("rotation corpus has a .lo_ artifact");

    let basename = rollover["originalBasename"]
        .as_str()
        .expect("rollover artifact has an original basename");
    if basename != "ccmsetup.lo_" {
        failures.push(format!(
            "rotation-boundary: standard ConfigMgr rollover basename must be ccmsetup.lo_, got {basename}"
        ));
    }

    let relative_path = rollover["relativePath"]
        .as_str()
        .expect("captured rollover has a relative path");
    if !relative_path.ends_with("/ccmsetup.lo_") {
        failures.push(format!(
            "rotation-boundary: rollover relativePath must end in /ccmsetup.lo_, got {relative_path}"
        ));
    }
    let sanitized_path = rollover["sanitizedSourcePath"]
        .as_str()
        .expect("rollover artifact has sanitized provenance");
    if !sanitized_path.ends_with("/ccmsetup.lo_") {
        failures.push(format!(
            "rotation-boundary: sanitizedSourcePath must end in /ccmsetup.lo_, got {sanitized_path}"
        ));
    }
    let fixture_path = client_health_root()
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

    for entry in walkdir(client_health_root().as_path()) {
        let is_evidence = entry
            .components()
            .any(|component| component.as_os_str() == std::ffi::OsStr::new("evidence"));
        if !entry.is_file() || !is_evidence {
            continue;
        }
        let contents = std::fs::read_to_string(&entry).expect("evidence fixture is UTF-8");
        for suffix in contents.split("siteCode=").skip(1) {
            let site_code = suffix
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric())
                .collect::<String>();
            if !is_exact_site_code(&site_code) {
                failures.push(format!(
                    "{}: evidence siteCode must match ^[A-Z0-9]{{3}}$, got {site_code}",
                    entry.display()
                ));
            }
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn walkdir(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            let mut children = std::fs::read_dir(&path)
                .expect("fixture directory is readable")
                .map(|entry| entry.expect("fixture entry is readable").path())
                .collect::<Vec<_>>();
            children.sort();
            pending.extend(children.into_iter().rev());
        } else {
            files.push(path);
        }
    }
    files
}
