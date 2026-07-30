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

#[derive(Clone)]
struct ClientHealthSiteFactFile {
    scenario: String,
    relative_path: String,
    site_facts: Vec<(usize, String)>,
}

fn client_health_site_facts() -> Vec<ClientHealthSiteFactFile> {
    let root = client_health_root();
    let mut facts = Vec::new();

    for entry in walkdir(&root) {
        let is_evidence = entry
            .components()
            .any(|component| component.as_os_str() == std::ffi::OsStr::new("evidence"));
        if !entry.is_file() || !is_evidence {
            continue;
        }

        let contents = std::fs::read_to_string(&entry).expect("evidence fixture is UTF-8");
        let site_facts = contents
            .lines()
            .enumerate()
            .flat_map(|(line_index, line)| {
                line.split("siteCode=").skip(1).map(move |suffix| {
                    (
                        line_index + 1,
                        suffix
                            .chars()
                            .take_while(|character| character.is_ascii_alphanumeric())
                            .collect::<String>(),
                    )
                })
            })
            .collect::<Vec<_>>();
        if site_facts.is_empty() {
            continue;
        }

        let relative_path = entry
            .strip_prefix(&root)
            .expect("health evidence is below the fixture root");
        let scenario = relative_path
            .components()
            .next()
            .expect("health evidence has a scenario component")
            .as_os_str()
            .to_string_lossy()
            .into_owned();
        facts.push(ClientHealthSiteFactFile {
            scenario,
            relative_path: relative_path.to_string_lossy().into_owned(),
            site_facts,
        });
    }

    facts.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    facts
}

fn client_health_site_contract_failures(
    manifests: &[(String, Value)],
    facts: &[ClientHealthSiteFactFile],
) -> Vec<String> {
    let mut failures = Vec::new();

    if manifests.len() != 9 {
        failures.push(format!(
            "client health must contain exactly 9 manifests, got {}",
            manifests.len()
        ));
    }
    for (scenario, manifest) in manifests {
        match manifest["bundle"]["siteCode"].as_str() {
            Some("LAB") => {}
            Some(site_code) => failures.push(format!(
                "{scenario}: manifest siteCode must be LAB, got {site_code}"
            )),
            None => failures.push(format!(
                "{scenario}: manifest siteCode must be LAB, got null"
            )),
        }
    }

    let expected = [
        (
            "success",
            "success/evidence/client-location-services-shared/current/LocationServices.log",
        ),
        (
            "transport-failure",
            "transport-failure/evidence/client-location-services-shared/current/LocationServices.log",
        ),
    ];
    if facts.len() != expected.len() {
        failures.push(format!(
            "client health must contain siteCode facts in exactly 2 evidence files, got {}",
            facts.len()
        ));
    }

    for (scenario, relative_path) in expected {
        let matching_files = facts
            .iter()
            .filter(|fact| fact.relative_path == relative_path)
            .collect::<Vec<_>>();
        if matching_files.len() != 1 {
            failures.push(format!(
                "{relative_path}: expected exactly one siteCode evidence file, got {}",
                matching_files.len()
            ));
            continue;
        }

        let fact = matching_files[0];
        if fact.scenario != scenario {
            failures.push(format!(
                "{relative_path}: evidence scenario {} does not match {scenario}",
                fact.scenario
            ));
        }
        if fact.site_facts.len() != 2 {
            failures.push(format!(
                "{relative_path}: expected exactly 2 siteCode facts, got {}",
                fact.site_facts.len()
            ));
        }

        let manifest_site_code = manifests
            .iter()
            .find(|(manifest_scenario, _)| manifest_scenario == scenario)
            .and_then(|(_, manifest)| manifest["bundle"]["siteCode"].as_str());
        match manifest_site_code {
            Some(manifest_site_code) => {
                for (fact_index, (line_number, site_code)) in fact.site_facts.iter().enumerate() {
                    let expected_line = fact_index + 1;
                    if *line_number != expected_line {
                        failures.push(format!(
                            "{relative_path}: siteCode fact {} must be on line {expected_line}, got line {line_number}",
                            fact_index + 1
                        ));
                    }
                    if site_code != manifest_site_code {
                        failures.push(format!(
                            "{relative_path}: evidence siteCode {site_code} does not match manifest siteCode {manifest_site_code}"
                        ));
                    }
                }
            }
            None => failures.push(format!(
                "{relative_path}: matching manifest siteCode is unavailable"
            )),
        }
    }

    failures
}

#[test]
fn client_health_site_contract_pins_exact_lab_evidence() {
    let manifests = client_health_manifests();
    let facts = client_health_site_facts();
    assert!(
        client_health_site_contract_failures(&manifests, &facts).is_empty(),
        "canonical client health fixtures satisfy the exact site contract"
    );

    let mut wrong_manifest = manifests.clone();
    wrong_manifest[0].1["bundle"]["siteCode"] = Value::String("ABC".to_owned());
    assert!(
        client_health_site_contract_failures(&wrong_manifest, &facts)
            .iter()
            .any(|failure| failure.contains("siteCode must be LAB")),
        "a different valid three-character manifest code must fail closed"
    );

    let mut missing_fact = facts.clone();
    missing_fact[0].site_facts.pop();
    assert!(
        client_health_site_contract_failures(&manifests, &missing_fact)
            .iter()
            .any(|failure| failure.contains("exactly 2 siteCode facts")),
        "a missing evidence fact must fail closed"
    );

    let mut mismatched_fact = facts.clone();
    mismatched_fact[0].site_facts[0].1 = "XYZ".to_owned();
    assert!(
        client_health_site_contract_failures(&manifests, &mismatched_fact)
            .iter()
            .any(|failure| failure.contains("does not match manifest siteCode LAB")),
        "a different valid evidence code must fail closed"
    );

    let mut moved_fact = facts.clone();
    moved_fact[0].site_facts[0].0 = 3;
    assert!(
        client_health_site_contract_failures(&manifests, &moved_fact)
            .iter()
            .any(|failure| failure.contains("must be on line 1")),
        "the four evidence facts must remain on the contracted lines"
    );
}

fn client_health_rotation_contract_failures(manifest: &Value) -> Vec<String> {
    const EXPECTED_RELATIVE_PATH: &str = "evidence/client-ccmsetup/lo/ccmsetup.lo_";
    const EXPECTED_SANITIZED_PATH: &str = "SYNTHETIC://root-a/ccmsetup/Logs/ccmsetup.lo_";

    let mut failures = Vec::new();
    let Some(artifacts) = manifest["artifacts"].as_array() else {
        return vec!["rotation-boundary: artifacts must be an array".to_owned()];
    };
    let rollovers = artifacts
        .iter()
        .filter(|artifact| artifact["rotation"]["kind"] == "lo")
        .collect::<Vec<_>>();
    if rollovers.len() != 1 {
        return vec![format!(
            "rotation-boundary: expected exactly one .lo_ artifact, got {}",
            rollovers.len()
        )];
    }
    let rollover = rollovers[0];

    match rollover["originalBasename"].as_str() {
        Some("ccmsetup.lo_") => {}
        Some(basename) => failures.push(format!(
            "rotation-boundary: originalBasename must equal ccmsetup.lo_, got {basename}"
        )),
        None => failures.push(
            "rotation-boundary: originalBasename must equal ccmsetup.lo_, got null".to_owned(),
        ),
    }

    let relative_path = rollover["relativePath"].as_str();
    match relative_path {
        Some(EXPECTED_RELATIVE_PATH) => {}
        Some(relative_path) => failures.push(format!(
            "rotation-boundary: relativePath must equal {EXPECTED_RELATIVE_PATH}, got {relative_path}"
        )),
        None => failures.push(format!(
            "rotation-boundary: relativePath must equal {EXPECTED_RELATIVE_PATH}, got null"
        )),
    }

    match rollover["sanitizedSourcePath"].as_str() {
        Some(EXPECTED_SANITIZED_PATH) => {}
        Some(sanitized_path) => failures.push(format!(
            "rotation-boundary: sanitizedSourcePath must equal {EXPECTED_SANITIZED_PATH}, got {sanitized_path}"
        )),
        None => failures.push(format!(
            "rotation-boundary: sanitizedSourcePath must equal {EXPECTED_SANITIZED_PATH}, got null"
        )),
    }

    if relative_path == Some(EXPECTED_RELATIVE_PATH) {
        let fixture_path = client_health_root()
            .join("rotation-boundary")
            .join(EXPECTED_RELATIVE_PATH);
        if !fixture_path.is_file() {
            failures.push(format!(
                "rotation-boundary: manifest path does not resolve to a fixture: {}",
                fixture_path.display()
            ));
        } else {
            let actual_bytes = std::fs::metadata(&fixture_path)
                .expect("rollover fixture metadata is readable")
                .len();
            match rollover["bytesCopied"].as_u64() {
                Some(bytes_copied) if bytes_copied == actual_bytes => {}
                Some(bytes_copied) => failures.push(format!(
                    "rotation-boundary: bytesCopied {bytes_copied} does not match fixture length {actual_bytes}"
                )),
                None => failures.push(
                    "rotation-boundary: captured rollover must record bytesCopied".to_owned(),
                ),
            }
        }
    }

    failures
}

#[test]
fn client_health_rotation_contract_pins_full_paths() {
    let manifests = client_health_manifests();
    let rotations = manifests
        .iter()
        .find(|(scenario, _)| scenario == "rotation-boundary")
        .map(|(_, manifest)| manifest)
        .expect("client health has a rotation-boundary scenario");
    assert!(
        client_health_rotation_contract_failures(rotations).is_empty(),
        "canonical client health rotation fixture satisfies the exact path contract"
    );

    let mut wrong_relative_path = rotations.clone();
    let rollover = wrong_relative_path["artifacts"]
        .as_array_mut()
        .expect("rotation artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["rotation"]["kind"] == "lo")
        .expect("rotation corpus has a .lo_ artifact");
    rollover["relativePath"] = Value::String("evidence/other/ccmsetup.lo_".to_owned());
    assert!(
        client_health_rotation_contract_failures(&wrong_relative_path)
            .iter()
            .any(|failure| failure.contains("relativePath must equal")),
        "a filename-matching but layout-changing relative path must fail closed"
    );

    let mut wrong_provenance = rotations.clone();
    let rollover = wrong_provenance["artifacts"]
        .as_array_mut()
        .expect("rotation artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["rotation"]["kind"] == "lo")
        .expect("rotation corpus has a .lo_ artifact");
    rollover["sanitizedSourcePath"] =
        Value::String("SYNTHETIC://different-root/ccmsetup.lo_".to_owned());
    assert!(
        client_health_rotation_contract_failures(&wrong_provenance)
            .iter()
            .any(|failure| failure.contains("sanitizedSourcePath must equal")),
        "a filename-matching but provenance-changing source path must fail closed"
    );

    let mut duplicate_rollover = rotations.clone();
    let artifacts = duplicate_rollover["artifacts"]
        .as_array_mut()
        .expect("rotation artifacts are an array");
    let duplicate = artifacts
        .iter()
        .find(|artifact| artifact["rotation"]["kind"] == "lo")
        .expect("rotation corpus has a .lo_ artifact")
        .clone();
    artifacts.push(duplicate);
    assert!(
        client_health_rotation_contract_failures(&duplicate_rollover)
            .iter()
            .any(|failure| failure.contains("exactly one .lo_ artifact")),
        "a duplicate .lo_ artifact must fail closed"
    );
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
    failures.extend(client_health_site_contract_failures(
        &manifests,
        &client_health_site_facts(),
    ));

    let rotations = manifests
        .iter()
        .find(|(scenario, _)| scenario == "rotation-boundary")
        .map(|(_, manifest)| manifest)
        .expect("client health has a rotation-boundary scenario");
    failures.extend(client_health_rotation_contract_failures(rotations));

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
