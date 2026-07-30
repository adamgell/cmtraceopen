use cmtraceopen_parser::models::log_entry::LogFormat;
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

const SCENARIOS: [&str; 12] = [
    "bits-transfer-failure",
    "cache-failure",
    "dependency-failure",
    "detection-false-negative",
    "dp-content-missing",
    "enforcement-exit",
    "incomplete",
    "location-missing",
    "not-targeted",
    "requirements-failure",
    "rotation-boundary",
    "success",
];

const STATE_CHAIN: [&str; 8] = [
    "intent",
    "requirements",
    "locateContent",
    "transfer",
    "cache",
    "enforce",
    "detect",
    "report",
];

const DOCUMENTED_CORPUS_DIGEST: &str =
    "27e0f8b6fab7bc584902718229824a45bdab9d1c9c78601e04f9d571e34c5c53";

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Debug, PartialEq, Eq)]
struct CorpusInventory {
    scenarios: usize,
    artifacts: usize,
    evidence_files: usize,
    evidence_bytes: u64,
    capture_states: BTreeMap<String, usize>,
    digest: String,
}

fn deployment_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/client/deployment")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let bit_length = (bytes.len() as u64)
        .checked_mul(8)
        .expect("fixture byte length fits SHA-256");
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];

    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let sigma0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let sigma1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(sigma0)
                .wrapping_add(words[index - 7])
                .wrapping_add(sigma1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn corpus_inventory() -> CorpusInventory {
    let mut artifacts = 0;
    let mut evidence_files = 0;
    let mut evidence_bytes = 0;
    let mut capture_states = BTreeMap::new();
    let mut digest_rows = Vec::new();

    for scenario in scenario_names() {
        let scenario_root = deployment_root().join(&scenario);
        let manifest = load_json(&scenario_root.join("manifest.json"));
        for artifact in manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
        {
            artifacts += 1;
            let state = artifact["captureState"]
                .as_str()
                .expect("captureState is a string");
            *capture_states.entry(state.to_owned()).or_insert(0) += 1;

            let Some(relative_path) = artifact["relativePath"].as_str() else {
                continue;
            };
            let bytes = std::fs::read(scenario_root.join(relative_path))
                .expect("evidence bytes are readable");
            evidence_files += 1;
            evidence_bytes += bytes.len() as u64;
            let artifact_id = artifact["artifactId"]
                .as_str()
                .expect("artifactId is a string");
            digest_rows.push(format!(
                "{scenario}\0{artifact_id}\0{relative_path}\0{}\n",
                hex_digest(&sha256(&bytes))
            ));
        }
    }
    digest_rows.sort();

    CorpusInventory {
        scenarios: SCENARIOS.len(),
        artifacts,
        evidence_files,
        evidence_bytes,
        capture_states,
        digest: hex_digest(&sha256(digest_rows.concat().as_bytes())),
    }
}

fn load_json(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} contains valid JSON: {error}", path.display()))
}

fn scenario_names() -> Vec<String> {
    let mut scenarios = std::fs::read_dir(deployment_root())
        .expect("deployment fixture root exists")
        .map(|entry| {
            entry
                .expect("deployment fixture directory entry is readable")
                .path()
        })
        .filter(|path| path.is_dir())
        .map(|path| {
            path.file_name()
                .expect("scenario directory has a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    scenarios.sort();
    scenarios
}

fn walk_files(root: &Path) -> Vec<PathBuf> {
    if !root.exists() {
        return Vec::new();
    }

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

#[test]
fn missing_evidence_root_is_an_empty_corpus() {
    let missing = deployment_root().join("__missing_evidence_root__");
    assert!(!missing.exists(), "test sentinel must stay absent");
    assert!(
        walk_files(&missing).is_empty(),
        "an all-noncapture scenario has no physical evidence directory"
    );
}

fn collect_evidence_refs(value: &Value, refs: &mut Vec<(String, u64, u64)>) {
    match value {
        Value::Object(object) => {
            if let (Some(artifact_id), Some(start_line), Some(end_line)) = (
                object.get("artifactId").and_then(Value::as_str),
                object.get("startLine").and_then(Value::as_u64),
                object.get("endLine").and_then(Value::as_u64),
            ) {
                refs.push((artifact_id.to_owned(), start_line, end_line));
            }
            for child in object.values() {
                collect_evidence_refs(child, refs);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_evidence_refs(child, refs);
            }
        }
        _ => {}
    }
}

fn json_string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("value is an array")
        .iter()
        .map(|item| item.as_str().expect("array item is a string").to_owned())
        .collect()
}

fn sorted_ids(value: &Value, field: &str) -> Vec<String> {
    value
        .as_array()
        .expect("value is an array")
        .iter()
        .map(|item| {
            item[field]
                .as_str()
                .unwrap_or_else(|| panic!("{field} is a string"))
                .to_owned()
        })
        .collect()
}

fn artifact_effective_state(artifact: &Value) -> Result<String, String> {
    let state = artifact["captureState"]
        .as_str()
        .ok_or_else(|| "artifact captureState is not a string".to_owned())?;
    match state {
        "captured" => {
            let fragment_complete = artifact["rotation"]["fragmentComplete"]
                .as_bool()
                .ok_or_else(|| "captured artifact has no fragmentComplete flag".to_owned())?;
            Ok(if fragment_complete {
                "captured".to_owned()
            } else {
                "partial".to_owned()
            })
        }
        "capped" | "absent" | "accessDenied" | "skipped" | "unsupported" | "parseFailed"
        | "unsafePath" => Ok(state.to_owned()),
        other => Err(format!("unsupported captureState {other}")),
    }
}

fn combine_coverage_states(states: &[String]) -> Result<String, String> {
    if states.iter().any(|state| state == "captured") {
        return Ok("captured".to_owned());
    }
    if states.iter().any(|state| state == "capped") {
        return Ok("capped".to_owned());
    }
    if states.iter().any(|state| state == "partial") {
        return Ok("partial".to_owned());
    }
    let distinct = states.iter().cloned().collect::<BTreeSet<_>>();
    if distinct.len() == 1 {
        return Ok(distinct.into_iter().next().expect("one coverage state"));
    }
    Err(format!("ambiguous noncapture coverage states {distinct:?}"))
}

fn evidence_text(
    scenario_root: &Path,
    artifacts_by_id: &BTreeMap<&str, &Value>,
    evidence_ref: &Value,
) -> Result<String, String> {
    let artifact_id = evidence_ref["artifactId"]
        .as_str()
        .ok_or_else(|| "evidence reference has no artifactId".to_owned())?;
    let artifact = artifacts_by_id
        .get(artifact_id)
        .ok_or_else(|| format!("unknown evidence artifact {artifact_id}"))?;
    let relative_path = artifact["relativePath"]
        .as_str()
        .ok_or_else(|| format!("{artifact_id} has no captured evidence path"))?;
    let contents = std::fs::read_to_string(scenario_root.join(relative_path))
        .map_err(|error| format!("{artifact_id} is unreadable: {error}"))?;
    let lines = contents.lines().collect::<Vec<_>>();
    let start = evidence_ref["startLine"]
        .as_u64()
        .ok_or_else(|| format!("{artifact_id} evidence has no startLine"))?
        as usize;
    let end = evidence_ref["endLine"]
        .as_u64()
        .ok_or_else(|| format!("{artifact_id} evidence has no endLine"))? as usize;
    if start == 0 || end < start || end > lines.len() {
        return Err(format!(
            "{artifact_id} evidence lines {start}-{end}/{} are invalid",
            lines.len()
        ));
    }
    Ok(lines[start - 1..end].join("\n"))
}

fn key_needle(field: &str, value: &Value) -> Result<Option<String>, String> {
    if matches!(
        field,
        "keyProfileKind" | "confidence" | "extractionProfileId"
    ) {
        return Ok(None);
    }
    if let Some(value) = value.as_str() {
        return Ok(Some(format!("{field}={value}")));
    }
    if value.is_number() {
        return Ok(Some(format!("{field}={value}")));
    }
    Err(format!("transaction key field {field} is not scalar"))
}

fn validate_semantic_contract(
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
    expected: &Value,
) -> Result<(), String> {
    let artifacts = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| "manifest artifacts are not an array".to_owned())?;
    let mut artifacts_by_id = BTreeMap::new();
    let mut artifact_paths = BTreeMap::new();
    let mut physical_by_logical = BTreeMap::<String, Vec<&Value>>::new();

    for artifact in artifacts {
        let artifact_id = artifact["artifactId"]
            .as_str()
            .ok_or_else(|| "artifactId is not a string".to_owned())?;
        if artifacts_by_id.insert(artifact_id, artifact).is_some() {
            return Err(format!("duplicate artifactId {artifact_id}"));
        }
        artifact_effective_state(artifact)?;
        let logical_id = artifact["designOnlyCatalog"]["entryId"]
            .as_str()
            .ok_or_else(|| format!("{artifact_id} has no design-only logical ID"))?;
        physical_by_logical
            .entry(logical_id.to_owned())
            .or_default()
            .push(artifact);

        if let Some(relative_path) = artifact["relativePath"].as_str() {
            if let Some(previous) = artifact_paths.insert(relative_path, artifact_id) {
                return Err(format!(
                    "duplicate evidence path {relative_path} aliases {previous} and {artifact_id}"
                ));
            }
        }
    }

    let mut derived_coverage = BTreeMap::new();
    let mut derived_partial_ids = BTreeMap::<String, Vec<String>>::new();
    for (logical_id, physical) in &physical_by_logical {
        let states = physical
            .iter()
            .map(|artifact| artifact_effective_state(artifact))
            .collect::<Result<Vec<_>, _>>()?;
        let state = combine_coverage_states(&states)?;
        if state == "partial" {
            let mut artifact_ids = physical
                .iter()
                .filter_map(|artifact| {
                    (artifact_effective_state(artifact).ok().as_deref() == Some("partial"))
                        .then(|| artifact["artifactId"].as_str().map(str::to_owned))
                        .flatten()
                })
                .collect::<Vec<_>>();
            artifact_ids.sort();
            derived_partial_ids.insert(logical_id.clone(), artifact_ids);
        }
        derived_coverage.insert(logical_id.clone(), state);
    }

    let mut declared_coverage = BTreeMap::new();
    for coverage in expected["coverage"]
        .as_array()
        .ok_or_else(|| "expected coverage is not an array".to_owned())?
    {
        let logical_id = coverage["logicalArtifactId"]
            .as_str()
            .ok_or_else(|| "coverage logicalArtifactId is not a string".to_owned())?;
        let state = coverage["state"]
            .as_str()
            .ok_or_else(|| format!("{logical_id} coverage state is not a string"))?;
        if declared_coverage
            .insert(logical_id.to_owned(), state.to_owned())
            .is_some()
        {
            return Err(format!("duplicate coverage row {logical_id}"));
        }
        if state == "partial" {
            let mut declared_ids = json_string_array(&coverage["artifactIds"]);
            declared_ids.sort();
            let expected_ids = derived_partial_ids.get(logical_id).ok_or_else(|| {
                format!("{logical_id} declares partial without partial artifacts")
            })?;
            if &declared_ids != expected_ids {
                return Err(format!(
                    "{logical_id} partial coverage artifact IDs {declared_ids:?} != {expected_ids:?}"
                ));
            }
        }
    }
    if declared_coverage != derived_coverage {
        return Err(format!(
            "coverage mismatch: declared {declared_coverage:?}, derived {derived_coverage:?}"
        ));
    }

    for transaction in expected["transactions"]
        .as_array()
        .ok_or_else(|| "transactions are not an array".to_owned())?
    {
        let transaction_id = transaction["transactionId"]
            .as_str()
            .ok_or_else(|| "transactionId is not a string".to_owned())?;
        let evidence_refs = transaction["evidence"]
            .as_array()
            .ok_or_else(|| format!("{transaction_id} evidence is not an array"))?;
        let mut cited_text = String::new();
        for evidence_ref in evidence_refs {
            cited_text.push_str(&evidence_text(
                scenario_root,
                &artifacts_by_id,
                evidence_ref,
            )?);
            cited_text.push('\n');
        }
        for (field, value) in transaction["key"]
            .as_object()
            .ok_or_else(|| format!("{transaction_id} key is not an object"))?
        {
            let Some(needle) = key_needle(field, value)? else {
                continue;
            };
            if !cited_text.contains(&needle) {
                return Err(format!(
                    "{transaction_id} key {field} is not bound to cited evidence ({needle})"
                ));
            }
        }

        for artifact_id in json_string_array(&transaction["coverageGapArtifactIds"]) {
            let artifact = artifacts_by_id
                .get(artifact_id.as_str())
                .ok_or_else(|| format!("{transaction_id} coverage gap references {artifact_id}"))?;
            if artifact_effective_state(artifact)? == "captured" {
                return Err(format!(
                    "{transaction_id} coverage gap {artifact_id} is complete/captured"
                ));
            }
        }

        let fact = &transaction["counterpartReadyFact"];
        if !fact.is_null() {
            let fact_evidence = &fact["evidence"];
            let fact_text = evidence_text(scenario_root, &artifacts_by_id, fact_evidence)?;
            for field in [
                "packageId",
                "contentId",
                "contentVersion",
                "distributionPointHostHandle",
                "requestId",
            ] {
                let needle = key_needle(field, &fact[field])?
                    .ok_or_else(|| format!("counterpart key {field} is metadata"))?;
                if !fact_text.contains(&needle) {
                    return Err(format!(
                        "{transaction_id} counterpart {field} is not bound to cited evidence"
                    ));
                }
            }

            let timestamp = &fact["timestampProvenance"];
            let normalized = timestamp["normalizedUtc"]
                .as_str()
                .ok_or_else(|| format!("{transaction_id} counterpart timestamp is missing"))?;
            let expected_millis = chrono::DateTime::parse_from_rfc3339(normalized)
                .map_err(|error| format!("{transaction_id} counterpart timestamp: {error}"))?
                .timestamp_millis();
            let expected_offset = timestamp["offsetMinutes"]
                .as_i64()
                .ok_or_else(|| format!("{transaction_id} counterpart offset is missing"))?;
            let artifact_id = fact_evidence["artifactId"]
                .as_str()
                .ok_or_else(|| format!("{transaction_id} counterpart artifact is missing"))?;
            let (entries, errors) =
                cmtraceopen_parser::parser::ccm::parse_content(&fact_text, artifact_id, None);
            let ccm_entries = entries
                .iter()
                .filter(|entry| entry.format == LogFormat::Ccm)
                .collect::<Vec<_>>();
            if errors != 0 || ccm_entries.len() != 1 {
                return Err(format!(
                    "{transaction_id} counterpart citation is not one complete CCM record"
                ));
            }
            let entry = ccm_entries[0];
            if entry.timestamp != Some(expected_millis)
                || entry.timezone_offset.map(i64::from) != Some(expected_offset)
            {
                return Err(format!(
                    "{transaction_id} counterpart timestamp/offset is not bound to cited evidence"
                ));
            }
        }
    }

    let incomplete_physical_ids = artifacts
        .iter()
        .filter(|artifact| {
            artifact["relativePath"].is_string()
                && artifact["rotation"]["fragmentComplete"] == false
        })
        .filter_map(|artifact| artifact["artifactId"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let mut incomplete_observation_ids = BTreeSet::new();

    for observation in expected["sourceLocalObservations"]
        .as_array()
        .ok_or_else(|| "sourceLocalObservations is not an array".to_owned())?
    {
        let observation_id = observation["observationId"]
            .as_str()
            .ok_or_else(|| "source-local observation has no ID".to_owned())?;
        let key_confidence = observation["keyConfidence"]
            .as_str()
            .ok_or_else(|| format!("{observation_id} has no keyConfidence"))?;
        let ceiling = observation["confidenceCeiling"]
            .as_str()
            .ok_or_else(|| format!("{observation_id} has no confidenceCeiling"))?;
        let correlation_eligible = observation["correlationEligible"]
            .as_bool()
            .ok_or_else(|| format!("{observation_id} has no correlationEligible flag"))?;
        if !matches!(key_confidence, "none" | "candidate")
            || ceiling != "low"
            || correlation_eligible
            || observation["confidence"]
                .as_str()
                .is_some_and(|confidence| confidence != "low")
        {
            return Err(format!(
                "source-local observation {observation_id} must stay Low and non-correlatable"
            ));
        }

        if observation["completeLogicalRecord"] == false {
            let artifact_id = observation["artifactId"]
                .as_str()
                .ok_or_else(|| format!("{observation_id} has no artifactId"))?;
            if observation["evidence"]["artifactId"] != artifact_id {
                return Err(format!(
                    "source-local observation {observation_id} cites a different artifact"
                ));
            }
            let artifact = artifacts_by_id
                .get(artifact_id)
                .ok_or_else(|| format!("{observation_id} references {artifact_id}"))?;
            if artifact["rotation"]["fragmentComplete"] != false {
                return Err(format!(
                    "source-local observation {observation_id} is incomplete but its artifact is complete"
                ));
            }
            if !incomplete_observation_ids.insert(artifact_id.to_owned()) {
                return Err(format!(
                    "source-local observation artifact {artifact_id} is duplicated"
                ));
            }
        }
    }
    if incomplete_observation_ids != incomplete_physical_ids {
        return Err(format!(
            "incomplete source-local observations {incomplete_observation_ids:?} do not match physical fragments {incomplete_physical_ids:?}"
        ));
    }

    if expected["scenario"] != scenario {
        return Err(format!(
            "expected scenario {} does not match {scenario}",
            expected["scenario"]
        ));
    }
    Ok(())
}

#[test]
fn deployment_corpus_inventory_and_path_artifact_digest_are_pinned() {
    assert_eq!(
        hex_digest(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "test-only SHA-256 implementation must match the standard vector"
    );

    let mut capture_states = BTreeMap::new();
    capture_states.insert("absent".to_owned(), 2);
    capture_states.insert("accessDenied".to_owned(), 1);
    capture_states.insert("capped".to_owned(), 1);
    capture_states.insert("captured".to_owned(), 32);
    assert_eq!(
        corpus_inventory(),
        CorpusInventory {
            scenarios: 12,
            artifacts: 36,
            evidence_files: 33,
            evidence_bytes: 16_840,
            capture_states,
            digest: DOCUMENTED_CORPUS_DIGEST.to_owned(),
        }
    );
}

#[test]
fn ccm_records_and_physical_rotation_boundaries_are_pinned() {
    for scenario in SCENARIOS {
        let scenario_root = deployment_root().join(scenario);
        let manifest = load_json(&scenario_root.join("manifest.json"));
        for artifact in manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
        {
            let Some(relative_path) = artifact["relativePath"].as_str() else {
                continue;
            };
            if artifact["kind"] != "ccmLog" {
                continue;
            }

            let content = std::fs::read_to_string(scenario_root.join(relative_path))
                .expect("CCM evidence is UTF-8");
            let (entries, errors) =
                cmtraceopen_parser::parser::ccm::parse_content(&content, relative_path, None);
            let complete = artifact["rotation"]["fragmentComplete"] == true;
            if complete {
                assert_eq!(
                    errors, 0,
                    "{scenario}/{relative_path}: complete CCM parse errors"
                );
                assert!(
                    !entries.is_empty()
                        && entries.iter().all(|entry| entry.format == LogFormat::Ccm),
                    "{scenario}/{relative_path}: complete evidence must contain only logical CCM records"
                );
            } else {
                assert!(
                    entries.iter().all(|entry| entry.format != LogFormat::Ccm),
                    "{scenario}/{relative_path}: incomplete physical evidence formed a CCM record"
                );
            }
        }
    }

    let rotation_root = deployment_root().join("rotation-boundary");
    let manifest = load_json(&rotation_root.join("manifest.json"));
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts are an array");
    let current = artifacts
        .iter()
        .find(|artifact| artifact["artifactId"] == "deployment-rotation-boundary-content-current")
        .expect("rotation current artifact");
    let archived = artifacts
        .iter()
        .find(|artifact| artifact["artifactId"] == "deployment-rotation-boundary-content-lo")
        .expect("rotation archived artifact");

    assert_eq!(current["originalBasename"], "CAS.log");
    assert_eq!(current["rotation"]["kind"], "current");
    assert_eq!(current["rotation"]["fragmentComplete"], false);
    assert_eq!(archived["originalBasename"], "CAS.lo_");
    assert_eq!(archived["rotation"]["kind"], "lo");
    assert_eq!(archived["rotation"]["fragmentComplete"], false);
    assert_eq!(current["pathFingerprint"], archived["pathFingerprint"]);
    assert_ne!(current["relativePath"], archived["relativePath"]);

    let archived_content = std::fs::read_to_string(
        rotation_root.join(
            archived["relativePath"]
                .as_str()
                .expect("archived relative path"),
        ),
    )
    .expect("archived rotation fixture");
    let current_content = std::fs::read_to_string(
        rotation_root.join(
            current["relativePath"]
                .as_str()
                .expect("current relative path"),
        ),
    )
    .expect("current rotation fixture");
    let combined = format!("{archived_content}{current_content}");
    let (combined_entries, combined_errors) = cmtraceopen_parser::parser::ccm::parse_content(
        &combined,
        "CAS.combined-for-test.log",
        None,
    );
    assert_eq!(combined_errors, 0, "controlled join forms one CCM record");
    assert_eq!(combined_entries.len(), 1, "controlled join record count");
    assert_eq!(combined_entries[0].format, LogFormat::Ccm);
}

#[test]
fn manifest_coverage_citations_and_observation_ceilings_are_bound() {
    for scenario in SCENARIOS {
        let scenario_root = deployment_root().join(scenario);
        let manifest = load_json(&scenario_root.join("manifest.json"));
        let expected = load_json(&scenario_root.join("expected.json"));
        validate_semantic_contract(scenario, &scenario_root, &manifest, &expected)
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
    }
}

#[test]
fn adversarial_self_declared_contract_mutations_fail_closed() {
    let scenario_root = deployment_root().join("location-missing");
    let manifest = load_json(&scenario_root.join("manifest.json"));
    let mut expected = load_json(&scenario_root.join("expected.json"));
    expected["coverage"][1]["state"] = Value::String("captured".to_owned());
    let error =
        validate_semantic_contract("location-missing", &scenario_root, &manifest, &expected)
            .expect_err("absent manifest coverage cannot be self-declared captured");
    assert!(error.contains("coverage"), "{error}");

    let scenario_root = deployment_root().join("success");
    let manifest = load_json(&scenario_root.join("manifest.json"));
    let mut expected = load_json(&scenario_root.join("expected.json"));
    expected["transactions"][0]["key"]["packageId"] = Value::String("LAB99999".to_owned());
    let error = validate_semantic_contract("success", &scenario_root, &manifest, &expected)
        .expect_err("a transaction key must be present in its cited evidence");
    assert!(error.contains("packageId"), "{error}");

    let mut expected = load_json(&scenario_root.join("expected.json"));
    expected["transactions"][0]["counterpartReadyFact"]["timestampProvenance"]["normalizedUtc"] =
        Value::String("2026-07-30T03:00:03Z".to_owned());
    let error = validate_semantic_contract("success", &scenario_root, &manifest, &expected)
        .expect_err("counterpart timestamp must bind to the cited CCM record");
    assert!(error.contains("timestamp"), "{error}");

    let mut duplicate_path_manifest = manifest.clone();
    duplicate_path_manifest["artifacts"][1]["relativePath"] =
        duplicate_path_manifest["artifacts"][0]["relativePath"].clone();
    let expected = load_json(&scenario_root.join("expected.json"));
    let error = validate_semantic_contract(
        "success",
        &scenario_root,
        &duplicate_path_manifest,
        &expected,
    )
    .expect_err("two artifact IDs cannot alias one evidence path");
    assert!(error.contains("duplicate evidence path"), "{error}");

    let scenario_root = deployment_root().join("rotation-boundary");
    let manifest = load_json(&scenario_root.join("manifest.json"));
    let mut expected = load_json(&scenario_root.join("expected.json"));
    expected["sourceLocalObservations"][0]["keyConfidence"] = Value::String("exact".to_owned());
    let error =
        validate_semantic_contract("rotation-boundary", &scenario_root, &manifest, &expected)
            .expect_err("incomplete candidates cannot claim exact keys");
    assert!(error.contains("source-local observation"), "{error}");

    let mut expected = load_json(&scenario_root.join("expected.json"));
    expected["sourceLocalObservations"][0]["confidenceCeiling"] = Value::String("high".to_owned());
    let error =
        validate_semantic_contract("rotation-boundary", &scenario_root, &manifest, &expected)
            .expect_err("incomplete candidates must stay low");
    assert!(error.contains("source-local observation"), "{error}");

    let mut expected = load_json(&scenario_root.join("expected.json"));
    expected["sourceLocalObservations"][0]["correlationEligible"] = Value::Bool(true);
    let error =
        validate_semantic_contract("rotation-boundary", &scenario_root, &manifest, &expected)
            .expect_err("incomplete candidates must stay non-correlatable");
    assert!(error.contains("source-local observation"), "{error}");
}

#[test]
fn deployment_fixture_matrix_is_exact_safe_and_deterministic() {
    assert_eq!(
        scenario_names(),
        SCENARIOS.map(str::to_owned),
        "the #322 scenario matrix changed"
    );

    let privacy_patterns = [
        (
            "user profile path",
            Regex::new(r"(?i)[A-Z]:\\Users\\").expect("user path regex"),
        ),
        (
            "Windows SID",
            Regex::new(r"\bS-1-\d+(?:-\d+){2,}\b").expect("SID regex"),
        ),
        (
            "email address",
            Regex::new(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b").expect("email regex"),
        ),
    ];

    for scenario in SCENARIOS {
        let scenario_root = deployment_root().join(scenario);
        let manifest = load_json(&scenario_root.join("manifest.json"));
        let expected = load_json(&scenario_root.join("expected.json"));

        assert_eq!(
            manifest["scenario"], scenario,
            "{scenario}: manifest scenario"
        );
        assert_eq!(
            manifest["proposalOnly"], true,
            "{scenario}: proposal boundary"
        );
        assert_eq!(
            manifest["syntheticFixture"], true,
            "{scenario}: synthetic boundary"
        );
        assert_eq!(manifest["bundle"]["role"], "client", "{scenario}: role");
        assert_eq!(
            manifest["bundle"]["workflow"], "deployment",
            "{scenario}: workflow"
        );
        assert_eq!(
            manifest["bundle"]["siteCode"], "LAB",
            "{scenario}: exact synthetic site code"
        );

        assert_eq!(
            expected["contractState"], "proposedPending318And319",
            "{scenario}: dependency boundary"
        );
        assert_eq!(expected["workflow"], "deployment", "{scenario}: workflow");
        assert_eq!(
            expected["scenario"], scenario,
            "{scenario}: expected scenario"
        );
        assert_eq!(
            json_string_array(&expected["stateChain"]),
            STATE_CHAIN.map(str::to_owned),
            "{scenario}: phase chain"
        );
        assert_eq!(
            expected["analysisContract"]["independentReducer"], true,
            "{scenario}: independent reducer"
        );
        assert_eq!(
            expected["analysisContract"]["consumesPolicyReducerOutput"], false,
            "{scenario}: deployment must not consume policy output"
        );
        assert_eq!(
            expected["analysisContract"]["policyCoverageRequired"], false,
            "{scenario}: missing policy coverage must not block deployment facts"
        );
        assert_eq!(
            expected["analysisContract"]["crossSideCorrelationPerformed"], false,
            "{scenario}: no cross-side correlation"
        );
        assert_eq!(
            expected["reorderedInputDeterministic"], true,
            "{scenario}: deterministic input reordering contract"
        );

        let artifacts = manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array");
        let mut artifacts_by_id = BTreeMap::new();
        let mut referenced_files = BTreeSet::new();

        for artifact in artifacts {
            let artifact_id = artifact["artifactId"]
                .as_str()
                .expect("artifactId is a string");
            assert!(
                artifacts_by_id.insert(artifact_id, artifact).is_none(),
                "{scenario}: duplicate artifactId {artifact_id}"
            );
            assert_eq!(artifact["role"], "client", "{scenario}/{artifact_id}: role");

            let state = artifact["captureState"]
                .as_str()
                .expect("captureState is a string");
            let captured = matches!(state, "captured" | "capped");
            if captured {
                assert_eq!(
                    artifact["encoding"], "utf-8",
                    "{scenario}/{artifact_id}: encoding"
                );
                let relative_path = artifact["relativePath"]
                    .as_str()
                    .expect("captured artifact has a relativePath");
                let relative = Path::new(relative_path);
                assert!(
                    !relative.is_absolute()
                        && relative
                            .components()
                            .all(|component| matches!(component, Component::Normal(_))),
                    "{scenario}/{artifact_id}: unsafe relativePath {relative_path}"
                );
                assert_eq!(
                    relative.components().next(),
                    Some(Component::Normal(std::ffi::OsStr::new("evidence"))),
                    "{scenario}/{artifact_id}: evidence path root"
                );

                let fixture_path = scenario_root.join(relative);
                assert!(
                    fixture_path.is_file(),
                    "{scenario}/{artifact_id}: missing {}",
                    fixture_path.display()
                );
                let actual_bytes = std::fs::metadata(&fixture_path)
                    .expect("evidence metadata is readable")
                    .len();
                assert_eq!(
                    artifact["bytesCopied"].as_u64(),
                    Some(actual_bytes),
                    "{scenario}/{artifact_id}: exact bytes"
                );
                let contents =
                    std::fs::read_to_string(&fixture_path).expect("evidence fixture is UTF-8");
                if artifact["rotation"]["fragmentComplete"] == true {
                    assert!(
                        contents.contains("SYNTHETIC FIXTURE"),
                        "{scenario}/{artifact_id}: complete evidence needs a marker"
                    );
                }
                let canonical_path = fixture_path
                    .canonicalize()
                    .expect("evidence fixture canonicalizes");
                assert!(
                    referenced_files.insert(canonical_path),
                    "{scenario}/{artifact_id}: duplicate canonical evidence path"
                );
            } else {
                assert_eq!(
                    artifact["bytesCopied"], 0,
                    "{scenario}/{artifact_id}: noncapture bytes"
                );
                assert!(
                    artifact["relativePath"].is_null(),
                    "{scenario}/{artifact_id}: noncapture relativePath"
                );
                assert!(
                    artifact["encoding"].is_null(),
                    "{scenario}/{artifact_id}: noncapture encoding"
                );
                assert!(
                    artifact["collectionLimit"].is_null(),
                    "{scenario}/{artifact_id}: noncapture collectionLimit"
                );
            }
        }

        let evidence_files = walk_files(&scenario_root.join("evidence"))
            .into_iter()
            .map(|path| path.canonicalize().expect("evidence path canonicalizes"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            evidence_files, referenced_files,
            "{scenario}: evidence files must be referenced exactly once"
        );

        let provenance = expected["artifactProvenance"]
            .as_array()
            .expect("artifactProvenance is an array");
        let provenance_ids = sorted_ids(&expected["artifactProvenance"], "artifactId");
        let mut sorted_provenance_ids = provenance_ids.clone();
        sorted_provenance_ids.sort();
        assert_eq!(
            provenance_ids, sorted_provenance_ids,
            "{scenario}: provenance order"
        );
        let mut physical_evidence_ids = artifacts
            .iter()
            .filter(|artifact| artifact["relativePath"].is_string())
            .map(|artifact| {
                artifact["artifactId"]
                    .as_str()
                    .expect("artifactId is a string")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        physical_evidence_ids.sort();
        assert_eq!(
            provenance_ids, physical_evidence_ids,
            "{scenario}: provenance must cover every physical evidence artifact exactly once"
        );
        for item in provenance {
            let artifact_id = item["artifactId"]
                .as_str()
                .expect("provenance artifactId is a string");
            let artifact = artifacts_by_id
                .get(artifact_id)
                .unwrap_or_else(|| panic!("{scenario}: unknown provenance {artifact_id}"));
            assert_eq!(
                item["bytesCopied"], artifact["bytesCopied"],
                "{scenario}/{artifact_id}: expected bytes mirror manifest"
            );
            assert_eq!(
                item["encoding"], artifact["encoding"],
                "{scenario}/{artifact_id}: expected encoding mirrors manifest"
            );
            assert_eq!(
                item["byteLimit"], artifact["collectionLimit"]["byteLimit"],
                "{scenario}/{artifact_id}: expected byte limit mirrors manifest"
            );
            assert_eq!(
                item["limitApplied"], artifact["collectionLimit"]["limitApplied"],
                "{scenario}/{artifact_id}: expected cap flag mirrors manifest"
            );
        }

        let transaction_ids = sorted_ids(&expected["transactions"], "transactionId");
        let mut sorted_transaction_ids = transaction_ids.clone();
        sorted_transaction_ids.sort();
        assert_eq!(
            transaction_ids, sorted_transaction_ids,
            "{scenario}: transaction order"
        );
        let finding_ids = sorted_ids(&expected["findings"], "findingId");
        let mut sorted_finding_ids = finding_ids.clone();
        sorted_finding_ids.sort();
        assert_eq!(finding_ids, sorted_finding_ids, "{scenario}: finding order");

        let mut evidence_refs = Vec::new();
        collect_evidence_refs(&expected, &mut evidence_refs);
        for (artifact_id, start_line, end_line) in evidence_refs {
            let artifact = artifacts_by_id
                .get(artifact_id.as_str())
                .unwrap_or_else(|| panic!("{scenario}: unknown evidence artifact {artifact_id}"));
            let relative_path = artifact["relativePath"]
                .as_str()
                .unwrap_or_else(|| panic!("{scenario}/{artifact_id}: evidence is not captured"));
            let contents = std::fs::read_to_string(scenario_root.join(relative_path))
                .expect("evidence fixture is readable");
            let line_count = contents.lines().count() as u64;
            assert!(
                start_line >= 1 && end_line >= start_line && end_line <= line_count,
                "{scenario}/{artifact_id}: invalid evidence lines {start_line}-{end_line}/{line_count}"
            );
        }

        for transaction in expected["transactions"]
            .as_array()
            .expect("transactions are an array")
        {
            if let Some(next_artifact) = transaction["nextArtifact"].as_object() {
                let logical_id = next_artifact["logicalArtifactId"]
                    .as_str()
                    .expect("next artifact logical ID is a string");
                assert!(
                    matches!(
                        logical_id,
                        "client-app-intent"
                            | "client-app-enforce"
                            | "client-content"
                            | "client-policy-state"
                    ),
                    "{scenario}: unbounded next artifact {logical_id}"
                );
                assert_ne!(
                    logical_id, "client-policy-agent",
                    "{scenario}: deployment must not depend on policy output"
                );
            }
        }

        for file in walk_files(&scenario_root) {
            let contents = std::fs::read_to_string(&file).expect("fixture file is UTF-8");
            for forbidden in [
                "CONTOSO",
                ".log.lo_",
                "C:\\Users\\",
                "Authorization:",
                "Bearer ",
                "client_secret",
                "S-1-",
            ] {
                assert!(
                    !contents.contains(forbidden),
                    "{} contains forbidden fixture material {forbidden}",
                    file.display()
                );
            }
            for (label, pattern) in &privacy_patterns {
                assert!(
                    !pattern.is_match(&contents),
                    "{} contains possible {label}",
                    file.display()
                );
            }
        }
    }
}

#[test]
fn deployment_outcomes_keep_phases_and_coverage_conservative() {
    let cases = [
        (
            "bits-transfer-failure",
            1,
            "transfer",
            "failed",
            "locateContent",
            "confirmedFailure",
            "high",
            None,
        ),
        (
            "cache-failure",
            1,
            "cache",
            "failed",
            "transfer",
            "confirmedFailure",
            "high",
            None,
        ),
        (
            "dependency-failure",
            1,
            "requirements",
            "failed",
            "intent",
            "confirmedFailure",
            "high",
            None,
        ),
        (
            "detection-false-negative",
            1,
            "detect",
            "detectionMismatch",
            "enforce",
            "symptom",
            "medium",
            None,
        ),
        (
            "dp-content-missing",
            1,
            "locateContent",
            "insufficientEvidence",
            "requirements",
            "insufficientEvidence",
            "low",
            Some("client-content"),
        ),
        (
            "enforcement-exit",
            1,
            "enforce",
            "failed",
            "cache",
            "confirmedFailure",
            "high",
            None,
        ),
        (
            "incomplete",
            2,
            "locateContent",
            "insufficientEvidence",
            "requirements",
            "insufficientEvidence",
            "low",
            Some("client-content"),
        ),
        (
            "location-missing",
            1,
            "locateContent",
            "insufficientEvidence",
            "requirements",
            "insufficientEvidence",
            "low",
            Some("client-content"),
        ),
        (
            "not-targeted",
            1,
            "intent",
            "notTargeted",
            "",
            "notTargeted",
            "high",
            None,
        ),
        (
            "requirements-failure",
            1,
            "requirements",
            "failed",
            "intent",
            "confirmedFailure",
            "high",
            None,
        ),
        (
            "rotation-boundary",
            1,
            "locateContent",
            "insufficientEvidence",
            "requirements",
            "insufficientEvidence",
            "low",
            Some("client-content"),
        ),
        (
            "success",
            1,
            "report",
            "succeeded",
            "report",
            "success",
            "high",
            None,
        ),
    ];

    for (
        scenario,
        transaction_count,
        phase,
        state,
        last_success,
        classification,
        confidence,
        next_artifact,
    ) in cases
    {
        let expected = load_json(&deployment_root().join(scenario).join("expected.json"));
        let transactions = expected["transactions"]
            .as_array()
            .expect("transactions are an array");
        assert_eq!(
            transactions.len(),
            transaction_count,
            "{scenario}: transaction count"
        );
        for transaction in transactions {
            assert_eq!(transaction["phase"], phase, "{scenario}: phase");
            assert_eq!(transaction["state"], state, "{scenario}: state");
            if last_success.is_empty() {
                assert!(
                    transaction["lastSuccessfulPhase"].is_null(),
                    "{scenario}: last successful phase"
                );
            } else {
                assert_eq!(
                    transaction["lastSuccessfulPhase"], last_success,
                    "{scenario}: last successful phase"
                );
            }
            assert_eq!(
                transaction["classification"], classification,
                "{scenario}: classification"
            );
            assert_eq!(
                transaction["confidence"], confidence,
                "{scenario}: confidence"
            );
            assert_eq!(
                transaction["confidenceCeiling"], confidence,
                "{scenario}: confidence ceiling"
            );
            match next_artifact {
                Some(logical_id) => assert_eq!(
                    transaction["nextArtifact"]["logicalArtifactId"], logical_id,
                    "{scenario}: next artifact"
                ),
                None => assert!(
                    transaction["nextArtifact"].is_null(),
                    "{scenario}: unexpected next artifact"
                ),
            }
        }
    }
}

#[test]
fn counterpart_facts_require_exact_keys_and_adversarial_inputs_stay_unlinked() {
    let counterpart_scenarios = [
        "bits-transfer-failure",
        "cache-failure",
        "detection-false-negative",
        "dp-content-missing",
        "enforcement-exit",
        "success",
    ];

    for scenario in SCENARIOS {
        let expected = load_json(&deployment_root().join(scenario).join("expected.json"));
        let should_emit = counterpart_scenarios.contains(&scenario);
        let mut emitted = 0;

        for transaction in expected["transactions"]
            .as_array()
            .expect("transactions are an array")
        {
            let fact = &transaction["counterpartReadyFact"];
            if fact.is_null() {
                continue;
            }
            emitted += 1;
            assert!(should_emit, "{scenario}: unexpected counterpart-ready fact");
            assert_eq!(
                transaction["key"]["confidence"], "exact",
                "{scenario}: counterpart transaction key confidence"
            );
            assert_eq!(
                transaction["key"]["extractionProfileId"], "deployment-client-5.00.test-v1",
                "{scenario}: counterpart transaction profile"
            );
            assert_eq!(
                fact["extractionProfileId"], transaction["key"]["extractionProfileId"],
                "{scenario}: counterpart profile"
            );
            for field in [
                "packageId",
                "contentId",
                "contentVersion",
                "distributionPointHostHandle",
                "requestId",
            ] {
                assert_eq!(
                    fact[field], transaction["key"][field],
                    "{scenario}: counterpart {field}"
                );
            }
            assert_eq!(
                fact["timestampProvenance"]["kind"], "explicitOffset",
                "{scenario}: timestamp provenance"
            );
            assert_eq!(
                fact["timestampProvenance"]["offsetMinutes"], 0,
                "{scenario}: timestamp offset"
            );
            assert_eq!(
                fact["phase"], "locateContent",
                "{scenario}: counterpart phase"
            );
        }

        assert_eq!(
            emitted,
            usize::from(should_emit),
            "{scenario}: counterpart-ready fact count"
        );
        assert_eq!(
            expected["correlationHandoff"]["performed"], false,
            "{scenario}: #333 is not performed"
        );
        assert_eq!(
            expected["correlationHandoff"]["timeOnlyEligible"], false,
            "{scenario}: time-only cannot correlate"
        );
        assert_eq!(
            expected["correlationHandoff"]["topologyCompatibilityEvaluated"], false,
            "{scenario}: topology belongs to #333"
        );
        assert_eq!(
            expected["correlationHandoff"]["serverCauseClaimed"], false,
            "{scenario}: no DP/server cause"
        );
    }

    let incomplete = load_json(&deployment_root().join("incomplete").join("expected.json"));
    let transactions = incomplete["transactions"]
        .as_array()
        .expect("incomplete transactions are an array");
    assert_eq!(transactions.len(), 2);
    assert_ne!(
        transactions[0]["transactionId"], transactions[1]["transactionId"],
        "same-minute exact keys must stay separate"
    );
    assert_eq!(
        incomplete["adversarialControls"]["sameMinuteDifferentExactKeysStaySeparate"],
        true
    );

    let enforcement = load_json(
        &deployment_root()
            .join("enforcement-exit")
            .join("expected.json"),
    );
    let observations = enforcement["sourceLocalObservations"]
        .as_array()
        .expect("source-local observations are an array");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0]["keyConfidence"], "none");
    assert_eq!(observations[0]["confidenceCeiling"], "low");
    assert_eq!(observations[0]["correlationEligible"], false);

    let success = load_json(&deployment_root().join("success").join("expected.json"));
    assert!(
        success["coverage"]
            .as_array()
            .expect("success coverage is an array")
            .iter()
            .any(|coverage| {
                coverage["logicalArtifactId"] == "client-policy-agent"
                    && coverage["state"] == "absent"
            }),
        "success must prove deployment independence from absent policy coverage"
    );
    assert_eq!(success["transactions"][0]["state"], "succeeded");
}
