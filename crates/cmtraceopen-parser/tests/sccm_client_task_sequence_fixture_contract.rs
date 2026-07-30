use cmtraceopen_parser::{
    models::log_entry::LogFormat,
    parser::ccm::parse_content,
    sccm::{
        normalize_ccm_artifact, SccmArtifact, SccmCoverageState, SccmEvidence, SccmRole,
        SccmRotation, SccmTimeOrderingState,
    },
};
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

const SCENARIOS: [&str; 17] = [
    "client-install-failure",
    "client-installed",
    "complete-looking-unkeyed",
    "completed",
    "disk-image-failure",
    "incomplete",
    "invalid-offset",
    "post-format",
    "pre-client",
    "reboot-continuation",
    "relocated-fragments",
    "rotation-boundary",
    "software-install-failure",
    "terminal-preflight",
    "unknown-profile",
    "unrelated-runs",
    "winpe",
];

const STATE_CHAIN: [&str; 8] = [
    "start",
    "preflight",
    "diskOrImage",
    "setupWindows",
    "installClient",
    "installSoftware",
    "postAction",
    "complete",
];

const PATH_CLASSES: [&str; 5] = ["client", "fullOs", "setup", "unknown", "winpe"];
const EXPECTED_ARTIFACTS: usize = 22;
const EXPECTED_EVIDENCE_FILES: usize = 21;
const EXPECTED_EVIDENCE_BYTES: u64 = 8_243;
const EXPECTED_EVIDENCE_LINES: usize = 21;
const EXPECTED_CORPUS_DIGEST: &str =
    "917df82bdf96ae4debd3e02e669669a9b564e932d7052091fb39094305593c8b";

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
    evidence_lines: usize,
    capture_states: BTreeMap<String, usize>,
    digest: String,
}

fn task_sequence_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/client/task_sequence")
}

fn read_json(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} must contain valid JSON: {error}", path.display()))
}

fn scenario_directories() -> Vec<String> {
    let mut scenarios = std::fs::read_dir(task_sequence_root())
        .expect("the #324 Task Sequence fixture root must exist")
        .map(|entry| {
            entry
                .expect("Task Sequence fixture directory entry is readable")
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
    let mut evidence_lines = 0;
    let mut capture_states = BTreeMap::new();
    let mut digest_rows = Vec::new();

    for scenario in scenario_directories() {
        let scenario_root = task_sequence_root().join(&scenario);
        let manifest = read_json(&scenario_root.join("manifest.json"));
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
            evidence_lines += String::from_utf8(bytes.clone())
                .expect("evidence is UTF-8")
                .lines()
                .count();
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
        evidence_lines,
        capture_states,
        digest: hex_digest(&sha256(digest_rows.concat().as_bytes())),
    }
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

fn string_array(value: &Value) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or_else(|| "value is not an array".to_owned())?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "array item is not a string".to_owned())
        })
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

fn manifest_artifact<'a>(
    artifacts_by_id: &'a BTreeMap<&str, &Value>,
    evidence_ref: &Value,
) -> Result<&'a Value, String> {
    let artifact_id = evidence_ref["artifactId"]
        .as_str()
        .ok_or_else(|| "evidence reference has no artifactId".to_owned())?;
    artifacts_by_id
        .get(artifact_id)
        .copied()
        .ok_or_else(|| format!("unknown evidence artifact {artifact_id}"))
}

fn normalized_evidence(
    scenario_root: &Path,
    artifact: &Value,
) -> Result<Vec<SccmEvidence>, String> {
    let relative_path = artifact["relativePath"]
        .as_str()
        .ok_or_else(|| "artifact has no physical evidence path".to_owned())?;
    let contents = std::fs::read_to_string(scenario_root.join(relative_path))
        .map_err(|error| format!("{relative_path} is unreadable: {error}"))?;
    let rotation = match artifact["rotation"]["kind"].as_str() {
        Some("current") => SccmRotation::Current,
        Some("lo") => SccmRotation::LoUnderscore,
        other => return Err(format!("unsupported test rotation {other:?}")),
    };
    let source = SccmArtifact {
        artifact_id: artifact["artifactId"]
            .as_str()
            .ok_or_else(|| "artifactId is not a string".to_owned())?
            .to_owned(),
        display_name: artifact["originalBasename"]
            .as_str()
            .ok_or_else(|| "originalBasename is not a string".to_owned())?
            .to_owned(),
        original_path: artifact["sanitizedSourcePath"].as_str().map(str::to_owned),
        host: None,
        role: SccmRole::Client,
        configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
        collected_at_utc: artifact["capturedUtc"].as_str().map(str::to_owned),
        rotation,
        coverage: SccmCoverageState::Captured,
        encoding: artifact["encoding"].as_str().map(str::to_owned),
    };
    Ok(normalize_ccm_artifact(source, &contents))
}

fn ordering_state_name(state: &SccmTimeOrderingState) -> &'static str {
    match state {
        SccmTimeOrderingState::NormalizedUtc => "normalizedUtc",
        SccmTimeOrderingState::OffsetMissing => "offsetMissing",
        SccmTimeOrderingState::OffsetInvalid => "offsetInvalid",
        SccmTimeOrderingState::TimestampMissing => "timestampMissing",
    }
}

fn validate_manifest_and_storage(
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
) -> Result<BTreeMap<String, String>, String> {
    if manifest["sccmManifestVersion"] != 1
        || manifest["scenario"] != scenario
        || manifest["proposalOnly"] != true
        || manifest["syntheticFixture"] != true
        || manifest["bundle"]["role"] != "client"
        || manifest["bundle"]["workflow"] != "taskSequence"
        || manifest["bundle"]["siteCode"] != "LAB"
    {
        return Err(format!("{scenario}: manifest boundary metadata drifted"));
    }

    let artifacts = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| format!("{scenario}: artifacts are not an array"))?;
    let mut artifact_ids = BTreeSet::new();
    let mut relative_paths = BTreeMap::new();
    let mut canonical_paths = BTreeSet::new();
    let mut referenced_files = BTreeSet::new();
    let mut logical_states = BTreeMap::<String, Vec<String>>::new();
    let mut logical_paths = BTreeMap::<String, BTreeSet<String>>::new();

    for artifact in artifacts {
        let artifact_id = artifact["artifactId"]
            .as_str()
            .ok_or_else(|| format!("{scenario}: artifactId is not a string"))?;
        if !artifact_ids.insert(artifact_id) {
            return Err(format!("{scenario}: duplicate artifactId {artifact_id}"));
        }
        if artifact["role"] != "client" || artifact["kind"] != "ccmLog" {
            return Err(format!(
                "{scenario}/{artifact_id}: Task Sequence artifacts stay client CCM evidence"
            ));
        }
        let logical_id = artifact["designOnlyCatalog"]["entryId"]
            .as_str()
            .ok_or_else(|| format!("{scenario}/{artifact_id}: missing design-only entry ID"))?;
        if logical_id != "client-task-sequence-smsts" {
            return Err(format!(
                "{scenario}/{artifact_id}: unexpected logical source {logical_id}"
            ));
        }
        if string_array(&artifact["designOnlyCatalog"]["groupMemberships"])?
            != ["client-task-sequence-smsts"]
        {
            return Err(format!(
                "{scenario}/{artifact_id}: design-only group membership drifted"
            ));
        }
        let path_fingerprint = artifact["pathFingerprint"]
            .as_str()
            .ok_or_else(|| format!("{scenario}/{artifact_id}: pathFingerprint is missing"))?;
        if !path_fingerprint.starts_with("synthetic:") {
            return Err(format!(
                "{scenario}/{artifact_id}: pathFingerprint is not synthetic"
            ));
        }
        let path_class = artifact["pathClass"]
            .as_str()
            .ok_or_else(|| format!("{scenario}/{artifact_id}: pathClass is not a string"))?;
        if !PATH_CLASSES.contains(&path_class) {
            return Err(format!(
                "{scenario}/{artifact_id}: unsupported pathClass {path_class}"
            ));
        }
        logical_paths
            .entry(logical_id.to_owned())
            .or_default()
            .insert(path_class.to_owned());
        logical_states
            .entry(logical_id.to_owned())
            .or_default()
            .push(artifact_effective_state(artifact)?);

        let original_basename = artifact["originalBasename"]
            .as_str()
            .ok_or_else(|| format!("{scenario}/{artifact_id}: originalBasename is missing"))?;
        let rotation_kind = artifact["rotation"]["kind"]
            .as_str()
            .ok_or_else(|| format!("{scenario}/{artifact_id}: rotation kind is missing"))?;
        if !matches!(
            (original_basename, rotation_kind),
            ("smsts.log", "current") | ("smsts.lo_", "lo")
        ) {
            return Err(format!(
                "{scenario}/{artifact_id}: noncanonical basename/rotation {original_basename}/{rotation_kind}"
            ));
        }

        let state = artifact["captureState"]
            .as_str()
            .ok_or_else(|| format!("{scenario}/{artifact_id}: captureState is missing"))?;
        if state == "captured" {
            if artifact["encoding"] != "utf-8" {
                return Err(format!("{scenario}/{artifact_id}: captured encoding"));
            }
            if artifact["collectionLimit"]["byteLimit"] != 4096
                || artifact["collectionLimit"]["limitApplied"] != false
                || !artifact["sourceVersion"].is_string()
                || !artifact["capturedUtc"].is_string()
            {
                return Err(format!(
                    "{scenario}/{artifact_id}: captured provenance metadata drifted"
                ));
            }
            let relative_path = artifact["relativePath"]
                .as_str()
                .ok_or_else(|| format!("{scenario}/{artifact_id}: captured path is missing"))?;
            if let Some(previous) = relative_paths.insert(relative_path, artifact_id) {
                return Err(format!(
                    "{scenario}: duplicate evidence path {relative_path} aliases {previous} and {artifact_id}"
                ));
            }
            let relative = Path::new(relative_path);
            if relative.is_absolute()
                || !relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
                || relative.components().next()
                    != Some(Component::Normal(std::ffi::OsStr::new("evidence")))
            {
                return Err(format!(
                    "{scenario}/{artifact_id}: unsafe relativePath {relative_path}"
                ));
            }
            let fixture_path = scenario_root.join(relative);
            if !fixture_path.is_file() {
                return Err(format!(
                    "{scenario}/{artifact_id}: missing {}",
                    fixture_path.display()
                ));
            }
            let canonical = fixture_path
                .canonicalize()
                .map_err(|error| format!("{relative_path} cannot canonicalize: {error}"))?;
            if !canonical_paths.insert(canonical.clone()) {
                return Err(format!(
                    "{scenario}/{artifact_id}: duplicate canonical evidence path"
                ));
            }
            referenced_files.insert(canonical);
            let bytes = std::fs::metadata(&fixture_path)
                .map_err(|error| format!("{relative_path} metadata: {error}"))?
                .len();
            if artifact["bytesCopied"].as_u64() != Some(bytes) {
                return Err(format!(
                    "{scenario}/{artifact_id}: bytesCopied does not match {bytes}"
                ));
            }
            let sanitized_path = artifact["sanitizedSourcePath"]
                .as_str()
                .ok_or_else(|| format!("{scenario}/{artifact_id}: no sanitized source path"))?;
            if !sanitized_path.starts_with("SYNTHETIC://")
                || artifact["smstsLogPathEvidence"] != sanitized_path
            {
                return Err(format!(
                    "{scenario}/{artifact_id}: _SMSTSLogPath provenance is not bound"
                ));
            }
            let contents = std::fs::read_to_string(&fixture_path)
                .map_err(|error| format!("{relative_path} is not UTF-8: {error}"))?;
            if artifact["rotation"]["fragmentComplete"] == true
                && !contents.contains("SYNTHETIC FIXTURE")
            {
                return Err(format!(
                    "{scenario}/{artifact_id}: complete evidence lacks synthetic marker"
                ));
            }
        } else if artifact["relativePath"].is_string()
            || artifact["sanitizedSourcePath"].is_string()
            || artifact["smstsLogPathEvidence"].is_string()
            || artifact["encoding"].is_string()
            || !artifact["collectionLimit"].is_null()
            || artifact["bytesCopied"] != 0
        {
            return Err(format!(
                "{scenario}/{artifact_id}: noncapture artifact invents physical provenance"
            ));
        }
    }

    let actual_files = walk_files(&scenario_root.join("evidence"))
        .into_iter()
        .map(|path| {
            path.canonicalize()
                .map_err(|error| format!("{} cannot canonicalize: {error}", path.display()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual_files != referenced_files {
        return Err(format!(
            "{scenario}: physical evidence must be referenced exactly once"
        ));
    }

    logical_states
        .into_iter()
        .map(|(logical_id, states)| {
            combine_coverage_states(&states).map(|state| (logical_id, state))
        })
        .collect()
}

fn validate_contract(
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
    expected: &Value,
) -> Result<(), String> {
    let derived_coverage = validate_manifest_and_storage(scenario, scenario_root, manifest)?;
    if expected["contractState"] != "proposedPending318And319"
        || expected["workflow"] != "taskSequence"
        || expected["scenario"] != scenario
        || string_array(&expected["stateChain"])? != STATE_CHAIN.map(str::to_owned)
        || expected["analysisContract"]["independentReducer"] != true
        || expected["analysisContract"]["consumesAppOrPolicyReducerOutput"] != false
        || expected["analysisContract"]["crossSideCorrelationPerformed"] != false
        || expected["analysisContract"]["nativeAcceptanceClaimed"] != false
        || expected["reorderedInputDeterministic"] != true
    {
        return Err(format!("{scenario}: expected boundary metadata drifted"));
    }

    let artifacts = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| "manifest artifacts are not an array".to_owned())?;
    let artifacts_by_id = artifacts
        .iter()
        .map(|artifact| {
            artifact["artifactId"]
                .as_str()
                .map(|artifact_id| (artifact_id, artifact))
                .ok_or_else(|| "artifactId is not a string".to_owned())
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

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
            .ok_or_else(|| format!("{logical_id}: coverage state is not a string"))?;
        if declared_coverage
            .insert(logical_id.to_owned(), state.to_owned())
            .is_some()
        {
            return Err(format!("duplicate coverage row {logical_id}"));
        }

        let mut declared_path_classes = string_array(&coverage["pathClasses"])?;
        declared_path_classes.sort();
        declared_path_classes.dedup();
        let mut derived_path_classes = artifacts
            .iter()
            .filter(|artifact| artifact["designOnlyCatalog"]["entryId"] == logical_id)
            .filter_map(|artifact| artifact["pathClass"].as_str().map(str::to_owned))
            .collect::<Vec<_>>();
        derived_path_classes.sort();
        derived_path_classes.dedup();
        if declared_path_classes != derived_path_classes {
            return Err(format!(
                "{logical_id}: declared path classes {declared_path_classes:?} != {derived_path_classes:?}"
            ));
        }
        if state == "partial" {
            let mut declared_ids = string_array(&coverage["artifactIds"])?;
            declared_ids.sort();
            let mut derived_ids = artifacts
                .iter()
                .filter(|artifact| {
                    artifact["designOnlyCatalog"]["entryId"] == logical_id
                        && artifact["captureState"] == "captured"
                        && artifact["rotation"]["fragmentComplete"] == false
                })
                .filter_map(|artifact| artifact["artifactId"].as_str().map(str::to_owned))
                .collect::<Vec<_>>();
            derived_ids.sort();
            if declared_ids != derived_ids {
                return Err(format!(
                    "{logical_id}: partial artifact IDs {declared_ids:?} != {derived_ids:?}"
                ));
            }
        }
    }
    if declared_coverage != derived_coverage {
        return Err(format!(
            "coverage mismatch: declared {declared_coverage:?}, derived {derived_coverage:?}"
        ));
    }

    let provenance = expected["artifactProvenance"]
        .as_array()
        .ok_or_else(|| "artifactProvenance is not an array".to_owned())?;
    let mut provenance_ids = provenance
        .iter()
        .map(|item| {
            item["artifactId"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "provenance artifactId is not a string".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let original_provenance_ids = provenance_ids.clone();
    provenance_ids.sort();
    let mut physical_ids = artifacts
        .iter()
        .filter(|artifact| artifact["relativePath"].is_string())
        .filter_map(|artifact| artifact["artifactId"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    physical_ids.sort();
    if original_provenance_ids != provenance_ids || provenance_ids != physical_ids {
        return Err(format!(
            "{scenario}: provenance must deterministically cover every physical artifact"
        ));
    }
    for item in provenance {
        let artifact_id = item["artifactId"]
            .as_str()
            .ok_or_else(|| "provenance artifactId is not a string".to_owned())?;
        let artifact = artifacts_by_id
            .get(artifact_id)
            .ok_or_else(|| format!("unknown provenance artifact {artifact_id}"))?;
        for field in [
            "bytesCopied",
            "pathClass",
            "sanitizedSourcePath",
            "smstsLogPathEvidence",
        ] {
            if item[field] != artifact[field] {
                return Err(format!(
                    "{scenario}/{artifact_id}: provenance field {field} drifted"
                ));
            }
        }
        if item["rotationKind"] != artifact["rotation"]["kind"]
            || item["fragmentComplete"] != artifact["rotation"]["fragmentComplete"]
            || item["relocationOrdinal"] != artifact["relocationOrdinal"]
        {
            return Err(format!(
                "{scenario}/{artifact_id}: rotation/relocation provenance drifted"
            ));
        }
    }

    let transactions = expected["transactions"]
        .as_array()
        .ok_or_else(|| "transactions are not an array".to_owned())?;
    let transaction_ids = sorted_ids(&expected["transactions"], "transactionId");
    let mut sorted_transaction_ids = transaction_ids.clone();
    sorted_transaction_ids.sort();
    if transaction_ids != sorted_transaction_ids
        || transaction_ids.iter().collect::<BTreeSet<_>>().len() != transaction_ids.len()
    {
        return Err(format!(
            "{scenario}: transaction IDs must be unique and sorted"
        ));
    }

    for transaction in transactions {
        let transaction_id = transaction["transactionId"]
            .as_str()
            .ok_or_else(|| "transactionId is not a string".to_owned())?;
        let key = transaction["key"]
            .as_object()
            .ok_or_else(|| format!("{transaction_id}: key is not an object"))?;
        for required in [
            "executionId",
            "taskSequencePackageId",
            "advertisementId",
            "runContext",
        ] {
            if !key.get(required).is_some_and(Value::is_string) {
                return Err(format!(
                    "{transaction_id}: missing exact key field {required}"
                ));
            }
        }
        for forbidden in ["filename", "path", "timestamp", "displayName", "component"] {
            if key.contains_key(forbidden) {
                return Err(format!(
                    "{transaction_id}: forbidden join field {forbidden}"
                ));
            }
        }
        if key.get("confidence").and_then(Value::as_str) != Some("exact")
            || key.get("extractionProfileId").and_then(Value::as_str)
                != Some("task-sequence-client-5.00.test-v1")
        {
            return Err(format!(
                "{transaction_id}: exact key is not profile-qualified"
            ));
        }

        let evidence_refs = transaction["evidence"]
            .as_array()
            .ok_or_else(|| format!("{transaction_id}: evidence is not an array"))?;
        let key_needles = key
            .iter()
            .filter(|(field, _)| {
                !matches!(
                    field.as_str(),
                    "keyProfileKind" | "confidence" | "extractionProfileId"
                )
            })
            .map(|(field, value)| {
                value
                    .as_str()
                    .map(|value| format!("{field}={value}"))
                    .ok_or_else(|| format!("{transaction_id}: key {field} is not a string"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut cited_record_texts = Vec::new();
        for evidence_ref in evidence_refs {
            let artifact = manifest_artifact(&artifacts_by_id, evidence_ref)?;
            let start_line = evidence_ref["startLine"]
                .as_u64()
                .ok_or_else(|| format!("{transaction_id}: evidence startLine is missing"))?
                as u32;
            let end_line = evidence_ref["endLine"]
                .as_u64()
                .ok_or_else(|| format!("{transaction_id}: evidence endLine is missing"))?
                as u32;
            let normalized = normalized_evidence(scenario_root, artifact)?;
            if !normalized.iter().any(|item| {
                item.reference.line_start == Some(start_line)
                    && item.reference.line_end == Some(end_line)
            }) {
                return Err(format!(
                    "{transaction_id}: cited evidence is not one complete CCM record"
                ));
            }

            let record_text = evidence_text(scenario_root, &artifacts_by_id, evidence_ref)?;
            if let Some(missing_needle) = key_needles
                .iter()
                .find(|needle| !record_text.contains(needle.as_str()))
            {
                return Err(format!(
                    "{transaction_id}: declared key fields do not co-occur in cited complete CCM record ({missing_needle})"
                ));
            }
            cited_record_texts.push(record_text);
        }

        let phase = transaction["phase"]
            .as_str()
            .ok_or_else(|| format!("{transaction_id}: phase is not a string"))?;
        let state = transaction["state"]
            .as_str()
            .ok_or_else(|| format!("{transaction_id}: state is not a string"))?;
        let last_successful_phase = transaction["lastSuccessfulPhase"]
            .as_str()
            .ok_or_else(|| format!("{transaction_id}: lastSuccessfulPhase is not a string"))?;
        if !STATE_CHAIN.contains(&phase)
            || !STATE_CHAIN.contains(&last_successful_phase)
            || !["inProgress", "blockedOrDeferred", "failed", "succeeded"].contains(&state)
            || !cited_record_texts.iter().any(|record_text| {
                record_text.contains(&format!("phase={phase}"))
                    && record_text.contains(&format!("state={state}"))
            })
        {
            return Err(format!(
                "{transaction_id}: phase/state semantics are not bound to cited evidence"
            ));
        }

        let mut expected_path_sequence = Vec::new();
        for path_item in transaction["pathSequence"]
            .as_array()
            .ok_or_else(|| format!("{transaction_id}: pathSequence is not an array"))?
        {
            let artifact_id = path_item["artifactId"]
                .as_str()
                .ok_or_else(|| format!("{transaction_id}: path artifactId is missing"))?;
            let artifact = artifacts_by_id
                .get(artifact_id)
                .ok_or_else(|| format!("{transaction_id}: unknown path artifact {artifact_id}"))?;
            if !evidence_refs
                .iter()
                .any(|evidence_ref| evidence_ref["artifactId"] == artifact_id)
            {
                return Err(format!(
                    "{transaction_id}: path artifact {artifact_id} is not key-bound cited evidence"
                ));
            }
            if path_item["pathClass"] != artifact["pathClass"]
                || path_item["relocationOrdinal"] != artifact["relocationOrdinal"]
            {
                return Err(format!(
                    "{transaction_id}: path provenance does not match {artifact_id}"
                ));
            }
            expected_path_sequence.push((
                path_item["relocationOrdinal"]
                    .as_u64()
                    .ok_or_else(|| format!("{transaction_id}: relocationOrdinal is missing"))?,
                artifact_id.to_owned(),
            ));
        }
        let mut sorted_path_sequence = expected_path_sequence.clone();
        sorted_path_sequence.sort();
        if expected_path_sequence != sorted_path_sequence {
            return Err(format!(
                "{transaction_id}: path sequence is not deterministic"
            ));
        }

        let timestamp = &transaction["timestampProvenance"];
        let ordering_ref = &transaction["orderingEvidence"];
        if !evidence_refs
            .iter()
            .any(|evidence_ref| evidence_ref == ordering_ref)
        {
            return Err(format!(
                "{transaction_id}: ordering evidence is not key-bound transaction evidence"
            ));
        }
        let artifact = manifest_artifact(&artifacts_by_id, ordering_ref)?;
        let normalized = normalized_evidence(scenario_root, artifact)?;
        let start_line = ordering_ref["startLine"]
            .as_u64()
            .ok_or_else(|| format!("{transaction_id}: ordering startLine is missing"))?
            as u32;
        let end_line = ordering_ref["endLine"]
            .as_u64()
            .ok_or_else(|| format!("{transaction_id}: ordering endLine is missing"))?
            as u32;
        let evidence = normalized
            .iter()
            .find(|item| {
                item.reference.line_start == Some(start_line)
                    && item.reference.line_end == Some(end_line)
            })
            .ok_or_else(|| {
                format!("{transaction_id}: ordering citation is not one complete CCM record")
            })?;
        if timestamp["orderingState"].as_str()
            != Some(ordering_state_name(&evidence.timestamp.ordering_state))
            || timestamp["offsetMinutes"].as_i64()
                != evidence.timestamp.offset_minutes.map(i64::from)
        {
            return Err(format!(
                "{transaction_id}: timestamp ordering/offset is not bound"
            ));
        }
        let declared_utc = timestamp["normalizedUtc"].as_str().map(str::to_owned);
        let parsed_utc = evidence.timestamp.utc_millis.map(|millis| {
            chrono::DateTime::from_timestamp_millis(millis)
                .expect("fixture timestamp is representable")
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        });
        if declared_utc != parsed_utc {
            return Err(format!(
                "{transaction_id}: normalized timestamp is not bound ({declared_utc:?} != {parsed_utc:?})"
            ));
        }

        for artifact_id in string_array(&transaction["coverageGapArtifactIds"])? {
            let artifact = artifacts_by_id
                .get(artifact_id.as_str())
                .ok_or_else(|| format!("{transaction_id}: unknown coverage gap {artifact_id}"))?;
            if artifact_effective_state(artifact)? == "captured" {
                return Err(format!(
                    "{transaction_id}: complete artifact {artifact_id} is a coverage gap"
                ));
            }
        }
        if let Some(next_artifact) = transaction["nextArtifact"].as_object() {
            if next_artifact["logicalArtifactId"] != "client-task-sequence-smsts"
                || !PATH_CLASSES.contains(
                    &next_artifact["pathClass"]
                        .as_str()
                        .ok_or_else(|| format!("{transaction_id}: next pathClass is missing"))?,
                )
                || !next_artifact["reason"].is_string()
            {
                return Err(format!(
                    "{transaction_id}: next artifact request is not bounded"
                ));
            }
        }

        if transaction["classification"] == "confirmedFailure" {
            if transaction["state"] != "failed" || transaction["terminalEvidence"].is_null() {
                return Err(format!(
                    "{transaction_id}: confirmed failure lacks terminal evidence"
                ));
            }
            if !evidence_refs
                .iter()
                .any(|evidence_ref| evidence_ref == &transaction["terminalEvidence"])
            {
                return Err(format!(
                    "{transaction_id}: terminal evidence is not key-bound transaction evidence"
                ));
            }
            let terminal_text = evidence_text(
                scenario_root,
                &artifacts_by_id,
                &transaction["terminalEvidence"],
            )?;
            if !terminal_text.contains("terminal=true") || !terminal_text.contains("state=failed") {
                return Err(format!(
                    "{transaction_id}: terminal citation is not a terminal failure record"
                ));
            }
        }
    }

    let observations = expected["sourceLocalObservations"]
        .as_array()
        .ok_or_else(|| "sourceLocalObservations is not an array".to_owned())?;
    let observation_ids = sorted_ids(&expected["sourceLocalObservations"], "observationId");
    let mut sorted_observation_ids = observation_ids.clone();
    sorted_observation_ids.sort();
    if observation_ids != sorted_observation_ids {
        return Err(format!(
            "{scenario}: source-local observations are not sorted"
        ));
    }
    for observation in observations {
        let observation_id = observation["observationId"]
            .as_str()
            .ok_or_else(|| "source-local observation has no ID".to_owned())?;
        if !matches!(
            observation["keyConfidence"].as_str(),
            Some("none" | "candidate")
        ) || observation["confidence"] != "low"
            || observation["confidenceCeiling"] != "low"
            || observation["correlationEligible"] != false
        {
            return Err(format!(
                "{observation_id}: source-local observation must stay Low and non-correlatable"
            ));
        }
        let artifact_id = observation["artifactId"]
            .as_str()
            .ok_or_else(|| format!("{observation_id}: artifactId is missing"))?;
        if observation["evidence"]["artifactId"] != artifact_id {
            return Err(format!("{observation_id}: citation changed artifact"));
        }
        evidence_text(scenario_root, &artifacts_by_id, &observation["evidence"])?;
    }

    let finding_ids = sorted_ids(&expected["findings"], "findingId");
    let mut sorted_finding_ids = finding_ids.clone();
    sorted_finding_ids.sort();
    if finding_ids != sorted_finding_ids {
        return Err(format!("{scenario}: finding IDs are not sorted"));
    }
    for finding in expected["findings"]
        .as_array()
        .ok_or_else(|| "findings are not an array".to_owned())?
    {
        let finding_id = finding["findingId"]
            .as_str()
            .ok_or_else(|| "findingId is not a string".to_owned())?;
        let evidence = finding["evidence"]
            .as_array()
            .ok_or_else(|| format!("{finding_id}: evidence is not an array"))?;
        let coverage_gaps = string_array(&finding["coverageGapArtifactIds"])?;
        if evidence.is_empty() && coverage_gaps.is_empty() {
            return Err(format!(
                "{finding_id}: finding has neither evidence nor coverage"
            ));
        }
        if finding["serverCauseClaimed"] != false
            || finding["appOrPolicyCauseClaimed"] != false
            || finding["nativeAcceptanceClaimed"] != false
        {
            return Err(format!("{finding_id}: prohibited cause/acceptance claim"));
        }
    }

    let mut refs = Vec::new();
    collect_evidence_refs(expected, &mut refs);
    for (artifact_id, start_line, end_line) in refs {
        let artifact = artifacts_by_id
            .get(artifact_id.as_str())
            .ok_or_else(|| format!("{scenario}: unknown evidence artifact {artifact_id}"))?;
        let relative_path = artifact["relativePath"]
            .as_str()
            .ok_or_else(|| format!("{scenario}/{artifact_id}: citation is not physical"))?;
        let line_count = std::fs::read_to_string(scenario_root.join(relative_path))
            .map_err(|error| format!("{relative_path}: {error}"))?
            .lines()
            .count() as u64;
        if start_line == 0 || end_line < start_line || end_line > line_count {
            return Err(format!(
                "{scenario}/{artifact_id}: invalid evidence lines {start_line}-{end_line}/{line_count}"
            ));
        }
    }

    Ok(())
}

#[test]
fn source_path_execution_and_phase_contract_is_pinned() {
    assert_eq!(
        scenario_directories(),
        SCENARIOS.map(str::to_owned),
        "the #324 preparation scenario matrix changed"
    );

    for scenario in SCENARIOS {
        let scenario_root = task_sequence_root().join(scenario);
        let manifest = read_json(&scenario_root.join("manifest.json"));
        let expected = read_json(&scenario_root.join("expected.json"));
        validate_contract(scenario, &scenario_root, &manifest, &expected)
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));

        let expected_path_classes = match scenario {
            "client-install-failure" | "pre-client" => "fullOs",
            "client-installed"
            | "complete-looking-unkeyed"
            | "completed"
            | "invalid-offset"
            | "reboot-continuation"
            | "rotation-boundary"
            | "software-install-failure"
            | "unrelated-runs" => "client",
            "disk-image-failure" | "post-format" => "setup",
            "incomplete" | "unknown-profile" => "unknown",
            "relocated-fragments" => "client,fullOs,setup,winpe",
            "terminal-preflight" | "winpe" => "winpe",
            _ => unreachable!("SCENARIOS is exhaustive"),
        };
        assert_eq!(
            string_array(&expected["coverage"][0]["pathClasses"])
                .expect("pathClasses are strings")
                .join(","),
            expected_path_classes,
            "{scenario}: exact path-class matrix"
        );

        let (profile_id, profile_status) = match scenario {
            "incomplete" => (None, "notObserved"),
            "unknown-profile" => (None, "unknownVersionRejected"),
            "rotation-boundary" => (
                Some("task-sequence-client-5.00.test-v1"),
                "matchedAfterControlledJoinOnly",
            ),
            _ => (Some("task-sequence-client-5.00.test-v1"), "matched"),
        };
        assert_eq!(
            expected["extractionProfile"]["id"].as_str(),
            profile_id,
            "{scenario}: profile ID"
        );
        assert_eq!(
            expected["extractionProfile"]["status"].as_str(),
            Some(profile_status),
            "{scenario}: profile status"
        );
    }
}

#[test]
fn corpus_inventory_digest_bytes_lines_and_states_are_pinned() {
    assert_eq!(
        hex_digest(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "test-only SHA-256 implementation must match the standard vector"
    );
    let mut capture_states = BTreeMap::new();
    capture_states.insert("absent".to_owned(), 1);
    capture_states.insert("captured".to_owned(), 21);
    assert_eq!(
        corpus_inventory(),
        CorpusInventory {
            scenarios: 17,
            artifacts: EXPECTED_ARTIFACTS,
            evidence_files: EXPECTED_EVIDENCE_FILES,
            evidence_bytes: EXPECTED_EVIDENCE_BYTES,
            evidence_lines: EXPECTED_EVIDENCE_LINES,
            capture_states,
            digest: EXPECTED_CORPUS_DIGEST.to_owned(),
        }
    );
}

#[test]
fn complete_and_incomplete_ccm_records_and_rotation_are_pinned() {
    for scenario in SCENARIOS {
        let scenario_root = task_sequence_root().join(scenario);
        let manifest = read_json(&scenario_root.join("manifest.json"));
        for artifact in manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
        {
            let Some(relative_path) = artifact["relativePath"].as_str() else {
                continue;
            };
            let contents = std::fs::read_to_string(scenario_root.join(relative_path))
                .expect("Task Sequence evidence is UTF-8");
            let normalized =
                normalized_evidence(&scenario_root, artifact).expect("CCM evidence normalizes");
            let (entries, errors) = parse_content(&contents, relative_path, None);
            if artifact["rotation"]["fragmentComplete"] == true {
                assert_eq!(errors, 0, "{scenario}/{relative_path}: CCM errors");
                assert!(
                    !normalized.is_empty()
                        && !entries.is_empty()
                        && entries.iter().all(|entry| entry.format == LogFormat::Ccm),
                    "{scenario}/{relative_path}: complete artifact must contain logical CCM records"
                );
            } else {
                assert!(
                    normalized.is_empty()
                        && entries.iter().all(|entry| entry.format != LogFormat::Ccm),
                    "{scenario}/{relative_path}: physical fragment formed a logical CCM record"
                );
            }
        }
    }

    let rotation_root = task_sequence_root().join("rotation-boundary");
    let manifest = read_json(&rotation_root.join("manifest.json"));
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array");
    let archived = artifacts
        .iter()
        .find(|artifact| artifact["rotation"]["kind"] == "lo")
        .expect("archived rotation artifact");
    let current = artifacts
        .iter()
        .find(|artifact| artifact["rotation"]["kind"] == "current")
        .expect("current rotation artifact");
    assert_eq!(archived["originalBasename"], "smsts.lo_");
    assert_eq!(current["originalBasename"], "smsts.log");
    assert_eq!(archived["pathFingerprint"], current["pathFingerprint"]);
    assert_ne!(archived["relativePath"], current["relativePath"]);
    assert_eq!(archived["rotation"]["fragmentComplete"], false);
    assert_eq!(current["rotation"]["fragmentComplete"], false);

    let archived_text = std::fs::read_to_string(
        rotation_root.join(
            archived["relativePath"]
                .as_str()
                .expect("archived relative path"),
        ),
    )
    .expect("archived fragment is readable");
    let current_text = std::fs::read_to_string(
        rotation_root.join(
            current["relativePath"]
                .as_str()
                .expect("current relative path"),
        ),
    )
    .expect("current fragment is readable");
    let (joined_entries, joined_errors) = parse_content(
        &format!("{archived_text}{current_text}"),
        "test-only-join.log",
        None,
    );
    assert_eq!(joined_errors, 0);
    assert_eq!(joined_entries.len(), 1);
    assert_eq!(joined_entries[0].format, LogFormat::Ccm);
}

#[test]
fn relocation_order_and_same_time_execution_separation_are_explicit() {
    let relocated = read_json(
        &task_sequence_root()
            .join("relocated-fragments")
            .join("expected.json"),
    );
    let transaction = &relocated["transactions"][0];
    let path_classes = transaction["pathSequence"]
        .as_array()
        .expect("pathSequence is an array")
        .iter()
        .map(|item| item["pathClass"].as_str().expect("pathClass is a string"))
        .collect::<Vec<_>>();
    assert_eq!(path_classes, ["winpe", "setup", "fullOs", "client"]);
    assert_eq!(transaction["phase"], "complete");
    assert_eq!(transaction["state"], "succeeded");

    let unrelated = read_json(
        &task_sequence_root()
            .join("unrelated-runs")
            .join("expected.json"),
    );
    let transactions = unrelated["transactions"]
        .as_array()
        .expect("transactions are an array");
    assert_eq!(transactions.len(), 2);
    assert_ne!(
        transactions[0]["key"]["executionId"],
        transactions[1]["key"]["executionId"]
    );
    assert_eq!(
        transactions[0]["timestampProvenance"]["normalizedUtc"],
        transactions[1]["timestampProvenance"]["normalizedUtc"],
        "same-time adversarial executions must be pinned"
    );
    let first_evidence = transactions[0]["evidence"][0]["artifactId"]
        .as_str()
        .expect("first evidence artifact ID");
    let second_evidence = transactions[1]["evidence"][0]["artifactId"]
        .as_str()
        .expect("second evidence artifact ID");
    assert_ne!(first_evidence, second_evidence);
}

#[test]
fn terminal_deferred_and_unkeyed_semantics_remain_conservative() {
    let phase_matrix = [
        (
            "client-install-failure",
            0,
            "installClient",
            "failed",
            "setupWindows",
            "confirmedFailure",
            true,
        ),
        (
            "client-installed",
            0,
            "installClient",
            "inProgress",
            "setupWindows",
            "insufficientEvidence",
            false,
        ),
        (
            "completed",
            0,
            "complete",
            "succeeded",
            "complete",
            "success",
            true,
        ),
        (
            "disk-image-failure",
            0,
            "diskOrImage",
            "failed",
            "preflight",
            "confirmedFailure",
            true,
        ),
        (
            "invalid-offset",
            0,
            "installSoftware",
            "inProgress",
            "installClient",
            "insufficientEvidence",
            false,
        ),
        (
            "post-format",
            0,
            "diskOrImage",
            "inProgress",
            "preflight",
            "insufficientEvidence",
            false,
        ),
        (
            "pre-client",
            0,
            "setupWindows",
            "blockedOrDeferred",
            "diskOrImage",
            "blockedOrDeferred",
            false,
        ),
        (
            "reboot-continuation",
            0,
            "postAction",
            "blockedOrDeferred",
            "installSoftware",
            "blockedOrDeferred",
            false,
        ),
        (
            "relocated-fragments",
            0,
            "complete",
            "succeeded",
            "complete",
            "success",
            true,
        ),
        (
            "software-install-failure",
            0,
            "installSoftware",
            "failed",
            "installClient",
            "confirmedFailure",
            true,
        ),
        (
            "terminal-preflight",
            0,
            "preflight",
            "failed",
            "start",
            "confirmedFailure",
            true,
        ),
        (
            "unrelated-runs",
            0,
            "installSoftware",
            "inProgress",
            "installClient",
            "insufficientEvidence",
            false,
        ),
        (
            "unrelated-runs",
            1,
            "preflight",
            "inProgress",
            "start",
            "insufficientEvidence",
            false,
        ),
        (
            "winpe",
            0,
            "preflight",
            "inProgress",
            "start",
            "insufficientEvidence",
            false,
        ),
    ];
    for (
        scenario,
        transaction_index,
        phase,
        state,
        last_successful_phase,
        classification,
        has_terminal_evidence,
    ) in phase_matrix
    {
        let expected = read_json(&task_sequence_root().join(scenario).join("expected.json"));
        let transaction = &expected["transactions"][transaction_index];
        assert_eq!(transaction["phase"], phase, "{scenario}: phase");
        assert_eq!(transaction["state"], state, "{scenario}: state");
        assert_eq!(
            transaction["lastSuccessfulPhase"], last_successful_phase,
            "{scenario}: last successful phase"
        );
        assert_eq!(
            transaction["classification"], classification,
            "{scenario}: classification"
        );
        assert_eq!(
            !transaction["terminalEvidence"].is_null(),
            has_terminal_evidence,
            "{scenario}: terminality"
        );
    }

    let terminal_cases = [
        ("terminal-preflight", "preflight"),
        ("disk-image-failure", "diskOrImage"),
        ("client-install-failure", "installClient"),
        ("software-install-failure", "installSoftware"),
    ];
    for (scenario, phase) in terminal_cases {
        let expected = read_json(&task_sequence_root().join(scenario).join("expected.json"));
        let transaction = &expected["transactions"][0];
        assert_eq!(transaction["phase"], phase, "{scenario}: phase");
        assert_eq!(transaction["state"], "failed", "{scenario}: state");
        assert_eq!(
            transaction["classification"], "confirmedFailure",
            "{scenario}: classification"
        );
        assert!(
            !transaction["terminalEvidence"].is_null(),
            "{scenario}: terminal evidence"
        );
    }

    let reboot = read_json(
        &task_sequence_root()
            .join("reboot-continuation")
            .join("expected.json"),
    );
    assert_eq!(
        reboot["transactions"][0]["classification"],
        "blockedOrDeferred"
    );
    assert_ne!(reboot["transactions"][0]["state"], "failed");

    for scenario in [
        "rotation-boundary",
        "unknown-profile",
        "complete-looking-unkeyed",
    ] {
        let expected = read_json(&task_sequence_root().join(scenario).join("expected.json"));
        assert!(
            expected["transactions"]
                .as_array()
                .expect("transactions are an array")
                .is_empty(),
            "{scenario}: unvalidated evidence cannot create a transaction"
        );
        let observations = expected["sourceLocalObservations"]
            .as_array()
            .expect("sourceLocalObservations is an array");
        assert!(
            !observations.is_empty(),
            "{scenario}: source-local retention"
        );
        assert!(
            observations.iter().all(|observation| {
                observation["confidenceCeiling"] == "low"
                    && observation["correlationEligible"] == false
            }),
            "{scenario}: Low/non-correlatable ceiling"
        );
    }
}

#[test]
fn missing_smsts_is_coverage_not_a_no_run_claim() {
    let scenario_root = task_sequence_root().join("incomplete");
    assert!(
        walk_files(&scenario_root.join("evidence")).is_empty(),
        "all-noncapture scenario has an empty physical evidence corpus"
    );
    let expected = read_json(&scenario_root.join("expected.json"));
    assert_eq!(expected["coverage"][0]["state"], "absent");
    assert!(expected["transactions"]
        .as_array()
        .expect("transactions are an array")
        .is_empty());
    assert_eq!(
        expected["findings"][0]["classification"],
        "insufficientEvidence"
    );
    let serialized = serde_json::to_string(&expected).expect("expected JSON serializes");
    assert!(!serialized.contains("noTaskSequenceRan"));
    assert!(!serialized.contains("noTaskSequence"));
}

#[test]
fn fixture_privacy_and_scope_boundaries_are_pinned() {
    let profile_path =
        Regex::new(r"(?i)\b[A-Z]:\\{1,2}(?:Users|Windows|_SMSTaskSequence)\\{1,2}").unwrap();
    assert!(profile_path.is_match(r"C:\Windows\synthetic.log"));
    assert!(profile_path.is_match(r"C:\\Windows\\synthetic.log"));
    assert!(!profile_path.is_match("SYNTHETIC://winpe/Windows/synthetic.log"));
    let sid = Regex::new(r"\bS-1-\d+(?:-\d+){2,}\b").unwrap();
    let email = Regex::new(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b").unwrap();
    for file in walk_files(&task_sequence_root()) {
        let contents = std::fs::read_to_string(&file).expect("fixture file is UTF-8");
        for forbidden in [
            "CONTOSO",
            "Authorization:",
            "Bearer ",
            "client_secret",
            "serverRootCause",
            "appPolicyRootCause",
            "nativeWindowsAccepted",
            ".log.lo_",
        ] {
            assert!(
                !contents.contains(forbidden),
                "{} contains forbidden fixture material {forbidden}",
                file.display()
            );
        }
        assert!(
            !profile_path.is_match(&contents),
            "{} contains an unsanitized Windows path",
            file.display()
        );
        assert!(
            !sid.is_match(&contents) && !email.is_match(&contents),
            "{} contains possible private identity material",
            file.display()
        );
    }
}

#[test]
fn adversarial_contract_mutations_fail_closed() {
    let incomplete_root = task_sequence_root().join("incomplete");
    let manifest = read_json(&incomplete_root.join("manifest.json"));
    let mut expected = read_json(&incomplete_root.join("expected.json"));
    expected["coverage"][0]["state"] = Value::String("captured".to_owned());
    let error = validate_contract("incomplete", &incomplete_root, &manifest, &expected)
        .expect_err("absent manifest coverage cannot self-declare captured");
    assert!(error.contains("coverage"), "{error}");

    let mut version_drift = manifest.clone();
    version_drift["sccmManifestVersion"] = Value::from(2);
    let expected = read_json(&incomplete_root.join("expected.json"));
    let error = validate_contract("incomplete", &incomplete_root, &version_drift, &expected)
        .expect_err("manifest version drift must fail closed");
    assert!(error.contains("boundary metadata"), "{error}");

    let winpe_root = task_sequence_root().join("winpe");
    let manifest = read_json(&winpe_root.join("manifest.json"));
    let mut expected = read_json(&winpe_root.join("expected.json"));
    expected["transactions"][0]["phase"] = Value::String("complete".to_owned());
    let error = validate_contract("winpe", &winpe_root, &manifest, &expected)
        .expect_err("phase must bind to cited CCM evidence");
    assert!(error.contains("phase/state"), "{error}");

    let unrelated_root = task_sequence_root().join("unrelated-runs");
    let manifest = read_json(&unrelated_root.join("manifest.json"));
    let mut expected = read_json(&unrelated_root.join("expected.json"));
    let run_b_evidence = expected["transactions"][1]["evidence"][0].clone();
    expected["transactions"][0]["evidence"]
        .as_array_mut()
        .expect("run A evidence is an array")
        .push(run_b_evidence);
    expected["transactions"][0]["key"]["advertisementId"] = Value::String("LAB20308".to_owned());
    let error = validate_contract("unrelated-runs", &unrelated_root, &manifest, &expected)
        .expect_err("one exact key cannot be pooled across unrelated complete records");
    assert!(error.contains("co-occur"), "{error}");

    let completed_root = task_sequence_root().join("completed");
    let manifest = read_json(&completed_root.join("manifest.json"));
    let mut group_drift = manifest.clone();
    group_drift["artifacts"][0]["designOnlyCatalog"]["groupMemberships"] =
        serde_json::json!(["client-task-sequence-other"]);
    let expected = read_json(&completed_root.join("expected.json"));
    let error = validate_contract("completed", &completed_root, &group_drift, &expected)
        .expect_err("design-only group drift must fail closed");
    assert!(error.contains("group membership"), "{error}");

    let mut expected = read_json(&completed_root.join("expected.json"));
    expected["transactions"][0]["key"]["executionId"] =
        Value::String("ffffffff-ffff-ffff-ffff-ffffffffffff".to_owned());
    let error = validate_contract("completed", &completed_root, &manifest, &expected)
        .expect_err("execution key must bind to cited evidence");
    assert!(error.contains("executionId"), "{error}");

    let mut expected = read_json(&completed_root.join("expected.json"));
    expected["transactions"][0]["timestampProvenance"]["normalizedUtc"] =
        Value::String("2026-07-30T23:59:59Z".to_owned());
    let error = validate_contract("completed", &completed_root, &manifest, &expected)
        .expect_err("timestamp must bind to one cited CCM record");
    assert!(error.contains("timestamp"), "{error}");

    let mut duplicate_manifest = manifest.clone();
    let duplicate_artifact = duplicate_manifest["artifacts"][0].clone();
    duplicate_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .push(duplicate_artifact);
    duplicate_manifest["artifacts"][1]["artifactId"] =
        Value::String("task-sequence-completed-alias".to_owned());
    let expected = read_json(&completed_root.join("expected.json"));
    let error = validate_contract("completed", &completed_root, &duplicate_manifest, &expected)
        .expect_err("two artifact IDs cannot alias one evidence path");
    assert!(error.contains("duplicate evidence path"), "{error}");

    let unkeyed_root = task_sequence_root().join("complete-looking-unkeyed");
    let manifest = read_json(&unkeyed_root.join("manifest.json"));
    let mut expected = read_json(&unkeyed_root.join("expected.json"));
    expected["sourceLocalObservations"][0]["confidenceCeiling"] = Value::String("high".to_owned());
    let error = validate_contract(
        "complete-looking-unkeyed",
        &unkeyed_root,
        &manifest,
        &expected,
    )
    .expect_err("unkeyed complete-looking evidence stays Low");
    assert!(error.contains("Low"), "{error}");

    let failure_root = task_sequence_root().join("terminal-preflight");
    let manifest = read_json(&failure_root.join("manifest.json"));
    let mut expected = read_json(&failure_root.join("expected.json"));
    expected["transactions"][0]["terminalEvidence"] = Value::Null;
    let error = validate_contract("terminal-preflight", &failure_root, &manifest, &expected)
        .expect_err("confirmed failure requires cited terminal evidence");
    assert!(error.contains("terminal"), "{error}");
}
