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
const EXACT_KEY_JOIN_FIELDS: [&str; 4] = [
    "executionId",
    "taskSequencePackageId",
    "advertisementId",
    "runContext",
];
const FORBIDDEN_JOIN_FIELDS: [&str; 5] =
    ["component", "displayName", "filename", "path", "timestamp"];
const TRANSACTION_CORRELATION_SCOPES: [&str; 4] = [
    "clientOnly",
    "clientOnlyOrderingUnknown",
    "clientRelocationOnly",
    "taskSequenceOnly",
];
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

struct TemporaryScenario {
    root: PathBuf,
}

impl Drop for TemporaryScenario {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn copy_scenario_to_temporary_root(scenario: &str, mutation: &str) -> TemporaryScenario {
    let source_root = task_sequence_root().join(scenario);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "cmtraceopen-sccm-324-{}-{nonce}-{mutation}",
        std::process::id()
    ));
    for source in walk_files(&source_root) {
        let relative = source
            .strip_prefix(&source_root)
            .expect("scenario file is below its root");
        let destination = root.join(relative);
        std::fs::create_dir_all(
            destination
                .parent()
                .expect("scenario file has a parent directory"),
        )
        .expect("temporary scenario directory is created");
        std::fs::copy(&source, &destination).expect("scenario file is copied");
    }
    TemporaryScenario { root }
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
    let mut scenario_count = 0;
    let mut artifacts = 0;
    let mut evidence_files = 0;
    let mut evidence_bytes = 0;
    let mut evidence_lines = 0;
    let mut capture_states = BTreeMap::new();
    let mut digest_rows = Vec::new();

    for scenario in scenario_directories() {
        scenario_count += 1;
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
        scenarios: scenario_count,
        artifacts,
        evidence_files,
        evidence_bytes,
        evidence_lines,
        capture_states,
        digest: hex_digest(&sha256(digest_rows.concat().as_bytes())),
    }
}

/// An evidence reference is exactly the identity triple. Only these three
/// fields are read when a citation is resolved, so any extra key would let two
/// references that name one physical record compare as different citations.
fn evidence_reference_identity(value: &Value) -> Option<(&str, u64, u64)> {
    let object = value.as_object()?;
    Some((
        object.get("artifactId")?.as_str()?,
        object.get("startLine")?.as_u64()?,
        object.get("endLine")?.as_u64()?,
    ))
}

fn same_evidence_reference(left: &Value, right: &Value) -> bool {
    match (
        evidence_reference_identity(left),
        evidence_reference_identity(right),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn validate_evidence_reference_shapes(scenario: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            if evidence_reference_identity(value).is_some() && object.len() != 3 {
                let unmodeled = object
                    .keys()
                    .filter(|field| {
                        !matches!(field.as_str(), "artifactId" | "startLine" | "endLine")
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                return Err(format!(
                    "{scenario}: evidence reference declares unmodeled fields {unmodeled:?}"
                ));
            }
            for child in object.values() {
                validate_evidence_reference_shapes(scenario, child)?;
            }
            Ok(())
        }
        Value::Array(array) => array
            .iter()
            .try_for_each(|child| validate_evidence_reference_shapes(scenario, child)),
        _ => Ok(()),
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

fn smsts_log_paths(contents: &str) -> BTreeSet<String> {
    contents
        .match_indices("_SMSTSLogPath=")
        .filter_map(|(start, _)| {
            let value = &contents[start + "_SMSTSLogPath=".len()..];
            let end = value
                .find(|character: char| character.is_whitespace() || character == ']')
                .unwrap_or(value.len());
            (end > 0).then(|| value[..end].to_owned())
        })
        .collect()
}

/// Only whitespace and the record body edges bound a token: inside a CCM body a
/// bare bracket is a legal value character, and only the full `]LOG]!>`
/// sequence terminates the body. Returns `None` when the body cannot be
/// delimited, so an undelimitable citation fails closed instead of widening
/// admission to the `<time=... context=...>` trailer.
fn complete_field_tokens(record_text: &str) -> Option<BTreeSet<&str>> {
    let after_prefix = record_text.strip_prefix("<![LOG[")?;
    let terminator = after_prefix.find("]LOG]!>")?;
    Some(after_prefix[..terminator].split_whitespace().collect())
}

fn sanitized_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn sanitized_parent(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(parent, _)| parent)
}

fn path_class_for_sanitized_path(path: &str) -> Option<&'static str> {
    [
        ("SYNTHETIC://client/", "client"),
        ("SYNTHETIC://full-os/", "fullOs"),
        ("SYNTHETIC://setup/", "setup"),
        ("SYNTHETIC://unknown/", "unknown"),
        ("SYNTHETIC://winpe/", "winpe"),
    ]
    .into_iter()
    .find_map(|(prefix, path_class)| path.starts_with(prefix).then_some(path_class))
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
            let captured_utc = artifact["capturedUtc"]
                .as_str()
                .expect("capturedUtc was checked as a string");
            if chrono::DateTime::parse_from_rfc3339(captured_utc).is_err() {
                return Err(format!(
                    "{scenario}/{artifact_id}: capturedUtc is not RFC 3339"
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
            if !sanitized_path.starts_with("SYNTHETIC://") {
                return Err(format!(
                    "{scenario}/{artifact_id}: sanitized source path is not synthetic"
                ));
            }
            if path_class_for_sanitized_path(sanitized_path) != Some(path_class) {
                return Err(format!(
                    "{scenario}/{artifact_id}: pathClass is not bound to sanitized capture provenance"
                ));
            }
            if sanitized_basename(sanitized_path) != original_basename {
                return Err(format!(
                    "{scenario}/{artifact_id}: capture source path does not name the {original_basename} physical file"
                ));
            }
            let contents = std::fs::read_to_string(&fixture_path)
                .map_err(|error| format!("{relative_path} is not UTF-8: {error}"))?;
            let (entries, errors) = parse_content(&contents, relative_path, None);
            let normalized = normalized_evidence(scenario_root, artifact)?;
            let has_complete_ccm = errors == 0
                && !normalized.is_empty()
                && entries.iter().any(|entry| entry.format == LogFormat::Ccm);
            let fragment_complete = artifact["rotation"]["fragmentComplete"]
                .as_bool()
                .ok_or_else(|| {
                    format!("{scenario}/{artifact_id}: fragmentComplete is not a Boolean")
                })?;
            if fragment_complete != has_complete_ccm {
                return Err(format!(
                    "{scenario}/{artifact_id}: fragmentComplete is not bound to physical CCM grammar"
                ));
            }
            let observed_paths = smsts_log_paths(&contents);
            let declared_path = if artifact["smstsLogPathEvidence"].is_null() {
                None
            } else {
                Some(
                    artifact["smstsLogPathEvidence"]
                        .as_str()
                        .ok_or_else(|| {
                            format!(
                                "{scenario}/{artifact_id}: smstsLogPathEvidence is neither a string nor null"
                            )
                        })?,
                )
            };
            // Capture provenance and the in-record observation are separate: a
            // rotated fragment is captured from smsts.lo_ while the record it
            // physically contains still names the active log. The declared
            // observation must be present in these bytes; it is never taken
            // from the capture path.
            match declared_path {
                Some(declared_path)
                    if observed_paths.len() == 1
                        && observed_paths.contains(declared_path)
                        && sanitized_parent(declared_path) == sanitized_parent(sanitized_path) => {}
                Some(_) => {
                    return Err(format!(
                        "{scenario}/{artifact_id}: _SMSTSLogPath is not observed in this physical artifact"
                    ));
                }
                None if observed_paths.is_empty() => {}
                None => {
                    return Err(format!(
                        "{scenario}/{artifact_id}: physical _SMSTSLogPath presence/absence is not declared exactly"
                    ));
                }
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
        } else if !artifact["rotation"]["fragmentComplete"].is_null() {
            return Err(format!(
                "{scenario}/{artifact_id}: noncapture artifact declares physical fragment completeness"
            ));
        } else if path_class != "unknown" {
            return Err(format!(
                "{scenario}/{artifact_id}: noncapture pathClass must remain unknown"
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
    validate_evidence_reference_shapes(scenario, expected)?;
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

    let captured_artifacts = artifacts
        .iter()
        .filter(|artifact| artifact["captureState"] == "captured")
        .collect::<Vec<_>>();
    let reviewed_profile_matches = !captured_artifacts.is_empty()
        && captured_artifacts.iter().all(|artifact| {
            artifact["sourceVersion"] == "5.00.TEST.0000" && artifact["pathClass"] != "unknown"
        });
    let (derived_profile_id, derived_profile_status) = if captured_artifacts.is_empty() {
        (None, "notObserved")
    } else if reviewed_profile_matches {
        let has_partial_fragment = captured_artifacts
            .iter()
            .any(|artifact| artifact["rotation"]["fragmentComplete"] == false);
        (
            Some("task-sequence-client-5.00.test-v1"),
            if has_partial_fragment {
                "matchedAfterControlledJoinOnly"
            } else {
                "matched"
            },
        )
    } else {
        (None, "unknownVersionRejected")
    };
    let extraction_profile_id = expected["extractionProfile"]["id"].as_str();
    let extraction_profile_status = expected["extractionProfile"]["status"].as_str();
    if extraction_profile_id != derived_profile_id
        || extraction_profile_status != Some(derived_profile_status)
    {
        return Err(format!(
            "{scenario}: extraction profile is not bound to sourceVersion/pathClass evidence"
        ));
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

    let logical_reconstructions = expected
        .as_object()
        .ok_or_else(|| "expected contract is not an object".to_owned())?
        .get("logicalReconstructions")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| "logicalReconstructions is not an array".to_owned())
        })
        .transpose()?
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let reconstruction_ids = logical_reconstructions
        .iter()
        .map(|reconstruction| {
            reconstruction["reconstructionId"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "logical reconstruction ID is not a string".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut sorted_reconstruction_ids = reconstruction_ids.clone();
    sorted_reconstruction_ids.sort();
    if reconstruction_ids != sorted_reconstruction_ids
        || reconstruction_ids.iter().collect::<BTreeSet<_>>().len() != reconstruction_ids.len()
    {
        return Err(format!(
            "{scenario}: logical reconstruction IDs must be unique and sorted"
        ));
    }

    let incomplete_fragments_missing_path_evidence = artifacts
        .iter()
        .filter(|artifact| {
            artifact["captureState"] == "captured"
                && artifact["rotation"]["fragmentComplete"] == false
                && artifact["smstsLogPathEvidence"].is_null()
        })
        .map(|artifact| {
            artifact["artifactId"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "artifactId is not a string".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut reconstructed_missing_path_evidence = BTreeSet::new();
    let mut reconstructed_artifacts = BTreeSet::new();
    for reconstruction in logical_reconstructions {
        let reconstruction_id = reconstruction["reconstructionId"]
            .as_str()
            .expect("reconstruction IDs were checked as strings");
        let logical_artifact_id = reconstruction["logicalArtifactId"]
            .as_str()
            .ok_or_else(|| format!("{reconstruction_id}: logicalArtifactId is not a string"))?;
        let ordered_ids = string_array(&reconstruction["orderedArtifactIds"])?;
        if ordered_ids.len() != 2 {
            return Err(format!(
                "{reconstruction_id}: controlled rotation must name exactly lo then current"
            ));
        }
        let lo_id = &ordered_ids[0];
        let current_id = &ordered_ids[1];
        if !reconstructed_artifacts.insert(lo_id.clone())
            || !reconstructed_artifacts.insert(current_id.clone())
        {
            return Err(format!(
                "{reconstruction_id}: physical fragment is reconstructed more than once"
            ));
        }
        let lo = artifacts_by_id
            .get(lo_id.as_str())
            .ok_or_else(|| format!("{reconstruction_id}: unknown lo artifact {lo_id}"))?;
        let current = artifacts_by_id
            .get(current_id.as_str())
            .ok_or_else(|| format!("{reconstruction_id}: unknown current artifact {current_id}"))?;
        let sanitized_path = reconstruction["sanitizedSourcePath"]
            .as_str()
            .ok_or_else(|| format!("{reconstruction_id}: sanitizedSourcePath is missing"))?;
        let path_class = reconstruction["pathClass"]
            .as_str()
            .ok_or_else(|| format!("{reconstruction_id}: pathClass is missing"))?;
        let path_fingerprint = reconstruction["pathFingerprint"]
            .as_str()
            .ok_or_else(|| format!("{reconstruction_id}: pathFingerprint is missing"))?;
        if logical_artifact_id != "client-task-sequence-smsts"
            || reconstruction["coverageState"] != "partial"
            || reconstruction["confidence"] != "low"
            || reconstruction["correlationEligible"] != false
            || lo["captureState"] != "captured"
            || current["captureState"] != "captured"
            || lo["rotation"]["kind"] != "lo"
            || current["rotation"]["kind"] != "current"
            || lo["rotation"]["fragmentComplete"] != false
            || current["rotation"]["fragmentComplete"] != false
            || lo["pathFingerprint"] != path_fingerprint
            || current["pathFingerprint"] != path_fingerprint
            || lo["sanitizedSourcePath"].as_str().map(sanitized_parent)
                != Some(sanitized_parent(sanitized_path))
            || current["sanitizedSourcePath"] != sanitized_path
            || lo["pathClass"] != path_class
            || current["pathClass"] != path_class
            || lo["sourceVersion"] != current["sourceVersion"]
            || lo["relocationOrdinal"] != current["relocationOrdinal"]
            || lo["smstsLogPathEvidence"] != sanitized_path
            || !current["smstsLogPathEvidence"].is_null()
            || derived_coverage
                .get(logical_artifact_id)
                .map(String::as_str)
                != Some("partial")
            || expected["correlationBoundary"]["scope"] != "sourceLocalOnly"
            || !string_array(&expected["correlationBoundary"]["joinFields"])?.is_empty()
            || string_array(&expected["correlationBoundary"]["rotationOrder"])?
                != ["lo".to_owned(), "current".to_owned()]
            || !expected["transactions"]
                .as_array()
                .is_some_and(Vec::is_empty)
        {
            return Err(format!(
                "{reconstruction_id}: controlled lo-to-current reconstruction metadata is invalid"
            ));
        }
        reconstructed_missing_path_evidence.insert(current_id.clone());
        let source_local_artifact_ids = expected["sourceLocalObservations"]
            .as_array()
            .ok_or_else(|| format!("{reconstruction_id}: sourceLocalObservations is missing"))?
            .iter()
            .filter_map(|observation| observation["artifactId"].as_str())
            .collect::<BTreeSet<_>>();
        if ![lo_id.as_str(), current_id.as_str()]
            .into_iter()
            .all(|artifact_id| source_local_artifact_ids.contains(artifact_id))
        {
            return Err(format!(
                "{reconstruction_id}: both physical fragments must remain source-local observations"
            ));
        }

        let path_evidence = &reconstruction["smstsLogPathEvidence"];
        if path_evidence["artifactId"] != lo_id.as_str() {
            return Err(format!(
                "{reconstruction_id}: logical path evidence must cite the lo fragment"
            ));
        }
        let path_evidence_text = evidence_text(scenario_root, &artifacts_by_id, path_evidence)?;
        let observed_paths = smsts_log_paths(&path_evidence_text);
        if observed_paths.len() != 1 || !observed_paths.contains(sanitized_path) {
            return Err(format!(
                "{reconstruction_id}: logical path citation does not contain the declared _SMSTSLogPath"
            ));
        }

        let mut joined_contents = String::new();
        for artifact in [*lo, *current] {
            let relative_path = artifact["relativePath"]
                .as_str()
                .ok_or_else(|| format!("{reconstruction_id}: fragment path is missing"))?;
            joined_contents.push_str(
                &std::fs::read_to_string(scenario_root.join(relative_path))
                    .map_err(|error| format!("{reconstruction_id}/{relative_path}: {error}"))?,
            );
        }
        let (joined_entries, joined_errors) = parse_content(
            &joined_contents,
            "controlled-logical-reconstruction.log",
            None,
        );
        if joined_errors != 0
            || joined_entries.len() != 1
            || joined_entries[0].format != LogFormat::Ccm
        {
            return Err(format!(
                "{reconstruction_id}: ordered physical fragments do not form exactly one CCM record"
            ));
        }
    }
    if reconstructed_missing_path_evidence != incomplete_fragments_missing_path_evidence {
        return Err(format!(
            "{scenario}: every incomplete fragment missing _SMSTSLogPath must have one explicit logical reconstruction"
        ));
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

    let declared_scope = expected["correlationBoundary"]["scope"]
        .as_str()
        .ok_or_else(|| format!("{scenario}: correlation scope is not a string"))?;
    let mut declared_join_fields = string_array(&expected["correlationBoundary"]["joinFields"])?;
    declared_join_fields.sort();
    let mut declared_forbidden_fields =
        string_array(&expected["correlationBoundary"]["forbiddenJoinFields"])?;
    declared_forbidden_fields.sort();
    if declared_forbidden_fields != FORBIDDEN_JOIN_FIELDS.map(str::to_owned) {
        return Err(format!(
            "{scenario}: declared forbidden join fields do not match the enforced list"
        ));
    }
    if transactions.is_empty() {
        let enforced_scope = if expected["sourceLocalObservations"]
            .as_array()
            .is_some_and(|observations| !observations.is_empty())
        {
            "sourceLocalOnly"
        } else {
            "coverageOnly"
        };
        if declared_scope != enforced_scope {
            return Err(format!(
                "{scenario}: correlation scope exceeds source-local enforcement"
            ));
        }
        if !declared_join_fields.is_empty() {
            return Err(format!(
                "{scenario}: an unkeyed scenario cannot declare join fields"
            ));
        }
    } else {
        if !TRANSACTION_CORRELATION_SCOPES.contains(&declared_scope) {
            return Err(format!(
                "{scenario}: correlation scope is not an enforced client-side scope"
            ));
        }
        let mut enforced_join_fields = EXACT_KEY_JOIN_FIELDS.map(str::to_owned);
        enforced_join_fields.sort();
        if declared_join_fields != enforced_join_fields {
            return Err(format!(
                "{scenario}: declared join fields do not match the enforced exact key fields"
            ));
        }
    }

    for transaction in transactions {
        let transaction_id = transaction["transactionId"]
            .as_str()
            .ok_or_else(|| "transactionId is not a string".to_owned())?;
        let key = transaction["key"]
            .as_object()
            .ok_or_else(|| format!("{transaction_id}: key is not an object"))?;
        for required in EXACT_KEY_JOIN_FIELDS {
            if !key.get(required).is_some_and(Value::is_string) {
                return Err(format!(
                    "{transaction_id}: missing exact key field {required}"
                ));
            }
        }
        for forbidden in FORBIDDEN_JOIN_FIELDS {
            if key.contains_key(forbidden) {
                return Err(format!(
                    "{transaction_id}: forbidden join field {forbidden}"
                ));
            }
        }
        if key.get("keyProfileKind").and_then(Value::as_str)
            != Some("executionPackageAdvertisementContext")
        {
            return Err(format!(
                "{transaction_id}: keyProfileKind is not the reviewed task sequence profile"
            ));
        }
        if key.get("confidence").and_then(Value::as_str) != Some("exact")
            || key.get("extractionProfileId").and_then(Value::as_str) != extraction_profile_id
            || extraction_profile_id.is_none()
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
        let mut cited_record_token_sets = Vec::new();
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
            let record_tokens = complete_field_tokens(&record_text).ok_or_else(|| {
                format!("{transaction_id}: cited record body is not delimited by the CCM framing")
            })?;
            if let Some(missing_needle) = key_needles
                .iter()
                .find(|needle| !record_tokens.contains(needle.as_str()))
            {
                return Err(format!(
                    "{transaction_id}: declared key fields do not co-occur as complete tokens in cited complete CCM record ({missing_needle})"
                ));
            }
            cited_record_token_sets.push(
                record_tokens
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>(),
            );
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
            || !cited_record_token_sets.iter().any(|record_tokens| {
                record_tokens.contains(&format!("phase={phase}"))
                    && record_tokens.contains(&format!("state={state}"))
            })
        {
            return Err(format!(
                "{transaction_id}: phase/state semantics are not bound to cited evidence"
            ));
        }
        let admissible_last_successful_phase = if state == "succeeded" {
            phase
        } else {
            let phase_index = STATE_CHAIN
                .iter()
                .position(|candidate| candidate == &phase)
                .expect("phase membership was validated");
            phase_index
                .checked_sub(1)
                .map(|index| STATE_CHAIN[index])
                .ok_or_else(|| {
                    format!(
                        "{transaction_id}: lastSuccessfulPhase has no admissible observed predecessor"
                    )
                })?
        };
        if last_successful_phase != admissible_last_successful_phase {
            return Err(format!(
                "{transaction_id}: lastSuccessfulPhase is not the admissible observed phase"
            ));
        }

        let path_items = transaction["pathSequence"]
            .as_array()
            .ok_or_else(|| format!("{transaction_id}: pathSequence is not an array"))?;
        let mut declared_path_sequence = Vec::new();
        let mut evidence_path_sequence = Vec::new();
        let mut path_artifact_ids = BTreeSet::new();
        for path_item in path_items {
            let artifact_id = path_item["artifactId"]
                .as_str()
                .ok_or_else(|| format!("{transaction_id}: path artifactId is missing"))?;
            if !path_artifact_ids.insert(artifact_id) {
                return Err(format!(
                    "{transaction_id}: pathSequence repeats artifact {artifact_id}"
                ));
            }
            let artifact = artifacts_by_id
                .get(artifact_id)
                .ok_or_else(|| format!("{transaction_id}: unknown path artifact {artifact_id}"))?;
            let evidence_ref = evidence_refs
                .iter()
                .find(|evidence_ref| evidence_ref["artifactId"] == artifact_id)
                .ok_or_else(|| {
                    format!(
                        "{transaction_id}: path artifact {artifact_id} is not key-bound cited evidence"
                    )
                })?;
            if path_item["pathClass"] != artifact["pathClass"]
                || path_item["relocationOrdinal"] != artifact["relocationOrdinal"]
            {
                return Err(format!(
                    "{transaction_id}: path provenance does not match {artifact_id}"
                ));
            }
            declared_path_sequence.push((
                path_item["relocationOrdinal"]
                    .as_u64()
                    .ok_or_else(|| format!("{transaction_id}: relocationOrdinal is missing"))?,
                artifact_id.to_owned(),
            ));
            let start_line = evidence_ref["startLine"]
                .as_u64()
                .ok_or_else(|| format!("{transaction_id}: path evidence startLine is missing"))?
                as u32;
            let end_line = evidence_ref["endLine"]
                .as_u64()
                .ok_or_else(|| format!("{transaction_id}: path evidence endLine is missing"))?
                as u32;
            let normalized = normalized_evidence(scenario_root, artifact)?;
            let evidence = normalized
                .iter()
                .find(|item| {
                    item.reference.line_start == Some(start_line)
                        && item.reference.line_end == Some(end_line)
                })
                .ok_or_else(|| {
                    format!(
                        "{transaction_id}: path citation for {artifact_id} is not one complete CCM record"
                    )
                })?;
            evidence_path_sequence.push((evidence.timestamp.utc_millis, artifact_id.to_owned()));
        }
        let declared_artifact_order = declared_path_sequence
            .iter()
            .map(|(_, artifact_id)| artifact_id.as_str())
            .collect::<Vec<_>>();
        let evidence_artifact_order = evidence_refs
            .iter()
            .map(|evidence_ref| {
                evidence_ref["artifactId"]
                    .as_str()
                    .ok_or_else(|| format!("{transaction_id}: evidence artifactId is missing"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if evidence_artifact_order != declared_artifact_order {
            return Err(format!(
                "{transaction_id}: evidence order must be unique and match canonical path sequence"
            ));
        }
        let relocation_ordinals = declared_path_sequence
            .iter()
            .map(|(ordinal, _)| *ordinal)
            .collect::<Vec<_>>();
        if relocation_ordinals != (0..declared_path_sequence.len() as u64).collect::<Vec<_>>() {
            return Err(format!(
                "{transaction_id}: relocation ordinals are not contiguous evidence order"
            ));
        }
        if evidence_path_sequence.len() > 1 {
            let mut derived_order = evidence_path_sequence
                .into_iter()
                .map(|(utc_millis, artifact_id)| {
                    utc_millis
                        .map(|utc_millis| (utc_millis, artifact_id))
                        .ok_or_else(|| {
                            format!(
                                "{transaction_id}: relocation order lacks normalized timestamp evidence"
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            derived_order.sort_by_key(|(utc_millis, _)| *utc_millis);
            if derived_order.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(format!(
                    "{transaction_id}: relocation order is ambiguous at equal cited timestamps"
                ));
            }
            let derived_artifact_order = derived_order
                .iter()
                .map(|(_, artifact_id)| artifact_id.as_str())
                .collect::<Vec<_>>();
            if declared_artifact_order != derived_artifact_order {
                return Err(format!(
                    "{transaction_id}: relocation order is not derived from cited evidence"
                ));
            }
        }

        let timestamp = &transaction["timestampProvenance"];
        let ordering_ref = &transaction["orderingEvidence"];
        if !evidence_refs
            .iter()
            .any(|evidence_ref| same_evidence_reference(evidence_ref, ordering_ref))
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
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
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
        if !transaction["nextArtifact"].is_null() {
            let next_artifact = transaction["nextArtifact"]
                .as_object()
                .ok_or_else(|| format!("{transaction_id}: next artifact is not an object"))?;
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

        let classification = transaction["classification"]
            .as_str()
            .ok_or_else(|| format!("{transaction_id}: classification is not a string"))?;
        let confidence = transaction["confidence"]
            .as_str()
            .ok_or_else(|| format!("{transaction_id}: confidence is not a string"))?;
        let confidence_ceiling = transaction["confidenceCeiling"]
            .as_str()
            .ok_or_else(|| format!("{transaction_id}: confidenceCeiling is not a string"))?;
        if confidence != confidence_ceiling || !matches!(confidence, "low" | "medium" | "high") {
            return Err(format!(
                "{transaction_id}: confidence exceeds or does not match its ceiling"
            ));
        }
        let ordering_state = timestamp["orderingState"]
            .as_str()
            .ok_or_else(|| format!("{transaction_id}: orderingState is not a string"))?;
        if ordering_state != "normalizedUtc" && confidence != "low" {
            return Err(format!(
                "{transaction_id}: non-normalized timestamp cannot exceed Low confidence"
            ));
        }

        let terminal_state = match classification {
            "success"
                if phase == "complete"
                    && state == "succeeded"
                    && last_successful_phase == "complete"
                    && confidence == "high" =>
            {
                Some("succeeded")
            }
            "confirmedFailure" if state == "failed" && confidence == "high" => Some("failed"),
            "blockedOrDeferred"
                if state == "blockedOrDeferred"
                    && matches!(confidence, "low" | "medium")
                    && transaction["terminalEvidence"].is_null() =>
            {
                None
            }
            "insufficientEvidence"
                if state == "inProgress"
                    && matches!(confidence, "low" | "medium")
                    && transaction["terminalEvidence"].is_null() =>
            {
                None
            }
            _ => {
                return Err(format!(
                    "{transaction_id}: classification/state/confidence semantics are invalid"
                ));
            }
        };
        if let Some(terminal_state) = terminal_state {
            if transaction["terminalEvidence"].is_null() {
                return Err(format!(
                    "{transaction_id}: terminal outcome lacks terminal evidence"
                ));
            }
            if !evidence_refs.iter().any(|evidence_ref| {
                same_evidence_reference(evidence_ref, &transaction["terminalEvidence"])
            }) {
                return Err(format!(
                    "{transaction_id}: terminal evidence is not key-bound transaction evidence"
                ));
            }
            let terminal_text = evidence_text(
                scenario_root,
                &artifacts_by_id,
                &transaction["terminalEvidence"],
            )?;
            let terminal_tokens = complete_field_tokens(&terminal_text).ok_or_else(|| {
                format!(
                    "{transaction_id}: terminal record body is not delimited by the CCM framing"
                )
            })?;
            if !terminal_tokens.contains("terminal=true")
                || !terminal_tokens.contains(format!("state={terminal_state}").as_str())
                || !terminal_tokens.contains(format!("phase={phase}").as_str())
            {
                return Err(format!(
                    "{transaction_id}: terminal citation does not prove the terminal outcome"
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
    if observation_ids != sorted_observation_ids
        || observation_ids.iter().collect::<BTreeSet<_>>().len() != observation_ids.len()
    {
        return Err(format!(
            "{scenario}: source-local observation IDs must be unique and sorted"
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
        // The ordering and terminal disjuncts are redundant today, because both
        // must already be members of their transaction's evidence, but they are
        // kept so this rule stays correct if that membership requirement moves.
        let cites_keyed_transaction_evidence = transactions.iter().any(|transaction| {
            transaction["evidence"]
                .as_array()
                .is_some_and(|transaction_evidence| {
                    transaction_evidence.iter().any(|transaction_ref| {
                        same_evidence_reference(transaction_ref, &observation["evidence"])
                    })
                })
                || same_evidence_reference(
                    &transaction["orderingEvidence"],
                    &observation["evidence"],
                )
                || same_evidence_reference(
                    &transaction["terminalEvidence"],
                    &observation["evidence"],
                )
        });
        if cites_keyed_transaction_evidence {
            return Err(format!(
                "{observation_id}: keyed transaction evidence cannot double as a source-local observation"
            ));
        }
        evidence_text(scenario_root, &artifacts_by_id, &observation["evidence"])?;
    }

    let finding_ids = sorted_ids(&expected["findings"], "findingId");
    let mut sorted_finding_ids = finding_ids.clone();
    sorted_finding_ids.sort();
    if finding_ids != sorted_finding_ids
        || finding_ids.iter().collect::<BTreeSet<_>>().len() != finding_ids.len()
    {
        return Err(format!("{scenario}: finding IDs must be unique and sorted"));
    }
    for finding in expected["findings"]
        .as_array()
        .ok_or_else(|| "findings are not an array".to_owned())?
    {
        let finding_id = finding["findingId"]
            .as_str()
            .ok_or_else(|| "findingId is not a string".to_owned())?;
        let finding_object = finding
            .as_object()
            .ok_or_else(|| format!("{finding_id}: finding is not an object"))?;
        if finding_object
            .keys()
            .any(|field| field.to_ascii_lowercase().contains("notasksequence"))
        {
            return Err(format!(
                "{finding_id}: absent coverage cannot become a no-run claim"
            ));
        }
        let evidence = finding["evidence"]
            .as_array()
            .ok_or_else(|| format!("{finding_id}: evidence is not an array"))?;
        let coverage_gaps = string_array(&finding["coverageGapArtifactIds"])?;
        if evidence.is_empty() && coverage_gaps.is_empty() {
            return Err(format!(
                "{finding_id}: finding has neither evidence nor coverage"
            ));
        }
        for evidence_ref in evidence {
            evidence_text(scenario_root, &artifacts_by_id, evidence_ref)?;
        }
        for artifact_id in &coverage_gaps {
            let artifact = artifacts_by_id
                .get(artifact_id.as_str())
                .ok_or_else(|| format!("{finding_id}: unknown coverage gap {artifact_id}"))?;
            if artifact_effective_state(artifact)? == "captured" {
                return Err(format!(
                    "{finding_id}: complete artifact {artifact_id} is a coverage gap"
                ));
            }
        }
        if !finding["boundedNextArtifact"].is_null() {
            let next_artifact = finding["boundedNextArtifact"]
                .as_object()
                .ok_or_else(|| format!("{finding_id}: next artifact is not an object"))?;
            if next_artifact["logicalArtifactId"] != "client-task-sequence-smsts"
                || !PATH_CLASSES.contains(
                    &next_artifact["pathClass"]
                        .as_str()
                        .ok_or_else(|| format!("{finding_id}: next pathClass is missing"))?,
                )
                || !next_artifact["reason"].is_string()
            {
                return Err(format!(
                    "{finding_id}: next artifact request is not bounded"
                ));
            }
        }
        let classification = finding["classification"]
            .as_str()
            .ok_or_else(|| format!("{finding_id}: classification is not a string"))?;
        let binding_transactions = transactions
            .iter()
            .filter(|transaction| {
                transaction["classification"] == classification
                    && !evidence.is_empty()
                    && transaction["evidence"]
                        .as_array()
                        .is_some_and(|transaction_evidence| {
                            evidence.iter().all(|evidence_ref| {
                                transaction_evidence.iter().any(|transaction_ref| {
                                    same_evidence_reference(transaction_ref, evidence_ref)
                                })
                            })
                        })
            })
            .collect::<Vec<_>>();
        let cited_refs_are_source_local = !evidence.is_empty()
            && evidence.iter().all(|evidence_ref| {
                observations.iter().any(|observation| {
                    same_evidence_reference(&observation["evidence"], evidence_ref)
                })
            });
        let outcome_is_transaction_bound = match classification {
            "success" | "confirmedFailure" => {
                matches!(binding_transactions.as_slice(), [transaction] if {
                    !transaction["terminalEvidence"].is_null()
                        && evidence
                            .iter()
                            .any(|evidence_ref| same_evidence_reference(evidence_ref, &transaction["terminalEvidence"]))
                })
            }
            "blockedOrDeferred" => binding_transactions.len() == 1,
            "insufficientEvidence" => {
                binding_transactions.len() == 1
                    || (binding_transactions.is_empty()
                        && (evidence.is_empty() || cited_refs_are_source_local))
            }
            _ => false,
        };
        if !outcome_is_transaction_bound {
            return Err(format!(
                "{finding_id}: finding outcome is not bound to exactly one keyed transaction or its source-local citations"
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

#[test]
fn last_successful_phase_requires_the_admissible_observed_phase() {
    for scenario in [
        "terminal-preflight",
        "client-installed",
        "reboot-continuation",
    ] {
        let scenario_root = task_sequence_root().join(scenario);
        let manifest = read_json(&scenario_root.join("manifest.json"));
        let mut expected = read_json(&scenario_root.join("expected.json"));
        expected["transactions"][0]["lastSuccessfulPhase"] = Value::String("complete".to_owned());

        let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
            .expect_err("an uncited later phase cannot become the last successful phase");
        assert!(error.contains("lastSuccessfulPhase"), "{scenario}: {error}");
    }
}

#[test]
fn exact_key_kind_is_bound_to_the_task_sequence_profile() {
    let scenario = "completed";
    let scenario_root = task_sequence_root().join(scenario);
    let manifest = read_json(&scenario_root.join("manifest.json"));
    let mut expected = read_json(&scenario_root.join("expected.json"));
    expected["transactions"][0]["key"]["keyProfileKind"] =
        Value::String("filenameTimestamp".to_owned());

    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("an exact key cannot advertise an unrelated profile kind");
    assert!(error.contains("keyProfileKind"), "{error}");
}

#[test]
fn transaction_evidence_order_is_canonical_and_unique() {
    let scenario = "relocated-fragments";
    let scenario_root = task_sequence_root().join(scenario);
    let manifest = read_json(&scenario_root.join("manifest.json"));
    let mut expected = read_json(&scenario_root.join("expected.json"));
    let evidence = expected["transactions"][0]["evidence"]
        .as_array_mut()
        .expect("transaction evidence is an array");
    let last = evidence.len() - 1;
    evidence.swap(0, last);

    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("transaction evidence must retain canonical relocation order");
    assert!(error.contains("evidence order"), "{error}");
}

#[test]
fn source_local_observation_ids_must_be_unique() {
    let scenario = "unknown-profile";
    let scenario_root = task_sequence_root().join(scenario);
    let manifest = read_json(&scenario_root.join("manifest.json"));
    let mut expected = read_json(&scenario_root.join("expected.json"));
    let duplicate = expected["sourceLocalObservations"][0].clone();
    expected["sourceLocalObservations"]
        .as_array_mut()
        .expect("source-local observations are an array")
        .push(duplicate);

    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("sorted duplicate observation IDs must fail closed");
    assert!(error.contains("observation IDs"), "{error}");
}

#[test]
fn finding_ids_must_be_unique() {
    let scenario = "winpe";
    let scenario_root = task_sequence_root().join(scenario);
    let manifest = read_json(&scenario_root.join("manifest.json"));
    let mut expected = read_json(&scenario_root.join("expected.json"));
    let duplicate = expected["findings"][0].clone();
    expected["findings"]
        .as_array_mut()
        .expect("findings are an array")
        .push(duplicate);

    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("sorted duplicate finding IDs must fail closed");
    assert!(error.contains("finding IDs"), "{error}");
}

#[test]
fn complete_winpe_record_may_have_no_smsts_path_observation() {
    let scenario = "winpe";
    let temporary = copy_scenario_to_temporary_root(scenario, "no-smsts-path-token");
    let mut manifest = read_json(&temporary.root.join("manifest.json"));
    let mut expected = read_json(&temporary.root.join("expected.json"));
    let relative_path = manifest["artifacts"][0]["relativePath"]
        .as_str()
        .expect("WinPE artifact has a relative path");
    let evidence_path = temporary.root.join(relative_path);
    let original = std::fs::read_to_string(&evidence_path).expect("WinPE evidence is readable");
    let without_path = original.replace(
        " _SMSTSLogPath=SYNTHETIC://winpe/Windows/temp/smstslog/smsts.log",
        "",
    );
    assert_ne!(
        without_path, original,
        "the path token mutation is effective"
    );
    std::fs::write(&evidence_path, &without_path).expect("mutated evidence is writable");

    manifest["artifacts"][0]["bytesCopied"] = Value::from(without_path.len() as u64);
    manifest["artifacts"][0]["smstsLogPathEvidence"] = Value::Null;
    expected["artifactProvenance"][0]["bytesCopied"] = Value::from(without_path.len() as u64);
    expected["artifactProvenance"][0]["smstsLogPathEvidence"] = Value::Null;

    validate_contract(scenario, &temporary.root, &manifest, &expected)
        .expect("a complete logical CCM record may lack an observed _SMSTSLogPath");
}

#[test]
fn equal_relocation_timestamps_are_ambiguous() {
    let scenario = "relocated-fragments";
    let temporary = copy_scenario_to_temporary_root(scenario, "equal-relocation-timestamps");
    let mut manifest = read_json(&temporary.root.join("manifest.json"));
    let mut expected = read_json(&temporary.root.join("expected.json"));
    let artifact_id = "task-sequence-relocated-02-setup";
    let artifact_index = manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array")
        .iter()
        .position(|artifact| artifact["artifactId"] == artifact_id)
        .expect("setup relocation artifact exists");
    let relative_path = manifest["artifacts"][artifact_index]["relativePath"]
        .as_str()
        .expect("setup relocation artifact has a relative path")
        .to_owned();
    let evidence_path = temporary.root.join(relative_path);
    let original = std::fs::read_to_string(&evidence_path).expect("setup evidence is readable");
    let tied = original.replace("01:10:01.000+000", "01:10:00.000+000");
    assert_ne!(tied, original, "the equal-timestamp mutation is effective");
    std::fs::write(&evidence_path, &tied).expect("mutated setup evidence is writable");

    manifest["artifacts"][artifact_index]["bytesCopied"] = Value::from(tied.len() as u64);
    let provenance_index = expected["artifactProvenance"]
        .as_array()
        .expect("artifact provenance is an array")
        .iter()
        .position(|item| item["artifactId"] == artifact_id)
        .expect("setup relocation provenance exists");
    expected["artifactProvenance"][provenance_index]["bytesCopied"] =
        Value::from(tied.len() as u64);

    let error = validate_contract(scenario, &temporary.root, &manifest, &expected)
        .expect_err("equal cited timestamps cannot establish relocation order");
    assert!(error.contains("ambiguous"), "{error}");
}

#[test]
fn timestamp_binding_preserves_millisecond_precision() {
    let scenario = "winpe";
    let temporary = copy_scenario_to_temporary_root(scenario, "subsecond-timestamp");
    let mut manifest = read_json(&temporary.root.join("manifest.json"));
    let mut expected = read_json(&temporary.root.join("expected.json"));
    let relative_path = manifest["artifacts"][0]["relativePath"]
        .as_str()
        .expect("WinPE artifact has a relative path");
    let evidence_path = temporary.root.join(relative_path);
    let original = std::fs::read_to_string(&evidence_path).expect("WinPE evidence is readable");
    let subsecond = original.replace("01:00:01.000+000", "01:00:01.123+000");
    assert_ne!(
        subsecond, original,
        "the subsecond timestamp mutation is effective"
    );
    std::fs::write(&evidence_path, &subsecond).expect("mutated evidence is writable");

    manifest["artifacts"][0]["bytesCopied"] = Value::from(subsecond.len() as u64);
    expected["artifactProvenance"][0]["bytesCopied"] = Value::from(subsecond.len() as u64);

    let error = validate_contract(scenario, &temporary.root, &manifest, &expected)
        .expect_err("whole-second expected output cannot match subsecond evidence");
    assert!(error.contains("timestamp"), "{error}");
}

#[test]
fn coherent_review_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let completed_root = task_sequence_root().join("completed");
    let completed_manifest = read_json(&completed_root.join("manifest.json"));
    let completed_expected = read_json(&completed_root.join("expected.json"));

    let mut manifest = completed_manifest.clone();
    let mut expected = completed_expected.clone();
    manifest["artifacts"][0]["pathClass"] = Value::String("setup".to_owned());
    expected["coverage"][0]["pathClasses"] = serde_json::json!(["setup"]);
    expected["artifactProvenance"][0]["pathClass"] = Value::String("setup".to_owned());
    expected["transactions"][0]["pathSequence"][0]["pathClass"] = Value::String("setup".to_owned());
    if validate_contract("completed", &completed_root, &manifest, &expected).is_ok() {
        accepted.push("pathClass drift");
    }

    let mut manifest = completed_manifest.clone();
    let mut expected = completed_expected.clone();
    let drifted_path = Value::String("SYNTHETIC://client/drift/smsts.log".to_owned());
    manifest["artifacts"][0]["sanitizedSourcePath"] = drifted_path.clone();
    manifest["artifacts"][0]["smstsLogPathEvidence"] = drifted_path.clone();
    expected["artifactProvenance"][0]["sanitizedSourcePath"] = drifted_path.clone();
    expected["artifactProvenance"][0]["smstsLogPathEvidence"] = drifted_path;
    if validate_contract("completed", &completed_root, &manifest, &expected).is_ok() {
        accepted.push("_SMSTSLogPath drift");
    }

    let mut manifest = completed_manifest.clone();
    manifest["artifacts"][0]["sourceVersion"] = Value::String("5.00.UNKNOWN.0000".to_owned());
    if validate_contract("completed", &completed_root, &manifest, &completed_expected).is_ok() {
        accepted.push("sourceVersion drift");
    }

    let mut expected = completed_expected.clone();
    expected["extractionProfile"]["id"] =
        Value::String("task-sequence-client-9.99.drift-v1".to_owned());
    if validate_contract("completed", &completed_root, &completed_manifest, &expected).is_ok() {
        accepted.push("extraction profile drift");
    }

    let mut manifest = completed_manifest.clone();
    manifest["artifacts"][0]["capturedUtc"] = Value::String("not-a-timestamp".to_owned());
    if validate_contract("completed", &completed_root, &manifest, &completed_expected).is_ok() {
        accepted.push("invalid capturedUtc");
    }

    let rotation_root = task_sequence_root().join("rotation-boundary");
    let mut manifest = read_json(&rotation_root.join("manifest.json"));
    let mut expected = read_json(&rotation_root.join("expected.json"));
    let lo_index = manifest["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array")
        .iter()
        .position(|artifact| artifact["rotation"]["kind"] == "lo")
        .expect("rotation corpus has smsts.lo_");
    manifest["artifacts"][lo_index]["rotation"]["fragmentComplete"] = Value::Bool(true);
    let lo_id = manifest["artifacts"][lo_index]["artifactId"].clone();
    let provenance_index = expected["artifactProvenance"]
        .as_array()
        .expect("rotation provenance is an array")
        .iter()
        .position(|item| item["artifactId"] == lo_id)
        .expect("rotation provenance contains smsts.lo_");
    expected["artifactProvenance"][provenance_index]["fragmentComplete"] = Value::Bool(true);
    expected["coverage"][0]["state"] = Value::String("captured".to_owned());
    if validate_contract("rotation-boundary", &rotation_root, &manifest, &expected).is_ok() {
        accepted.push("partial smsts.lo_ promoted complete");
    }

    let relocated_root = task_sequence_root().join("relocated-fragments");
    let mut manifest = read_json(&relocated_root.join("manifest.json"));
    let mut expected = read_json(&relocated_root.join("expected.json"));
    manifest["artifacts"][1]["relocationOrdinal"] = Value::from(2);
    manifest["artifacts"][2]["relocationOrdinal"] = Value::from(1);
    expected["artifactProvenance"][1]["relocationOrdinal"] = Value::from(2);
    expected["artifactProvenance"][2]["relocationOrdinal"] = Value::from(1);
    expected["transactions"][0]["pathSequence"][1]["relocationOrdinal"] = Value::from(2);
    expected["transactions"][0]["pathSequence"][2]["relocationOrdinal"] = Value::from(1);
    expected["transactions"][0]["pathSequence"]
        .as_array_mut()
        .expect("path sequence is an array")
        .swap(1, 2);
    if validate_contract("relocated-fragments", &relocated_root, &manifest, &expected).is_ok() {
        accepted.push("relocation order drift");
    }

    let unkeyed_root = task_sequence_root().join("complete-looking-unkeyed");
    let unkeyed_manifest = read_json(&unkeyed_root.join("manifest.json"));
    let mut expected = read_json(&unkeyed_root.join("expected.json"));
    expected["findings"][0]["classification"] = Value::String("success".to_owned());
    if validate_contract(
        "complete-looking-unkeyed",
        &unkeyed_root,
        &unkeyed_manifest,
        &expected,
    )
    .is_ok()
    {
        accepted.push("unkeyed evidence promoted success");
    }

    let mut expected = completed_expected.clone();
    expected["transactions"][0]["terminalEvidence"] = Value::Null;
    if validate_contract("completed", &completed_root, &completed_manifest, &expected).is_ok() {
        accepted.push("success without terminal citation");
    }

    let nonterminal_root = task_sequence_root().join("client-installed");
    let nonterminal_manifest = read_json(&nonterminal_root.join("manifest.json"));
    let mut expected = read_json(&nonterminal_root.join("expected.json"));
    expected["findings"][0]["classification"] = Value::String("confirmedFailure".to_owned());
    if validate_contract(
        "client-installed",
        &nonterminal_root,
        &nonterminal_manifest,
        &expected,
    )
    .is_ok()
    {
        accepted.push("nonterminal finding promoted confirmedFailure");
    }

    let invalid_offset_root = task_sequence_root().join("invalid-offset");
    let invalid_offset_manifest = read_json(&invalid_offset_root.join("manifest.json"));
    let mut expected = read_json(&invalid_offset_root.join("expected.json"));
    expected["transactions"][0]["confidence"] = Value::String("high".to_owned());
    expected["transactions"][0]["confidenceCeiling"] = Value::String("high".to_owned());
    if validate_contract(
        "invalid-offset",
        &invalid_offset_root,
        &invalid_offset_manifest,
        &expected,
    )
    .is_ok()
    {
        accepted.push("invalid offset promoted High");
    }

    let unknown_root = task_sequence_root().join("unknown-profile");
    let unknown_manifest = read_json(&unknown_root.join("manifest.json"));
    let mut expected = read_json(&unknown_root.join("expected.json"));
    let winpe_expected = read_json(&task_sequence_root().join("winpe").join("expected.json"));
    let mut transaction = winpe_expected["transactions"][0].clone();
    transaction["transactionId"] = Value::String("task-sequence-016".to_owned());
    transaction["key"]["executionId"] =
        Value::String("72400000-0000-0000-0000-000000000016".to_owned());
    transaction["key"]["advertisementId"] = Value::String("LAB20316".to_owned());
    transaction["evidence"][0]["artifactId"] =
        Value::String("task-sequence-unknown-profile-smsts-current".to_owned());
    transaction["pathSequence"][0]["artifactId"] =
        Value::String("task-sequence-unknown-profile-smsts-current".to_owned());
    transaction["pathSequence"][0]["pathClass"] = Value::String("unknown".to_owned());
    transaction["orderingEvidence"]["artifactId"] =
        Value::String("task-sequence-unknown-profile-smsts-current".to_owned());
    transaction["timestampProvenance"]["normalizedUtc"] =
        Value::String("2026-07-30T01:46:00Z".to_owned());
    transaction["nextArtifact"] = Value::Null;
    transaction["confidence"] = Value::String("high".to_owned());
    transaction["confidenceCeiling"] = Value::String("high".to_owned());
    expected["extractionProfile"] = serde_json::json!({
        "id": "task-sequence-client-5.00.test-v1",
        "status": "matched"
    });
    expected["transactions"] = serde_json::json!([transaction]);
    expected["sourceLocalObservations"] = serde_json::json!([]);
    if validate_contract(
        "unknown-profile",
        &unknown_root,
        &unknown_manifest,
        &expected,
    )
    .is_ok()
    {
        accepted.push("unknown source promoted exact High");
    }

    let incomplete_root = task_sequence_root().join("incomplete");
    let incomplete_manifest = read_json(&incomplete_root.join("manifest.json"));
    let mut expected = read_json(&incomplete_root.join("expected.json"));
    expected["findings"][0]["boundedNextArtifact"] = serde_json::json!({
        "logicalArtifactId": "all-device-artifacts",
        "pathClass": "everywhere",
        "reason": "Collect everything."
    });
    if validate_contract(
        "incomplete",
        &incomplete_root,
        &incomplete_manifest,
        &expected,
    )
    .is_ok()
    {
        accepted.push("unbounded finding request");
    }

    let mut expected = read_json(&incomplete_root.join("expected.json"));
    expected["findings"][0]["classification"] = Value::String("success".to_owned());
    expected["findings"][0]["noTaskSequenceRan"] = Value::Bool(true);
    if validate_contract(
        "incomplete",
        &incomplete_root,
        &incomplete_manifest,
        &expected,
    )
    .is_ok()
    {
        accepted.push("absent coverage promoted success/no-run");
    }

    assert!(
        accepted.is_empty(),
        "validate_contract accepted {} coherent review mutations: {}",
        accepted.len(),
        accepted.join(", ")
    );
}

#[test]
fn rotation_path_provenance_cannot_be_borrowed_from_a_shared_fingerprint() {
    let scenario = "rotation-boundary";
    let source_root = task_sequence_root().join(scenario);
    let source_manifest = read_json(&source_root.join("manifest.json"));
    let source_expected = read_json(&source_root.join("expected.json"));
    let original_path = "SYNTHETIC://client/CCM/Logs/smsts.log";
    let drifted_path = "SYNTHETIC://client/CCM/Logs/drift/smsts.log";
    let lo_id = "task-sequence-rotation-boundary-lo";
    let mut accepted = Vec::new();

    let changed = copy_scenario_to_temporary_root(scenario, "changed-path-token");
    let mut manifest = source_manifest.clone();
    let mut expected = source_expected.clone();
    let lo_index = manifest["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array")
        .iter()
        .position(|artifact| artifact["artifactId"] == lo_id)
        .expect("rotation corpus has smsts.lo_");
    let lo_relative_path = manifest["artifacts"][lo_index]["relativePath"]
        .as_str()
        .expect("smsts.lo_ has a relative path");
    let lo_path = changed.root.join(lo_relative_path);
    let original_lo = std::fs::read_to_string(&lo_path).expect("smsts.lo_ is UTF-8");
    let changed_lo = original_lo.replace(original_path, drifted_path);
    assert_ne!(original_lo, changed_lo, "the path token mutation applies");
    std::fs::write(&lo_path, &changed_lo).expect("mutated smsts.lo_ is written");
    let changed_bytes = changed_lo.len() as u64;
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .expect("rotation artifacts are an array")
    {
        artifact["sanitizedSourcePath"] = Value::String(drifted_path.to_owned());
        artifact["smstsLogPathEvidence"] = Value::String(drifted_path.to_owned());
        if artifact["artifactId"] == lo_id {
            artifact["bytesCopied"] = Value::from(changed_bytes);
        }
    }
    for provenance in expected["artifactProvenance"]
        .as_array_mut()
        .expect("rotation provenance is an array")
    {
        provenance["sanitizedSourcePath"] = Value::String(drifted_path.to_owned());
        provenance["smstsLogPathEvidence"] = Value::String(drifted_path.to_owned());
        if provenance["artifactId"] == lo_id {
            provenance["bytesCopied"] = Value::from(changed_bytes);
        }
    }
    expected["logicalReconstructions"][0]["sanitizedSourcePath"] =
        Value::String(drifted_path.to_owned());
    if validate_contract(scenario, &changed.root, &manifest, &expected).is_ok() {
        accepted.push("current fragment borrowed changed lo path");
    }

    let donor = copy_scenario_to_temporary_root(scenario, "same-fingerprint-donor");
    let mut manifest = source_manifest.clone();
    let mut expected = source_expected.clone();
    let lo_index = manifest["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array")
        .iter()
        .position(|artifact| artifact["artifactId"] == lo_id)
        .expect("rotation corpus has smsts.lo_");
    let lo_relative_path = manifest["artifacts"][lo_index]["relativePath"]
        .as_str()
        .expect("smsts.lo_ has a relative path")
        .to_owned();
    let lo_path = donor.root.join(&lo_relative_path);
    let original_lo = std::fs::read_to_string(&lo_path).expect("smsts.lo_ is UTF-8");
    let removed_lo = original_lo.replace("_SMSTSLogPath=", "_REMOVEDLogPath=");
    assert_ne!(original_lo, removed_lo, "the path token removal applies");
    std::fs::write(&lo_path, &removed_lo).expect("mutated smsts.lo_ is written");
    let removed_bytes = removed_lo.len() as u64;
    manifest["artifacts"][lo_index]["bytesCopied"] = Value::from(removed_bytes);
    let lo_provenance_index = expected["artifactProvenance"]
        .as_array()
        .expect("rotation provenance is an array")
        .iter()
        .position(|item| item["artifactId"] == lo_id)
        .expect("rotation provenance contains smsts.lo_");
    expected["artifactProvenance"][lo_provenance_index]["bytesCopied"] = Value::from(removed_bytes);

    let donor_id = "task-sequence-rotation-boundary-donor";
    let donor_relative_path = "evidence/client-task-sequence-smsts/client/donor/smsts.lo_";
    let donor_path = donor.root.join(donor_relative_path);
    std::fs::create_dir_all(
        donor_path
            .parent()
            .expect("donor evidence has a parent directory"),
    )
    .expect("donor directory is created");
    std::fs::write(&donor_path, &original_lo).expect("donor evidence is written");
    let mut donor_artifact = manifest["artifacts"][lo_index].clone();
    donor_artifact["artifactId"] = Value::String(donor_id.to_owned());
    donor_artifact["relativePath"] = Value::String(donor_relative_path.to_owned());
    donor_artifact["bytesCopied"] = Value::from(original_lo.len() as u64);
    manifest["artifacts"]
        .as_array_mut()
        .expect("rotation artifacts are an array")
        .push(donor_artifact);

    let mut donor_provenance = expected["artifactProvenance"][lo_provenance_index].clone();
    donor_provenance["artifactId"] = Value::String(donor_id.to_owned());
    donor_provenance["bytesCopied"] = Value::from(original_lo.len() as u64);
    expected["artifactProvenance"]
        .as_array_mut()
        .expect("rotation provenance is an array")
        .insert(1, donor_provenance);
    expected["coverage"][0]["artifactIds"]
        .as_array_mut()
        .expect("partial artifact IDs are an array")
        .insert(1, Value::String(donor_id.to_owned()));
    if validate_contract(scenario, &donor.root, &manifest, &expected).is_ok() {
        accepted.push("same-fingerprint donor supplied another fragment path");
    }

    assert!(
        accepted.is_empty(),
        "validate_contract accepted {} shared-fingerprint provenance mutations: {}",
        accepted.len(),
        accepted.join(", ")
    );
}

#[test]
fn exact_key_admission_requires_complete_value_tokens() {
    let scenario = "completed";
    let scenario_root = task_sequence_root().join(scenario);
    let manifest = read_json(&scenario_root.join("manifest.json"));
    let mut expected = read_json(&scenario_root.join("expected.json"));
    expected["transactions"][0]["key"]["executionId"] =
        Value::String("72400000-0000-0000-0000-00000000000".to_owned());
    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("a strict prefix of the recorded execution token is not the exact key");
    assert!(error.contains("co-occur"), "{error}");

    let temporary = copy_scenario_to_temporary_root(scenario, "suffixed-execution-token");
    let mut manifest = read_json(&temporary.root.join("manifest.json"));
    let mut expected = read_json(&temporary.root.join("expected.json"));
    let relative_path = manifest["artifacts"][0]["relativePath"]
        .as_str()
        .expect("completed artifact has a relative path");
    let evidence_path = temporary.root.join(relative_path);
    let original = std::fs::read_to_string(&evidence_path).expect("completed evidence is readable");
    let suffixed = original.replace(
        "executionId=72400000-0000-0000-0000-000000000005 ",
        "executionId=72400000-0000-0000-0000-000000000005X ",
    );
    assert_ne!(
        suffixed, original,
        "the suffixed execution token mutation is effective"
    );
    std::fs::write(&evidence_path, &suffixed).expect("mutated evidence is writable");
    manifest["artifacts"][0]["bytesCopied"] = Value::from(suffixed.len() as u64);
    expected["artifactProvenance"][0]["bytesCopied"] = Value::from(suffixed.len() as u64);

    let error = validate_contract(scenario, &temporary.root, &manifest, &expected)
        .expect_err("a suffixed recorded token cannot satisfy the declared exact key");
    assert!(error.contains("co-occur"), "{error}");
}

#[test]
fn correlation_boundary_declaration_is_bound_to_enforcement() {
    let scenario = "completed";
    let scenario_root = task_sequence_root().join(scenario);
    let manifest = read_json(&scenario_root.join("manifest.json"));

    let mut expected = read_json(&scenario_root.join("expected.json"));
    expected["correlationBoundary"]["scope"] = Value::String("crossSideHighConfidence".to_owned());
    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("a cross-side scope exceeds the enforced client-side boundary");
    assert!(error.contains("correlation scope"), "{error}");

    let mut expected = read_json(&scenario_root.join("expected.json"));
    expected["correlationBoundary"]["joinFields"] = serde_json::json!(["timestamp"]);
    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("declared join fields must be the enforced exact key fields");
    assert!(error.contains("exact key fields"), "{error}");

    let mut expected = read_json(&scenario_root.join("expected.json"));
    expected["correlationBoundary"]["forbiddenJoinFields"] =
        serde_json::json!(["filename", "path", "timestamp", "displayName"]);
    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("a forbidden list omitting component is not the enforced list");
    assert!(error.contains("forbidden join fields"), "{error}");

    let mut expected = read_json(&scenario_root.join("expected.json"));
    expected["correlationBoundary"]["forbiddenJoinFields"] = serde_json::json!([]);
    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("an empty forbidden list is not the enforced list");
    assert!(error.contains("forbidden join fields"), "{error}");
}

#[test]
fn noncapture_artifacts_cannot_carry_fragment_rotation_metadata() {
    let scenario = "incomplete";
    let scenario_root = task_sequence_root().join(scenario);
    let mut manifest = read_json(&scenario_root.join("manifest.json"));
    let expected = read_json(&scenario_root.join("expected.json"));
    manifest["artifacts"][0]["rotation"]["fragmentComplete"] = Value::Bool(false);

    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("an absent artifact cannot claim physical fragment completeness");
    assert!(error.contains("fragment"), "{error}");
}

#[test]
fn finding_evidence_cannot_mix_unrelated_exact_runs() {
    let scenario = "unrelated-runs";
    let scenario_root = task_sequence_root().join(scenario);
    let manifest = read_json(&scenario_root.join("manifest.json"));
    let mut expected = read_json(&scenario_root.join("expected.json"));
    let run_b_evidence = expected["transactions"][1]["evidence"][0].clone();
    expected["findings"][0]["evidence"]
        .as_array_mut()
        .expect("run A finding evidence is an array")
        .push(run_b_evidence);

    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("one finding cannot cite evidence from a different exact run");
    assert!(error.contains("bound"), "{error}");
}

#[test]
fn exact_key_admission_ignores_bracket_bounded_prefixes() {
    let scenario = "completed";
    for (mutation, original_token, mutated_token) in [
        (
            "bracket-suffixed-run-context",
            "runContext=osd ",
            "runContext=osd]stray ",
        ),
        (
            "angle-suffixed-advertisement",
            "advertisementId=LAB20305 ",
            "advertisementId=LAB20305<junk> ",
        ),
    ] {
        let temporary = copy_scenario_to_temporary_root(scenario, mutation);
        let mut manifest = read_json(&temporary.root.join("manifest.json"));
        let mut expected = read_json(&temporary.root.join("expected.json"));
        let relative_path = manifest["artifacts"][0]["relativePath"]
            .as_str()
            .expect("completed artifact has a relative path");
        let evidence_path = temporary.root.join(relative_path);
        let original =
            std::fs::read_to_string(&evidence_path).expect("completed evidence is readable");
        let mutated = original.replace(original_token, mutated_token);
        assert_ne!(mutated, original, "{mutation}: the mutation is effective");
        std::fs::write(&evidence_path, &mutated).expect("mutated evidence is writable");
        manifest["artifacts"][0]["bytesCopied"] = Value::from(mutated.len() as u64);
        expected["artifactProvenance"][0]["bytesCopied"] = Value::from(mutated.len() as u64);

        let error = validate_contract(scenario, &temporary.root, &manifest, &expected)
            .expect_err("a bracket-bounded prefix of the recorded value is not the exact key");
        assert!(error.contains("co-occur"), "{mutation}: {error}");
    }
}

fn aliasing_observation(observation_id: &str, evidence: &Value) -> Value {
    serde_json::json!({
        "observationId": observation_id,
        "artifactId": evidence["artifactId"].clone(),
        "keyConfidence": "candidate",
        "confidence": "low",
        "confidenceCeiling": "low",
        "correlationEligible": false,
        "evidence": evidence.clone(),
        "reason": "Synthetic alias of already keyed evidence."
    })
}

#[test]
fn padded_evidence_references_cannot_alias_keyed_records() {
    let scenario = "unrelated-runs";
    let scenario_root = task_sequence_root().join(scenario);
    let manifest = read_json(&scenario_root.join("manifest.json"));
    let source = read_json(&scenario_root.join("expected.json"));
    let run_a_evidence = source["transactions"][0]["evidence"][0].clone();

    let mut expected = source.clone();
    expected["sourceLocalObservations"] = serde_json::json!([aliasing_observation(
        "unrelated-runs-alias-a",
        &run_a_evidence
    )]);
    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("control: an unpadded alias of keyed evidence is rejected");
    assert!(error.contains("source-local"), "{error}");

    let mut padded_evidence = run_a_evidence.clone();
    padded_evidence["reviewerNote"] = Value::String("evidence_text ignores this key".to_owned());
    let mut expected = source;
    expected["sourceLocalObservations"] = serde_json::json!([aliasing_observation(
        "unrelated-runs-alias-a",
        &padded_evidence
    )]);
    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("a padded alias resolves to the same record and must also be rejected");
    assert!(error.contains("unmodeled"), "{error}");
}

#[test]
fn padded_observations_cannot_launder_cross_run_findings() {
    let scenario = "unrelated-runs";
    let scenario_root = task_sequence_root().join(scenario);
    let manifest = read_json(&scenario_root.join("manifest.json"));
    let mut expected = read_json(&scenario_root.join("expected.json"));
    let mut padded_a = expected["transactions"][0]["evidence"][0].clone();
    let mut padded_b = expected["transactions"][1]["evidence"][0].clone();
    padded_a["reviewerNote"] = Value::String("padding".to_owned());
    padded_b["reviewerNote"] = Value::String("padding".to_owned());
    expected["sourceLocalObservations"] = serde_json::json!([
        aliasing_observation("unrelated-runs-alias-a", &padded_a),
        aliasing_observation("unrelated-runs-alias-b", &padded_b)
    ]);
    // The finding cites the padded aliases, so every reference resolves to a
    // keyed physical record while matching only the laundering observations.
    expected["findings"][0]["evidence"] = serde_json::json!([padded_a, padded_b]);

    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("padded observations cannot launder a finding across two exact runs");
    assert!(error.contains("unmodeled"), "{error}");
}

#[test]
fn undelimitable_record_bodies_fail_closed() {
    let scenario = "completed";
    let key_fields = concat!(
        "executionId=72400000-0000-0000-0000-000000000005 ",
        "taskSequencePackageId=LAB00324 advertisementId=LAB20305 runContext=osd"
    );

    for (mutation, leading_space, relocate_key_fields, must_fail_at_head) in [
        ("leading-space", true, false, false),
        ("relocated-key-fields-indented", true, true, false),
        ("relocated-key-fields-flush", false, true, true),
    ] {
        let temporary = copy_scenario_to_temporary_root(scenario, mutation);
        let mut manifest = read_json(&temporary.root.join("manifest.json"));
        let mut expected = read_json(&temporary.root.join("expected.json"));
        let relative_path = manifest["artifacts"][0]["relativePath"]
            .as_str()
            .expect("completed artifact has a relative path");
        let evidence_path = temporary.root.join(relative_path);
        let original =
            std::fs::read_to_string(&evidence_path).expect("completed evidence is readable");

        let mut mutated = original.clone();
        if relocate_key_fields {
            mutated = mutated.replace(&format!("{key_fields} "), "");
            mutated = mutated.replace("context=\"\"", &format!("context=\"{key_fields}\""));
            assert!(
                mutated.contains(&format!("context=\"{key_fields}\"")),
                "{mutation}: the key fields moved into the record trailer"
            );
        }
        if leading_space {
            mutated = format!(" {mutated}");
        }
        assert_ne!(mutated, original, "{mutation}: the mutation is effective");
        std::fs::write(&evidence_path, &mutated).expect("mutated evidence is writable");
        manifest["artifacts"][0]["bytesCopied"] = Value::from(mutated.len() as u64);
        expected["artifactProvenance"][0]["bytesCopied"] = Value::from(mutated.len() as u64);

        let result = validate_contract(scenario, &temporary.root, &manifest, &expected);
        if must_fail_at_head {
            result.expect_err("control: a flush record never exposes its trailer to key admission");
        } else {
            let error = result.expect_err(
                "a record body that cannot be delimited by the CCM framing must fail closed",
            );
            assert!(error.contains("framing"), "{mutation}: {error}");
        }
    }
}

#[test]
fn rotated_fragment_capture_path_names_the_rotated_file() {
    let scenario_root = task_sequence_root().join("rotation-boundary");
    let manifest = read_json(&scenario_root.join("manifest.json"));
    let expected = read_json(&scenario_root.join("expected.json"));
    let lo_id = "task-sequence-rotation-boundary-lo";
    let lo = manifest["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array")
        .iter()
        .find(|artifact| artifact["artifactId"] == lo_id)
        .expect("rotation corpus has smsts.lo_");

    assert_eq!(
        lo["sanitizedSourcePath"], "SYNTHETIC://client/CCM/Logs/smsts.lo_",
        "the rotated artifact's capture provenance must name the rotated physical file"
    );
    assert_eq!(
        lo["smstsLogPathEvidence"], "SYNTHETIC://client/CCM/Logs/smsts.log",
        "the in-record observation stays the active log path it physically records"
    );
    let lo_provenance = expected["artifactProvenance"]
        .as_array()
        .expect("rotation provenance is an array")
        .iter()
        .find(|item| item["artifactId"] == lo_id)
        .expect("rotation provenance contains smsts.lo_");
    assert_eq!(
        lo_provenance["sanitizedSourcePath"], lo["sanitizedSourcePath"],
        "expected output mirrors the corrected capture provenance"
    );
}

#[test]
fn capture_source_path_basename_is_bound_to_rotation() {
    let rotation_root = task_sequence_root().join("rotation-boundary");
    let rotation_manifest = read_json(&rotation_root.join("manifest.json"));
    let mut manifest = rotation_manifest.clone();
    let mut expected = read_json(&rotation_root.join("expected.json"));
    let lo_id = "task-sequence-rotation-boundary-lo";
    let active_log_path = Value::String("SYNTHETIC://client/CCM/Logs/smsts.log".to_owned());
    let lo_index = manifest["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array")
        .iter()
        .position(|artifact| artifact["artifactId"] == lo_id)
        .expect("rotation corpus has smsts.lo_");
    manifest["artifacts"][lo_index]["sanitizedSourcePath"] = active_log_path.clone();
    let lo_provenance_index = expected["artifactProvenance"]
        .as_array()
        .expect("rotation provenance is an array")
        .iter()
        .position(|item| item["artifactId"] == lo_id)
        .expect("rotation provenance contains smsts.lo_");
    expected["artifactProvenance"][lo_provenance_index]["sanitizedSourcePath"] = active_log_path;

    let error = validate_contract("rotation-boundary", &rotation_root, &manifest, &expected)
        .expect_err("a rotated artifact cannot claim the active log as its capture source");
    assert!(error.contains("capture source path"), "{error}");

    let completed_root = task_sequence_root().join("completed");
    let mut manifest = read_json(&completed_root.join("manifest.json"));
    let mut expected = read_json(&completed_root.join("expected.json"));
    let rotated_path = Value::String("SYNTHETIC://client/CCM/Logs/smsts.lo_".to_owned());
    manifest["artifacts"][0]["sanitizedSourcePath"] = rotated_path.clone();
    expected["artifactProvenance"][0]["sanitizedSourcePath"] = rotated_path;

    let error = validate_contract("completed", &completed_root, &manifest, &expected)
        .expect_err("a current artifact cannot claim a rotated capture source");
    assert!(error.contains("capture source path"), "{error}");
}

#[test]
fn keyed_evidence_cannot_be_laundered_through_source_local_observations() {
    let scenario = "unrelated-runs";
    let scenario_root = task_sequence_root().join(scenario);
    let manifest = read_json(&scenario_root.join("manifest.json"));
    let mut expected = read_json(&scenario_root.join("expected.json"));
    let run_a_evidence = expected["transactions"][0]["evidence"][0].clone();
    let run_b_evidence = expected["transactions"][1]["evidence"][0].clone();
    expected["sourceLocalObservations"] = serde_json::json!([
        {
            "observationId": "unrelated-runs-alias-a",
            "artifactId": run_a_evidence["artifactId"].clone(),
            "keyConfidence": "candidate",
            "confidence": "low",
            "confidenceCeiling": "low",
            "correlationEligible": false,
            "evidence": run_a_evidence.clone(),
            "reason": "Synthetic alias of already keyed run A evidence."
        },
        {
            "observationId": "unrelated-runs-alias-b",
            "artifactId": run_b_evidence["artifactId"].clone(),
            "keyConfidence": "candidate",
            "confidence": "low",
            "confidenceCeiling": "low",
            "correlationEligible": false,
            "evidence": run_b_evidence.clone(),
            "reason": "Synthetic alias of already keyed run B evidence."
        }
    ]);
    expected["findings"][0]["evidence"]
        .as_array_mut()
        .expect("run A finding evidence is an array")
        .push(run_b_evidence);

    let error = validate_contract(scenario, &scenario_root, &manifest, &expected)
        .expect_err("keyed transaction evidence cannot be laundered into source-local citations");
    assert!(error.contains("source-local"), "{error}");
}

#[test]
fn phase_state_and_terminal_bind_to_body_tokens_only() {
    // The completed scenario declares the strongest claim in the corpus:
    // success, high confidence, phase complete, state succeeded, terminal.
    let scenario = "completed";
    let mut accepted = Vec::new();

    for (mutation, body_removal, trailer_claim, body_rewrite) in [
        (
            "phase-and-state-relocated-to-trailer",
            Some("phase=complete state=succeeded "),
            Some("phase=complete state=succeeded"),
            None,
        ),
        (
            "terminal-relocated-to-trailer",
            Some("terminal=true "),
            Some("terminal=true"),
            None,
        ),
        (
            "phase-token-suffixed",
            None,
            None,
            Some(("phase=complete", "phase=completeX")),
        ),
        (
            "state-token-suffixed",
            None,
            None,
            Some(("state=succeeded", "state=succeededX")),
        ),
        (
            "terminal-token-suffixed",
            None,
            None,
            Some(("terminal=true", "terminal=trueX")),
        ),
        (
            "terminal-state-token-extended",
            None,
            None,
            Some(("state=succeeded", "state=succeededLater")),
        ),
    ] {
        let temporary = copy_scenario_to_temporary_root(scenario, mutation);
        let mut manifest = read_json(&temporary.root.join("manifest.json"));
        let mut expected = read_json(&temporary.root.join("expected.json"));
        let relative_path = manifest["artifacts"][0]["relativePath"]
            .as_str()
            .expect("completed artifact has a relative path");
        let evidence_path = temporary.root.join(relative_path);
        let original =
            std::fs::read_to_string(&evidence_path).expect("completed evidence is readable");

        let mut mutated = original.clone();
        if let Some(body_removal) = body_removal {
            mutated = mutated.replace(body_removal, "");
        }
        if let Some(trailer_claim) = trailer_claim {
            mutated = mutated.replace("context=\"\"", &format!("context=\"{trailer_claim}\""));
            assert!(
                mutated.contains(&format!("context=\"{trailer_claim}\"")),
                "{mutation}: the claim moved into the record trailer"
            );
        }
        if let Some((from, to)) = body_rewrite {
            mutated = mutated.replace(from, to);
        }
        assert_ne!(mutated, original, "{mutation}: the mutation is effective");
        std::fs::write(&evidence_path, &mutated).expect("mutated evidence is writable");
        manifest["artifacts"][0]["bytesCopied"] = Value::from(mutated.len() as u64);
        expected["artifactProvenance"][0]["bytesCopied"] = Value::from(mutated.len() as u64);

        if validate_contract(scenario, &temporary.root, &manifest, &expected).is_ok() {
            accepted.push(mutation);
        }
    }

    assert!(
        accepted.is_empty(),
        "validate_contract accepted {} trailer or partial-token outcome claims: {}",
        accepted.len(),
        accepted.join(", ")
    );
}
