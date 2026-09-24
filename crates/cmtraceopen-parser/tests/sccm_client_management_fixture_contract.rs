use chrono::{DateTime, SecondsFormat, Utc};
use cmtraceopen_parser::sccm::{
    normalize_ccm_artifact, SccmArtifact, SccmCoverageState, SccmRole, SccmRotation,
    SccmTimeOrderingState,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const SCENARIOS: [&str; 14] = [
    "co-management-intune-owned",
    "co-management-sccm-owned",
    "co-management-transitioning",
    "co-management-unknown",
    "mixed-unrelated",
    "notification-deferred",
    "notification-failure",
    "notification-received",
    "script-failure",
    "script-incomplete",
    "script-intune-handoff",
    "script-success",
    "software-center-insufficient",
    "software-center-observed",
];

const DOCUMENTED_CORPUS_DIGEST: &str = "409619f730304018";

const PROHIBITED_CLAIMS: [&str; 4] = [
    "time alone proves causality",
    "Intune handoff is an Intune failure",
    "unsupported Software Center source is parsed",
    "missing coverage proves success or failure",
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

#[derive(Debug)]
struct EvidenceRecord {
    fields: BTreeMap<String, String>,
    timestamp: Option<i64>,
    ordering_state: SccmTimeOrderingState,
    source_version: String,
}

static TEMP_SCENARIO_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TemporaryScenario {
    root: PathBuf,
}

impl Drop for TemporaryScenario {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn management_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/client/management")
}

fn load_json(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} contains valid JSON: {error}", path.display()))
}

fn load_contract(scenario: &str) -> (PathBuf, Value, Value) {
    let scenario_root = management_root().join(scenario);
    (
        scenario_root.clone(),
        load_json(&scenario_root.join("manifest.json")),
        load_json(&scenario_root.join("expected.json")),
    )
}

fn scenario_names() -> Vec<String> {
    let mut names = std::fs::read_dir(management_root())
        .expect("management fixture root exists")
        .map(|entry| entry.expect("management fixture entry is readable").path())
        .filter(|path| path.is_dir())
        .map(|path| {
            path.file_name()
                .expect("scenario directory has a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// Manifests reference evidence with forward slashes on every platform, so
/// filesystem-derived relative paths must be normalized before comparison.
fn normalize_manifest_relative_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            let mut children = std::fs::read_dir(&path)
                .map_err(|error| format!("{} is readable: {error}", path.display()))?
                .map(|entry| {
                    entry
                        .map(|entry| entry.path())
                        .map_err(|error| error.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            children.sort();
            pending.extend(children.into_iter().rev());
        } else {
            files.push(path);
        }
    }
    Ok(files)
}

fn copy_scenario_to_temporary_root(scenario: &str, mutation: &str) -> TemporaryScenario {
    let counter = TEMP_SCENARIO_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "cmtraceopen-sccm-326-{}-{mutation}-{counter}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("temporary scenario root is created");
    let source_root = management_root().join(scenario);
    let mut pending = vec![source_root.clone()];
    while let Some(source) = pending.pop() {
        let relative = source
            .strip_prefix(&source_root)
            .expect("source remains below scenario root");
        let destination = root.join(relative);
        if source.is_dir() {
            std::fs::create_dir_all(&destination).expect("temporary scenario directory is created");
            let mut children = std::fs::read_dir(&source)
                .expect("source scenario is readable")
                .map(|entry| entry.expect("source entry is readable").path())
                .collect::<Vec<_>>();
            children.sort();
            pending.extend(children.into_iter().rev());
        } else {
            std::fs::copy(&source, &destination).expect("scenario file is copied");
        }
    }
    TemporaryScenario { root }
}

fn required_string<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{context} {field} is not a string"))
}

fn require_exact_object_fields(
    value: &Value,
    expected_fields: &[&str],
    context: &str,
) -> Result<(), String> {
    let actual_fields = value
        .as_object()
        .ok_or_else(|| format!("{context} is not an object"))?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_fields = expected_fields.iter().copied().collect::<BTreeSet<_>>();
    if actual_fields != expected_fields {
        return Err(format!(
            "{context} fields are not closed: {actual_fields:?} != {expected_fields:?}"
        ));
    }
    Ok(())
}

fn captured_utc_millis(artifact: &Value, context: &str) -> Result<i64, String> {
    let raw = required_string(artifact, "capturedUtc", context)?;
    let parsed = DateTime::parse_from_rfc3339(raw)
        .map_err(|error| format!("{context} capturedUtc is invalid: {error}"))?
        .with_timezone(&Utc);
    if parsed.to_rfc3339_opts(SecondsFormat::Secs, true) != raw {
        return Err(format!("{context} capturedUtc is not canonical UTC"));
    }
    Ok(parsed.timestamp_millis())
}

fn expected_profile(workflow: &str) -> Result<&'static str, String> {
    match workflow {
        "coManagement" => Ok("sccm-client-co-management-5.00.test-v1"),
        "scripts" => Ok("sccm-client-scripts-5.00.test-v1"),
        "notification" => Ok("sccm-client-notification-5.00.test-v1"),
        "softwareCenter" => Ok("sccm-client-software-center-candidate-v1"),
        "mixed" => Ok("sccm-client-management-mixed-test-v1"),
        other => Err(format!("unsupported workflow {other}")),
    }
}

fn workflow_logical_artifacts(workflow: &str) -> Result<&'static [&'static str], String> {
    match workflow {
        "coManagement" => Ok(&["client-co-management"]),
        "scripts" => Ok(&["client-co-management", "client-scripts"]),
        "notification" => Ok(&["client-co-management", "client-notification"]),
        "softwareCenter" => Ok(&["client-co-management", "client-software-center"]),
        "mixed" => Ok(&[
            "client-co-management",
            "client-notification",
            "client-scripts",
        ]),
        other => Err(format!("unsupported workflow {other}")),
    }
}

fn expected_workload(workflow: &str) -> Result<&'static str, String> {
    match workflow {
        "coManagement" | "scripts" | "mixed" => Ok("Scripts"),
        "notification" => Ok("ClientNotification"),
        "softwareCenter" => Ok("SoftwareCenter"),
        other => Err(format!("unsupported workflow {other}")),
    }
}

fn expected_transaction_count(scenario: &str) -> usize {
    match scenario {
        "notification-deferred"
        | "notification-failure"
        | "notification-received"
        | "script-failure"
        | "script-success" => 1,
        _ => 0,
    }
}

fn source_contract(
    logical_artifact: &str,
    source_name: &str,
) -> Result<(&'static str, bool), String> {
    match (logical_artifact, source_name) {
        ("client-co-management", "CoManagementHandler.log")
        | ("client-scripts", "Scripts.log")
        | ("client-scripts", "Scripts.lo_")
        | ("client-notification", "CcmNotificationAgent.log") => Ok(("admitted", true)),
        ("client-software-center", "SCClient_SYNTHETIC_1.log")
        | ("client-software-center", "SCClient_SYNTHETIC_2.log")
        | ("client-software-center", "SCNotify_SYNTHETIC_1.log") => {
            Ok(("candidateUnsupported", false))
        }
        _ => Err(format!(
            "{logical_artifact} does not admit exact source {source_name}"
        )),
    }
}

fn validate_relative_path(
    relative_path: &str,
    logical_artifact: &str,
    source_name: &str,
    rotation_kind: &str,
) -> Result<(), String> {
    let path = Path::new(relative_path);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe relative evidence path {relative_path}"));
    }
    let components = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if components.first().map(String::as_str) != Some("evidence")
        || components.get(1).map(String::as_str) != Some(logical_artifact)
        || components.last().map(String::as_str) != Some(source_name)
        || !components
            .iter()
            .any(|component| component == rotation_kind)
    {
        return Err(format!(
            "evidence path {relative_path} does not bind source/rotation provenance"
        ));
    }
    Ok(())
}

fn validate_source_path(
    scenario: &str,
    logical_artifact: &str,
    source_name: &str,
    sanitized_source_path: &str,
) -> Result<(), String> {
    let required_prefix = format!("SYNTHETIC://client/management/{scenario}/{logical_artifact}/");
    let suffix = sanitized_source_path
        .strip_prefix(&required_prefix)
        .unwrap_or_default();
    let lower_suffix = suffix.to_ascii_lowercase();
    let components = suffix.split('/').collect::<Vec<_>>();
    let shape_is_exact = match components.as_slice() {
        [basename] => *basename == source_name,
        [segment, basename] if *basename == source_name => matches!(
            (scenario, logical_artifact, *segment),
            (
                "mixed-unrelated",
                "client-notification",
                "access" | "current"
            ) | ("mixed-unrelated", "client-scripts", "root-a" | "root-b")
        ),
        _ => false,
    };
    if !sanitized_source_path.starts_with(&required_prefix)
        || !sanitized_source_path.ends_with(source_name)
        || sanitized_source_path.contains(['\\', '\n', '\r'])
        || !shape_is_exact
        || suffix.split('/').any(|component| {
            component.is_empty()
                || matches!(component, "." | "..")
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
        || lower_suffix.contains("%2e")
        || suffix.contains(['?', '#'])
    {
        return Err(format!(
            "source path {sanitized_source_path} is not bounded synthetic provenance"
        ));
    }
    Ok(())
}

fn path_fingerprint_is_safe(value: &str) -> bool {
    value.strip_prefix("safe:path:326:").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix.split('-').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
    })
}

fn source_version_matches_selected_profile(value: &str) -> bool {
    value
        .strip_prefix("5.00.TEST.")
        .is_some_and(|suffix| suffix.len() == 4 && suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Whitespace tokens with their edge punctuation trimmed. Free-text identity
/// rules run per token so that ordinary sentence punctuation cannot extend a
/// token and hide the shape being screened for.
fn public_free_text_tokens(value: &str) -> impl Iterator<Item = &str> {
    value.split_ascii_whitespace().map(|token| {
        token.trim_matches(|character: char| {
            matches!(
                character,
                '.' | ',' | ';' | ':' | '!' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\''
            )
        })
    })
}

/// True when a single token carries `s-1-` followed by at least two numeric
/// subauthority segments. Applied per token on free-text surfaces and to the
/// whole value on the identifier surface, which is one token by construction.
fn contains_sid_shaped_run(value: &str) -> bool {
    value.match_indices("s-1-").any(|(index, _)| {
        let mut numeric_segments = 0usize;
        for segment in value[index + 4..].split('-') {
            if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()) {
                break;
            }
            numeric_segments += 1;
        }
        numeric_segments >= 2
    })
}

fn public_identifier_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.as_bytes()[0].is_ascii_lowercase()
        && !value.starts_with("s-1-5-")
        && !contains_sid_shaped_run(value)
        && value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn public_free_text_is_safe(value: &str) -> bool {
    if value.trim() != value
        || value.is_empty()
        || value.len() > 240
        || value.chars().any(char::is_control)
    {
        return false;
    }

    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b' ' | b'.' | b',' | b';' | b'\'' | b'-' | b'(' | b')')
    }) {
        return false;
    }

    let lower = value.to_ascii_lowercase();
    if lower.contains("s-1-5-") || public_free_text_tokens(&lower).any(contains_sid_shaped_run) {
        return false;
    }

    !public_free_text_tokens(value).any(|token| {
        let labels = token.split('.').collect::<Vec<_>>();
        if labels.iter().any(|label| label.is_empty()) {
            return false;
        }
        // Two or more dots with non-empty labels is network-identifier shaped
        // (dotted quads, multi-label hostnames) regardless of label charset.
        if labels.len() >= 3 {
            return true;
        }
        labels.len() == 2
            && labels[1].len() >= 2
            && labels[1].bytes().all(|byte| byte.is_ascii_alphabetic())
    })
}

fn evidence_refs_cite_unique_records(references: &[(String, u64, u64)]) -> bool {
    let mut cited_records = BTreeSet::new();
    references
        .iter()
        .all(|(artifact_id, start_line, end_line)| {
            (*start_line..=*end_line).all(|line| cited_records.insert((artifact_id.clone(), line)))
        })
}

fn string_array(value: &Value, context: &str) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{context} is not an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{context} item is not a string"))
        })
        .collect()
}

fn effective_state(artifact: &Value) -> Result<&'static str, String> {
    let capture_state = required_string(artifact, "captureState", "artifact")?;
    match capture_state {
        "captured"
            if artifact["catalogState"] == "candidateUnsupported"
                && artifact["parserEligible"] == false =>
        {
            Ok("unsupported")
        }
        "captured" if artifact["rotation"]["fragmentComplete"] == true => Ok("captured"),
        "captured" => Ok("partial"),
        "capped" => Ok("capped"),
        "parseFailed" => Ok("malformed"),
        "absent" => Ok("absent"),
        "accessDenied" => Ok("accessDenied"),
        "unsupported" => Ok("unsupported"),
        other => Err(format!("unsupported capture state {other}")),
    }
}

fn physical_capture(artifact: &Value) -> Result<bool, String> {
    Ok(matches!(
        required_string(artifact, "captureState", "artifact")?,
        "captured" | "capped" | "parseFailed"
    ))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn fnv1a64(bytes: &[u8]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn corpus_inventory() -> CorpusInventory {
    let mut artifacts = 0;
    let mut evidence_files = 0;
    let mut evidence_bytes = 0;
    let mut capture_states = BTreeMap::new();
    let mut digest_rows = Vec::new();

    for scenario in SCENARIOS {
        let (scenario_root, manifest, _) = load_contract(scenario);
        for artifact in manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
        {
            artifacts += 1;
            let capture_state = artifact["captureState"]
                .as_str()
                .expect("captureState is a string");
            *capture_states.entry(capture_state.to_owned()).or_insert(0) += 1;
            let Some(relative_path) = artifact["relativePath"].as_str() else {
                continue;
            };
            let bytes = std::fs::read(scenario_root.join(relative_path))
                .expect("evidence bytes are readable");
            evidence_files += 1;
            evidence_bytes += bytes.len() as u64;
            digest_rows.push(format!(
                "{scenario}\0{}\0{relative_path}\0{}\n",
                artifact["artifactId"]
                    .as_str()
                    .expect("artifactId is a string"),
                hex_bytes(&bytes)
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
        digest: fnv1a64(digest_rows.concat().as_bytes()),
    }
}

fn evidence_records(
    scenario_root: &Path,
    artifacts: &BTreeMap<String, &Value>,
    refs: &Value,
) -> Result<Vec<EvidenceRecord>, String> {
    let refs = refs
        .as_array()
        .ok_or_else(|| "evidence refs are not an array".to_owned())?;
    let mut records = Vec::new();
    for evidence_ref in refs {
        require_exact_object_fields(
            evidence_ref,
            &["artifactId", "endLine", "startLine"],
            "evidence ref",
        )?;
        let artifact_id = required_string(evidence_ref, "artifactId", "evidence ref")?;
        let artifact = artifacts
            .get(artifact_id)
            .ok_or_else(|| format!("evidence ref uses unknown artifact {artifact_id}"))?;
        if !physical_capture(artifact)?
            || artifact["parserEligible"] != true
            || effective_state(artifact)? != "captured"
        {
            return Err(format!(
                "evidence ref {artifact_id} does not cite a complete parser-eligible artifact"
            ));
        }
        let relative_path = required_string(artifact, "relativePath", artifact_id)?;
        let contents = std::fs::read_to_string(scenario_root.join(relative_path))
            .map_err(|error| format!("{artifact_id} evidence is readable: {error}"))?;
        let lines = contents.lines().collect::<Vec<_>>();
        let start = evidence_ref["startLine"]
            .as_u64()
            .ok_or_else(|| format!("{artifact_id} startLine is not an integer"))?
            as usize;
        let end = evidence_ref["endLine"]
            .as_u64()
            .ok_or_else(|| format!("{artifact_id} endLine is not an integer"))?
            as usize;
        if start == 0 || end < start || end > lines.len() {
            return Err(format!(
                "{artifact_id} evidence line range {start}..={end} is invalid"
            ));
        }
        for line in &lines[start - 1..end] {
            records.push(normalized_record(artifact, line)?);
        }
    }
    Ok(records)
}

fn all_artifact_records(
    scenario_root: &Path,
    artifact: &Value,
) -> Result<Vec<EvidenceRecord>, String> {
    if !physical_capture(artifact)?
        || artifact["parserEligible"] != true
        || effective_state(artifact)? != "captured"
    {
        return Ok(Vec::new());
    }
    let artifact_id = required_string(artifact, "artifactId", "artifact")?;
    let relative_path = required_string(artifact, "relativePath", artifact_id)?;
    let contents = std::fs::read_to_string(scenario_root.join(relative_path))
        .map_err(|error| format!("{artifact_id} evidence is readable: {error}"))?;
    let mut records = Vec::new();
    for line in contents.lines() {
        records.push(normalized_record(artifact, line)?);
    }
    Ok(records)
}

fn normalized_record(artifact: &Value, line: &str) -> Result<EvidenceRecord, String> {
    let artifact_id = required_string(artifact, "artifactId", "artifact")?;
    if !line.starts_with("<![LOG[")
        || line.matches("<![LOG[").count() != 1
        || line.matches("]LOG]!>").count() != 1
        || !line.contains("]LOG]!><time=\"")
    {
        return Err(format!(
            "{artifact_id} line is not one unnested complete CCM record"
        ));
    }

    let source_name = required_string(artifact, "sourceName", artifact_id)?;
    let source_version = required_string(artifact, "sourceVersion", artifact_id)?;
    let model = SccmArtifact {
        artifact_id: artifact_id.to_owned(),
        display_name: source_name.to_owned(),
        original_path: None,
        host: None,
        role: SccmRole::Client,
        configmgr_version: Some(source_version.to_owned()),
        collected_at_utc: Some(required_string(artifact, "capturedUtc", artifact_id)?.to_owned()),
        rotation: match required_string(&artifact["rotation"], "kind", artifact_id)? {
            "current" => SccmRotation::Current,
            "lo" => SccmRotation::LoUnderscore,
            other => return Err(format!("{artifact_id} has unsupported rotation {other}")),
        },
        coverage: match required_string(artifact, "captureState", artifact_id)? {
            "captured" => SccmCoverageState::Captured,
            "absent" => SccmCoverageState::Absent,
            "accessDenied" => SccmCoverageState::AccessDenied,
            "capped" => SccmCoverageState::Capped,
            "parseFailed" => SccmCoverageState::ParseFailed,
            "unsupported" => SccmCoverageState::Unsupported,
            other => return Err(format!("{artifact_id} has unsupported coverage {other}")),
        },
        encoding: artifact["encoding"].as_str().map(str::to_owned),
    };
    let evidence = normalize_ccm_artifact(model, line);
    if evidence.len() != 1
        || evidence[0].reference.line_start != Some(1)
        || evidence[0].reference.line_end != Some(1)
    {
        return Err(format!(
            "{artifact_id} line does not normalize to one logical CCM record"
        ));
    }
    let evidence = &evidence[0];
    let message = evidence
        .message
        .strip_prefix("[sccm-public-message-v1] ")
        .ok_or_else(|| format!("{artifact_id} lacks the versioned public message projection"))?
        .to_owned();
    let fields = record_fields(&message, artifact_id)?;
    validate_record_field_contract(
        required_string(artifact, "logicalArtifactId", artifact_id)?,
        &fields,
        artifact_id,
    )?;
    let captured = captured_utc_millis(artifact, artifact_id)?;
    if evidence
        .timestamp
        .utc_millis
        .is_some_and(|timestamp| timestamp > captured)
    {
        return Err(format!("{artifact_id} record postdates capturedUtc"));
    }

    Ok(EvidenceRecord {
        fields,
        timestamp: evidence.timestamp.utc_millis,
        ordering_state: evidence.timestamp.ordering_state.clone(),
        source_version: source_version.to_owned(),
    })
}

fn record_fields(message: &str, context: &str) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();
    for token in message.split_ascii_whitespace() {
        let Some((field, value)) = token.split_once('=') else {
            continue;
        };
        if field.is_empty()
            || value.is_empty()
            || !field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(format!(
                "{context} contains malformed structured token {token}"
            ));
        }
        if fields.insert(field.to_owned(), value.to_owned()).is_some() {
            return Err(format!(
                "{context} contains duplicate structured field {field}"
            ));
        }
    }
    Ok(fields)
}

fn validate_record_field_contract(
    logical_artifact: &str,
    fields: &BTreeMap<String, String>,
    context: &str,
) -> Result<(), String> {
    let actual = fields.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let exact = |required: &[&str], optional: &[&str]| {
        let required = required.iter().copied().collect::<BTreeSet<_>>();
        let mut allowed = required.clone();
        allowed.extend(optional.iter().copied());
        actual.is_superset(&required) && actual.is_subset(&allowed)
    };

    let valid = match logical_artifact {
        "client-co-management" => exact(
            &[
                "Disposition",
                "Ownership",
                "OwnershipEpochId",
                "Terminal",
                "Workload",
            ],
            &[],
        ),
        "client-notification" => exact(
            &[
                "ChannelId",
                "Disposition",
                "NotificationId",
                "Phase",
                "ResourceHandle",
                "Terminal",
            ],
            &["Signal"],
        ),
        "client-scripts" if fields.contains_key("ScriptId") => exact(
            &[
                "CommandContextHandle",
                "Disposition",
                "ExecutionId",
                "Phase",
                "ResourceHandle",
                "ScriptId",
                "Terminal",
            ],
            &["Signal"],
        ),
        "client-scripts" => {
            let allowed = BTreeSet::from([
                "Disposition",
                "SameMinute",
                "Signal",
                "Terminal",
                "UnkeyedCandidate",
                "UnrelatedServiceError",
            ]);
            !actual.is_empty()
                && actual.is_subset(&allowed)
                && (actual.contains("UnkeyedCandidate") || actual.contains("UnrelatedServiceError"))
        }
        other => return Err(format!("{context} has unsupported record family {other}")),
    };
    if !valid {
        return Err(format!(
            "{context} structured fields are outside the closed {logical_artifact} contract: {actual:?}"
        ));
    }
    Ok(())
}

fn key_fields(workflow: &str) -> Result<&'static [&'static str], String> {
    match workflow {
        "scripts" => Ok(&["ScriptId", "ExecutionId", "ResourceHandle"]),
        "notification" => Ok(&["NotificationId", "ChannelId", "ResourceHandle"]),
        other => Err(format!(
            "{other} does not have operational transaction keys"
        )),
    }
}

fn allowed_phases(workflow: &str) -> Result<&'static [&'static str], String> {
    match workflow {
        "scripts" => Ok(&["Receive", "Execute", "Report"]),
        "notification" => Ok(&["Receive", "DeferOrDispatch", "Acknowledge"]),
        other => Err(format!("{other} does not have operational phases")),
    }
}

fn phase_rank(workflow: &str, record: &EvidenceRecord) -> Result<usize, String> {
    let phase = record
        .fields
        .get("Phase")
        .ok_or_else(|| "cited operational record does not have one exact phase".to_owned())?;
    allowed_phases(workflow)?
        .iter()
        .position(|candidate| *candidate == phase)
        .ok_or_else(|| format!("cited operational record has unknown phase {phase}"))
}

fn validate_temporal_progression(
    workflow: &str,
    transaction_id: &str,
    asserted_phase: &str,
    records: &[EvidenceRecord],
    latest_ownership_timestamp: i64,
) -> Result<(), String> {
    let asserted_rank = allowed_phases(workflow)?
        .iter()
        .position(|phase| *phase == asserted_phase)
        .ok_or_else(|| format!("{transaction_id} has unknown asserted phase {asserted_phase}"))?;
    let mut phase_bounds = BTreeMap::<usize, (i64, i64)>::new();
    for record in records {
        let timestamp = record
            .timestamp
            .ok_or_else(|| format!("{transaction_id} cites a record without a usable timestamp"))?;
        let rank =
            phase_rank(workflow, record).map_err(|error| format!("{transaction_id}: {error}"))?;
        phase_bounds
            .entry(rank)
            .and_modify(|(minimum, maximum)| {
                *minimum = (*minimum).min(timestamp);
                *maximum = (*maximum).max(timestamp);
            })
            .or_insert((timestamp, timestamp));
    }

    let required_ranks = match (workflow, asserted_phase) {
        ("notification", "Acknowledge") => vec![0, 2],
        _ => (0..=asserted_rank).collect::<Vec<_>>(),
    };
    if phase_bounds.keys().copied().ne(required_ranks) {
        return Err(format!(
            "{transaction_id} cited phases do not contain the required workflow progression"
        ));
    }

    let earliest_operational = phase_bounds
        .values()
        .map(|(minimum, _)| *minimum)
        .min()
        .expect("nonempty transaction evidence was checked");
    if latest_ownership_timestamp >= earliest_operational {
        return Err(format!(
            "{transaction_id} ownership is late or temporally ambiguous"
        ));
    }

    let mut previous_maximum = None;
    for (minimum, maximum) in phase_bounds.values() {
        if previous_maximum.is_some_and(|previous| previous >= *minimum) {
            return Err(format!(
                "{transaction_id} cited phase timestamps are reversed or ambiguous"
            ));
        }
        previous_maximum = Some(*maximum);
    }

    Ok(())
}

fn validate_contract(
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
    expected: &Value,
) -> Result<(), String> {
    require_exact_object_fields(
        manifest,
        &[
            "artifacts",
            "bundle",
            "contractState",
            "proposalOnly",
            "sccmManifestVersion",
            "scenario",
            "syntheticFixture",
            "workflowFamily",
        ],
        "manifest",
    )?;
    require_exact_object_fields(
        &manifest["bundle"],
        &["bundleId", "captureHost", "role", "siteCode"],
        "manifest bundle",
    )?;
    require_exact_object_fields(
        expected,
        &[
            "contractState",
            "coverage",
            "extractionProfile",
            "findings",
            "ownership",
            "prohibitedClaims",
            "scenario",
            "sourceLocalObservations",
            "transactions",
            "workflow",
        ],
        "expected contract",
    )?;
    if manifest["sccmManifestVersion"] != 1
        || manifest["contractState"] != "proposedPending318And319"
        || manifest["proposalOnly"] != true
        || manifest["syntheticFixture"] != true
        || manifest["scenario"] != scenario
    {
        return Err("manifest identity/proposal contract is invalid".to_owned());
    }
    let workflow = required_string(manifest, "workflowFamily", "manifest")?;
    if expected["contractState"] != "proposedPending318And319"
        || expected["scenario"] != scenario
        || expected["workflow"] != workflow
    {
        return Err("expected identity/workflow contract is invalid".to_owned());
    }
    if manifest["bundle"]["bundleId"] != format!("sccm-326-{scenario}")
        || manifest["bundle"]["captureHost"] != "LAB-CLIENT-01"
        || manifest["bundle"]["role"] != "client"
        || manifest["bundle"]["siteCode"] != "LAB"
    {
        return Err("bundle identity/role is not the bounded synthetic client".to_owned());
    }

    let artifacts = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| "manifest artifacts are not an array".to_owned())?;
    if artifacts.is_empty() {
        return Err("scenario has no artifacts".to_owned());
    }
    let mut artifacts_by_id = BTreeMap::new();
    let mut artifact_order = Vec::new();
    let mut referenced_files = BTreeSet::new();
    let mut relative_paths = BTreeSet::new();
    let mut path_fingerprints = BTreeSet::new();
    let mut physical_source_identities = BTreeSet::new();
    let mut expected_coverage = BTreeMap::new();
    let mut unknown_version_artifacts = BTreeSet::new();
    let mut invalid_offset_artifacts = BTreeSet::new();

    for artifact in artifacts {
        let artifact_id = required_string(artifact, "artifactId", "artifact")?;
        require_exact_object_fields(
            artifact,
            &[
                "artifactId",
                "capturedUtc",
                "captureState",
                "catalogState",
                "collectionLimit",
                "encoding",
                "logicalArtifactId",
                "parserEligible",
                "pathFingerprint",
                "relativePath",
                "role",
                "rotation",
                "sanitizedSourcePath",
                "sourceName",
                "sourceVersion",
            ],
            artifact_id,
        )?;
        require_exact_object_fields(
            &artifact["rotation"],
            &["fragmentComplete", "kind"],
            &format!("{artifact_id} rotation"),
        )?;
        require_exact_object_fields(
            &artifact["collectionLimit"],
            &["capped", "limitBytes"],
            &format!("{artifact_id} collectionLimit"),
        )?;
        captured_utc_millis(artifact, artifact_id)?;
        artifact_order.push(artifact_id.to_owned());
        if artifacts_by_id
            .insert(artifact_id.to_owned(), artifact)
            .is_some()
        {
            return Err(format!("duplicate artifactId {artifact_id}"));
        }
        if artifact["role"] != "client" {
            return Err(format!("{artifact_id} does not preserve client role"));
        }
        let logical_artifact = required_string(artifact, "logicalArtifactId", artifact_id)?;
        if !workflow_logical_artifacts(workflow)?.contains(&logical_artifact) {
            return Err(format!(
                "{artifact_id} crosses the {workflow} logical source boundary"
            ));
        }
        let source_name = required_string(artifact, "sourceName", artifact_id)?;
        let (required_catalog_state, required_parser_eligibility) =
            source_contract(logical_artifact, source_name)?;
        if artifact["catalogState"] != required_catalog_state
            || artifact["parserEligible"] != required_parser_eligibility
        {
            return Err(format!(
                "{artifact_id} source capability does not match its exact catalog contract"
            ));
        }
        let rotation_kind = required_string(&artifact["rotation"], "kind", artifact_id)?;
        match rotation_kind {
            "current" if source_name.ends_with(".lo_") => {
                return Err(format!(
                    "{artifact_id} current artifact uses an archive suffix"
                ));
            }
            "lo" if !source_name.ends_with(".lo_") => {
                return Err(format!("{artifact_id} archived artifact lacks .lo_ suffix"));
            }
            "current" | "lo" => {}
            other => {
                return Err(format!(
                    "{artifact_id} uses unsupported rotation kind {other}"
                ));
            }
        }
        expected_coverage.insert(
            artifact_id.to_owned(),
            (
                logical_artifact.to_owned(),
                effective_state(artifact)?.to_owned(),
            ),
        );
        let physical = physical_capture(artifact)?;
        let relative_path = artifact["relativePath"].as_str();
        if physical != relative_path.is_some() {
            return Err(format!(
                "{artifact_id} physical capture does not match relativePath"
            ));
        }
        if let Some(relative_path) = relative_path {
            validate_relative_path(relative_path, logical_artifact, source_name, rotation_kind)?;
            if !relative_paths.insert(relative_path.to_owned()) {
                return Err(format!("duplicate physical evidence path {relative_path}"));
            }
            let sanitized_source_path =
                required_string(artifact, "sanitizedSourcePath", artifact_id)?;
            validate_source_path(
                scenario,
                logical_artifact,
                source_name,
                sanitized_source_path,
            )?;
            if !physical_source_identities.insert(sanitized_source_path.to_ascii_lowercase()) {
                return Err(format!(
                    "{artifact_id} collides with a sanitized physical source identity"
                ));
            }
            let path_fingerprint = required_string(artifact, "pathFingerprint", artifact_id)?;
            if !path_fingerprint_is_safe(path_fingerprint)
                || !path_fingerprints.insert(path_fingerprint.to_ascii_lowercase())
            {
                return Err(format!(
                    "{artifact_id} has blank, unsafe, or colliding path provenance"
                ));
            }
            let source_version = required_string(artifact, "sourceVersion", artifact_id)?;
            if required_parser_eligibility
                && !source_version_matches_selected_profile(source_version)
            {
                unknown_version_artifacts.insert(artifact_id.to_owned());
            }
            let path = scenario_root.join(relative_path);
            let bytes = std::fs::read(&path)
                .map_err(|error| format!("{} is readable: {error}", path.display()))?;
            if std::str::from_utf8(&bytes).is_err() || artifact["encoding"] != "utf-8" {
                return Err(format!("{artifact_id} is not declared and encoded UTF-8"));
            }
            if !String::from_utf8_lossy(&bytes).contains("SYNTHETIC FIXTURE") {
                return Err(format!("{artifact_id} lacks the synthetic marker"));
            }
            referenced_files.insert(relative_path.to_owned());
        } else {
            let capture_state = required_string(artifact, "captureState", artifact_id)?;
            if artifact["encoding"].is_string() {
                return Err(format!(
                    "{artifact_id} nonphysical artifact invents an encoding"
                ));
            }
            match capture_state {
                "absent" => {
                    if !artifact["sanitizedSourcePath"].is_null()
                        || !artifact["pathFingerprint"].is_null()
                        || !artifact["sourceVersion"].is_null()
                    {
                        return Err(format!(
                            "{artifact_id} absent source invents path/version provenance"
                        ));
                    }
                }
                "accessDenied" | "unsupported" => {
                    let source_path =
                        required_string(artifact, "sanitizedSourcePath", artifact_id)?;
                    validate_source_path(scenario, logical_artifact, source_name, source_path)?;
                    if !physical_source_identities.insert(source_path.to_ascii_lowercase()) {
                        return Err(format!(
                            "{artifact_id} collides with a sanitized physical source identity"
                        ));
                    }
                    let path_fingerprint =
                        required_string(artifact, "pathFingerprint", artifact_id)?;
                    if !path_fingerprint_is_safe(path_fingerprint)
                        || !path_fingerprints.insert(path_fingerprint.to_ascii_lowercase())
                    {
                        return Err(format!(
                            "{artifact_id} attempted path fingerprint is unsafe or colliding"
                        ));
                    }
                    if !artifact["sourceVersion"].is_null() {
                        return Err(format!(
                            "{artifact_id} noncapture state invents source version"
                        ));
                    }
                }
                other => {
                    return Err(format!("{artifact_id} state {other} cannot be nonphysical"));
                }
            }
        }

        let records = all_artifact_records(scenario_root, artifact)?;
        if !records.is_empty()
            && records
                .iter()
                .any(|record| record.ordering_state == SccmTimeOrderingState::OffsetInvalid)
        {
            invalid_offset_artifacts.insert(artifact_id.to_owned());
        }
        let capped = artifact["collectionLimit"]["capped"]
            .as_bool()
            .ok_or_else(|| format!("{artifact_id} collectionLimit.capped is not a boolean"))?;
        let fragment_complete = artifact["rotation"]["fragmentComplete"]
            .as_bool()
            .ok_or_else(|| format!("{artifact_id} fragmentComplete is not a boolean"))?;
        if required_string(artifact, "captureState", artifact_id)? == "capped" {
            if !capped
                || fragment_complete
                || artifact["collectionLimit"]["limitBytes"]
                    .as_u64()
                    .is_none_or(|limit| limit == 0)
            {
                return Err(format!(
                    "{artifact_id} capped state lacks explicit cap/partial provenance"
                ));
            }
        } else if capped || !artifact["collectionLimit"]["limitBytes"].is_null() {
            return Err(format!(
                "{artifact_id} noncapped state invents collection-limit provenance"
            ));
        }
    }
    let mut sorted_artifact_order = artifact_order.clone();
    sorted_artifact_order.sort();
    if artifact_order != sorted_artifact_order {
        return Err("manifest artifacts are not deterministically sorted".to_owned());
    }

    let actual_files = walk_files(&scenario_root.join("evidence"))?
        .into_iter()
        .map(|path| {
            let relative_path = path
                .strip_prefix(scenario_root)
                .expect("walk root is below scenario")
                .to_string_lossy();
            normalize_manifest_relative_path(&relative_path)
        })
        .collect::<BTreeSet<_>>();
    if actual_files != referenced_files {
        return Err(format!(
            "manifest evidence projection differs: {actual_files:?} != {referenced_files:?}"
        ));
    }

    let coverage = expected["coverage"]
        .as_array()
        .ok_or_else(|| "expected coverage is not an array".to_owned())?;
    let mut declared_coverage = BTreeMap::new();
    let mut coverage_order = Vec::new();
    for row in coverage {
        let artifact_id = required_string(row, "artifactId", "coverage row")?;
        require_exact_object_fields(
            row,
            &["artifactId", "logicalArtifactId", "state"],
            artifact_id,
        )?;
        coverage_order.push(artifact_id.to_owned());
        if declared_coverage
            .insert(
                artifact_id.to_owned(),
                (
                    required_string(row, "logicalArtifactId", artifact_id)?.to_owned(),
                    required_string(row, "state", artifact_id)?.to_owned(),
                ),
            )
            .is_some()
        {
            return Err(format!("duplicate coverage row {artifact_id}"));
        }
    }
    let mut sorted_coverage_order = coverage_order.clone();
    sorted_coverage_order.sort();
    if coverage_order != sorted_coverage_order {
        return Err("coverage rows are not deterministically sorted".to_owned());
    }
    if declared_coverage != expected_coverage {
        return Err(format!(
            "coverage is not an exact manifest projection: {declared_coverage:?} != {expected_coverage:?}"
        ));
    }

    let required_profile_selection = match workflow {
        "softwareCenter" => "unsupportedCandidate",
        "mixed"
            if !unknown_version_artifacts.is_empty() && !invalid_offset_artifacts.is_empty() =>
        {
            "mixedUnknownAndInvalid"
        }
        _ if !unknown_version_artifacts.is_empty() => "unknownProfile",
        _ => "selected",
    };
    let profile = &expected["extractionProfile"];
    require_exact_object_fields(
        profile,
        &["id", "selectionState", "versionPrefix"],
        "extractionProfile",
    )?;
    if profile["id"] != expected_profile(workflow)?
        || profile["versionPrefix"] != "5.00.TEST."
        || profile["selectionState"] != required_profile_selection
    {
        return Err("extraction profile identity/selection is invalid".to_owned());
    }

    if expected["findings"]
        .as_array()
        .is_none_or(|findings| !findings.is_empty())
    {
        return Err("preparation corpus must not ship production findings".to_owned());
    }
    let prohibited_claims = expected["prohibitedClaims"]
        .as_array()
        .ok_or_else(|| "prohibitedClaims is not an array".to_owned())?;
    if prohibited_claims
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .ne(PROHIBITED_CLAIMS)
    {
        return Err("prohibitedClaims safety boundary is not exact".to_owned());
    }

    let ownership = &expected["ownership"];
    require_exact_object_fields(
        ownership,
        &[
            "classification",
            "confidence",
            "coverageGapArtifactIds",
            "evidence",
            "terminalHandoff",
            "workload",
        ],
        "ownership",
    )?;
    let ownership_class = required_string(ownership, "classification", "ownership")?;
    let ownership_confidence = required_string(ownership, "confidence", "ownership")?;
    if ownership["workload"] != expected_workload(workflow)? {
        return Err(format!(
            "ownership workload does not match the exact {workflow} workflow"
        ));
    }
    if !matches!(
        ownership_class,
        "SccmOwned" | "IntuneOwned" | "SharedOrTransitioning" | "UnknownOwnership"
    ) {
        return Err(format!(
            "unsupported ownership classification {ownership_class}"
        ));
    }
    match ownership_class {
        "SccmOwned" | "IntuneOwned" if ownership_confidence != "high" => {
            return Err("terminal ownership classification is not high confidence".to_owned());
        }
        "SharedOrTransitioning" if ownership_confidence != "medium" => {
            return Err("transitioning ownership is not medium confidence".to_owned());
        }
        "UnknownOwnership" if ownership_confidence != "low" => {
            return Err("unknown ownership is not low confidence".to_owned());
        }
        _ => {}
    }
    let ownership_records =
        evidence_records(scenario_root, &artifacts_by_id, &ownership["evidence"])?;
    let ownership_evidence = ownership["evidence"]
        .as_array()
        .ok_or_else(|| "ownership evidence is not an array".to_owned())?;
    let mut ownership_ref_order = Vec::new();
    for evidence_ref in ownership_evidence {
        let artifact_id = required_string(evidence_ref, "artifactId", "ownership evidence")?;
        ownership_ref_order.push((
            artifact_id.to_owned(),
            evidence_ref["startLine"].as_u64().unwrap_or(0),
            evidence_ref["endLine"].as_u64().unwrap_or(0),
        ));
        let artifact = artifacts_by_id
            .get(artifact_id)
            .ok_or_else(|| format!("ownership cites unknown artifact {artifact_id}"))?;
        if artifact["logicalArtifactId"] != "client-co-management" {
            return Err(format!(
                "ownership borrows non-co-management evidence {artifact_id}"
            ));
        }
    }
    let mut sorted_ownership_refs = ownership_ref_order.clone();
    sorted_ownership_refs.sort();
    if ownership_ref_order != sorted_ownership_refs
        || sorted_ownership_refs
            .windows(2)
            .any(|references| references[0] == references[1])
    {
        return Err("ownership evidence is duplicated or not deterministically sorted".to_owned());
    }
    if !evidence_refs_cite_unique_records(&ownership_ref_order) {
        return Err(
            "ownership evidence ranges overlap and double-count a logical record".to_owned(),
        );
    }
    if ownership_class != "UnknownOwnership" {
        let workload = required_string(ownership, "workload", "ownership")?;
        if ownership_records.is_empty()
            || ownership_records.iter().any(|record| {
                record.fields.get("Workload").map(String::as_str) != Some(workload)
                    || record.fields.get("Ownership").map(String::as_str) != Some(ownership_class)
            })
        {
            return Err("ownership classification is not bound to cited evidence".to_owned());
        }
        if ownership_records.iter().any(|record| {
            record.ordering_state != SccmTimeOrderingState::NormalizedUtc
                || record.timestamp.is_none()
                || !source_version_matches_selected_profile(record.source_version.as_str())
        }) {
            return Err(
                "ownership classification lacks usable timestamp/profile provenance".to_owned(),
            );
        }
        match ownership_class {
            "SccmOwned"
                if ownership_records.iter().any(|record| {
                    record.fields.get("Disposition").map(String::as_str) != Some("Owned")
                        || record.fields.get("Terminal").map(String::as_str) != Some("true")
                }) =>
            {
                return Err("SCCM ownership lacks terminal owned evidence".to_owned());
            }
            "IntuneOwned"
                if ownership_records.iter().any(|record| {
                    record.fields.get("Disposition").map(String::as_str) != Some("Handoff")
                        || record.fields.get("Terminal").map(String::as_str) != Some("true")
                }) =>
            {
                return Err("Intune ownership lacks terminal handoff evidence".to_owned());
            }
            "SharedOrTransitioning"
                if ownership_records.iter().any(|record| {
                    record.fields.get("Disposition").map(String::as_str) != Some("Transitioning")
                        || record.fields.get("Terminal").map(String::as_str) != Some("false")
                }) =>
            {
                return Err("transitioning ownership lacks nonterminal evidence".to_owned());
            }
            _ => {}
        }
    } else if ownership_records.is_empty() {
        if ownership["coverageGapArtifactIds"]
            .as_array()
            .is_none_or(Vec::is_empty)
        {
            return Err("unknown ownership has neither evidence nor a coverage gap".to_owned());
        }
    } else if !ownership_records
        .iter()
        .any(|record| record.fields.get("Ownership").map(String::as_str) == Some("SccmOwned"))
        || !ownership_records
            .iter()
            .any(|record| record.fields.get("Ownership").map(String::as_str) == Some("IntuneOwned"))
    {
        return Err("cited unknown ownership is not an explicit contradiction".to_owned());
    }
    if (ownership_class == "IntuneOwned") != (ownership["terminalHandoff"] == true) {
        return Err("terminal handoff flag does not match ownership classification".to_owned());
    }
    let ownership_gap_ids = string_array(
        &ownership["coverageGapArtifactIds"],
        "ownership coverageGapArtifactIds",
    )?;
    let mut sorted_ownership_gap_ids = ownership_gap_ids.clone();
    sorted_ownership_gap_ids.sort();
    sorted_ownership_gap_ids.dedup();
    if ownership_gap_ids != sorted_ownership_gap_ids {
        return Err("ownership coverage gaps are duplicated or not sorted".to_owned());
    }
    for artifact_id in ownership_gap_ids {
        let artifact = artifacts_by_id
            .get(&artifact_id)
            .ok_or_else(|| format!("ownership gap cites unknown {artifact_id}"))?;
        if artifact["logicalArtifactId"] != "client-co-management"
            || effective_state(artifact)? == "captured"
        {
            return Err(format!(
                "ownership gap {artifact_id} is not a bounded noncomplete co-management source"
            ));
        }
    }

    let transactions = expected["transactions"]
        .as_array()
        .ok_or_else(|| "transactions are not an array".to_owned())?;
    if transactions.len() != expected_transaction_count(scenario) {
        return Err(format!(
            "{scenario} transaction cardinality is not the exact scenario contract"
        ));
    }
    if ownership_class != "SccmOwned" && !transactions.is_empty() {
        return Err("operational transactions require evidenced SCCM ownership".to_owned());
    }
    if matches!(workflow, "coManagement" | "softwareCenter" | "mixed") && !transactions.is_empty() {
        return Err(format!("{workflow} cannot ship operational transactions"));
    }
    let latest_ownership_timestamp = ownership_records
        .iter()
        .filter_map(|record| record.timestamp)
        .max();
    let mut transaction_ids = BTreeSet::new();
    let mut transaction_keys = BTreeSet::new();
    let mut transaction_order = Vec::new();
    for transaction in transactions {
        let transaction_id = required_string(transaction, "transactionId", "transaction")?;
        if !public_identifier_is_safe(transaction_id) {
            return Err(format!(
                "transaction id {transaction_id} is outside the closed public identifier grammar"
            ));
        }
        require_exact_object_fields(
            transaction,
            &[
                "classification",
                "confidence",
                "coverageGapArtifactIds",
                "evidence",
                "key",
                "lastSuccessfulPhase",
                "nextArtifact",
                "phase",
                "state",
                "transactionId",
                "workflow",
            ],
            transaction_id,
        )?;
        transaction_order.push(transaction_id.to_owned());
        if !transaction_ids.insert(transaction_id.to_owned()) {
            return Err(format!("duplicate transactionId {transaction_id}"));
        }
        if transaction["workflow"] != workflow {
            return Err(format!("{transaction_id} crosses workflow families"));
        }
        let key = &transaction["key"];
        if key["keyProfileKind"]
            != match workflow {
                "scripts" => "scriptExact",
                "notification" => "notificationExact",
                _ => unreachable!("operational workflows checked above"),
            }
            || key["extractionProfileId"] != expected_profile(workflow)?
            || key["confidence"] != "exact"
        {
            return Err(format!("{transaction_id} key is not exact and versioned"));
        }
        let fields = key_fields(workflow)?;
        let mut expected_key_fields = fields.iter().copied().collect::<BTreeSet<_>>();
        expected_key_fields.extend(["confidence", "extractionProfileId", "keyProfileKind"]);
        let actual_key_fields = key
            .as_object()
            .ok_or_else(|| format!("{transaction_id} key is not an object"))?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if actual_key_fields != expected_key_fields {
            return Err(format!(
                "{transaction_id} key fields are not the exact {workflow} contract"
            ));
        }
        for field in fields {
            let value = required_string(key, field, transaction_id)?;
            if value.is_empty()
                || value.contains(['\n', '\r'])
                || (*field == "ResourceHandle" && !value.starts_with("safe:"))
            {
                return Err(format!("{transaction_id} key {field} is unsafe"));
            }
            let required_prefix = match *field {
                "ScriptId" => "SCRIPT-326-",
                "ExecutionId" => "EXEC-326-",
                "NotificationId" => "NOTIFY-326-",
                "ChannelId" => "CHANNEL-326-",
                "ResourceHandle" => "safe:resource-326-",
                _ => unreachable!("exact key field table"),
            };
            if !value.starts_with(required_prefix) {
                return Err(format!(
                    "{transaction_id} key {field} is outside the synthetic profile"
                ));
            }
        }
        let transaction_key = fields
            .iter()
            .map(|field| required_string(key, field, transaction_id).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        if !transaction_keys.insert(transaction_key) {
            return Err(format!(
                "{transaction_id} duplicates an exact normalized transaction key"
            ));
        }
        let transaction_evidence = transaction["evidence"]
            .as_array()
            .ok_or_else(|| format!("{transaction_id} evidence is not an array"))?;
        let expected_logical = if workflow == "scripts" {
            "client-scripts"
        } else {
            "client-notification"
        };
        let mut transaction_ref_order = Vec::new();
        for evidence_ref in transaction_evidence {
            let artifact_id = required_string(evidence_ref, "artifactId", transaction_id)?;
            transaction_ref_order.push((
                artifact_id.to_owned(),
                evidence_ref["startLine"].as_u64().unwrap_or(0),
                evidence_ref["endLine"].as_u64().unwrap_or(0),
            ));
            let artifact = artifacts_by_id
                .get(artifact_id)
                .ok_or_else(|| format!("{transaction_id} cites unknown {artifact_id}"))?;
            if artifact["logicalArtifactId"] != expected_logical {
                return Err(format!(
                    "{transaction_id} borrows evidence outside {expected_logical}"
                ));
            }
        }
        let mut sorted_transaction_refs = transaction_ref_order.clone();
        sorted_transaction_refs.sort();
        if transaction_ref_order != sorted_transaction_refs
            || sorted_transaction_refs
                .windows(2)
                .any(|references| references[0] == references[1])
        {
            return Err(format!(
                "{transaction_id} evidence references are duplicated or not sorted"
            ));
        }
        let records = evidence_records(scenario_root, &artifacts_by_id, &transaction["evidence"])?;
        if !evidence_refs_cite_unique_records(&transaction_ref_order) {
            return Err(format!(
                "{transaction_id} evidence ranges overlap and double-count a logical record"
            ));
        }
        if records.is_empty() {
            return Err(format!("{transaction_id} has no cited evidence"));
        }
        for record in &records {
            for field in fields {
                let value = required_string(key, field, transaction_id)?;
                if record.fields.get(*field).map(String::as_str) != Some(value) {
                    return Err(format!(
                        "{transaction_id} key {field} is not co-located in every cited record"
                    ));
                }
            }
        }
        let phase = required_string(transaction, "phase", transaction_id)?;
        if !allowed_phases(workflow)?.contains(&phase) {
            return Err(format!("{transaction_id} has unsupported phase {phase}"));
        }
        let last_successful_phase = transaction["lastSuccessfulPhase"]
            .as_str()
            .ok_or_else(|| format!("{transaction_id} lastSuccessfulPhase is not a string"))?;
        if !allowed_phases(workflow)?.contains(&last_successful_phase) {
            return Err(format!(
                "{transaction_id} has unsupported last successful phase {last_successful_phase}"
            ));
        }
        let confidence = required_string(transaction, "confidence", transaction_id)?;
        if records.iter().any(|record| {
            record.ordering_state != SccmTimeOrderingState::NormalizedUtc
                || record.timestamp.is_none()
                || !source_version_matches_selected_profile(record.source_version.as_str())
        }) {
            return Err(format!(
                "{transaction_id} lacks usable time/profile provenance"
            ));
        }
        validate_temporal_progression(
            workflow,
            transaction_id,
            phase,
            &records,
            latest_ownership_timestamp.ok_or_else(|| {
                format!("{transaction_id} lacks timestamped SCCM ownership evidence")
            })?,
        )?;
        let classification = required_string(transaction, "classification", transaction_id)?;
        let state = required_string(transaction, "state", transaction_id)?;
        let has_record = |disposition: &str, terminal: bool| {
            records.iter().any(|record| {
                record.fields.get("Phase").map(String::as_str) == Some(phase)
                    && record.fields.get("Disposition").map(String::as_str) == Some(disposition)
                    && record.fields.get("Terminal").map(String::as_str)
                        == Some(if terminal { "true" } else { "false" })
            })
        };
        match classification {
            "success" => {
                let disposition = if workflow == "notification" {
                    "Acknowledged"
                } else {
                    "Succeeded"
                };
                if confidence != "high"
                    || !matches!(state, "succeeded" | "acknowledged")
                    || (workflow == "scripts" && phase != "Report")
                    || (workflow == "notification" && phase != "Acknowledge")
                    || last_successful_phase != phase
                    || !has_record(disposition, true)
                {
                    return Err(format!(
                        "{transaction_id} success lacks cited terminal evidence"
                    ));
                }
            }
            "confirmedFailure" => {
                if confidence != "high"
                    || state != "failed"
                    || last_successful_phase == phase
                    || !has_record("Failed", true)
                    || !records.iter().any(|record| {
                        record.fields.get("Phase").map(String::as_str)
                            == Some(last_successful_phase)
                            && record.fields.get("Disposition").map(String::as_str)
                                == Some("Succeeded")
                            && record.fields.get("Terminal").map(String::as_str) == Some("false")
                    })
                {
                    return Err(format!(
                        "{transaction_id} failure lacks cited terminal evidence"
                    ));
                }
            }
            "blockedOrDeferred" => {
                if workflow != "notification"
                    || confidence != "medium"
                    || state != "deferred"
                    || phase != "DeferOrDispatch"
                    || last_successful_phase != "Receive"
                    || !has_record("Deferred", false)
                {
                    return Err(format!(
                        "{transaction_id} deferred state is not conservative"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "{transaction_id} has unsupported classification {other}"
                ));
            }
        }
        let coverage_gap_ids = string_array(
            &transaction["coverageGapArtifactIds"],
            &format!("{transaction_id} coverageGapArtifactIds"),
        )?;
        let mut sorted_gap_ids = coverage_gap_ids.clone();
        sorted_gap_ids.sort();
        sorted_gap_ids.dedup();
        if coverage_gap_ids != sorted_gap_ids {
            return Err(format!(
                "{transaction_id} coverage gaps are duplicated or not sorted"
            ));
        }
        for artifact_id in coverage_gap_ids {
            let artifact = artifacts_by_id
                .get(&artifact_id)
                .ok_or_else(|| format!("{transaction_id} gap cites unknown {artifact_id}"))?;
            if effective_state(artifact)? == "captured" {
                return Err(format!(
                    "{transaction_id} gap cites complete artifact {artifact_id}"
                ));
            }
        }
        match classification {
            "blockedOrDeferred" => {
                let next = transaction["nextArtifact"]
                    .as_object()
                    .ok_or_else(|| format!("{transaction_id} lacks a bounded next artifact"))?;
                if next.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    != BTreeSet::from(["logicalArtifactId", "reason"])
                    || next["logicalArtifactId"] != "client-notification"
                {
                    return Err(format!(
                        "{transaction_id} next artifact is not the exact notification group"
                    ));
                }
                let reason = next["reason"]
                    .as_str()
                    .ok_or_else(|| format!("{transaction_id} next reason is not a string"))?;
                if !public_free_text_is_safe(reason) {
                    return Err(format!(
                        "{transaction_id} next artifact reason leaks identity or path data"
                    ));
                }
                let lower_reason = reason.to_ascii_lowercase();
                if reason.trim() != reason
                    || reason.len() > 240
                    || reason.contains(['*', '?', '\\'])
                    || reason.starts_with('/')
                    || lower_reason.contains("all files")
                    || lower_reason.contains("entire disk")
                    || lower_reason.contains("whole filesystem")
                {
                    return Err(format!(
                        "{transaction_id} next artifact request is unbounded"
                    ));
                }
            }
            _ if !transaction["nextArtifact"].is_null() => {
                return Err(format!(
                    "{transaction_id} terminal result invents a next artifact"
                ));
            }
            _ => {}
        }
    }
    let mut sorted_transaction_order = transaction_order.clone();
    sorted_transaction_order.sort();
    if transaction_order != sorted_transaction_order {
        return Err("transactions are not deterministically sorted".to_owned());
    }

    let observations = expected["sourceLocalObservations"]
        .as_array()
        .ok_or_else(|| "sourceLocalObservations are not an array".to_owned())?;
    let mut observed_noncomplete = BTreeSet::new();
    let mut observed_malformed = BTreeSet::new();
    let mut observed_unknown_profiles = BTreeSet::new();
    let mut observed_invalid_offsets = BTreeSet::new();
    let mut observation_ids = BTreeSet::new();
    let mut observation_order = Vec::new();
    for observation in observations {
        let observation_id = required_string(observation, "observationId", "observation")?;
        if !public_identifier_is_safe(observation_id) {
            return Err(format!(
                "observation id {observation_id} is outside the closed public identifier grammar"
            ));
        }
        require_exact_object_fields(
            observation,
            &[
                "artifactIds",
                "claim",
                "confidenceCeiling",
                "correlationEligible",
                "kind",
                "observationId",
            ],
            observation_id,
        )?;
        observation_order.push(observation_id.to_owned());
        if !observation_ids.insert(observation_id.to_owned()) {
            return Err(format!("duplicate observationId {observation_id}"));
        }
        if observation["confidenceCeiling"] != "low" || observation["correlationEligible"] != false
        {
            return Err(format!("{observation_id} exceeds its source-local ceiling"));
        }
        let kind = required_string(observation, "kind", observation_id)?;
        if !matches!(
            kind,
            "coverageGap"
                | "rotationSplit"
                | "unkeyedRecord"
                | "unsupportedCandidate"
                | "malformedRecord"
                | "unknownProfile"
                | "invalidOffset"
                | "physicalCollision"
        ) {
            return Err(format!("{observation_id} has unsupported kind {kind}"));
        }
        let claim = required_string(observation, "claim", observation_id)?;
        let lower_claim = claim.to_ascii_lowercase();
        let claim_tokens = lower_claim
            .split(|character: char| !character.is_ascii_alphanumeric())
            .filter(|token| !token.is_empty())
            .collect::<BTreeSet<_>>();
        if claim.trim() != claim
            || claim.is_empty()
            || claim_tokens.iter().any(|token| {
                matches!(
                    *token,
                    "cause" | "caused" | "causes" | "causal" | "causality"
                )
            })
            || claim_tokens
                .iter()
                .any(|token| matches!(*token, "prove" | "proved" | "proves"))
            || (claim_tokens.contains("because")
                && claim_tokens.iter().any(|token| {
                    matches!(
                        *token,
                        "failed"
                            | "failure"
                            | "unavailable"
                            | "outcome"
                            | "succeeded"
                            | "success"
                            | "broken"
                    )
                }))
            || claim_tokens
                .iter()
                .any(|token| matches!(*token, "server" | "servers"))
            || lower_claim.contains("intune failure")
            || lower_claim.contains("resulted in")
            || lower_claim.contains("responsible for")
            || lower_claim.contains("due to")
            || lower_claim.contains("led to")
            || lower_claim.contains("root cause")
        {
            return Err(format!(
                "{observation_id} makes an unsupported causal claim"
            ));
        }
        if !public_free_text_is_safe(claim) {
            return Err(format!(
                "{observation_id} contains unsafe public identity or path data"
            ));
        }
        let artifact_ids = string_array(
            &observation["artifactIds"],
            &format!("{observation_id} artifactIds"),
        )?;
        if artifact_ids.is_empty() {
            return Err(format!("{observation_id} has no bounded artifact identity"));
        }
        let mut sorted_artifact_ids = artifact_ids.clone();
        sorted_artifact_ids.sort();
        sorted_artifact_ids.dedup();
        if artifact_ids != sorted_artifact_ids {
            return Err(format!(
                "{observation_id} artifact IDs are duplicated or unsorted"
            ));
        }
        for artifact_id in &artifact_ids {
            let artifact = artifacts_by_id
                .get(artifact_id.as_str())
                .ok_or_else(|| format!("{observation_id} cites unknown {artifact_id}"))?;
            if effective_state(artifact)? != "captured" {
                observed_noncomplete.insert(artifact_id.to_owned());
            }
            if kind == "unknownProfile" {
                observed_unknown_profiles.insert(artifact_id.to_owned());
            }
            if kind == "invalidOffset" {
                observed_invalid_offsets.insert(artifact_id.to_owned());
            }
            if kind == "malformedRecord" {
                observed_malformed.insert(artifact_id.to_owned());
            }
        }
        match kind {
            "coverageGap"
                if artifact_ids.iter().any(|artifact_id| {
                    artifacts_by_id
                        .get(artifact_id.as_str())
                        .is_some_and(|artifact| {
                            matches!(
                                effective_state(artifact),
                                Ok("captured" | "malformed" | "unsupported")
                            )
                        })
                }) =>
            {
                return Err(format!(
                    "{observation_id} coverage gap cites complete evidence"
                ));
            }
            "rotationSplit" => {
                let rotations = artifact_ids
                    .iter()
                    .map(|artifact_id| {
                        let artifact = artifacts_by_id
                            .get(artifact_id.as_str())
                            .expect("observation artifacts validated");
                        (
                            required_string(&artifact["rotation"], "kind", artifact_id),
                            artifact["rotation"]["fragmentComplete"] == false,
                            artifact["logicalArtifactId"].as_str(),
                        )
                    })
                    .collect::<Vec<_>>();
                if rotations.len() < 2
                    || rotations
                        .iter()
                        .any(|(rotation, incomplete, _)| rotation.is_err() || !incomplete)
                    || !rotations.iter().any(|(rotation, _, _)| {
                        rotation
                            .as_ref()
                            .is_ok_and(|rotation| *rotation == "current")
                    })
                    || !rotations.iter().any(|(rotation, _, _)| {
                        rotation.as_ref().is_ok_and(|rotation| *rotation == "lo")
                    })
                    || rotations
                        .iter()
                        .filter_map(|(_, _, logical)| *logical)
                        .collect::<BTreeSet<_>>()
                        .len()
                        != 1
                {
                    return Err(format!(
                        "{observation_id} is not a physical incomplete rotation split"
                    ));
                }
            }
            "unsupportedCandidate"
                if artifact_ids.iter().any(|artifact_id| {
                    let artifact = artifacts_by_id
                        .get(artifact_id.as_str())
                        .expect("observation artifacts validated");
                    artifact["catalogState"] != "candidateUnsupported"
                        || artifact["parserEligible"] != false
                        || effective_state(artifact) != Ok("unsupported")
                }) =>
            {
                return Err(format!(
                    "{observation_id} promotes a parser-eligible or admitted source"
                ));
            }
            "malformedRecord"
                if artifact_ids.iter().any(|artifact_id| {
                    artifacts_by_id
                        .get(artifact_id.as_str())
                        .is_some_and(|artifact| effective_state(artifact) != Ok("malformed"))
                }) =>
            {
                return Err(format!(
                    "{observation_id} malformed claim lacks malformed coverage"
                ));
            }
            "physicalCollision" => {
                let collision_artifacts = artifact_ids
                    .iter()
                    .map(|artifact_id| {
                        artifacts_by_id
                            .get(artifact_id.as_str())
                            .expect("observation artifacts validated")
                    })
                    .collect::<Vec<_>>();
                let source_names = collision_artifacts
                    .iter()
                    .filter_map(|artifact| artifact["sourceName"].as_str())
                    .collect::<BTreeSet<_>>();
                let collision_paths = collision_artifacts
                    .iter()
                    .filter_map(|artifact| artifact["relativePath"].as_str())
                    .collect::<BTreeSet<_>>();
                let fingerprints = collision_artifacts
                    .iter()
                    .filter_map(|artifact| artifact["pathFingerprint"].as_str())
                    .collect::<BTreeSet<_>>();
                if collision_artifacts.len() < 2
                    || source_names.len() != 1
                    || collision_paths.len() != collision_artifacts.len()
                    || fingerprints.len() != collision_artifacts.len()
                {
                    return Err(format!(
                        "{observation_id} does not preserve a real cross-root collision"
                    ));
                }
            }
            "unkeyedRecord" => {
                for artifact_id in &artifact_ids {
                    let artifact = artifacts_by_id
                        .get(artifact_id.as_str())
                        .expect("observation artifacts validated");
                    for record in all_artifact_records(scenario_root, artifact)? {
                        let has_script_key = ["ScriptId", "ExecutionId", "ResourceHandle"]
                            .iter()
                            .all(|field| record.fields.contains_key(*field));
                        let has_notification_key =
                            ["NotificationId", "ChannelId", "ResourceHandle"]
                                .iter()
                                .all(|field| record.fields.contains_key(*field));
                        if has_script_key || has_notification_key {
                            return Err(format!(
                                "{observation_id} labels an exact-key record unkeyed"
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut sorted_observation_order = observation_order.clone();
    sorted_observation_order.sort();
    if observation_order != sorted_observation_order {
        return Err("source-local observations are not deterministically sorted".to_owned());
    }
    let noncomplete = expected_coverage
        .iter()
        .filter(|(_, (_, state))| state != "captured")
        .map(|(artifact_id, _)| artifact_id.to_owned())
        .collect::<BTreeSet<_>>();
    if observed_noncomplete != noncomplete {
        return Err(format!(
            "noncomplete coverage is not surfaced exactly: {observed_noncomplete:?} != {noncomplete:?}"
        ));
    }
    let malformed = expected_coverage
        .iter()
        .filter(|(_, (_, state))| state == "malformed")
        .map(|(artifact_id, _)| artifact_id.to_owned())
        .collect::<BTreeSet<_>>();
    if observed_malformed != malformed {
        return Err(format!(
            "malformed coverage is not surfaced exactly: {observed_malformed:?} != {malformed:?}"
        ));
    }
    if observed_unknown_profiles != unknown_version_artifacts {
        return Err(format!(
            "unknown profile observations differ: {observed_unknown_profiles:?} != {unknown_version_artifacts:?}"
        ));
    }
    if observed_invalid_offsets != invalid_offset_artifacts {
        return Err(format!(
            "invalid offset observations differ: {observed_invalid_offsets:?} != {invalid_offset_artifacts:?}"
        ));
    }

    Ok(())
}

fn mutation_was_accepted(
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
    expected: &Value,
) -> bool {
    validate_contract(scenario, scenario_root, manifest, expected).is_ok()
}

fn replace_in_file(path: &Path, from: &str, to: &str) {
    let original = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    let mutated = original.replace(from, to);
    assert_ne!(
        original,
        mutated,
        "{} contains the mutation target {from:?}",
        path.display()
    );
    std::fs::write(path, mutated)
        .unwrap_or_else(|error| panic!("{} is writable: {error}", path.display()));
}

#[test]
fn management_fixture_matrix_is_exact_and_workflow_scoped() {
    assert_eq!(
        scenario_names(),
        SCENARIOS.map(str::to_owned),
        "fixture directories are an explicit issue #326 matrix"
    );
    let workflow_counts = SCENARIOS
        .iter()
        .map(|scenario| {
            let (_, manifest, _) = load_contract(scenario);
            manifest["workflowFamily"]
                .as_str()
                .expect("workflowFamily is a string")
                .to_owned()
        })
        .fold(BTreeMap::new(), |mut counts, workflow| {
            *counts.entry(workflow).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(
        workflow_counts,
        BTreeMap::from([
            ("coManagement".to_owned(), 4),
            ("mixed".to_owned(), 1),
            ("notification".to_owned(), 3),
            ("scripts".to_owned(), 4),
            ("softwareCenter".to_owned(), 2),
        ])
    );
}

#[test]
fn management_corpus_inventory_and_digest_are_pinned() {
    let inventory = corpus_inventory();
    assert_eq!(inventory.scenarios, 14);
    assert_eq!(inventory.artifacts, 30);
    assert_eq!(inventory.evidence_files, 25);
    assert_eq!(inventory.evidence_bytes, 8_648);
    assert_eq!(
        inventory.capture_states,
        BTreeMap::from([
            ("absent".to_owned(), 3),
            ("accessDenied".to_owned(), 1),
            ("capped".to_owned(), 1),
            ("captured".to_owned(), 23),
            ("parseFailed".to_owned(), 1),
            ("unsupported".to_owned(), 1),
        ])
    );
    assert_eq!(
        inventory.digest, DOCUMENTED_CORPUS_DIGEST,
        "path/artifact-qualified evidence digest changed"
    );
}

#[test]
fn parse_failed_capture_maps_to_malformed_effective_coverage() {
    let (_, manifest, expected) = load_contract("software-center-insufficient");
    let artifact = manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array")
        .iter()
        .find(|artifact| artifact["artifactId"] == "software-center-insufficient-malformed")
        .expect("malformed candidate artifact is present");
    assert_eq!(artifact["captureState"], "parseFailed");
    assert_eq!(effective_state(artifact), Ok("malformed"));

    let coverage = expected["coverage"]
        .as_array()
        .expect("coverage is an array")
        .iter()
        .find(|row| row["artifactId"] == "software-center-insufficient-malformed")
        .expect("malformed candidate has explicit coverage");
    assert_eq!(coverage["state"], "malformed");
}

#[test]
fn every_management_scenario_satisfies_the_preparation_contract() {
    for scenario in SCENARIOS {
        let (scenario_root, manifest, expected) = load_contract(scenario);
        validate_contract(scenario, &scenario_root, &manifest, &expected)
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
    }
}

#[test]
fn ownership_and_operational_outcomes_remain_conservative() {
    let (_, intune_manifest, intune) = load_contract("co-management-intune-owned");
    assert_eq!(intune["ownership"]["classification"], "IntuneOwned");
    assert_eq!(intune["ownership"]["terminalHandoff"], true);
    assert_eq!(intune["transactions"], Value::Array(Vec::new()));
    assert_eq!(intune["findings"], Value::Array(Vec::new()));
    assert_eq!(
        intune_manifest["artifacts"][0]["logicalArtifactId"],
        "client-co-management"
    );

    let (_, transitioning_manifest, transitioning) = load_contract("co-management-transitioning");
    assert_eq!(
        transitioning["ownership"]["classification"],
        "SharedOrTransitioning"
    );
    assert_eq!(transitioning["ownership"]["confidence"], "medium");
    assert_eq!(transitioning["transactions"], Value::Array(Vec::new()));
    assert_eq!(
        transitioning_manifest["artifacts"][0]["captureState"],
        "captured"
    );

    let (_, _, deferred) = load_contract("notification-deferred");
    assert_eq!(
        deferred["transactions"][0]["classification"],
        "blockedOrDeferred"
    );
    assert_eq!(deferred["transactions"][0]["state"], "deferred");
    assert_eq!(deferred["transactions"][0]["confidence"], "medium");

    let (_, _, software_center) = load_contract("software-center-observed");
    assert_eq!(
        software_center["extractionProfile"]["selectionState"],
        "unsupportedCandidate"
    );
    assert_eq!(software_center["transactions"], Value::Array(Vec::new()));
    assert_eq!(software_center["findings"], Value::Array(Vec::new()));
}

#[test]
fn incomplete_rotation_collision_and_same_time_inputs_stay_unlinked() {
    let (_, _, incomplete) = load_contract("script-incomplete");
    assert_eq!(incomplete["transactions"], Value::Array(Vec::new()));
    assert_eq!(incomplete["coverage"][0]["state"], "capped");
    assert_eq!(incomplete["coverage"][1]["state"], "partial");

    let (_, mixed_manifest, mixed) = load_contract("mixed-unrelated");
    assert_eq!(mixed["ownership"]["classification"], "UnknownOwnership");
    assert_eq!(mixed["transactions"], Value::Array(Vec::new()));
    assert_eq!(mixed["findings"], Value::Array(Vec::new()));
    assert_ne!(
        mixed_manifest["artifacts"][3]["pathFingerprint"],
        mixed_manifest["artifacts"][4]["pathFingerprint"],
        "same-basename roots retain distinct physical provenance"
    );
}

#[test]
fn fixture_bytes_are_synthetic_sanitized_and_context_safe() {
    for scenario in SCENARIOS {
        let scenario_root = management_root().join(scenario);
        let manifest = load_json(&scenario_root.join("manifest.json"));
        for artifact in manifest["artifacts"]
            .as_array()
            .expect("artifacts are an array")
        {
            if let Some(path) = artifact["sanitizedSourcePath"].as_str() {
                assert!(
                    path.starts_with("SYNTHETIC://"),
                    "{scenario} contains an unsanitized source path"
                );
            }
            let Some(relative_path) = artifact["relativePath"].as_str() else {
                continue;
            };
            let text = std::fs::read_to_string(scenario_root.join(relative_path))
                .expect("synthetic evidence is readable");
            assert!(text.contains("SYNTHETIC FIXTURE"));
            let lower = text.to_ascii_lowercase();
            for forbidden in [
                "c:\\users\\",
                "/users/",
                "s-1-5-",
                "password=",
                "token=",
                "contoso",
                "customer",
                "example.com",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "{scenario}/{relative_path} contains forbidden context {forbidden}"
                );
            }
        }
    }
}

#[test]
fn adversarial_role_source_path_and_collision_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let (scenario_root, manifest, expected) = load_contract("script-success");
    let mut role_alias = manifest.clone();
    role_alias["artifacts"][0]["role"] = Value::String("server".to_owned());
    if mutation_was_accepted("script-success", &scenario_root, &role_alias, &expected) {
        accepted.push("artifact role changed to server");
    }

    let mut source_alias = manifest.clone();
    source_alias["artifacts"][0]["sourceName"] = Value::String("scripts.LOG".to_owned());
    if mutation_was_accepted("script-success", &scenario_root, &source_alias, &expected) {
        accepted.push("case-folded source alias");
    }

    let mut unsafe_source_path = manifest.clone();
    unsafe_source_path["artifacts"][0]["sanitizedSourcePath"] =
        Value::String("C:\\Users\\SYNTHETIC\\Scripts.log".to_owned());
    if mutation_was_accepted(
        "script-success",
        &scenario_root,
        &unsafe_source_path,
        &expected,
    ) {
        accepted.push("raw Windows source path");
    }

    let mut logical_alias = manifest.clone();
    logical_alias["artifacts"][0]["logicalArtifactId"] = Value::String("client-script".to_owned());
    if mutation_was_accepted("script-success", &scenario_root, &logical_alias, &expected) {
        accepted.push("logical source alias");
    }

    let (mixed_root, mixed_manifest, mixed_expected) = load_contract("mixed-unrelated");
    let mut fingerprint_collision = mixed_manifest.clone();
    fingerprint_collision["artifacts"][4]["pathFingerprint"] =
        fingerprint_collision["artifacts"][3]["pathFingerprint"].clone();
    if mutation_was_accepted(
        "mixed-unrelated",
        &mixed_root,
        &fingerprint_collision,
        &mixed_expected,
    ) {
        accepted.push("cross-root path fingerprint collision");
    }

    assert!(
        accepted.is_empty(),
        "adversarial manifest mutations were accepted: {accepted:?}"
    );
}

#[test]
fn adversarial_key_profile_coverage_and_invalid_offset_mutations_fail_closed() {
    let mut accepted = Vec::new();
    let (scenario_root, manifest, expected) = load_contract("script-success");

    let mut key_alias = expected.clone();
    key_alias["transactions"][0]["key"]["ExecutionId"] =
        Value::String("EXEC-326-BORROWED".to_owned());
    if mutation_was_accepted("script-success", &scenario_root, &manifest, &key_alias) {
        accepted.push("borrowed exact key");
    }

    let mut profile_alias = expected.clone();
    profile_alias["extractionProfile"]["id"] =
        Value::String("sccm-client-scripts-latest".to_owned());
    if mutation_was_accepted("script-success", &scenario_root, &manifest, &profile_alias) {
        accepted.push("unversioned profile alias");
    }

    let (incomplete_root, incomplete_manifest, incomplete_expected) =
        load_contract("script-incomplete");
    let mut coverage_alias = incomplete_expected.clone();
    coverage_alias["coverage"][0]["state"] = Value::String("captured".to_owned());
    if mutation_was_accepted(
        "script-incomplete",
        &incomplete_root,
        &incomplete_manifest,
        &coverage_alias,
    ) {
        accepted.push("capped coverage promoted to captured");
    }

    let mut unknown_partial_manifest = incomplete_manifest.clone();
    unknown_partial_manifest["artifacts"][1]["sourceVersion"] =
        Value::String("5.99.UNKNOWN.3260".to_owned());
    let mut unknown_partial_expected = incomplete_expected.clone();
    unknown_partial_expected["sourceLocalObservations"]
        .as_array_mut()
        .expect("observations are an array")
        .push(serde_json::json!({
            "observationId": "script-incomplete-unknown-profile",
            "kind": "unknownProfile",
            "claim": "The partial source has no validated extraction profile.",
            "confidenceCeiling": "low",
            "correlationEligible": false,
            "artifactIds": ["script-incomplete-lo"]
        }));
    unknown_partial_expected["sourceLocalObservations"]
        .as_array_mut()
        .expect("observations are an array")
        .sort_by(|left, right| {
            left["observationId"]
                .as_str()
                .cmp(&right["observationId"].as_str())
        });
    if mutation_was_accepted(
        "script-incomplete",
        &incomplete_root,
        &unknown_partial_manifest,
        &unknown_partial_expected,
    ) {
        accepted.push("unknown source retained a selected extraction profile");
    }

    let temporary = copy_scenario_to_temporary_root("script-success", "invalid-offset");
    let evidence_path = temporary
        .root
        .join("evidence/client-scripts/current/Scripts.log");
    let original = std::fs::read_to_string(&evidence_path).expect("temporary evidence is readable");
    std::fs::write(&evidence_path, original.replace("+000", "+2500"))
        .expect("temporary evidence offset is mutated");
    let temporary_manifest = load_json(&temporary.root.join("manifest.json"));
    let temporary_expected = load_json(&temporary.root.join("expected.json"));
    if mutation_was_accepted(
        "script-success",
        &temporary.root,
        &temporary_manifest,
        &temporary_expected,
    ) {
        accepted.push("invalid timestamp offset retained high confidence");
    }

    assert!(
        accepted.is_empty(),
        "identity/profile/coverage mutations were accepted: {accepted:?}"
    );
}

#[test]
fn adversarial_reversed_phase_late_ownership_and_equal_time_fail_closed() {
    let mut accepted = Vec::new();

    let reversed_phase =
        copy_scenario_to_temporary_root("script-success", "reversed-terminal-phase");
    let reversed_phase_path = reversed_phase
        .root
        .join("evidence/client-scripts/current/Scripts.log");
    let original =
        std::fs::read_to_string(&reversed_phase_path).expect("temporary evidence is readable");
    std::fs::write(
        &reversed_phase_path,
        original.replace("11:00:03.000+000", "10:59:59.000+000"),
    )
    .expect("terminal phase timestamp is moved before receive");
    let manifest = load_json(&reversed_phase.root.join("manifest.json"));
    let expected = load_json(&reversed_phase.root.join("expected.json"));
    if mutation_was_accepted("script-success", &reversed_phase.root, &manifest, &expected) {
        accepted.push("terminal script phase predates receive");
    }

    let late_ownership = copy_scenario_to_temporary_root("notification-received", "late-ownership");
    let late_ownership_path = late_ownership
        .root
        .join("evidence/client-co-management/current/CoManagementHandler.log");
    let original =
        std::fs::read_to_string(&late_ownership_path).expect("temporary evidence is readable");
    std::fs::write(
        &late_ownership_path,
        original.replace("12:00:00.000+000", "12:00:03.000+000"),
    )
    .expect("ownership timestamp is moved after operational evidence");
    let manifest = load_json(&late_ownership.root.join("manifest.json"));
    let expected = load_json(&late_ownership.root.join("expected.json"));
    if mutation_was_accepted(
        "notification-received",
        &late_ownership.root,
        &manifest,
        &expected,
    ) {
        accepted.push("ownership evidence postdates the transaction");
    }

    let equal_time = copy_scenario_to_temporary_root("notification-deferred", "equal-phase-time");
    let equal_time_path = equal_time
        .root
        .join("evidence/client-notification/current/CcmNotificationAgent.log");
    let original =
        std::fs::read_to_string(&equal_time_path).expect("temporary evidence is readable");
    std::fs::write(
        &equal_time_path,
        original.replace("12:01:02.000+000", "12:01:01.000+000"),
    )
    .expect("distinct phases are assigned the same timestamp");
    let manifest = load_json(&equal_time.root.join("manifest.json"));
    let expected = load_json(&equal_time.root.join("expected.json"));
    if mutation_was_accepted(
        "notification-deferred",
        &equal_time.root,
        &manifest,
        &expected,
    ) {
        accepted.push("distinct notification phases share an ambiguous timestamp");
    }

    assert!(
        accepted.is_empty(),
        "temporal provenance mutations were accepted: {accepted:?}"
    );
}

#[test]
fn unsupported_candidate_and_causal_claim_mutations_fail_closed() {
    let mut accepted = Vec::new();
    let (scenario_root, manifest, expected) = load_contract("software-center-observed");

    let mut promoted_manifest = manifest.clone();
    promoted_manifest["artifacts"][0]["catalogState"] = Value::String("admitted".to_owned());
    promoted_manifest["artifacts"][0]["parserEligible"] = Value::Bool(true);
    let mut promoted_expected = expected.clone();
    promoted_expected["coverage"][0]["state"] = Value::String("captured".to_owned());
    if mutation_was_accepted(
        "software-center-observed",
        &scenario_root,
        &promoted_manifest,
        &promoted_expected,
    ) {
        accepted.push("unsupported Software Center candidate promoted coherently");
    }

    let mut causal_claim = expected.clone();
    causal_claim["sourceLocalObservations"][0]["claim"] =
        Value::String("The server caused the Software Center failure.".to_owned());
    if mutation_was_accepted(
        "software-center-observed",
        &scenario_root,
        &manifest,
        &causal_claim,
    ) {
        accepted.push("unsupported server causal claim");
    }

    let (intune_root, intune_manifest, mut intune_expected) =
        load_contract("script-intune-handoff");
    let (_, _, failure_expected) = load_contract("script-failure");
    intune_expected["transactions"] = failure_expected["transactions"].clone();
    if mutation_was_accepted(
        "script-intune-handoff",
        &intune_root,
        &intune_manifest,
        &intune_expected,
    ) {
        accepted.push("Intune handoff promoted to SCCM transaction causality");
    }

    assert!(
        accepted.is_empty(),
        "unsupported capability/causal mutations were accepted: {accepted:?}"
    );
}

#[test]
fn exact_record_field_and_envelope_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let key_lookalike = copy_scenario_to_temporary_root("script-success", "other-script-id");
    let key_path = key_lookalike
        .root
        .join("evidence/client-scripts/current/Scripts.log");
    replace_in_file(&key_path, "ScriptId=", "OtherScriptId=");
    let manifest = load_json(&key_lookalike.root.join("manifest.json"));
    let expected = load_json(&key_lookalike.root.join("expected.json"));
    if mutation_was_accepted("script-success", &key_lookalike.root, &manifest, &expected) {
        accepted.push("OtherScriptId satisfied ScriptId");
    }

    let terminal_lookalike =
        copy_scenario_to_temporary_root("script-success", "other-terminal-fields");
    let terminal_path = terminal_lookalike
        .root
        .join("evidence/client-scripts/current/Scripts.log");
    replace_in_file(&terminal_path, "Disposition=", "OtherDisposition=");
    replace_in_file(&terminal_path, "Terminal=", "OtherTerminal=");
    let manifest = load_json(&terminal_lookalike.root.join("manifest.json"));
    let expected = load_json(&terminal_lookalike.root.join("expected.json"));
    if mutation_was_accepted(
        "script-success",
        &terminal_lookalike.root,
        &manifest,
        &expected,
    ) {
        accepted.push("lookalike disposition and terminal fields");
    }

    let duplicate_key = copy_scenario_to_temporary_root("script-success", "conflicting-script-id");
    let duplicate_key_path = duplicate_key
        .root
        .join("evidence/client-scripts/current/Scripts.log");
    replace_in_file(
        &duplicate_key_path,
        "ScriptId=SCRIPT-326-SUCCESS",
        "ScriptId=SCRIPT-326-SUCCESS ScriptId=SCRIPT-326-SHADOW",
    );
    let manifest = load_json(&duplicate_key.root.join("manifest.json"));
    let expected = load_json(&duplicate_key.root.join("expected.json"));
    if mutation_was_accepted("script-success", &duplicate_key.root, &manifest, &expected) {
        accepted.push("conflicting duplicate ScriptId");
    }

    let nested_ccm = copy_scenario_to_temporary_root("script-success", "nested-ccm-envelope");
    let nested_ccm_path = nested_ccm
        .root
        .join("evidence/client-scripts/current/Scripts.log");
    replace_in_file(
        &nested_ccm_path,
        "]LOG]!><time=",
        "]LOG]!><![LOG[NARRATIVE ONLY]LOG]!><time=",
    );
    let manifest = load_json(&nested_ccm.root.join("manifest.json"));
    let expected = load_json(&nested_ccm.root.join("expected.json"));
    if mutation_was_accepted("script-success", &nested_ccm.root, &manifest, &expected) {
        accepted.push("nested premature CCM envelope");
    }

    assert!(
        accepted.is_empty(),
        "record-local field/envelope mutations were accepted: {accepted:?}"
    );
}

#[test]
fn ownership_and_workflow_separation_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let ownership_lookalike =
        copy_scenario_to_temporary_root("script-success", "other-ownership-fields");
    let ownership_path = ownership_lookalike
        .root
        .join("evidence/client-co-management/current/CoManagementHandler.log");
    replace_in_file(&ownership_path, "Workload=", "OtherWorkload=");
    replace_in_file(&ownership_path, "Ownership=", "OtherOwnership=");
    replace_in_file(&ownership_path, "Disposition=", "OtherDisposition=");
    replace_in_file(&ownership_path, "Terminal=", "OtherTerminal=");
    let manifest = load_json(&ownership_lookalike.root.join("manifest.json"));
    let expected = load_json(&ownership_lookalike.root.join("expected.json"));
    if mutation_was_accepted(
        "script-success",
        &ownership_lookalike.root,
        &manifest,
        &expected,
    ) {
        accepted.push("lookalike ownership fields");
    }

    let contradictory =
        copy_scenario_to_temporary_root("script-success", "contradictory-ownership");
    let contradictory_path = contradictory
        .root
        .join("evidence/client-co-management/current/CoManagementHandler.log");
    replace_in_file(
        &contradictory_path,
        "Disposition=Owned Terminal=true",
        "Disposition=Owned Terminal=true Ownership=IntuneOwned Disposition=Handoff",
    );
    let manifest = load_json(&contradictory.root.join("manifest.json"));
    let expected = load_json(&contradictory.root.join("expected.json"));
    if mutation_was_accepted("script-success", &contradictory.root, &manifest, &expected) {
        accepted.push("contradictory SCCM and Intune ownership");
    }

    let workflow_borrow =
        copy_scenario_to_temporary_root("script-success", "borrowed-notification-ownership");
    let workflow_borrow_path = workflow_borrow
        .root
        .join("evidence/client-co-management/current/CoManagementHandler.log");
    replace_in_file(
        &workflow_borrow_path,
        "Workload=Scripts",
        "Workload=ClientNotification",
    );
    let manifest = load_json(&workflow_borrow.root.join("manifest.json"));
    let mut expected = load_json(&workflow_borrow.root.join("expected.json"));
    expected["ownership"]["workload"] = Value::String("ClientNotification".to_owned());
    if mutation_was_accepted(
        "script-success",
        &workflow_borrow.root,
        &manifest,
        &expected,
    ) {
        accepted.push("scripts borrowed notification ownership");
    }

    assert!(
        accepted.is_empty(),
        "ownership/workflow mutations were accepted: {accepted:?}"
    );
}

#[test]
fn additive_timestamp_and_capture_chronology_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let fractional_tail = copy_scenario_to_temporary_root("script-success", "seven-digit-fraction");
    let fractional_path = fractional_tail
        .root
        .join("evidence/client-scripts/current/Scripts.log");
    replace_in_file(&fractional_path, "+000", "1234");
    let fractional_owner_path = fractional_tail
        .root
        .join("evidence/client-co-management/current/CoManagementHandler.log");
    replace_in_file(&fractional_owner_path, "+000", "1234");
    let manifest = load_json(&fractional_tail.root.join("manifest.json"));
    let expected = load_json(&fractional_tail.root.join("expected.json"));
    if mutation_was_accepted(
        "script-success",
        &fractional_tail.root,
        &manifest,
        &expected,
    ) {
        accepted.push("seven-digit fractional tail treated as offset");
    }

    let signless_fraction =
        copy_scenario_to_temporary_root("script-success", "signless-fraction-rejection");
    let signless_path = signless_fraction
        .root
        .join("evidence/client-scripts/current/Scripts.log");
    replace_in_file(&signless_path, "11:00:01.000+000", "14:00:01.000240");
    replace_in_file(&signless_path, "11:00:02.000+000", "14:00:02.000240");
    replace_in_file(&signless_path, "11:00:03.000+000", "14:00:03.000240");
    let manifest = load_json(&signless_fraction.root.join("manifest.json"));
    let expected = load_json(&signless_fraction.root.join("expected.json"));
    if mutation_was_accepted(
        "script-success",
        &signless_fraction.root,
        &manifest,
        &expected,
    ) {
        accepted.push("signless fraction chronology");
    }

    let (scenario_root, mut manifest, expected) = load_contract("script-success");
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
    {
        artifact["capturedUtc"] = Value::String("2026-07-30T00:00:00Z".to_owned());
    }
    if mutation_was_accepted("script-success", &scenario_root, &manifest, &expected) {
        accepted.push("capture time predates cited evidence");
    }

    assert!(
        accepted.is_empty(),
        "timestamp/capture mutations were accepted: {accepted:?}"
    );
}

#[test]
fn coverage_causal_and_unknown_semantic_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let (scenario_root, manifest, expected) = load_contract("software-center-insufficient");
    let mut generic_parse_failure = expected.clone();
    let malformed = generic_parse_failure["sourceLocalObservations"]
        .as_array_mut()
        .expect("observations are an array")
        .iter_mut()
        .find(|observation| {
            observation["observationId"] == "software-center-insufficient-malformed-gap"
        })
        .expect("malformed observation exists");
    malformed["kind"] = Value::String("coverageGap".to_owned());
    if mutation_was_accepted(
        "software-center-insufficient",
        &scenario_root,
        &manifest,
        &generic_parse_failure,
    ) {
        accepted.push("parseFailed surfaced as a generic coverage gap");
    }

    let (scenario_root, manifest, expected) = load_contract("software-center-observed");
    for (claim, label) in [
        (
            "The Management Point resulted in the client failure.",
            "Management Point resulted-in causality",
        ),
        (
            "The Intune service was responsible for the client outcome.",
            "Intune responsible-for causality",
        ),
        (
            "Because the BGB endpoint failed, notification was unavailable.",
            "BGB because causality",
        ),
    ] {
        let mut causal = expected.clone();
        causal["sourceLocalObservations"][0]["claim"] = Value::String(claim.to_owned());
        if mutation_was_accepted(
            "software-center-observed",
            &scenario_root,
            &manifest,
            &causal,
        ) {
            accepted.push(label);
        }
    }

    let (scenario_root, manifest, mut expected) = load_contract("script-success");
    expected["ownership"]["intuneFailure"] = Value::Bool(true);
    expected["transactions"][0]["serverCause"] = Value::String("ManagementPoint".to_owned());
    if mutation_was_accepted("script-success", &scenario_root, &manifest, &expected) {
        accepted.push("unknown ownership and transaction semantics");
    }

    assert!(
        accepted.is_empty(),
        "coverage/causal/unknown semantic mutations were accepted: {accepted:?}"
    );
}

#[test]
fn transaction_identity_cardinality_and_phase_mutations_fail_closed() {
    let mut accepted = Vec::new();
    let (scenario_root, manifest, expected) = load_contract("script-success");

    let mut missing_transaction = expected.clone();
    missing_transaction["transactions"] = Value::Array(Vec::new());
    if mutation_was_accepted(
        "script-success",
        &scenario_root,
        &manifest,
        &missing_transaction,
    ) {
        accepted.push("required transaction removed");
    }

    let mut duplicate_key = expected.clone();
    let mut cloned_transaction = duplicate_key["transactions"][0].clone();
    cloned_transaction["transactionId"] = Value::String("script-success-exec-326-z".to_owned());
    duplicate_key["transactions"]
        .as_array_mut()
        .expect("transactions are an array")
        .push(cloned_transaction);
    if mutation_was_accepted("script-success", &scenario_root, &manifest, &duplicate_key) {
        accepted.push("exact transaction key cloned under another ID");
    }

    let mut missing_phase = expected.clone();
    missing_phase["transactions"][0]["evidence"] = serde_json::json!([
        {
            "artifactId": "script-success-current",
            "startLine": 1,
            "endLine": 1
        },
        {
            "artifactId": "script-success-current",
            "startLine": 3,
            "endLine": 3
        }
    ]);
    if mutation_was_accepted("script-success", &scenario_root, &manifest, &missing_phase) {
        accepted.push("Execute phase omitted between Receive and Report");
    }

    assert!(
        accepted.is_empty(),
        "transaction identity/cardinality/phase mutations were accepted: {accepted:?}"
    );
}

#[test]
fn source_workflow_root_and_sanitized_role_path_mutation_fails_closed() {
    let temporary = copy_scenario_to_temporary_root("script-success", "cross-root-server-path");
    let old_path = temporary
        .root
        .join("evidence/client-scripts/current/Scripts.log");
    let new_path = temporary
        .root
        .join("evidence/client-co-management/current/Scripts.log");
    std::fs::create_dir_all(
        new_path
            .parent()
            .expect("cross-root destination has a parent"),
    )
    .expect("cross-root destination exists");
    std::fs::rename(&old_path, &new_path).expect("evidence is moved across workflow roots");

    let mut manifest = load_json(&temporary.root.join("manifest.json"));
    manifest["artifacts"][0]["relativePath"] =
        Value::String("evidence/client-co-management/current/Scripts.log".to_owned());
    manifest["artifacts"][0]["sanitizedSourcePath"] = Value::String(
        "SYNTHETIC://client/management/script-success/server/mp/Scripts.log".to_owned(),
    );
    let expected = load_json(&temporary.root.join("expected.json"));

    assert!(
        !mutation_was_accepted("script-success", &temporary.root, &manifest, &expected),
        "cross-workflow evidence root and server-shaped sanitized path were accepted"
    );
}

#[test]
fn version_and_physical_identity_provenance_mutations_fail_closed() {
    let (script_root, script_manifest, script_expected) = load_contract("script-success");
    validate_contract(
        "script-success",
        &script_root,
        &script_manifest,
        &script_expected,
    )
    .expect("the bounded synthetic source contract remains valid");
    let mut accepted = Vec::new();

    let coherent_unknown_profile_expected = |artifact_id: &str| {
        let mut expected = script_expected.clone();
        expected["extractionProfile"]["selectionState"] =
            Value::String("unknownProfile".to_owned());
        expected["sourceLocalObservations"] = serde_json::json!([{
            "observationId": format!("{artifact_id}-unknown-profile"),
            "kind": "unknownProfile",
            "claim": "The synthetic source version cannot select a validated extraction profile.",
            "confidenceCeiling": "low",
            "correlationEligible": false,
            "artifactIds": [artifact_id],
        }]);
        expected
    };

    let mut malformed_transaction_version = script_manifest.clone();
    malformed_transaction_version["artifacts"][0]["sourceVersion"] =
        Value::String("5.00.TEST.UNKNOWN".to_owned());
    if mutation_was_accepted(
        "script-success",
        &script_root,
        &malformed_transaction_version,
        &coherent_unknown_profile_expected("script-success-current"),
    ) {
        accepted.push("malformed transaction source version retained high confidence");
    }

    let mut malformed_ownership_version = script_manifest.clone();
    malformed_ownership_version["artifacts"][1]["sourceVersion"] =
        Value::String("5.00.TEST.UNKNOWN".to_owned());
    if mutation_was_accepted(
        "script-success",
        &script_root,
        &malformed_ownership_version,
        &coherent_unknown_profile_expected("script-success-owner"),
    ) {
        accepted.push("malformed ownership source version retained high confidence");
    }

    let mut leaking_fingerprint = script_manifest.clone();
    leaking_fingerprint["artifacts"][0]["pathFingerprint"] =
        Value::String("safe:path:326:C:/Users/RealUser/Scripts.log".to_owned());
    if mutation_was_accepted(
        "script-success",
        &script_root,
        &leaking_fingerprint,
        &script_expected,
    ) {
        accepted.push("identity-bearing path fingerprint");
    }

    let mut leaking_source_path = script_manifest.clone();
    leaking_source_path["artifacts"][0]["sanitizedSourcePath"] = Value::String(
        "SYNTHETIC://client/management/script-success/client-scripts/C:/Users/RealUser/current/Scripts.log"
            .to_owned(),
    );
    if mutation_was_accepted(
        "script-success",
        &script_root,
        &leaking_source_path,
        &script_expected,
    ) {
        accepted.push("identity-bearing synthetic source path");
    }

    let (mixed_root, mixed_manifest, mixed_expected) = load_contract("mixed-unrelated");
    let mut duplicate_source_identity = mixed_manifest;
    duplicate_source_identity["artifacts"][4]["sanitizedSourcePath"] =
        duplicate_source_identity["artifacts"][3]["sanitizedSourcePath"].clone();
    if mutation_was_accepted(
        "mixed-unrelated",
        &mixed_root,
        &duplicate_source_identity,
        &mixed_expected,
    ) {
        accepted.push("duplicate physical source identity under distinct fingerprints");
    }

    assert!(
        accepted.is_empty(),
        "version or physical provenance mutations were accepted: {accepted:?}"
    );
}

#[test]
fn profile_citation_and_public_observation_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let (mixed_root, mut mixed_manifest, mut mixed_expected) = load_contract("mixed-unrelated");
    let formerly_unknown = mixed_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "mixed-owner-unknown")
        .expect("mixed corpus has the unknown-profile artifact");
    formerly_unknown["sourceVersion"] = Value::String("5.00.TEST.3260".to_owned());
    mixed_expected["sourceLocalObservations"]
        .as_array_mut()
        .expect("observations are an array")
        .retain(|observation| observation["kind"] != "unknownProfile");
    if mutation_was_accepted(
        "mixed-unrelated",
        &mixed_root,
        &mixed_manifest,
        &mixed_expected,
    ) {
        accepted.push("stale mixed profile state after the unknown version was removed");
    }

    let (script_root, script_manifest, script_expected) = load_contract("script-success");
    let mut duplicate_ownership = script_expected.clone();
    let ownership_reference = duplicate_ownership["ownership"]["evidence"][0].clone();
    duplicate_ownership["ownership"]["evidence"]
        .as_array_mut()
        .expect("ownership evidence is an array")
        .push(ownership_reference);
    if mutation_was_accepted(
        "script-success",
        &script_root,
        &script_manifest,
        &duplicate_ownership,
    ) {
        accepted.push("duplicate ownership evidence citation");
    }

    let mut duplicate_transaction = script_expected;
    let transaction_reference = duplicate_transaction["transactions"][0]["evidence"][0].clone();
    duplicate_transaction["transactions"][0]["evidence"]
        .as_array_mut()
        .expect("transaction evidence is an array")
        .push(transaction_reference);
    if mutation_was_accepted(
        "script-success",
        &script_root,
        &script_manifest,
        &duplicate_transaction,
    ) {
        accepted.push("duplicate transaction evidence citation");
    }

    let (software_center_root, software_center_manifest, mut software_center_expected) =
        load_contract("software-center-observed");
    software_center_expected["sourceLocalObservations"][0]["claim"] = Value::String(
        r"Observed C:\Users\RealUser and real.user@customer.example remain source local."
            .to_owned(),
    );
    if mutation_was_accepted(
        "software-center-observed",
        &software_center_root,
        &software_center_manifest,
        &software_center_expected,
    ) {
        accepted.push("identity-bearing public observation claim");
    }

    assert!(
        accepted.is_empty(),
        "profile, citation, or public observation mutations were accepted: {accepted:?}"
    );
}

#[test]
fn overlapping_evidence_citation_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let (mixed_root, mixed_manifest, mut mixed_expected) = load_contract("mixed-unrelated");
    mixed_expected["ownership"]["evidence"] = serde_json::json!([
        { "artifactId": "mixed-owner-unknown", "startLine": 1, "endLine": 1 },
        { "artifactId": "mixed-owner-unknown", "startLine": 1, "endLine": 2 }
    ]);
    if mutation_was_accepted(
        "mixed-unrelated",
        &mixed_root,
        &mixed_manifest,
        &mixed_expected,
    ) {
        accepted.push("sorted overlapping ownership ranges double-count logical record 1");
    }

    let (script_root, script_manifest, mut script_expected) = load_contract("script-success");
    script_expected["transactions"][0]["evidence"] = serde_json::json!([
        { "artifactId": "script-success-current", "startLine": 1, "endLine": 2 },
        { "artifactId": "script-success-current", "startLine": 2, "endLine": 3 }
    ]);
    if mutation_was_accepted(
        "script-success",
        &script_root,
        &script_manifest,
        &script_expected,
    ) {
        accepted.push("sorted overlapping transaction ranges double-count the Execute record");
    }

    assert!(
        accepted.is_empty(),
        "overlapping evidence citation mutations were accepted: {accepted:?}"
    );
}

#[test]
fn public_surface_privacy_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let (observed_root, observed_manifest, observed_expected) =
        load_contract("software-center-observed");

    let mut alternate_drive_claim = observed_expected.clone();
    alternate_drive_claim["sourceLocalObservations"][0]["claim"] =
        Value::String("Observed under D:/Profiles/RealUser remains source local.".to_owned());
    if mutation_was_accepted(
        "software-center-observed",
        &observed_root,
        &observed_manifest,
        &alternate_drive_claim,
    ) {
        accepted.push("alternate drive-letter path in a public observation claim");
    }

    let mut unc_claim = observed_expected.clone();
    unc_claim["sourceLocalObservations"][0]["claim"] = Value::String(
        "Observed under //LAB-CLIENT-01/share/RealUser remains source local.".to_owned(),
    );
    if mutation_was_accepted(
        "software-center-observed",
        &observed_root,
        &observed_manifest,
        &unc_claim,
    ) {
        accepted.push("UNC share path in a public observation claim");
    }

    let mut identity_observation_id = observed_expected.clone();
    identity_observation_id["sourceLocalObservations"][0]["observationId"] =
        Value::String("software-center-observed-D:/Users/RealUser".to_owned());
    if mutation_was_accepted(
        "software-center-observed",
        &observed_root,
        &observed_manifest,
        &identity_observation_id,
    ) {
        accepted.push("identity-bearing public observation id");
    }

    let (deferred_root, deferred_manifest, mut deferred_expected) =
        load_contract("notification-deferred");
    deferred_expected["transactions"][0]["nextArtifact"]["reason"] = Value::String(
        "Collect D:/Profiles/RealUser for the same exact notification key.".to_owned(),
    );
    if mutation_was_accepted(
        "notification-deferred",
        &deferred_root,
        &deferred_manifest,
        &deferred_expected,
    ) {
        accepted.push("alternate drive-letter path in a next-artifact request reason");
    }

    assert!(
        accepted.is_empty(),
        "public surface privacy mutations were accepted: {accepted:?}"
    );
}

#[test]
fn duplicate_coverage_gap_ownership_mutations_fail_closed() {
    let mut accepted = Vec::new();

    for scenario in ["co-management-unknown", "software-center-insufficient"] {
        let (scenario_root, manifest, mut expected) = load_contract(scenario);
        let gaps = expected["ownership"]["coverageGapArtifactIds"]
            .as_array_mut()
            .expect("ownership coverage gaps are an array");
        let duplicate = gaps
            .first()
            .expect("scenario declares an ownership coverage gap")
            .clone();
        gaps.insert(0, duplicate);
        if mutation_was_accepted(scenario, &scenario_root, &manifest, &expected) {
            accepted.push(format!(
                "{scenario} adjacent duplicate ownership coverage gap"
            ));
        }
    }

    assert!(
        accepted.is_empty(),
        "duplicate coverage gap mutations were accepted: {accepted:?}"
    );
}

#[test]
fn stale_mixed_selection_state_mutations_fail_closed() {
    let stale_selection_error = "extraction profile identity/selection is invalid".to_owned();
    let (mixed_root, mixed_manifest, mixed_expected) = load_contract("mixed-unrelated");

    let upgrade_unknown_version = |manifest: &Value| {
        let mut upgraded = manifest.clone();
        let artifact = upgraded["artifacts"]
            .as_array_mut()
            .expect("artifacts are an array")
            .iter_mut()
            .find(|artifact| artifact["artifactId"] == "mixed-owner-unknown")
            .expect("mixed corpus has the unknown-version artifact");
        artifact["sourceVersion"] = Value::String("5.00.TEST.3260".to_owned());
        upgraded
    };
    let drop_unknown_profile_observation = |expected: &Value| {
        let mut dropped = expected.clone();
        dropped["sourceLocalObservations"]
            .as_array_mut()
            .expect("observations are an array")
            .retain(|observation| observation["kind"] != "unknownProfile");
        dropped
    };

    let upgraded_manifest = upgrade_unknown_version(&mixed_manifest);
    let stale_mixed = drop_unknown_profile_observation(&mixed_expected);
    assert_eq!(
        validate_contract(
            "mixed-unrelated",
            &mixed_root,
            &upgraded_manifest,
            &stale_mixed,
        ),
        Err(stale_selection_error.clone()),
        "stale mixedUnknownAndInvalid must fail on the derived selection state"
    );

    let mut stale_unknown_profile = drop_unknown_profile_observation(&mixed_expected);
    stale_unknown_profile["extractionProfile"]["selectionState"] =
        Value::String("unknownProfile".to_owned());
    assert_eq!(
        validate_contract(
            "mixed-unrelated",
            &mixed_root,
            &upgraded_manifest,
            &stale_unknown_profile,
        ),
        Err(stale_selection_error.clone()),
        "stale unknownProfile must also fail on the derived selection state"
    );

    let mut derived_selected = drop_unknown_profile_observation(&mixed_expected);
    derived_selected["extractionProfile"]["selectionState"] = Value::String("selected".to_owned());
    assert_eq!(
        validate_contract(
            "mixed-unrelated",
            &mixed_root,
            &upgraded_manifest,
            &derived_selected,
        ),
        Ok(()),
        "the selected state derived from the surviving sets must be accepted"
    );

    let temporary = copy_scenario_to_temporary_root("mixed-unrelated", "remove-unknown-artifact");
    std::fs::remove_file(
        temporary
            .root
            .join("evidence/client-co-management/current/CoManagementHandler.log"),
    )
    .expect("temporary unknown-version evidence is removable");
    let mut removed_manifest = mixed_manifest.clone();
    removed_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .retain(|artifact| artifact["artifactId"] != "mixed-owner-unknown");
    let mut removed_expected = mixed_expected.clone();
    removed_expected["coverage"]
        .as_array_mut()
        .expect("coverage is an array")
        .retain(|row| row["artifactId"] != "mixed-owner-unknown");
    assert_eq!(
        validate_contract(
            "mixed-unrelated",
            &temporary.root,
            &removed_manifest,
            &removed_expected,
        ),
        Err(stale_selection_error),
        "removing the only unknown-version artifact must flip the derived selection state"
    );
}

#[test]
fn sentence_final_hostname_privacy_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let (observed_root, observed_manifest, mut hostname_claim) =
        load_contract("software-center-observed");
    hostname_claim["sourceLocalObservations"][0]["claim"] =
        Value::String("Observed records remain under lab-client-01.corp.local.".to_owned());
    if mutation_was_accepted(
        "software-center-observed",
        &observed_root,
        &observed_manifest,
        &hostname_claim,
    ) {
        accepted.push("sentence-final dotted hostname in a public observation claim");
    }

    let (deferred_root, deferred_manifest, mut hostname_reason) =
        load_contract("notification-deferred");
    hostname_reason["transactions"][0]["nextArtifact"]["reason"] =
        Value::String("Collect the bounded continuation from lab-client-01.corp.local.".to_owned());
    if mutation_was_accepted(
        "notification-deferred",
        &deferred_root,
        &deferred_manifest,
        &hostname_reason,
    ) {
        accepted.push("sentence-final dotted hostname in a next-artifact request reason");
    }

    assert!(
        accepted.is_empty(),
        "sentence-final hostname mutations were accepted: {accepted:?}"
    );
}

#[test]
fn sid_shaped_public_identifier_mutations_fail_closed() {
    let synthetic_sid = "s-1-5-21-1004336348-1177238915-682003330-512";
    let mut accepted = Vec::new();

    let (observed_root, observed_manifest, mut sid_observation_id) =
        load_contract("software-center-observed");
    sid_observation_id["sourceLocalObservations"][0]["observationId"] =
        Value::String(synthetic_sid.to_owned());
    if mutation_was_accepted(
        "software-center-observed",
        &observed_root,
        &observed_manifest,
        &sid_observation_id,
    ) {
        accepted.push("SID-shaped public observation id");
    }

    let (script_root, script_manifest, mut sid_transaction_id) = load_contract("script-success");
    sid_transaction_id["transactions"][0]["transactionId"] =
        Value::String(synthetic_sid.to_owned());
    if mutation_was_accepted(
        "script-success",
        &script_root,
        &script_manifest,
        &sid_transaction_id,
    ) {
        accepted.push("SID-shaped public transaction id");
    }

    assert!(
        accepted.is_empty(),
        "SID-shaped public identifier mutations were accepted: {accepted:?}"
    );
}

#[test]
fn absurd_citation_ranges_fail_fast_before_expansion() {
    let (script_root, script_manifest, script_expected) = load_contract("script-success");

    let mut absurd_transaction_range = script_expected.clone();
    absurd_transaction_range["transactions"][0]["evidence"] = serde_json::json!([
        { "artifactId": "script-success-current", "startLine": 1, "endLine": u64::MAX }
    ]);
    let error = validate_contract(
        "script-success",
        &script_root,
        &script_manifest,
        &absurd_transaction_range,
    )
    .expect_err("absurd transaction endLine must be rejected");
    assert!(
        error.contains("evidence line range"),
        "absurd transaction endLine must fail range validation, got: {error}"
    );

    let mut absurd_ownership_range = script_expected;
    absurd_ownership_range["ownership"]["evidence"] = serde_json::json!([
        { "artifactId": "script-success-owner", "startLine": 1, "endLine": u64::MAX }
    ]);
    let error = validate_contract(
        "script-success",
        &script_root,
        &script_manifest,
        &absurd_ownership_range,
    )
    .expect_err("absurd ownership endLine must be rejected");
    assert!(
        error.contains("evidence line range"),
        "absurd ownership endLine must fail range validation, got: {error}"
    );
}

#[test]
fn network_identifier_token_mutations_fail_closed() {
    let mut accepted = Vec::new();

    let (observed_root, observed_manifest, observed_expected) =
        load_contract("software-center-observed");

    let mut dotted_quad_claim = observed_expected.clone();
    dotted_quad_claim["sourceLocalObservations"][0]["claim"] =
        Value::String("Observed records remain under 10.20.30.40.".to_owned());
    if mutation_was_accepted(
        "software-center-observed",
        &observed_root,
        &observed_manifest,
        &dotted_quad_claim,
    ) {
        accepted.push("sentence-final dotted quad in a public observation claim");
    }

    let mut hyphen_label_host_claim = observed_expected;
    hyphen_label_host_claim["sourceLocalObservations"][0]["claim"] =
        Value::String("Observed records remain under lab-client-01.corp.local-side.".to_owned());
    if mutation_was_accepted(
        "software-center-observed",
        &observed_root,
        &observed_manifest,
        &hyphen_label_host_claim,
    ) {
        accepted.push("hyphen-joined final label hostname in a public observation claim");
    }

    let (deferred_root, deferred_manifest, mut dotted_quad_reason) =
        load_contract("notification-deferred");
    dotted_quad_reason["transactions"][0]["nextArtifact"]["reason"] =
        Value::String("Collect the bounded continuation from 10.20.30.40.".to_owned());
    if mutation_was_accepted(
        "notification-deferred",
        &deferred_root,
        &deferred_manifest,
        &dotted_quad_reason,
    ) {
        accepted.push("sentence-final dotted quad in a next-artifact request reason");
    }

    assert!(
        accepted.is_empty(),
        "network-identifier token mutations were accepted: {accepted:?}"
    );
}

#[test]
fn sid_authority_variant_mutations_fail_closed() {
    let entra_sid = "s-1-12-1-1004336348-1177238915-682003330-512";
    let capability_sid = "s-1-15-3-1024-2044478260";
    let mut accepted = Vec::new();

    let (observed_root, observed_manifest, observed_expected) =
        load_contract("software-center-observed");

    let mut sid_observation_id = observed_expected.clone();
    sid_observation_id["sourceLocalObservations"][0]["observationId"] =
        Value::String(entra_sid.to_owned());
    if mutation_was_accepted(
        "software-center-observed",
        &observed_root,
        &observed_manifest,
        &sid_observation_id,
    ) {
        accepted.push("Entra-authority SID as a public observation id");
    }

    let mut sid_claim = observed_expected;
    sid_claim["sourceLocalObservations"][0]["claim"] = Value::String(format!(
        "Observed records remain under {entra_sid} markers."
    ));
    if mutation_was_accepted(
        "software-center-observed",
        &observed_root,
        &observed_manifest,
        &sid_claim,
    ) {
        accepted.push("Entra-authority SID inside a public observation claim");
    }

    let (script_root, script_manifest, mut sid_transaction_id) = load_contract("script-success");
    sid_transaction_id["transactions"][0]["transactionId"] =
        Value::String(capability_sid.to_owned());
    if mutation_was_accepted(
        "script-success",
        &script_root,
        &script_manifest,
        &sid_transaction_id,
    ) {
        accepted.push("capability-authority SID as a public transaction id");
    }

    let (deferred_root, deferred_manifest, mut sid_reason) = load_contract("notification-deferred");
    sid_reason["transactions"][0]["nextArtifact"]["reason"] = Value::String(format!(
        "Collect the bounded continuation for {capability_sid} records."
    ));
    if mutation_was_accepted(
        "notification-deferred",
        &deferred_root,
        &deferred_manifest,
        &sid_reason,
    ) {
        accepted.push("capability-authority SID inside a next-artifact request reason");
    }

    assert!(
        accepted.is_empty(),
        "SID authority variant mutations were accepted: {accepted:?}"
    );

    // Boundary controls: bare s-1-5 carries no subauthority run and is not a SID.
    assert!(
        public_free_text_is_safe("Access remained denied for the s-1-5 authority marker."),
        "bare s-1-5 free text must stay accepted"
    );
    assert!(
        public_identifier_is_safe("software-center-observed-s-1-5"),
        "bare s-1-5 identifier suffix must stay accepted"
    );
}

#[test]
fn two_subauthority_sid_free_text_mutations_fail_closed() {
    // Well-known SIDs that carry exactly two subauthorities outside the s-1-5
    // personal family: Nobody (s-1-0-0), Everyone (s-1-1-0), Local (s-1-2-0)
    // and the integrity levels (s-1-16-4096, s-1-16-8192, s-1-16-12288).
    const CLAIM_MUTATIONS: [(&str, &str); 5] = [
        (
            "mid-sentence Nobody SID",
            "Observed records remain under s-1-0-0 markers.",
        ),
        (
            "sentence-final integrity SID",
            "Observed records remain withheld at s-1-16-12288.",
        ),
        (
            "parenthesized Everyone SID",
            "Observed records remain bounded (s-1-1-0) for this capture.",
        ),
        (
            "comma-followed Local SID",
            "Observed records remain under s-1-2-0, and stay source local.",
        ),
        (
            "sentence-final Everyone SID",
            "Observed records remain withheld at s-1-1-0.",
        ),
    ];
    const REASON_MUTATIONS: [(&str, &str); 5] = [
        (
            "mid-sentence Everyone SID",
            "Collect the bounded continuation for s-1-1-0 records.",
        ),
        (
            "sentence-final Nobody SID",
            "Collect the bounded continuation for s-1-0-0.",
        ),
        (
            "parenthesized integrity SID",
            "Collect the bounded continuation (s-1-16-8192) for this group.",
        ),
        (
            "comma-followed integrity SID",
            "Collect the bounded continuation for s-1-16-4096, then stop.",
        ),
        (
            "mid-sentence Local SID",
            "Collect the bounded continuation for s-1-2-0 records.",
        ),
    ];

    let mut accepted = Vec::new();

    let (observed_root, observed_manifest, observed_expected) =
        load_contract("software-center-observed");
    for (label, claim) in CLAIM_MUTATIONS {
        let mut mutated = observed_expected.clone();
        mutated["sourceLocalObservations"][0]["claim"] = Value::String(claim.to_owned());
        if mutation_was_accepted(
            "software-center-observed",
            &observed_root,
            &observed_manifest,
            &mutated,
        ) {
            accepted.push(format!("{label} in a public observation claim"));
        }
    }

    let (deferred_root, deferred_manifest, deferred_expected) =
        load_contract("notification-deferred");
    for (label, reason) in REASON_MUTATIONS {
        let mut mutated = deferred_expected.clone();
        mutated["transactions"][0]["nextArtifact"]["reason"] = Value::String(reason.to_owned());
        if mutation_was_accepted(
            "notification-deferred",
            &deferred_root,
            &deferred_manifest,
            &mutated,
        ) {
            accepted.push(format!("{label} in a next-artifact request reason"));
        }
    }

    assert!(
        accepted.is_empty(),
        "two-subauthority SID free-text mutations were accepted: {accepted:?}"
    );

    // Designed acceptances that the token rule must preserve.
    for accepted_text in [
        "Access remained denied for the s-1-5 authority marker.",
        "Observed records remain under s-1-abc-123 markers.",
        "Collect the bounded continuation for s-1-abc-123 records.",
    ] {
        assert!(
            public_free_text_is_safe(accepted_text),
            "{accepted_text:?} must stay accepted"
        );
    }

    // The identifier surface already fails closed on these runs and must not move.
    for identifier in [
        "software-center-observed-s-1-0-0",
        "notification-deferred-s-1-16-12288",
    ] {
        assert!(
            !public_identifier_is_safe(identifier),
            "{identifier:?} must stay rejected as a public identifier"
        );
    }
    for identifier in ["software-center-observed-s-1-5", "s-1-abc-123"] {
        assert!(
            public_identifier_is_safe(identifier),
            "{identifier:?} must stay accepted as a public identifier"
        );
    }
}
