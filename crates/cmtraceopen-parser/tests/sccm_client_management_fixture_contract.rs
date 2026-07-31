use cmtraceopen_parser::models::log_entry::LogFormat;
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
    message: String,
    offset: Option<i32>,
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
    source_name: &str,
    sanitized_source_path: &str,
) -> Result<(), String> {
    let required_prefix = format!("SYNTHETIC://client/management/{scenario}/");
    let suffix = sanitized_source_path
        .strip_prefix(&required_prefix)
        .unwrap_or_default();
    let lower_suffix = suffix.to_ascii_lowercase();
    if !sanitized_source_path.starts_with(&required_prefix)
        || !sanitized_source_path.ends_with(source_name)
        || sanitized_source_path.contains(['\\', '\n', '\r'])
        || suffix
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || lower_suffix.contains("%2e")
        || suffix.contains(['?', '#'])
    {
        return Err(format!(
            "source path {sanitized_source_path} is not bounded synthetic provenance"
        ));
    }
    Ok(())
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
            let (entries, _) =
                cmtraceopen_parser::parser::ccm::parse_content(line, artifact_id, None);
            if entries.len() != 1 || entries[0].format != LogFormat::Ccm {
                return Err(format!(
                    "{artifact_id} cited line is not one complete CCM logical record"
                ));
            }
            records.push(EvidenceRecord {
                message: entries[0].message.clone(),
                offset: entries[0].timezone_offset,
                source_version: required_string(artifact, "sourceVersion", artifact_id)?.to_owned(),
            });
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
        let (entries, _) = cmtraceopen_parser::parser::ccm::parse_content(line, artifact_id, None);
        if entries.len() != 1 || entries[0].format != LogFormat::Ccm {
            return Err(format!(
                "{artifact_id} complete physical artifact has a malformed CCM record"
            ));
        }
        records.push(EvidenceRecord {
            message: entries[0].message.clone(),
            offset: entries[0].timezone_offset,
            source_version: required_string(artifact, "sourceVersion", artifact_id)?.to_owned(),
        });
    }
    Ok(records)
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

fn validate_contract(
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
    expected: &Value,
) -> Result<(), String> {
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
    let mut expected_coverage = BTreeMap::new();
    let mut unknown_version_artifacts = BTreeSet::new();
    let mut invalid_offset_artifacts = BTreeSet::new();

    for artifact in artifacts {
        let artifact_id = required_string(artifact, "artifactId", "artifact")?;
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
            validate_relative_path(relative_path, source_name, rotation_kind)?;
            if !relative_paths.insert(relative_path.to_owned()) {
                return Err(format!("duplicate physical evidence path {relative_path}"));
            }
            let sanitized_source_path =
                required_string(artifact, "sanitizedSourcePath", artifact_id)?;
            validate_source_path(scenario, source_name, sanitized_source_path)?;
            let path_fingerprint = required_string(artifact, "pathFingerprint", artifact_id)?;
            if !path_fingerprint.starts_with("safe:path:326:")
                || !path_fingerprints.insert(path_fingerprint.to_owned())
            {
                return Err(format!(
                    "{artifact_id} has blank, unsafe, or colliding path provenance"
                ));
            }
            let source_version = required_string(artifact, "sourceVersion", artifact_id)?;
            if required_parser_eligibility && !source_version.starts_with("5.00.TEST.") {
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
                    validate_source_path(scenario, source_name, source_path)?;
                    let path_fingerprint =
                        required_string(artifact, "pathFingerprint", artifact_id)?;
                    if !path_fingerprint.starts_with("safe:path:326:")
                        || !path_fingerprints.insert(path_fingerprint.to_owned())
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
                .any(|record| record.offset.is_some_and(|offset| offset.abs() > 1_439))
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
            path.strip_prefix(scenario_root)
                .expect("walk root is below scenario")
                .to_string_lossy()
                .into_owned()
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
        "mixed" => "mixedUnknownAndInvalid",
        _ if !unknown_version_artifacts.is_empty() => "unknownProfile",
        _ => "selected",
    };
    let profile = &expected["extractionProfile"];
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
    let ownership_class = required_string(ownership, "classification", "ownership")?;
    let ownership_confidence = required_string(ownership, "confidence", "ownership")?;
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
    if ownership_ref_order != sorted_ownership_refs {
        return Err("ownership evidence is not deterministically sorted".to_owned());
    }
    if ownership_class != "UnknownOwnership" {
        let workload = required_string(ownership, "workload", "ownership")?;
        if ownership_records.is_empty()
            || ownership_records.iter().any(|record| {
                !record.message.contains(&format!("Workload={workload}"))
                    || !record
                        .message
                        .contains(&format!("Ownership={ownership_class}"))
            })
        {
            return Err("ownership classification is not bound to cited evidence".to_owned());
        }
        if ownership_records.iter().any(|record| {
            record.offset.is_none_or(|offset| offset.abs() > 1_439)
                || !record.source_version.starts_with("5.00.TEST.")
        }) {
            return Err(
                "ownership classification lacks usable timestamp/profile provenance".to_owned(),
            );
        }
        match ownership_class {
            "SccmOwned"
                if ownership_records.iter().any(|record| {
                    !record.message.contains("Disposition=Owned")
                        || !record.message.contains("Terminal=true")
                }) =>
            {
                return Err("SCCM ownership lacks terminal owned evidence".to_owned());
            }
            "IntuneOwned"
                if ownership_records.iter().any(|record| {
                    !record.message.contains("Disposition=Handoff")
                        || !record.message.contains("Terminal=true")
                }) =>
            {
                return Err("Intune ownership lacks terminal handoff evidence".to_owned());
            }
            "SharedOrTransitioning"
                if ownership_records.iter().any(|record| {
                    !record.message.contains("Disposition=Transitioning")
                        || !record.message.contains("Terminal=false")
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
        .any(|record| record.message.contains("Ownership=SccmOwned"))
        || !ownership_records
            .iter()
            .any(|record| record.message.contains("Ownership=IntuneOwned"))
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
    if ownership_gap_ids != sorted_ownership_gap_ids {
        return Err("ownership coverage gaps are not sorted".to_owned());
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
    if ownership_class != "SccmOwned" && !transactions.is_empty() {
        return Err("operational transactions require evidenced SCCM ownership".to_owned());
    }
    if matches!(workflow, "coManagement" | "softwareCenter" | "mixed") && !transactions.is_empty() {
        return Err(format!("{workflow} cannot ship operational transactions"));
    }
    let mut transaction_ids = BTreeSet::new();
    let mut transaction_order = Vec::new();
    for transaction in transactions {
        let transaction_id = required_string(transaction, "transactionId", "transaction")?;
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
        if transaction_ref_order != sorted_transaction_refs {
            return Err(format!(
                "{transaction_id} evidence references are not sorted"
            ));
        }
        let records = evidence_records(scenario_root, &artifacts_by_id, &transaction["evidence"])?;
        if records.is_empty() {
            return Err(format!("{transaction_id} has no cited evidence"));
        }
        for record in &records {
            for field in fields {
                let value = required_string(key, field, transaction_id)?;
                if !record.message.contains(&format!("{field}={value}")) {
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
        if confidence == "high"
            && records.iter().any(|record| {
                record.offset.is_none_or(|offset| offset.abs() > 1_439)
                    || !record.source_version.starts_with("5.00.TEST.")
            })
        {
            return Err(format!(
                "{transaction_id} high confidence lacks usable time/profile provenance"
            ));
        }
        let classification = required_string(transaction, "classification", transaction_id)?;
        let state = required_string(transaction, "state", transaction_id)?;
        let has_record = |disposition: &str, terminal: bool| {
            records.iter().any(|record| {
                record.message.contains(&format!("Phase={phase}"))
                    && record
                        .message
                        .contains(&format!("Disposition={disposition}"))
                    && record.message.contains(&format!("Terminal={terminal}"))
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
                        record
                            .message
                            .contains(&format!("Phase={last_successful_phase}"))
                            && record.message.contains("Disposition=Succeeded")
                            && record.message.contains("Terminal=false")
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
        if coverage_gap_ids != sorted_gap_ids {
            return Err(format!("{transaction_id} coverage gaps are not sorted"));
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
    let mut observed_unknown_profiles = BTreeSet::new();
    let mut observed_invalid_offsets = BTreeSet::new();
    let mut observation_ids = BTreeSet::new();
    let mut observation_order = Vec::new();
    for observation in observations {
        let observation_id = required_string(observation, "observationId", "observation")?;
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
            || claim_tokens
                .iter()
                .any(|token| matches!(*token, "server" | "servers"))
            || lower_claim.contains("intune failure")
        {
            return Err(format!(
                "{observation_id} makes an unsupported causal claim"
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
        }
        match kind {
            "coverageGap"
                if artifact_ids.iter().any(|artifact_id| {
                    artifacts_by_id
                        .get(artifact_id.as_str())
                        .is_some_and(|artifact| effective_state(artifact) == Ok("captured"))
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
                        let has_script_key = ["ScriptId=", "ExecutionId=", "ResourceHandle="]
                            .iter()
                            .all(|token| record.message.contains(token));
                        let has_notification_key =
                            ["NotificationId=", "ChannelId=", "ResourceHandle="]
                                .iter()
                                .all(|token| record.message.contains(token));
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
