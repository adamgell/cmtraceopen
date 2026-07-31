use cmtraceopen_parser::models::log_entry::LogFormat;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

const INVENTORY_SCENARIOS: [&str; 6] = [
    "coverage-states",
    "recovery-contradictory",
    "rotation-boundary",
    "same-minute-collision",
    "success",
    "terminal-failures",
];

const COMPLIANCE_SCENARIOS: [&str; 8] = [
    "coverage-states",
    "malformed-unknown-profile-invalid-offset",
    "noncompliant-result",
    "recovery-contradictory",
    "remediation-success",
    "same-minute-collision",
    "success",
    "terminal-failures",
];

const METERING_SCENARIOS: [&str; 6] = [
    "coverage-states",
    "recovery-contradictory",
    "rotation-boundary",
    "same-minute-collision",
    "success",
    "terminal-failures",
];

const DOCUMENTED_CORPUS_DIGEST: &str = "409f976350ffbc05";

#[derive(Debug, PartialEq, Eq)]
struct CorpusInventory {
    scenarios: usize,
    artifacts: usize,
    evidence_files: usize,
    evidence_bytes: u64,
    capture_states: BTreeMap<String, usize>,
    digest: String,
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/client/inventory-compliance-metering")
}

fn directory_names(root: &Path) -> Vec<String> {
    let mut names = std::fs::read_dir(root)
        .unwrap_or_else(|error| panic!("{} exists and is readable: {error}", root.display()))
        .map(|entry| entry.expect("fixture directory entry is readable").path())
        .filter(|path| path.is_dir())
        .map(|path| {
            path.file_name()
                .expect("fixture directory has a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn load_json(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} contains valid JSON: {error}", path.display()))
}

fn family_scenarios() -> [(&'static str, &'static [&'static str]); 3] {
    [
        ("inventory", INVENTORY_SCENARIOS.as_slice()),
        ("compliance", COMPLIANCE_SCENARIOS.as_slice()),
        ("metering", METERING_SCENARIOS.as_slice()),
    ]
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

    for (family, scenarios) in family_scenarios() {
        for scenario in scenarios {
            let (scenario_root, manifest, _) = load_contract(family, scenario);
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
                    "{family}/{scenario}\0{}\0{relative_path}\0{}\n",
                    artifact["artifactId"]
                        .as_str()
                        .expect("artifactId is a string"),
                    hex_bytes(&bytes)
                ));
            }
        }
    }
    digest_rows.sort();

    CorpusInventory {
        scenarios: 20,
        artifacts,
        evidence_files,
        evidence_bytes,
        capture_states,
        digest: fnv1a64(digest_rows.concat().as_bytes()),
    }
}

fn load_contract(family: &str, scenario: &str) -> (PathBuf, Value, Value) {
    let scenario_root = corpus_root().join(family).join(scenario);
    (
        scenario_root.clone(),
        load_json(&scenario_root.join("manifest.json")),
        load_json(&scenario_root.join("expected.json")),
    )
}

fn required_key_fields(family: &str) -> Result<&'static [&'static str], String> {
    match family {
        "inventory" => Ok(&["InventoryCycleId", "ResourceHandle", "ReportId"]),
        "compliance" => Ok(&["CiId", "BaselineId", "StateId", "ResourceHandle"]),
        "metering" => Ok(&["MeteringCycleId", "RuleId", "ReportId", "ResourceHandle"]),
        other => Err(format!("unsupported workflow family {other}")),
    }
}

fn admitted_sources(family: &str) -> Result<&'static [&'static str], String> {
    match family {
        "inventory" => Ok(&[
            "InventoryAgent.log",
            "InventoryProvider.log",
            "InventoryAgentProvider.log",
        ]),
        "compliance" => Ok(&[
            "CIAgent.log",
            "CITaskMgr.log",
            "DCMAgent.log",
            "DCMReporting.log",
            "StateMessage.log",
        ]),
        "metering" => Ok(&["SWMTRReportGen.log"]),
        other => Err(format!("unsupported workflow family {other}")),
    }
}

fn admitted_phases(family: &str) -> Result<&'static [&'static str], String> {
    match family {
        "inventory" => Ok(&["Collect", "Provider", "Serialize", "Queue", "Report"]),
        "compliance" => Ok(&["Evaluate", "Remediate", "Report"]),
        "metering" => Ok(&["Collect", "Aggregate", "Report"]),
        other => Err(format!("unsupported workflow family {other}")),
    }
}

fn expected_logical_artifact(family: &str) -> Result<&'static str, String> {
    match family {
        "inventory" => Ok("client-inventory"),
        "compliance" => Ok("client-compliance"),
        "metering" => Ok("client-metering"),
        other => Err(format!("unsupported workflow family {other}")),
    }
}

fn expected_profile(family: &str) -> Result<&'static str, String> {
    match family {
        "inventory" => Ok("sccm-client-inventory-5.00.test-v1"),
        "compliance" => Ok("sccm-client-compliance-5.00.test-v1"),
        "metering" => Ok("sccm-client-metering-5.00.test-v1"),
        other => Err(format!("unsupported workflow family {other}")),
    }
}

fn required_scenario_semantics(
    family: &str,
    scenario: &str,
) -> Result<&'static [&'static str], String> {
    match (family, scenario) {
        ("inventory", "success") => Ok(&["Report|succeeded|success"]),
        ("inventory", "terminal-failures") => Ok(&[
            "Collect|failed|confirmedFailure",
            "Provider|failed|confirmedFailure",
            "Serialize|failed|confirmedFailure",
            "Queue|failed|confirmedFailure",
            "Report|failed|confirmedFailure",
        ]),
        ("inventory", "recovery-contradictory") => {
            Ok(&["Report|recovered|recovery", "Report|contradictory|symptom"])
        }
        ("inventory", "same-minute-collision") => {
            Ok(&["Report|succeeded|success", "Report|succeeded|success"])
        }
        ("inventory", "coverage-states" | "rotation-boundary") => Ok(&[]),
        ("compliance", "success") => Ok(&["Report|succeeded|success"]),
        ("compliance", "noncompliant-result") => {
            Ok(&["Evaluate|evaluatedNonCompliant|evaluationResult"])
        }
        ("compliance", "remediation-success") => Ok(&["Report|remediated|success"]),
        ("compliance", "terminal-failures") => Ok(&[
            "Evaluate|failed|confirmedFailure",
            "Remediate|failed|confirmedFailure",
            "Report|failed|confirmedFailure",
        ]),
        ("compliance", "recovery-contradictory") => Ok(&[
            "Report|recovered|recovery",
            "Evaluate|contradictory|symptom",
        ]),
        ("compliance", "same-minute-collision") => Ok(&[
            "Evaluate|evaluatedNonCompliant|evaluationResult",
            "Evaluate|evaluatedCompliant|evaluationResult",
        ]),
        ("compliance", "coverage-states" | "malformed-unknown-profile-invalid-offset") => Ok(&[]),
        ("metering", "success") => Ok(&["Report|succeeded|success"]),
        ("metering", "terminal-failures") => Ok(&[
            "Collect|failed|confirmedFailure",
            "Aggregate|failed|confirmedFailure",
            "Report|failed|confirmedFailure",
        ]),
        ("metering", "recovery-contradictory") => {
            Ok(&["Report|recovered|recovery", "Report|contradictory|symptom"])
        }
        ("metering", "same-minute-collision") => {
            Ok(&["Report|succeeded|success", "Report|succeeded|success"])
        }
        ("metering", "coverage-states" | "rotation-boundary") => Ok(&[]),
        _ => Err(format!(
            "required scenario semantics are undefined for {family}/{scenario}"
        )),
    }
}

fn required_string<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{context} {field} is not a string"))
}

fn effective_state(artifact: &Value) -> Result<String, String> {
    let artifact_id = artifact["artifactId"].as_str().unwrap_or("<unknown>");
    match required_string(artifact, "captureState", artifact_id)? {
        "captured" => {
            let complete = artifact["rotation"]["fragmentComplete"]
                .as_bool()
                .ok_or_else(|| format!("{artifact_id} fragmentComplete is not a bool"))?;
            Ok(if complete { "captured" } else { "partial" }.to_owned())
        }
        state @ ("absent" | "accessDenied" | "capped" | "skipped" | "unsupported"
        | "parseFailed") => Ok(state.to_owned()),
        other => Err(format!(
            "{artifact_id} has unsupported captureState {other}"
        )),
    }
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            let mut children = std::fs::read_dir(&path)
                .map_err(|error| format!("{} is readable: {error}", path.display()))?
                .map(|entry| {
                    entry
                        .map(|value| value.path())
                        .map_err(|error| format!("{} entry is readable: {error}", path.display()))
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

fn validate_relative_path(relative_path: &str, artifact_id: &str) -> Result<(), String> {
    let path = Path::new(relative_path);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "{artifact_id} relativePath escapes the scenario: {relative_path}"
        ));
    }
    if !relative_path.starts_with("evidence/") {
        return Err(format!(
            "{artifact_id} relativePath is outside the evidence root"
        ));
    }
    Ok(())
}

fn validate_next_artifact(
    family: &str,
    transaction_id: &str,
    next_artifact: &Value,
) -> Result<(), String> {
    if next_artifact.is_null() {
        return Ok(());
    }
    let object = next_artifact
        .as_object()
        .ok_or_else(|| format!("{transaction_id} nextArtifact is not an object"))?;
    let actual_fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_fields = ["logicalArtifactId", "reason", "sourceBasename"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual_fields != expected_fields {
        return Err(format!(
            "{transaction_id} nextArtifact fields are not the bounded contract"
        ));
    }
    if required_string(
        next_artifact,
        "logicalArtifactId",
        &format!("{transaction_id} nextArtifact"),
    )? != expected_logical_artifact(family)?
    {
        return Err(format!(
            "{transaction_id} nextArtifact crosses workflow families"
        ));
    }
    let source = required_string(
        next_artifact,
        "sourceBasename",
        &format!("{transaction_id} nextArtifact"),
    )?;
    if !admitted_sources(family)?.contains(&source) {
        return Err(format!(
            "{transaction_id} nextArtifact names unadmitted source {source}"
        ));
    }
    let reason = required_string(
        next_artifact,
        "reason",
        &format!("{transaction_id} nextArtifact"),
    )?;
    let lower = reason.to_ascii_lowercase();
    if reason.is_empty()
        || reason.len() > 120
        || reason.contains(['*', '\\', '/'])
        || [
            "recursive",
            "every log",
            "all logs",
            "all files",
            "volume",
            "drive",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return Err(format!(
            "{transaction_id} nextArtifact reason is unbounded or path-bearing"
        ));
    }
    Ok(())
}

fn evidence_record_texts(
    scenario_root: &Path,
    artifacts_by_id: &BTreeMap<String, &Value>,
    evidence_refs: &[Value],
) -> Result<Vec<(String, i32, String, i64)>, String> {
    let mut records = Vec::new();
    for evidence_ref in evidence_refs {
        let artifact_id = required_string(evidence_ref, "artifactId", "evidence reference")?;
        let artifact = artifacts_by_id
            .get(artifact_id)
            .ok_or_else(|| format!("evidence cites unknown artifact {artifact_id}"))?;
        if effective_state(artifact)? != "captured" {
            return Err(format!(
                "evidence cites non-complete artifact {artifact_id}"
            ));
        }
        let relative_path = required_string(artifact, "relativePath", artifact_id)?;
        let contents = std::fs::read_to_string(scenario_root.join(relative_path))
            .map_err(|error| format!("{artifact_id} evidence is readable: {error}"))?;
        let lines = contents.lines().collect::<Vec<_>>();
        let start = evidence_ref["startLine"]
            .as_u64()
            .ok_or_else(|| format!("{artifact_id} evidence startLine is not an integer"))?
            as usize;
        let end = evidence_ref["endLine"]
            .as_u64()
            .ok_or_else(|| format!("{artifact_id} evidence endLine is not an integer"))?
            as usize;
        if start == 0 || end < start || end > lines.len() {
            return Err(format!(
                "{artifact_id} evidence range {start}-{end}/{} is invalid",
                lines.len()
            ));
        }
        for (offset, line) in lines[start - 1..end].iter().enumerate() {
            let (entries, errors) =
                cmtraceopen_parser::parser::ccm::parse_content(line, artifact_id, None);
            if errors != 0
                || entries.len() != 1
                || entries[0].format != LogFormat::Ccm
                || entries[0].line_number != 1
            {
                return Err(format!(
                    "{artifact_id}:{} is not one complete CCM record",
                    start + offset
                ));
            }
            let offset_minutes = entries[0]
                .timezone_offset
                .ok_or_else(|| format!("{artifact_id}:{} has no source offset", start + offset))?;
            let timestamp = entries[0].timestamp.ok_or_else(|| {
                format!(
                    "{artifact_id}:{} has no usable source timestamp",
                    start + offset
                )
            })?;
            let source_version = required_string(artifact, "sourceVersion", artifact_id)?;
            records.push((
                (*line).to_owned(),
                offset_minutes,
                source_version.to_owned(),
                timestamp,
            ));
        }
    }
    Ok(records)
}

fn record_exact_token_values<'a>(record: &'a str, field: &str) -> Vec<&'a str> {
    const MESSAGE_PREFIX: &str = "<![LOG[";
    const MESSAGE_SUFFIX: &str = "]LOG]!>";
    let Some(message_start) = record.find(MESSAGE_PREFIX) else {
        return Vec::new();
    };
    let payload_start = message_start + MESSAGE_PREFIX.len();
    let Some(message_end) = record[payload_start..].find(MESSAGE_SUFFIX) else {
        return Vec::new();
    };
    record[payload_start..payload_start + message_end]
        .split_ascii_whitespace()
        .filter_map(|token| {
            let (name, value) = token.split_once('=')?;
            (name == field).then_some(value)
        })
        .collect()
}

fn record_contains_exact_key_pair(record: &str, field: &str, value: &str) -> bool {
    record_exact_token_values(record, field).contains(&value)
}

fn validate_contract(
    family: &str,
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
    expected: &Value,
) -> Result<(), String> {
    let logical_artifact = expected_logical_artifact(family)?;
    let sources = admitted_sources(family)?;
    let phases = admitted_phases(family)?;
    let profile = expected_profile(family)?;

    if manifest["sccmManifestVersion"] != 1
        || manifest["contractState"] != "proposedPending318And319"
        || manifest["proposalOnly"] != true
        || manifest["syntheticFixture"] != true
        || manifest["scenario"] != scenario
        || manifest["workflowFamily"] != family
    {
        return Err("manifest identity/version/proposal contract is invalid".to_owned());
    }
    if manifest["bundle"]["role"] != "client"
        || manifest["bundle"]["captureHost"] != "LAB-CLIENT-01"
        || manifest["bundle"]["siteCode"] != "LAB"
    {
        return Err("bundle identity is not the sanitized client fixture identity".to_owned());
    }
    let bundle_id = required_string(&manifest["bundle"], "bundleId", "bundle")?;
    if !bundle_id.starts_with(&format!("sccm-325-{family}-")) {
        return Err("bundleId is not issue/family scoped".to_owned());
    }

    let artifacts = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| "manifest artifacts are not an array".to_owned())?;
    if artifacts.is_empty() {
        return Err("scenario has no artifacts".to_owned());
    }
    let mut artifacts_by_id = BTreeMap::new();
    let mut relative_paths = BTreeSet::new();
    let mut path_fingerprints = BTreeSet::new();
    let mut referenced_files = BTreeSet::new();
    let mut expected_coverage = BTreeMap::new();
    let mut unknown_version_artifacts = BTreeSet::new();
    let mut invalid_offset_artifacts = BTreeSet::new();

    for artifact in artifacts {
        let artifact_id = required_string(artifact, "artifactId", "artifact")?;
        if artifacts_by_id
            .insert(artifact_id.to_owned(), artifact)
            .is_some()
        {
            return Err(format!("duplicate artifactId {artifact_id}"));
        }
        if artifact["role"] != "client" || artifact["kind"] != "ccmLog" {
            return Err(format!("{artifact_id} is not a client CCM artifact"));
        }
        let captured_utc = required_string(artifact, "capturedUtc", artifact_id)?;
        let parsed_captured_utc = chrono::DateTime::parse_from_rfc3339(captured_utc)
            .map_err(|error| format!("{artifact_id} capturedUtc is invalid: {error}"))?;
        let canonical_captured_utc =
            parsed_captured_utc.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        if parsed_captured_utc.offset().local_minus_utc() != 0
            || canonical_captured_utc != captured_utc
        {
            return Err(format!(
                "{artifact_id} capturedUtc is not canonical UTC provenance"
            ));
        }
        if artifact["designOnlyCatalog"]["entryId"] != logical_artifact
            || artifact["designOnlyCatalog"]["groupMemberships"] != json!([logical_artifact])
        {
            return Err(format!("{artifact_id} crosses logical workflow families"));
        }

        let basename = required_string(artifact, "originalBasename", artifact_id)?;
        let admitted_basename = basename.strip_suffix(".lo").unwrap_or(basename);
        if !sources.contains(&admitted_basename) {
            return Err(format!(
                "{artifact_id} uses unadmitted {family} source {basename}"
            ));
        }
        let rotation_kind = required_string(&artifact["rotation"], "kind", artifact_id)?;
        match rotation_kind {
            "current" if basename.ends_with(".lo") => {
                return Err(format!("{artifact_id} current rotation has .lo basename"));
            }
            "lo" if !basename.ends_with(".lo") => {
                return Err(format!("{artifact_id} lo rotation lacks .lo basename"));
            }
            "current" | "lo" => {}
            other => return Err(format!("{artifact_id} has unsupported rotation {other}")),
        }

        let state = effective_state(artifact)?;
        if expected_coverage
            .insert(artifact_id.to_owned(), state.clone())
            .is_some()
        {
            return Err(format!("duplicate coverage identity {artifact_id}"));
        }
        let capture_state = required_string(artifact, "captureState", artifact_id)?;
        let physical = matches!(capture_state, "captured" | "capped" | "parseFailed");
        let relative_path = artifact["relativePath"].as_str();
        if physical != relative_path.is_some() {
            return Err(format!(
                "{artifact_id} physical path does not match capture state {capture_state}"
            ));
        }

        if let Some(relative_path) = relative_path {
            validate_relative_path(relative_path, artifact_id)?;
            if !relative_path.contains(&format!("/{rotation_kind}/"))
                || !relative_path.ends_with(basename)
            {
                return Err(format!(
                    "{artifact_id} path is incoherent with rotation/basename"
                ));
            }
            if !relative_paths.insert(relative_path.to_owned()) {
                return Err(format!("duplicate physical evidence path {relative_path}"));
            }
            let full_path = scenario_root.join(relative_path);
            let bytes = std::fs::read(&full_path)
                .map_err(|error| format!("{} is readable: {error}", full_path.display()))?;
            let declared_bytes = artifact["bytesCopied"]
                .as_u64()
                .ok_or_else(|| format!("{artifact_id} bytesCopied is not an integer"))?;
            if declared_bytes != bytes.len() as u64 {
                return Err(format!(
                    "{artifact_id} bytesCopied {declared_bytes} != {}",
                    bytes.len()
                ));
            }
            if artifact["encoding"] != "utf-8" || std::str::from_utf8(&bytes).is_err() {
                return Err(format!("{artifact_id} is not declared and encoded UTF-8"));
            }
            if capture_state == "capped" {
                let byte_limit = artifact["collectionLimit"]["byteLimit"]
                    .as_u64()
                    .ok_or_else(|| format!("{artifact_id} capped byteLimit is not an integer"))?;
                if artifact["collectionLimit"]["limitApplied"] != true
                    || artifact["truncated"] != true
                    || artifact["rotation"]["fragmentComplete"] != false
                    || byte_limit != declared_bytes
                {
                    return Err(format!(
                        "{artifact_id} capped state is not an inclusive exact prefix"
                    ));
                }
            }
            if capture_state == "parseFailed" && artifact["rotation"]["fragmentComplete"] != false {
                return Err(format!(
                    "{artifact_id} parseFailed artifact is marked complete"
                ));
            }
            let sanitized_path = required_string(artifact, "sanitizedSourcePath", artifact_id)?;
            if !sanitized_path.starts_with("SYNTHETIC://") || !sanitized_path.ends_with(basename) {
                return Err(format!("{artifact_id} source path is not sanitized"));
            }
            let fingerprint = required_string(artifact, "pathFingerprint", artifact_id)?;
            if fingerprint.is_empty() || !path_fingerprints.insert(fingerprint.to_owned()) {
                return Err(format!(
                    "{artifact_id} has blank or aliased pathFingerprint"
                ));
            }
            referenced_files.insert(relative_path.to_owned());

            if let Some(version) = artifact["sourceVersion"].as_str() {
                if !version.starts_with("5.00.TEST.") {
                    unknown_version_artifacts.insert(artifact_id.to_owned());
                }
            } else {
                return Err(format!(
                    "{artifact_id} physical source has no sourceVersion"
                ));
            }

            if capture_state == "captured" && artifact["rotation"]["fragmentComplete"] == true {
                let contents = std::str::from_utf8(&bytes).expect("validated UTF-8");
                let (entries, _) =
                    cmtraceopen_parser::parser::ccm::parse_content(contents, artifact_id, None);
                if entries.iter().any(|entry| {
                    entry
                        .timezone_offset
                        .is_some_and(|offset| offset.abs() > 1_439)
                }) {
                    invalid_offset_artifacts.insert(artifact_id.to_owned());
                }
            }
        } else {
            if artifact["bytesCopied"] != 0 || artifact["rotation"]["fragmentComplete"] != false {
                return Err(format!(
                    "{artifact_id} nonphysical state has bytes or complete fragment"
                ));
            }
            if capture_state == "absent"
                && (!artifact["sanitizedSourcePath"].is_null()
                    || !artifact["pathFingerprint"].is_null()
                    || !artifact["sourceVersion"].is_null())
            {
                return Err(format!(
                    "{artifact_id} absent source invents path/version identity"
                ));
            }
            if capture_state != "absent" {
                let sanitized_path = required_string(artifact, "sanitizedSourcePath", artifact_id)?;
                if !sanitized_path.starts_with("SYNTHETIC://")
                    || !sanitized_path.ends_with(basename)
                {
                    return Err(format!(
                        "{artifact_id} attempted source path is unsanitized"
                    ));
                }
                let fingerprint = required_string(artifact, "pathFingerprint", artifact_id)?;
                if fingerprint.is_empty() || !path_fingerprints.insert(fingerprint.to_owned()) {
                    return Err(format!(
                        "{artifact_id} has blank or aliased attempted-path fingerprint"
                    ));
                }
            }
        }
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
            "manifest evidence projection differs: actual {actual_files:?}, referenced {referenced_files:?}"
        ));
    }

    if expected["contractState"] != "proposedPending318And319"
        || expected["scenario"] != scenario
        || expected["workflow"] != family
    {
        return Err("expected contract identity is invalid".to_owned());
    }
    if expected["extractionProfile"]["id"] != profile
        || expected["extractionProfile"]["versionPrefix"] != "5.00.TEST."
    {
        return Err("expected extraction profile is not family/version bound".to_owned());
    }
    let profile_selection = required_string(
        &expected["extractionProfile"],
        "selectionState",
        "extractionProfile",
    )?;
    let required_selection = if unknown_version_artifacts.is_empty() {
        "selected"
    } else {
        "mixedKnownAndUnknown"
    };
    if profile_selection != required_selection {
        return Err(format!(
            "profile selection {profile_selection} != {required_selection}"
        ));
    }

    let coverage = expected["coverage"]
        .as_array()
        .ok_or_else(|| "expected coverage is not an array".to_owned())?;
    let mut declared_coverage = BTreeMap::new();
    for row in coverage {
        let artifact_id = required_string(row, "artifactId", "coverage row")?;
        if row["logicalArtifactId"] != logical_artifact {
            return Err(format!("{artifact_id} coverage crosses workflow families"));
        }
        let state = required_string(row, "state", artifact_id)?;
        if declared_coverage
            .insert(artifact_id.to_owned(), state.to_owned())
            .is_some()
        {
            return Err(format!("duplicate coverage row {artifact_id}"));
        }
    }
    if declared_coverage != expected_coverage {
        return Err(format!(
            "coverage is not an exact manifest projection: {declared_coverage:?} != {expected_coverage:?}"
        ));
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
    if prohibited_claims.len() != 4 {
        return Err("prohibitedClaims does not cover all four safety boundaries".to_owned());
    }

    let observations = expected["sourceLocalObservations"]
        .as_array()
        .ok_or_else(|| "sourceLocalObservations is not an array".to_owned())?;
    let mut observation_ids = BTreeSet::new();
    let mut observed_artifact_ids = BTreeSet::new();
    let mut unknown_profile_observations = BTreeSet::new();
    let mut invalid_offset_observations = BTreeSet::new();
    for observation in observations {
        let observation_id = required_string(observation, "observationId", "observation")?;
        if !observation_ids.insert(observation_id.to_owned()) {
            return Err(format!("duplicate observationId {observation_id}"));
        }
        if observation["confidenceCeiling"] != "low" || observation["correlationEligible"] != false
        {
            return Err(format!(
                "{observation_id} exceeds the source-local confidence ceiling"
            ));
        }
        let kind = required_string(observation, "kind", observation_id)?;
        if !matches!(
            kind,
            "coverageGap"
                | "rotationSplit"
                | "malformedRecord"
                | "unknownProfile"
                | "invalidOffset"
        ) {
            return Err(format!("{observation_id} has unsupported kind {kind}"));
        }
        let claim = required_string(observation, "claim", observation_id)?;
        let lower_claim = claim.to_ascii_lowercase();
        let causal_word = lower_claim
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|word| {
                matches!(
                    word,
                    "cause"
                        | "caused"
                        | "causes"
                        | "causing"
                        | "causal"
                        | "because"
                        | "proves"
                        | "proof"
                )
            });
        if causal_word
            || ["root cause", "resulted in", "led to", "responsible for"]
                .iter()
                .any(|phrase| lower_claim.contains(phrase))
        {
            return Err(format!("{observation_id} makes a causal/proof claim"));
        }
        let artifact_ids = observation["artifactIds"]
            .as_array()
            .ok_or_else(|| format!("{observation_id} artifactIds is not an array"))?;
        if artifact_ids.is_empty() {
            return Err(format!(
                "{observation_id} has no bounded artifact references"
            ));
        }
        for artifact_id in artifact_ids {
            let artifact_id = artifact_id
                .as_str()
                .ok_or_else(|| format!("{observation_id} artifact ID is not a string"))?;
            if !artifacts_by_id.contains_key(artifact_id) {
                return Err(format!(
                    "{observation_id} references unknown artifact {artifact_id}"
                ));
            }
            observed_artifact_ids.insert(artifact_id.to_owned());
            if kind == "unknownProfile" {
                unknown_profile_observations.insert(artifact_id.to_owned());
            }
            if kind == "invalidOffset" {
                invalid_offset_observations.insert(artifact_id.to_owned());
            }
        }
    }
    for (artifact_id, state) in &expected_coverage {
        if state != "captured" && !observed_artifact_ids.contains(artifact_id) {
            return Err(format!(
                "{artifact_id} {state} coverage is not surfaced source-locally"
            ));
        }
    }
    if unknown_profile_observations != unknown_version_artifacts {
        return Err(format!(
            "unknown-profile observations {unknown_profile_observations:?} != artifacts {unknown_version_artifacts:?}"
        ));
    }
    if invalid_offset_observations != invalid_offset_artifacts {
        return Err(format!(
            "invalid-offset observations {invalid_offset_observations:?} != artifacts {invalid_offset_artifacts:?}"
        ));
    }

    let transactions = expected["transactions"]
        .as_array()
        .ok_or_else(|| "transactions are not an array".to_owned())?;
    let mut transaction_ids = BTreeSet::new();
    let mut scenario_semantics = Vec::new();
    for transaction in transactions {
        let transaction_id = required_string(transaction, "transactionId", "transaction")?;
        if !transaction_ids.insert(transaction_id.to_owned()) {
            return Err(format!("duplicate transactionId {transaction_id}"));
        }
        if transaction["workflow"] != family {
            return Err(format!("{transaction_id} crosses workflow families"));
        }

        let key = transaction["key"]
            .as_object()
            .ok_or_else(|| format!("{transaction_id} key is not an object"))?;
        let required_fields = required_key_fields(family)?;
        let mut expected_key_fields = required_fields.iter().copied().collect::<BTreeSet<_>>();
        expected_key_fields.extend(["keyProfileKind", "extractionProfileId", "confidence"]);
        let actual_key_fields = key.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual_key_fields != expected_key_fields {
            return Err(format!(
                "{transaction_id} key fields {actual_key_fields:?} are not exact {family} fields {expected_key_fields:?}"
            ));
        }
        if key["keyProfileKind"] != format!("{family}Exact")
            || key["extractionProfileId"] != profile
            || key["confidence"] != "exact"
        {
            return Err(format!(
                "{transaction_id} key profile/confidence is not exact and versioned"
            ));
        }
        for field in required_fields {
            let value = key[*field]
                .as_str()
                .ok_or_else(|| format!("{transaction_id} key {field} is not a string"))?;
            if value.is_empty()
                || value.contains(['\n', '\r'])
                || (field.ends_with("Handle") && !value.starts_with("safe:"))
            {
                return Err(format!("{transaction_id} key {field} is unsafe/empty"));
            }
        }

        let phase = required_string(transaction, "phase", transaction_id)?;
        if !phases.contains(&phase) {
            return Err(format!(
                "{transaction_id} has invalid {family} phase {phase}"
            ));
        }
        if let Some(last_phase) = transaction["lastSuccessfulPhase"].as_str() {
            if !phases.contains(&last_phase) {
                return Err(format!(
                    "{transaction_id} lastSuccessfulPhase {last_phase} is invalid"
                ));
            }
        } else if !transaction["lastSuccessfulPhase"].is_null() {
            return Err(format!(
                "{transaction_id} lastSuccessfulPhase is neither string nor null"
            ));
        }
        let evidence_refs = transaction["evidence"]
            .as_array()
            .ok_or_else(|| format!("{transaction_id} evidence is not an array"))?;
        if evidence_refs.is_empty() {
            return Err(format!("{transaction_id} has no cited evidence"));
        }
        let records = evidence_record_texts(scenario_root, &artifacts_by_id, evidence_refs)?;
        for (record, _, _, _) in &records {
            for field in required_fields {
                let value = key[*field].as_str().expect("validated key string");
                if !record_contains_exact_key_pair(record, field, value) {
                    return Err(format!(
                        "{transaction_id} {field} is not co-located in every cited CCM record"
                    ));
                }
            }
        }
        if !records
            .iter()
            .any(|(record, _, _, _)| record_contains_exact_key_pair(record, "Phase", phase))
        {
            return Err(format!(
                "{transaction_id} phase {phase} is not bound to cited evidence"
            ));
        }

        let confidence = required_string(transaction, "confidence", transaction_id)?;
        if records.iter().any(|(_, offset, version, _)| {
            offset.abs() > 1_439 || !version.starts_with("5.00.TEST.")
        }) {
            return Err(format!(
                "{transaction_id} exact-key transaction lacks usable offset/profile provenance"
            ));
        }
        let state = required_string(transaction, "state", transaction_id)?;
        let classification = required_string(transaction, "classification", transaction_id)?;
        let has_phase_record = |disposition: &str, terminal: bool| {
            records.iter().any(|(record, _, _, _)| {
                record_contains_exact_key_pair(record, "Phase", phase)
                    && record_contains_exact_key_pair(record, "Disposition", disposition)
                    && record_contains_exact_key_pair(
                        record,
                        "Terminal",
                        if terminal { "true" } else { "false" },
                    )
            })
        };
        let terminal_dispositions = records
            .iter()
            .filter(|(record, _, _, _)| {
                record_contains_exact_key_pair(record, "Phase", phase)
                    && record_contains_exact_key_pair(record, "Terminal", "true")
            })
            .flat_map(|(record, _, _, _)| {
                record_exact_token_values(record, "Disposition")
                    .into_iter()
                    .map(str::to_owned)
            })
            .collect::<BTreeSet<_>>();
        if confidence == "high" && terminal_dispositions.len() > 1 {
            return Err(format!(
                "{transaction_id} high confidence cites opposing terminal evidence"
            ));
        }
        scenario_semantics.push(format!("{phase}|{state}|{classification}"));
        match classification {
            "confirmedFailure" => {
                if state != "failed" || confidence != "high" || !has_phase_record("Failed", true) {
                    return Err(format!(
                        "{transaction_id} confirmed failure lacks a terminal cited failure"
                    ));
                }
            }
            "success" => {
                if !matches!(state, "succeeded" | "remediated")
                    || confidence != "high"
                    || phase != "Report"
                    || !has_phase_record("Succeeded", true)
                {
                    return Err(format!(
                        "{transaction_id} success lacks a terminal cited report"
                    ));
                }
            }
            "evaluationResult" => {
                let disposition = match state {
                    "evaluatedNonCompliant" => "NonCompliant",
                    "evaluatedCompliant" => "Compliant",
                    _ => {
                        return Err(format!(
                            "{transaction_id} evaluation result is misclassified as {state}"
                        ));
                    }
                };
                if family != "compliance"
                    || phase != "Evaluate"
                    || confidence != "high"
                    || !has_phase_record(disposition, true)
                    || !records.iter().any(|(record, _, _, _)| {
                        record_contains_exact_key_pair(record, "ResultType", "Evaluation")
                    })
                {
                    return Err(format!(
                        "{transaction_id} compliance evaluation result contract is invalid"
                    ));
                }
            }
            "recovery" => {
                if state != "recovered"
                    || confidence != "medium"
                    || !has_phase_record("Failed", true)
                    || !has_phase_record("Succeeded", true)
                {
                    return Err(format!(
                        "{transaction_id} recovery lacks both terminal failure and success"
                    ));
                }
                let latest_failure = records
                    .iter()
                    .filter(|(record, _, _, _)| {
                        record_contains_exact_key_pair(record, "Phase", phase)
                            && record_contains_exact_key_pair(record, "Disposition", "Failed")
                            && record_contains_exact_key_pair(record, "Terminal", "true")
                    })
                    .map(|(_, _, _, timestamp)| *timestamp)
                    .max()
                    .expect("terminal failure checked above");
                let earliest_success = records
                    .iter()
                    .filter(|(record, _, _, _)| {
                        record_contains_exact_key_pair(record, "Phase", phase)
                            && record_contains_exact_key_pair(record, "Disposition", "Succeeded")
                            && record_contains_exact_key_pair(record, "Terminal", "true")
                    })
                    .map(|(_, _, _, timestamp)| *timestamp)
                    .min()
                    .expect("terminal success checked above");
                if earliest_success <= latest_failure {
                    return Err(format!(
                        "{transaction_id} recovery is not strictly ordered after every cited failure"
                    ));
                }
            }
            "symptom" => {
                let has_opposing_terminal_records = (has_phase_record("Failed", true)
                    && has_phase_record("Succeeded", true))
                    || (has_phase_record("NonCompliant", true)
                        && has_phase_record("Compliant", true));
                if state != "contradictory"
                    || confidence != "low"
                    || records.len() < 2
                    || !has_opposing_terminal_records
                {
                    return Err(format!(
                        "{transaction_id} contradiction is not conservatively classified"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "{transaction_id} has unsupported preparation classification {other}"
                ));
            }
        }

        let coverage_gap_ids = transaction["coverageGapArtifactIds"]
            .as_array()
            .ok_or_else(|| format!("{transaction_id} coverageGapArtifactIds is not an array"))?;
        for artifact_id in coverage_gap_ids {
            let artifact_id = artifact_id
                .as_str()
                .ok_or_else(|| format!("{transaction_id} coverage gap ID is not a string"))?;
            let artifact = artifacts_by_id
                .get(artifact_id)
                .ok_or_else(|| format!("{transaction_id} coverage gap cites {artifact_id}"))?;
            if effective_state(artifact)? == "captured" {
                return Err(format!(
                    "{transaction_id} coverage gap cites complete artifact {artifact_id}"
                ));
            }
        }
        validate_next_artifact(family, transaction_id, &transaction["nextArtifact"])?;
    }
    if scenario_semantics != required_scenario_semantics(family, scenario)? {
        return Err(format!(
            "{family}/{scenario} required scenario semantics changed: {scenario_semantics:?}"
        ));
    }

    Ok(())
}

fn assert_rejected(
    label: &str,
    family: &str,
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
    expected: &Value,
) {
    assert!(
        validate_contract(family, scenario, scenario_root, manifest, expected).is_err(),
        "dynamic adversarial mutation `{label}` was accepted"
    );
}

fn assert_rejected_with(
    label: &str,
    family: &str,
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
    expected: &Value,
    required_error: &str,
) {
    let error = match validate_contract(family, scenario, scenario_root, manifest, expected) {
        Err(error) => error,
        Ok(()) => panic!("dynamic adversarial mutation `{label}` was accepted"),
    };
    assert!(
        error.contains(required_error),
        "`{label}` was rejected for the wrong reason: {error}"
    );
}

#[test]
fn corpus_matrix_keeps_inventory_compliance_and_metering_separate() {
    assert_eq!(
        directory_names(&corpus_root()),
        ["compliance", "inventory", "metering"],
        "the preparation corpus has exactly three independent workflow families"
    );

    for (family, expected) in family_scenarios() {
        assert_eq!(
            directory_names(&corpus_root().join(family)),
            expected,
            "{family} scenario matrix changed without an explicit contract update"
        );
    }
}

#[test]
fn corpus_inventory_is_deterministic_and_documented() {
    assert_eq!(
        corpus_inventory(),
        CorpusInventory {
            scenarios: 20,
            artifacts: 54,
            evidence_files: 42,
            evidence_bytes: 16_820,
            capture_states: BTreeMap::from([
                ("absent".to_owned(), 3),
                ("accessDenied".to_owned(), 3),
                ("capped".to_owned(), 3),
                ("captured".to_owned(), 35),
                ("parseFailed".to_owned(), 4),
                ("skipped".to_owned(), 3),
                ("unsupported".to_owned(), 3),
            ]),
            digest: DOCUMENTED_CORPUS_DIGEST.to_owned(),
        },
        "fixture inventory changed; review provenance and update the documented digest"
    );
}

#[test]
fn review_blocker_applied_caps_are_inclusive_exact_prefixes() {
    for family in ["inventory", "compliance", "metering"] {
        let (scenario_root, manifest, _) = load_contract(family, "coverage-states");
        let capped = manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
            .iter()
            .filter(|artifact| artifact["captureState"] == "capped")
            .collect::<Vec<_>>();
        assert_eq!(capped.len(), 1, "{family} has exactly one capped fixture");

        let artifact = capped[0];
        let artifact_id = artifact["artifactId"]
            .as_str()
            .expect("capped artifactId is a string");
        let relative_path = artifact["relativePath"]
            .as_str()
            .expect("capped artifact has retained evidence");
        let file_size = std::fs::metadata(scenario_root.join(relative_path))
            .expect("capped evidence metadata is readable")
            .len();
        let bytes_copied = artifact["bytesCopied"]
            .as_u64()
            .expect("capped bytesCopied is an integer");
        let byte_limit = artifact["collectionLimit"]["byteLimit"]
            .as_u64()
            .expect("capped byteLimit is an integer");

        assert_eq!(
            (
                artifact["collectionLimit"]["limitApplied"].as_bool(),
                artifact["truncated"].as_bool()
            ),
            (Some(true), Some(true)),
            "{artifact_id} records an applied truncating cap"
        );
        assert_eq!(
            artifact["rotation"]["fragmentComplete"], false,
            "{artifact_id} cannot claim a complete retained fragment"
        );
        assert_eq!(
            (bytes_copied, file_size, byte_limit),
            (byte_limit, byte_limit, byte_limit),
            "{artifact_id} must retain the exact inclusive prefix through byteLimit"
        );
    }
}

#[test]
fn physical_evidence_is_explicitly_synthetic_and_sanitized() {
    for (family, scenarios) in family_scenarios() {
        for scenario in scenarios {
            let (scenario_root, manifest, _) = load_contract(family, scenario);
            assert_eq!(manifest["syntheticFixture"], true);
            for artifact in manifest["artifacts"]
                .as_array()
                .expect("manifest artifacts are an array")
            {
                let Some(relative_path) = artifact["relativePath"].as_str() else {
                    continue;
                };
                let text = std::fs::read_to_string(scenario_root.join(relative_path))
                    .expect("synthetic evidence is readable");
                assert!(
                    text.contains("SYNTHETIC"),
                    "{family}/{scenario}/{relative_path} is not explicitly synthetic"
                );
                for forbidden in ["S-1-5-", "C:\\", "/Users/", "@", ".com", ".net", ".org"] {
                    assert!(
                        !text.contains(forbidden),
                        "{family}/{scenario}/{relative_path} contains forbidden identity `{forbidden}`"
                    );
                }
            }
        }
    }
}

#[test]
fn same_minute_inventory_and_compliance_failures_remain_separate() {
    let (inventory_root, inventory_manifest, inventory_expected) =
        load_contract("inventory", "terminal-failures");
    let (compliance_root, compliance_manifest, compliance_expected) =
        load_contract("compliance", "terminal-failures");

    validate_contract(
        "inventory",
        "terminal-failures",
        &inventory_root,
        &inventory_manifest,
        &inventory_expected,
    )
    .expect("inventory terminal fixture is valid");
    validate_contract(
        "compliance",
        "terminal-failures",
        &compliance_root,
        &compliance_manifest,
        &compliance_expected,
    )
    .expect("compliance terminal fixture is valid");

    let inventory_artifact = &inventory_manifest["artifacts"][0];
    let compliance_artifact = &compliance_manifest["artifacts"][0];
    let inventory_text = std::fs::read_to_string(
        inventory_root.join(
            inventory_artifact["relativePath"]
                .as_str()
                .expect("inventory relativePath"),
        ),
    )
    .expect("inventory evidence is readable");
    let compliance_text = std::fs::read_to_string(
        compliance_root.join(
            compliance_artifact["relativePath"]
                .as_str()
                .expect("compliance relativePath"),
        ),
    )
    .expect("compliance evidence is readable");
    let (inventory_entries, inventory_errors) =
        cmtraceopen_parser::parser::ccm::parse_content(&inventory_text, "inventory", None);
    let (compliance_entries, compliance_errors) =
        cmtraceopen_parser::parser::ccm::parse_content(&compliance_text, "compliance", None);

    assert_eq!(inventory_errors, 0);
    assert_eq!(compliance_errors, 0);
    assert_eq!(inventory_entries.len(), 1);
    assert_eq!(compliance_entries.len(), 1);
    assert_eq!(
        inventory_entries[0].timestamp, compliance_entries[0].timestamp,
        "the adversarial failures intentionally share the same source minute"
    );
    assert_eq!(
        inventory_expected["transactions"][0]["workflow"],
        "inventory"
    );
    assert_eq!(
        compliance_expected["transactions"][0]["workflow"],
        "compliance"
    );
    assert!(
        inventory_expected["transactions"][0]["key"]["CiId"].is_null(),
        "inventory cannot borrow a compliance identifier"
    );
    assert!(
        compliance_expected["transactions"][0]["key"]["InventoryCycleId"].is_null(),
        "compliance cannot borrow an inventory cycle identifier"
    );
}

#[test]
fn every_scenario_satisfies_the_preparation_contract() {
    for (family, scenarios) in family_scenarios() {
        for scenario in scenarios {
            let (scenario_root, manifest, expected) = load_contract(family, scenario);
            validate_contract(family, scenario, &scenario_root, &manifest, &expected)
                .unwrap_or_else(|error| panic!("{family}/{scenario}: {error}"));
        }
    }
}

#[test]
fn dynamic_manifest_mutations_cannot_escape_source_and_identity_boundaries() {
    let (scenario_root, manifest, expected) = load_contract("inventory", "success");

    let mut role_swap = manifest.clone();
    role_swap["bundle"]["role"] = json!("server");
    assert_rejected(
        "bundle role swap",
        "inventory",
        "success",
        &scenario_root,
        &role_swap,
        &expected,
    );

    let mut family_swap = manifest.clone();
    family_swap["artifacts"][0]["designOnlyCatalog"]["entryId"] = json!("client-compliance");
    assert_rejected(
        "logical family swap",
        "inventory",
        "success",
        &scenario_root,
        &family_swap,
        &expected,
    );

    let mut source_injection = manifest.clone();
    source_injection["artifacts"][0]["originalBasename"] = json!("CIAgent.log");
    assert_rejected(
        "foreign source injection",
        "inventory",
        "success",
        &scenario_root,
        &source_injection,
        &expected,
    );

    let mut path_escape = manifest.clone();
    path_escape["artifacts"][0]["relativePath"] = json!("../outside.log");
    assert_rejected(
        "relative path escape",
        "inventory",
        "success",
        &scenario_root,
        &path_escape,
        &expected,
    );

    let mut wrong_bytes = manifest.clone();
    wrong_bytes["artifacts"][0]["bytesCopied"] =
        json!(manifest["artifacts"][0]["bytesCopied"].as_u64().unwrap() + 1);
    assert_rejected(
        "incorrect copied byte count",
        "inventory",
        "success",
        &scenario_root,
        &wrong_bytes,
        &expected,
    );
}

#[test]
fn review_blocker_missing_capture_timestamp_is_rejected() {
    let (scenario_root, mut manifest, expected) = load_contract("inventory", "success");
    manifest["artifacts"][0]["capturedUtc"] = Value::Null;
    assert_rejected_with(
        "missing capturedUtc",
        "inventory",
        "success",
        &scenario_root,
        &manifest,
        &expected,
        "capturedUtc",
    );
}

#[test]
fn dynamic_evidence_mutations_cannot_fabricate_exact_or_high_confidence_facts() {
    let (scenario_root, manifest, expected) = load_contract("inventory", "success");

    let mut unbound_key = expected.clone();
    unbound_key["transactions"][0]["key"]["ReportId"] = json!("INV-REPORT-NOT-CITED");
    assert_rejected(
        "uncited key value",
        "inventory",
        "success",
        &scenario_root,
        &manifest,
        &unbound_key,
    );

    let mut cross_family_key = expected.clone();
    cross_family_key["transactions"][0]["key"]["CiId"] = json!("CI-INJECTED");
    assert_rejected(
        "cross-family key",
        "inventory",
        "success",
        &scenario_root,
        &manifest,
        &cross_family_key,
    );

    let mut wrong_phase_line = expected.clone();
    wrong_phase_line["transactions"][0]["evidence"][0]["startLine"] = json!(1);
    wrong_phase_line["transactions"][0]["evidence"][0]["endLine"] = json!(1);
    assert_rejected(
        "phase borrowed from another line",
        "inventory",
        "success",
        &scenario_root,
        &manifest,
        &wrong_phase_line,
    );

    let mut unknown_profile = manifest.clone();
    unknown_profile["artifacts"][2]["sourceVersion"] = json!("9.99.UNKNOWN");
    assert_rejected(
        "unknown source version at high confidence",
        "inventory",
        "success",
        &scenario_root,
        &unknown_profile,
        &expected,
    );

    let mut broad_next_artifact = load_contract("inventory", "terminal-failures").2;
    broad_next_artifact["transactions"][0]["nextArtifact"]["reason"] =
        json!("Recursively scan C:\\ and every log on every volume *");
    let (terminal_root, terminal_manifest, _) = load_contract("inventory", "terminal-failures");
    assert_rejected(
        "unbounded next-artifact instruction",
        "inventory",
        "terminal-failures",
        &terminal_root,
        &terminal_manifest,
        &broad_next_artifact,
    );
}

#[test]
fn exact_message_tokens_reject_key_and_semantic_lookalikes() {
    for (field, value) in [
        ("ReportId", "INV-REPORT-001"),
        ("Phase", "Report"),
        ("Disposition", "Succeeded"),
        ("Terminal", "true"),
        ("ResultType", "Evaluation"),
    ] {
        let exact = format!("<![LOG[{field}={value}]LOG]!>");
        assert!(record_contains_exact_key_pair(&exact, field, value));

        for lookalike in [
            format!("<![LOG[Other{field}={value}]LOG]!>"),
            format!("<![LOG[Prefix{field}={value}]LOG]!>"),
            format!("<![LOG[{field}={value}-suffix]LOG]!>"),
            format!("<![LOG[X={field}={value}]LOG]!>"),
        ] {
            assert!(
                !record_contains_exact_key_pair(&lookalike, field, value),
                "look-alike {field} token was accepted: {lookalike}"
            );
        }
    }
}

#[test]
fn noncapture_fragment_marker_matches_issue_319_preparation_schema() {
    for family in ["inventory", "compliance", "metering"] {
        let (_, manifest, _) = load_contract(family, "coverage-states");
        for artifact in manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
            .iter()
            .filter(|artifact| {
                matches!(
                    artifact["captureState"].as_str(),
                    Some("absent" | "accessDenied" | "skipped" | "unsupported")
                )
            })
        {
            let artifact_id = artifact["artifactId"]
                .as_str()
                .expect("noncapture artifactId is a string");
            assert_eq!(artifact["bytesCopied"], 0, "{artifact_id}");
            assert!(artifact["relativePath"].is_null(), "{artifact_id}");
            assert!(artifact.get("encoding").is_none(), "{artifact_id}");
            assert!(artifact.get("collectionLimit").is_none(), "{artifact_id}");
            assert_eq!(
                artifact["rotation"],
                json!({"kind": "current", "fragmentComplete": false}),
                "{artifact_id} must mirror #319's proposed noncapture marker"
            );
        }
    }
}

#[test]
fn dynamic_recovery_mutations_require_selected_profile_and_usable_offset() {
    let (unknown_root, mut unknown_manifest, mut unknown_expected) =
        load_contract("inventory", "recovery-contradictory");
    let unknown_artifact_id = unknown_manifest["artifacts"][0]["artifactId"]
        .as_str()
        .expect("artifactId")
        .to_owned();
    unknown_manifest["artifacts"][0]["sourceVersion"] = json!("9.99.UNKNOWN");
    unknown_expected["extractionProfile"]["selectionState"] = json!("mixedKnownAndUnknown");
    unknown_expected["sourceLocalObservations"]
        .as_array_mut()
        .expect("sourceLocalObservations")
        .push(json!({
            "observationId": "inventory-recovery-unknown-profile",
            "kind": "unknownProfile",
            "artifactIds": [unknown_artifact_id],
            "confidenceCeiling": "low",
            "correlationEligible": false,
            "claim": "Unknown source version cannot support ordered recovery."
        }));
    assert_rejected(
        "medium recovery from unknown source profile",
        "inventory",
        "recovery-contradictory",
        &unknown_root,
        &unknown_manifest,
        &unknown_expected,
    );

    let (offset_root, offset_manifest, mut offset_expected) =
        load_contract("compliance", "malformed-unknown-profile-invalid-offset");
    offset_expected["transactions"] = json!([{
        "transactionId": "invalid-offset-recovery",
        "workflow": "compliance",
        "key": {
            "CiId": "CI-041",
            "BaselineId": "BASELINE-041",
            "StateId": "STATE-041",
            "ResourceHandle": "safe:resource:compliance-041",
            "keyProfileKind": "complianceExact",
            "extractionProfileId": "sccm-client-compliance-5.00.test-v1",
            "confidence": "exact"
        },
        "phase": "Report",
        "state": "recovered",
        "classification": "recovery",
        "confidence": "medium",
        "lastSuccessfulPhase": "Report",
        "evidence": [
            {
                "artifactId": "compliance-malformed-unknown-profile-invalid-offset-invalid-offset",
                "startLine": 1,
                "endLine": 1
            },
            {
                "artifactId": "compliance-malformed-unknown-profile-invalid-offset-invalid-offset",
                "startLine": 2,
                "endLine": 2
            }
        ],
        "coverageGapArtifactIds": [],
        "nextArtifact": null
    }]);
    assert_rejected(
        "medium recovery from invalid timestamp offsets",
        "compliance",
        "malformed-unknown-profile-invalid-offset",
        &offset_root,
        &offset_manifest,
        &offset_expected,
    );
}

#[test]
fn review_blocker_same_timestamp_opposites_cannot_be_recovery() {
    let (scenario_root, manifest, mut expected) =
        load_contract("inventory", "recovery-contradictory");
    expected["transactions"][0]["key"] = expected["transactions"][1]["key"].clone();
    expected["transactions"][0]["evidence"] = expected["transactions"][1]["evidence"].clone();
    assert_rejected_with(
        "same-timestamp opposites relabeled recovery",
        "inventory",
        "recovery-contradictory",
        &scenario_root,
        &manifest,
        &expected,
        "strictly ordered",
    );
}

#[test]
fn review_blocker_opposing_terminal_records_cannot_be_promoted_high() {
    let (scenario_root, manifest, expected) = load_contract("inventory", "recovery-contradictory");

    let mut promoted_failure = expected.clone();
    promoted_failure["transactions"][0]["state"] = json!("failed");
    promoted_failure["transactions"][0]["classification"] = json!("confirmedFailure");
    promoted_failure["transactions"][0]["confidence"] = json!("high");
    assert_rejected_with(
        "opposing terminals promoted to confirmed failure",
        "inventory",
        "recovery-contradictory",
        &scenario_root,
        &manifest,
        &promoted_failure,
        "opposing terminal evidence",
    );

    let mut promoted_success = expected.clone();
    promoted_success["transactions"][0]["state"] = json!("succeeded");
    promoted_success["transactions"][0]["classification"] = json!("success");
    promoted_success["transactions"][0]["confidence"] = json!("high");
    assert_rejected_with(
        "opposing terminals promoted to success",
        "inventory",
        "recovery-contradictory",
        &scenario_root,
        &manifest,
        &promoted_success,
        "opposing terminal evidence",
    );
}

#[test]
fn dynamic_coverage_and_collision_mutations_remain_noncausal() {
    let (coverage_root, coverage_manifest, mut coverage_expected) =
        load_contract("metering", "coverage-states");
    coverage_expected["coverage"][0]["state"] = json!("captured");
    assert_rejected(
        "missing artifact promoted to captured",
        "metering",
        "coverage-states",
        &coverage_root,
        &coverage_manifest,
        &coverage_expected,
    );

    let (noncompliant_root, noncompliant_manifest, mut noncompliant_expected) =
        load_contract("compliance", "noncompliant-result");
    noncompliant_expected["transactions"][0]["classification"] = json!("confirmedFailure");
    noncompliant_expected["transactions"][0]["state"] = json!("failed");
    assert_rejected(
        "noncompliant result promoted to failure",
        "compliance",
        "noncompliant-result",
        &noncompliant_root,
        &noncompliant_manifest,
        &noncompliant_expected,
    );

    let (collision_root, mut collision_manifest, collision_expected) =
        load_contract("inventory", "same-minute-collision");
    collision_manifest["artifacts"][1]["pathFingerprint"] =
        collision_manifest["artifacts"][0]["pathFingerprint"].clone();
    assert_rejected(
        "cross-root fingerprint alias",
        "inventory",
        "same-minute-collision",
        &collision_root,
        &collision_manifest,
        &collision_expected,
    );

    let (_, collision_manifest, mut collision_expected) =
        load_contract("inventory", "same-minute-collision");
    collision_expected["transactions"][1]["key"] =
        collision_expected["transactions"][0]["key"].clone();
    assert_rejected(
        "same-minute key borrowing",
        "inventory",
        "same-minute-collision",
        &collision_root,
        &collision_manifest,
        &collision_expected,
    );
}

#[test]
fn review_blocker_source_local_observations_reject_causal_language() {
    let (scenario_root, manifest, mut expected) = load_contract("inventory", "coverage-states");
    expected["sourceLocalObservations"][0]["claim"] =
        json!("The client root cause caused the failure.");
    assert_rejected_with(
        "source-local causal claim",
        "inventory",
        "coverage-states",
        &scenario_root,
        &manifest,
        &expected,
        "causal",
    );
}

#[test]
fn review_blocker_required_scenario_semantics_cannot_be_erased() {
    for (family, scenario) in [
        ("inventory", "success"),
        ("inventory", "terminal-failures"),
        ("compliance", "noncompliant-result"),
        ("metering", "success"),
    ] {
        let (scenario_root, manifest, mut expected) = load_contract(family, scenario);
        expected["transactions"] = json!([]);
        assert_rejected_with(
            "required scenario transactions erased",
            family,
            scenario,
            &scenario_root,
            &manifest,
            &expected,
            "required scenario semantics",
        );
    }
}

#[test]
fn invalid_timestamp_offsets_cannot_be_promoted_to_high_confidence() {
    let (scenario_root, manifest, mut expected) =
        load_contract("compliance", "malformed-unknown-profile-invalid-offset");
    expected["transactions"] = json!([{
        "transactionId": "invalid-offset-promotion",
        "workflow": "compliance",
        "key": {
            "CiId": "CI-041",
            "BaselineId": "BASELINE-041",
            "StateId": "STATE-041",
            "ResourceHandle": "safe:resource:compliance-041",
            "keyProfileKind": "complianceExact",
            "extractionProfileId": "sccm-client-compliance-5.00.test-v1",
            "confidence": "exact"
        },
        "phase": "Report",
        "state": "succeeded",
        "classification": "success",
        "confidence": "high",
        "lastSuccessfulPhase": "Report",
        "evidence": [{
            "artifactId": "compliance-malformed-unknown-profile-invalid-offset-invalid-offset",
            "startLine": 1,
            "endLine": 1
        }],
        "coverageGapArtifactIds": [],
        "nextArtifact": null
    }]);
    assert_rejected(
        "invalid offset promoted to high confidence",
        "compliance",
        "malformed-unknown-profile-invalid-offset",
        &scenario_root,
        &manifest,
        &expected,
    );
}
