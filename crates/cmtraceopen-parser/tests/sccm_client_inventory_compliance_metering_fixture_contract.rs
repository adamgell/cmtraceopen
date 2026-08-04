use cmtraceopen_parser::sccm::{
    normalize_ccm_artifact, SccmArtifact, SccmCoverageState, SccmRole, SccmRotation,
    SccmTimeOrderingState, SccmTimestamp, SccmUnknownRotation,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

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

const METERING_SCENARIOS: [&str; 7] = [
    "coverage-states",
    "deferred",
    "recovery-contradictory",
    "rotation-boundary",
    "same-minute-collision",
    "success",
    "terminal-failures",
];

const DOCUMENTED_CORPUS_DIGEST: &str = "76504021b1fb7e87";

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
        scenarios: 21,
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

fn admitted_source_phases(
    family: &str,
    source_basename: &str,
) -> Result<&'static [&'static str], String> {
    match (family, source_basename) {
        ("inventory", "InventoryAgent.log") => Ok(&["Collect"]),
        ("inventory", "InventoryProvider.log") => Ok(&["Provider", "Serialize"]),
        ("inventory", "InventoryAgentProvider.log") => Ok(&["Queue", "Report"]),
        ("compliance", "CIAgent.log" | "CITaskMgr.log") => Ok(&["Evaluate"]),
        ("compliance", "DCMAgent.log") => Ok(&["Remediate"]),
        ("compliance", "DCMReporting.log") => Ok(&["Evaluate", "Report"]),
        ("compliance", "StateMessage.log") => Ok(&["Report"]),
        ("metering", "SWMTRReportGen.log") => Ok(&["Collect", "Aggregate", "Report"]),
        _ => Err(format!(
            "{source_basename} has no admitted {family} phase ownership"
        )),
    }
}

fn admitted_structured_fields(family: &str) -> Result<BTreeSet<&'static str>, String> {
    let fields = match family {
        "inventory" => &[
            "Family",
            "InventoryCycleId",
            "ResourceHandle",
            "ReportId",
            "Phase",
            "Disposition",
            "Terminal",
            "ErrorCode",
            "Recovery",
            "Ordering",
            "Coverage",
            "Rotation",
        ][..],
        "compliance" => &[
            "Family",
            "CiId",
            "BaselineId",
            "StateId",
            "ResourceHandle",
            "Phase",
            "Disposition",
            "Terminal",
            "ResultType",
            "ErrorCode",
            "Recovery",
            "Ordering",
            "PostRemediation",
            "Coverage",
            "Rotation",
        ][..],
        "metering" => &[
            "Family",
            "MeteringCycleId",
            "RuleId",
            "ReportId",
            "ResourceHandle",
            "Phase",
            "Disposition",
            "Terminal",
            "ErrorCode",
            "Recovery",
            "Ordering",
            "Coverage",
            "Rotation",
        ][..],
        other => return Err(format!("unsupported structured-field family {other}")),
    };
    Ok(fields.iter().copied().collect())
}

fn expected_logical_artifact(family: &str) -> Result<&'static str, String> {
    match family {
        "inventory" => Ok("client-inventory"),
        "compliance" => Ok("client-compliance"),
        "metering" => Ok("client-metering"),
        other => Err(format!("unsupported workflow family {other}")),
    }
}

fn validate_structured_field_vocabulary(
    fields: &BTreeMap<String, String>,
    context: &str,
) -> Result<(), String> {
    let family = fields
        .get("Family")
        .ok_or_else(|| format!("{context} has no structured Family field"))?;
    let admitted = admitted_structured_fields(family)?;
    for field in fields.keys() {
        if !admitted.contains(field.as_str()) {
            return Err(format!(
                "{context} has unadmitted structured field {field} for {family}"
            ));
        }
    }
    Ok(())
}

fn validate_cited_record_semantics(
    fields: &BTreeMap<String, String>,
    source_basename: &str,
    context: &str,
) -> Result<(), String> {
    let family = fields
        .get("Family")
        .ok_or_else(|| format!("{context} has no structured Family field"))?;
    let phase = fields
        .get("Phase")
        .ok_or_else(|| format!("{context} has no structured Phase field"))?;
    if !admitted_source_phases(family, source_basename)?.contains(&phase.as_str()) {
        return Err(format!(
            "{context} source {source_basename} does not own phase {phase}"
        ));
    }
    let disposition = fields
        .get("Disposition")
        .ok_or_else(|| format!("{context} has no structured Disposition field"))?;
    let terminal = fields
        .get("Terminal")
        .ok_or_else(|| format!("{context} has no structured Terminal field"))?;
    if !matches!(terminal.as_str(), "true" | "false") {
        return Err(format!("{context} has invalid Terminal={terminal}"));
    }
    if !matches!(
        disposition.as_str(),
        "Succeeded" | "Failed" | "Progress" | "Pending" | "Deferred" | "Compliant" | "NonCompliant"
    ) {
        return Err(format!(
            "{context} has unadmitted Disposition={disposition}"
        ));
    }

    let evaluation_disposition = matches!(disposition.as_str(), "Compliant" | "NonCompliant");
    if evaluation_disposition && (family != "compliance" || phase != "Evaluate") {
        return Err(format!(
            "{context} borrows compliance evaluation semantics outside compliance/Evaluate"
        ));
    }
    if let Some(result_type) = fields.get("ResultType") {
        if family != "compliance" || phase != "Evaluate" || result_type != "Evaluation" {
            return Err(format!(
                "{context} has unowned ResultType={result_type} semantics"
            ));
        }
    }
    if fields.contains_key("ErrorCode") && (disposition != "Failed" || terminal != "true") {
        return Err(format!(
            "{context} ErrorCode is not bound to a terminal failure"
        ));
    }
    if fields.contains_key("Recovery") && (disposition != "Succeeded" || terminal != "true") {
        return Err(format!(
            "{context} Recovery is not bound to terminal success"
        ));
    }
    if fields.contains_key("Ordering")
        && (!matches!(disposition.as_str(), "Succeeded" | "Compliant") || terminal != "true")
    {
        return Err(format!(
            "{context} Ordering is not bound to opposing terminal evidence"
        ));
    }
    if let Some(post_remediation) = fields.get("PostRemediation") {
        if family != "compliance"
            || phase != "Report"
            || disposition != "Succeeded"
            || terminal != "true"
            || post_remediation != "Compliant"
        {
            return Err(format!(
                "{context} has unowned PostRemediation={post_remediation} semantics"
            ));
        }
    }
    Ok(())
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
        ("metering", "deferred") => Ok(&["Report|blockedOrDeferred|blockedOrDeferred"]),
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

fn validate_canonical_id(value: &str, field: &str, required_prefix: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.starts_with(required_prefix)
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!("{field} is not canonical for {required_prefix}"));
    }
    Ok(())
}

fn validate_source_version(version: &str, artifact_id: &str) -> Result<(), String> {
    if version.is_empty()
        || version.len() > 64
        || version.split('.').any(|segment| {
            segment.is_empty()
                || segment.starts_with('-')
                || segment.ends_with('-')
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(format!("{artifact_id} sourceVersion is not canonical"));
    }
    Ok(())
}

fn require_exact_object_fields(
    value: &Value,
    expected_fields: &[&str],
    context: &str,
) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{context} is not an object"))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected_fields.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{context} fields {actual:?} are not exact {expected:?}"
        ));
    }
    Ok(())
}

fn require_canonical_string_field_order(
    rows: &[Value],
    field: &str,
    context: &str,
) -> Result<(), String> {
    let mut previous = None;
    for row in rows {
        let current = required_string(row, field, context)?;
        if previous.is_some_and(|value| value >= current) {
            return Err(format!("{context} order is not canonical by {field}"));
        }
        previous = Some(current);
    }
    Ok(())
}

fn expected_observation_claim(family: &str, kind: &str) -> Result<&'static str, String> {
    match (family, kind) {
        ("inventory", "coverageGap") => Ok(
            "All non-complete source states remain coverage only; no workflow outcome is inferred.",
        ),
        ("compliance", "coverageGap") => Ok(
            "All non-complete source states remain coverage only; no compliance outcome is inferred.",
        ),
        ("metering", "coverageGap") => Ok(
            "All non-complete source states remain coverage only; no metering outcome is inferred.",
        ),
        (_, "rotationSplit") => Ok(
            "Exact keys split only across incomplete rotation fragments cannot establish a complete workflow.",
        ),
        (_, "malformedRecord") => Ok("Malformed CCM remains a parse coverage state."),
        (_, "unknownProfile") => {
            Ok("Unknown source version has no selected extraction profile.")
        }
        (_, "invalidOffset") => Ok(
            "Invalid timestamp offset cannot support ordered or high-confidence workflow claims.",
        ),
        _ => Err(format!(
            "{family} observation kind {kind} has no canonical claim"
        )),
    }
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

fn normalize_manifest_relative_path(path: &str) -> String {
    path.replace('\\', "/")
}

static TEMP_SCENARIO_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct TemporaryScenario {
    root: PathBuf,
}

impl TemporaryScenario {
    fn copy_from(source: &Path, label: &str) -> Self {
        let sequence = TEMP_SCENARIO_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cmtraceopen-sccm-325-{}-{sequence}-{label}",
            std::process::id()
        ));
        std::fs::create_dir(&root)
            .unwrap_or_else(|error| panic!("{} can be created: {error}", root.display()));

        for source_file in walk_files(source).expect("source scenario is readable") {
            let relative = source_file
                .strip_prefix(source)
                .expect("scenario file is below source root");
            let destination = root.join(relative);
            std::fs::create_dir_all(
                destination
                    .parent()
                    .expect("scenario copy destination has a parent"),
            )
            .expect("scenario copy parent can be created");
            std::fs::copy(&source_file, &destination).unwrap_or_else(|error| {
                panic!(
                    "{} can be copied to {}: {error}",
                    source_file.display(),
                    destination.display()
                )
            });
        }

        Self { root }
    }
}

impl Drop for TemporaryScenario {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn rewrite_artifact_evidence(
    scenario_root: &Path,
    manifest: &mut Value,
    artifact_index: usize,
    contents: &str,
) {
    let artifact = &mut manifest["artifacts"][artifact_index];
    let relative_path = artifact["relativePath"]
        .as_str()
        .expect("rewritten artifact has a relativePath");
    std::fs::write(scenario_root.join(relative_path), contents)
        .expect("temporary evidence can be rewritten");
    artifact["bytesCopied"] = json!(contents.len() as u64);
}

fn rewrite_artifact_by_id(
    scenario_root: &Path,
    manifest: &mut Value,
    artifact_id: &str,
    contents: &str,
) {
    let artifact_index = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts are an array")
        .iter()
        .position(|artifact| artifact["artifactId"] == artifact_id)
        .unwrap_or_else(|| panic!("manifest contains artifact {artifact_id}"));
    rewrite_artifact_evidence(scenario_root, manifest, artifact_index, contents);
}

fn copied_contract_with_evidence_replacements(
    family: &str,
    scenario: &str,
    artifact_id: &str,
    label: &str,
    replacements: &[(&str, &str)],
) -> (TemporaryScenario, Value, Value) {
    let (source_root, mut manifest, expected) = load_contract(family, scenario);
    let temporary = TemporaryScenario::copy_from(&source_root, label);
    let artifact = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts are an array")
        .iter()
        .find(|artifact| artifact["artifactId"] == artifact_id)
        .unwrap_or_else(|| panic!("manifest contains artifact {artifact_id}"));
    let relative_path = artifact["relativePath"]
        .as_str()
        .expect("rewritten artifact has a relativePath");
    let mut contents = std::fs::read_to_string(temporary.root.join(relative_path))
        .expect("temporary evidence is readable");
    for (from, to) in replacements {
        assert!(
            contents.contains(from),
            "{artifact_id} contains replacement source {from}"
        );
        contents = contents.replace(from, to);
    }
    rewrite_artifact_by_id(&temporary.root, &mut manifest, artifact_id, &contents);
    (temporary, manifest, expected)
}

fn copied_inventory_recovery_with_time_replacements(
    label: &str,
    replacements: &[(&str, &str)],
) -> (TemporaryScenario, Value, Value) {
    let (source_root, mut manifest, expected) =
        load_contract("inventory", "recovery-contradictory");
    let temporary = TemporaryScenario::copy_from(&source_root, label);
    let relative_path = manifest["artifacts"][0]["relativePath"]
        .as_str()
        .expect("recovery artifact has a relativePath");
    let mut contents = std::fs::read_to_string(temporary.root.join(relative_path))
        .expect("temporary recovery evidence is readable");
    for (from, to) in replacements {
        assert!(
            contents.contains(from),
            "recovery fixture contains replacement source {from}"
        );
        contents = contents.replace(from, to);
    }
    rewrite_artifact_evidence(&temporary.root, &mut manifest, 0, &contents);
    manifest["artifacts"][0]["capturedUtc"] = json!("2026-07-30T11:00:00Z");
    (temporary, manifest, expected)
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

fn validate_source_topology(
    family: &str,
    artifact_id: &str,
    basename: &str,
    rotation_kind: &str,
    sanitized_path: &str,
    fingerprint: &str,
    relative_path: Option<&str>,
) -> Result<(), String> {
    let source_tail = sanitized_path
        .strip_prefix("SYNTHETIC://")
        .ok_or_else(|| format!("{artifact_id} source topology is not synthetic"))?;
    let root = source_tail
        .split('/')
        .next()
        .ok_or_else(|| format!("{artifact_id} source topology has no synthetic root"))?;
    if !root.starts_with("root-")
        || !root
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || sanitized_path != format!("SYNTHETIC://{root}/CCM/Logs/{basename}")
        || fingerprint != format!("synthetic-{artifact_id}-{root}")
    {
        return Err(format!(
            "{artifact_id} source topology does not bind path/fingerprint root"
        ));
    }
    if let Some(relative_path) = relative_path {
        let expected = format!("evidence/client-{family}/{root}/{rotation_kind}/{basename}");
        if relative_path != expected {
            return Err(format!(
                "{artifact_id} source topology does not bind relative path {relative_path}"
            ));
        }
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

fn expected_next_artifact(
    family: &str,
    phase: &str,
    classification: &str,
) -> Result<Option<Value>, String> {
    if !matches!(classification, "confirmedFailure" | "blockedOrDeferred") {
        return Ok(None);
    }

    let source_basename = match (family, phase) {
        ("inventory", "Collect") => "InventoryAgent.log",
        ("inventory", "Provider" | "Serialize") => "InventoryProvider.log",
        ("inventory", "Queue" | "Report") => "InventoryAgentProvider.log",
        ("compliance", "Evaluate") => "CIAgent.log",
        ("compliance", "Remediate") => "DCMAgent.log",
        ("compliance", "Report") => "DCMReporting.log",
        ("metering", "Collect" | "Aggregate" | "Report") => "SWMTRReportGen.log",
        _ => {
            return Err(format!(
                "no bounded nextArtifact contract for {family}/{phase}"
            ))
        }
    };

    Ok(Some(json!({
        "logicalArtifactId": expected_logical_artifact(family)?,
        "sourceBasename": source_basename,
        "reason": format!(
            "Inspect the same exact {family} key in this admitted {family} source."
        )
    })))
}

fn additive_artifact(artifact: &Value) -> Result<SccmArtifact, String> {
    let artifact_id = required_string(artifact, "artifactId", "artifact")?;
    let rotation = match required_string(&artifact["rotation"], "kind", artifact_id)? {
        "current" => SccmRotation::Current,
        "lo" => SccmRotation::Unknown(SccmUnknownRotation {
            kind: "lo".to_owned(),
            value: None,
        }),
        other => return Err(format!("{artifact_id} has unsupported rotation {other}")),
    };

    Ok(SccmArtifact {
        artifact_id: artifact_id.to_owned(),
        display_name: required_string(artifact, "originalBasename", artifact_id)?.to_owned(),
        original_path: artifact["sanitizedSourcePath"].as_str().map(str::to_owned),
        host: Some("LAB-CLIENT-01".to_owned()),
        role: SccmRole::Client,
        configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
        collected_at_utc: artifact["capturedUtc"].as_str().map(str::to_owned),
        rotation,
        coverage: SccmCoverageState::Captured,
        encoding: artifact["encoding"].as_str().map(str::to_owned),
    })
}

struct CitedEvidenceRecord {
    fields: BTreeMap<String, String>,
    source_version: String,
    timestamp: SccmTimestamp,
}

fn strict_ccm_structured_fields(
    record: &str,
    context: &str,
) -> Result<BTreeMap<String, String>, String> {
    const MESSAGE_PREFIX: &str = "<![LOG[";
    const MESSAGE_SUFFIX: &str = "]LOG]!>";
    if !record.starts_with(MESSAGE_PREFIX)
        || record.matches(MESSAGE_PREFIX).count() != 1
        || record.matches(MESSAGE_SUFFIX).count() != 1
    {
        return Err(format!("{context} must contain exactly one CCM envelope"));
    }
    let payload_start = MESSAGE_PREFIX.len();
    let message_end = record[payload_start..]
        .find(MESSAGE_SUFFIX)
        .ok_or_else(|| format!("{context} must contain exactly one CCM envelope"))?;
    let suffix_end = payload_start + message_end + MESSAGE_SUFFIX.len();
    let attributes = &record[suffix_end..];
    if !attributes.starts_with("<time=\"") || !attributes.ends_with('>') {
        return Err(format!("{context} must contain exactly one CCM envelope"));
    }

    let mut fields = BTreeMap::new();
    for token in record[payload_start..payload_start + message_end].split_ascii_whitespace() {
        let Some((name, value)) = token.split_once('=') else {
            continue;
        };
        if name.is_empty() || value.is_empty() {
            return Err(format!("{context} has an empty structured field"));
        }
        if fields.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(format!("{context} has duplicate structured field {name}"));
        }
    }
    Ok(fields)
}

fn rotation_lineage_key(
    family: &str,
    scenario_root: &Path,
    artifact: &Value,
) -> Result<String, String> {
    let artifact_id = required_string(artifact, "artifactId", "rotation artifact")?;
    let basename = required_string(artifact, "originalBasename", artifact_id)?;
    let source_basename = basename.strip_suffix(".lo").unwrap_or(basename);
    let source_version = required_string(artifact, "sourceVersion", artifact_id)?;
    let sanitized_path = required_string(artifact, "sanitizedSourcePath", artifact_id)?;
    let synthetic_root = sanitized_path
        .strip_prefix("SYNTHETIC://")
        .and_then(|path| path.split('/').next())
        .ok_or_else(|| format!("{artifact_id} rotation source has no synthetic root"))?;
    let relative_path = required_string(artifact, "relativePath", artifact_id)?;
    let contents = std::fs::read_to_string(scenario_root.join(relative_path))
        .map_err(|error| format!("{artifact_id} rotation evidence is readable: {error}"))?;
    let additive_artifact = additive_artifact(artifact)?;
    let required_fields = required_key_fields(family)?;
    let mut exact_keys = BTreeSet::new();

    for (index, line) in contents.lines().enumerate() {
        let context = format!("{artifact_id}:{}", index + 1);
        let normalized = normalize_ccm_artifact(additive_artifact.clone(), line);
        if normalized.len() != 1
            || normalized[0].reference.line_start != Some(1)
            || normalized[0].reference.line_end != Some(1)
        {
            return Err(format!("{context} is not one complete CCM record"));
        }
        let fields = strict_ccm_structured_fields(line, &context)?;
        validate_structured_field_vocabulary(&fields, &context)?;
        validate_cited_record_semantics(&fields, source_basename, &context)?;
        if fields.get("Family").map(String::as_str) != Some(family) {
            return Err(format!("{context} Family is not exact"));
        }
        let mut key_values = Vec::new();
        for field in required_fields {
            let value = fields
                .get(*field)
                .ok_or_else(|| format!("{context} has no exact key field {field}"))?;
            if value.is_empty()
                || value.contains(['\n', '\r'])
                || (field.ends_with("Handle") && !value.starts_with("safe:"))
            {
                return Err(format!("{context} exact key field {field} is unsafe/empty"));
            }
            key_values.push(value.as_str());
        }
        exact_keys.insert(key_values.join("\0"));
    }
    if exact_keys.len() != 1 {
        return Err(format!(
            "{artifact_id} rotation evidence has no single exact key"
        ));
    }

    Ok(format!(
        "{synthetic_root}\0{source_basename}\0{source_version}\0{}",
        exact_keys
            .into_iter()
            .next()
            .expect("one exact rotation key was checked")
    ))
}

fn record_field_is(record: &CitedEvidenceRecord, field: &str, value: &str) -> bool {
    record
        .fields
        .get(field)
        .is_some_and(|actual| actual == value)
}

fn evidence_backed_last_successful_phase<'a>(
    records: &[CitedEvidenceRecord],
    phases: &'a [&'a str],
    classification: &str,
) -> Option<&'a str> {
    if classification == "symptom" {
        return None;
    }

    records
        .iter()
        .filter_map(|record| {
            if !record_field_is(record, "Terminal", "true") {
                return None;
            }
            let disposition = record.fields.get("Disposition")?.as_str();
            let completed = match disposition {
                "Succeeded" => true,
                "Compliant" | "NonCompliant" => {
                    record_field_is(record, "Family", "compliance")
                        && record_field_is(record, "Phase", "Evaluate")
                        && record_field_is(record, "ResultType", "Evaluation")
                }
                _ => false,
            };
            if !completed {
                return None;
            }
            let phase = record.fields.get("Phase")?.as_str();
            phases
                .iter()
                .position(|candidate| *candidate == phase)
                .map(|index| (index, phases[index]))
        })
        .max_by_key(|(index, _)| *index)
        .map(|(_, phase)| phase)
}

fn evidence_record_texts(
    scenario_root: &Path,
    artifacts_by_id: &BTreeMap<String, &Value>,
    evidence_refs: &[Value],
) -> Result<Vec<CitedEvidenceRecord>, String> {
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
        let additive_artifact = additive_artifact(artifact)?;
        let captured_utc = required_string(artifact, "capturedUtc", artifact_id)?;
        let captured_utc_millis = chrono::DateTime::parse_from_rfc3339(captured_utc)
            .map_err(|error| format!("{artifact_id} capturedUtc is invalid: {error}"))?
            .timestamp_millis();
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
            let normalized = normalize_ccm_artifact(additive_artifact.clone(), line);
            if normalized.len() != 1
                || normalized[0].reference.line_start != Some(1)
                || normalized[0].reference.line_end != Some(1)
            {
                return Err(format!(
                    "{artifact_id}:{} is not one complete CCM record",
                    start + offset
                ));
            }
            let timestamp = normalized[0].timestamp.clone();
            let Some(utc_millis) = timestamp.utc_millis else {
                return Err(format!(
                    "{artifact_id}:{} lacks normalized additive SCCM timestamp provenance",
                    start + offset
                ));
            };
            if timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc {
                return Err(format!(
                    "{artifact_id}:{} lacks normalized additive SCCM timestamp provenance",
                    start + offset
                ));
            }
            if utc_millis > captured_utc_millis {
                return Err(format!(
                    "{artifact_id}:{} complete cited timestamp is after capturedUtc",
                    start + offset
                ));
            }
            let source_version = required_string(artifact, "sourceVersion", artifact_id)?;
            let record_context = format!("{artifact_id}:{}", start + offset);
            let fields = strict_ccm_structured_fields(line, &record_context)?;
            validate_structured_field_vocabulary(&fields, &record_context)?;
            let basename = required_string(artifact, "originalBasename", artifact_id)?;
            let source_basename = basename.strip_suffix(".lo").unwrap_or(basename);
            validate_cited_record_semantics(&fields, source_basename, &record_context)?;
            records.push(CitedEvidenceRecord {
                fields,
                source_version: source_version.to_owned(),
                timestamp,
            });
        }
    }
    Ok(records)
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

    require_exact_object_fields(
        manifest,
        &[
            "sccmManifestVersion",
            "contractState",
            "proposalOnly",
            "syntheticFixture",
            "scenario",
            "workflowFamily",
            "bundle",
            "artifacts",
        ],
        "manifest",
    )?;
    require_exact_object_fields(
        &manifest["bundle"],
        &[
            "bundleId",
            "captureHost",
            "role",
            "siteCode",
            "artifactOrder",
            "rotationOrder",
        ],
        "bundle",
    )?;
    require_exact_object_fields(
        expected,
        &[
            "contractState",
            "scenario",
            "workflow",
            "extractionProfile",
            "transactions",
            "sourceLocalObservations",
            "coverage",
            "findings",
            "productionAdmissionError",
            "productionOutputSha256",
            "prohibitedClaims",
        ],
        "expected",
    )?;
    require_exact_object_fields(
        &expected["extractionProfile"],
        &["id", "selectionState", "versionPrefix"],
        "extractionProfile",
    )?;

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
    let expected_bundle_id = format!("sccm-325-{family}-{scenario}");
    if bundle_id != expected_bundle_id {
        return Err("bundleId is not exact issue/family/scenario identity".to_owned());
    }
    for (field, expected_value) in [
        (
            "artifactOrder",
            "designOnlyCatalog.entryId,pathFingerprint,rotationRank,originalBasename,artifactId",
        ),
        (
            "rotationOrder",
            "current,lo,numeric-ascending,timestamp-ascending",
        ),
    ] {
        if required_string(&manifest["bundle"], field, "bundle")? != expected_value {
            return Err(format!("bundle {field} is not the deterministic contract"));
        }
    }

    let artifacts = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| "manifest artifacts are not an array".to_owned())?;
    if artifacts.is_empty() {
        return Err("scenario has no artifacts".to_owned());
    }
    require_canonical_string_field_order(artifacts, "artifactId", "manifest artifact")?;
    let mut artifacts_by_id = BTreeMap::new();
    let mut relative_paths = BTreeSet::new();
    let mut physical_source_identities = BTreeSet::new();
    let mut path_fingerprints = BTreeSet::new();
    let mut referenced_files = BTreeSet::new();
    let mut expected_coverage = BTreeMap::new();
    let mut unknown_version_artifacts = BTreeSet::new();
    let mut invalid_offset_artifacts = BTreeSet::new();
    let artifact_id_prefix = format!("{family}-{scenario}-");

    for artifact in artifacts {
        let artifact_id = required_string(artifact, "artifactId", "artifact")?;
        validate_canonical_id(artifact_id, "artifactId", &artifact_id_prefix)?;
        if artifacts_by_id
            .insert(artifact_id.to_owned(), artifact)
            .is_some()
        {
            return Err(format!("duplicate artifactId {artifact_id}"));
        }
        if artifact["role"] != "client" || artifact["kind"] != "ccmLog" {
            return Err(format!("{artifact_id} is not a client CCM artifact"));
        }
        require_exact_object_fields(
            &artifact["designOnlyCatalog"],
            &["entryId", "groupMemberships"],
            &format!("{artifact_id} designOnlyCatalog"),
        )?;
        require_exact_object_fields(
            &artifact["rotation"],
            &["kind", "fragmentComplete"],
            &format!("{artifact_id} rotation"),
        )?;
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
        let mut exact_artifact_fields = vec![
            "artifactId",
            "bytesCopied",
            "captureState",
            "capturedUtc",
            "designOnlyCatalog",
            "kind",
            "originalBasename",
            "pathFingerprint",
            "relativePath",
            "role",
            "rotation",
            "sanitizedSourcePath",
            "sourceVersion",
        ];
        if physical {
            exact_artifact_fields.extend(["collectionLimit", "encoding"]);
        }
        if capture_state == "capped" {
            exact_artifact_fields.push("truncated");
        }
        if capture_state == "captured"
            && (artifact["collectionLimit"]["limitApplied"] != false
                || artifact.get("truncated").is_some())
        {
            return Err(format!(
                "{artifact_id} captured state provenance claims a cap/truncation"
            ));
        }
        if !physical
            && (artifact.get("encoding").is_some()
                || artifact.get("collectionLimit").is_some()
                || artifact.get("truncated").is_some())
        {
            return Err(format!(
                "{artifact_id} nonphysical state provenance invents retained-byte fields"
            ));
        }
        require_exact_object_fields(artifact, &exact_artifact_fields, "artifact")?;
        let relative_path = match (&artifact["relativePath"], physical) {
            (Value::String(relative_path), true) => Some(relative_path.as_str()),
            (Value::Null, false) => None,
            _ => {
                return Err(format!(
                    "{artifact_id} relativePath type does not match capture state {capture_state}"
                ))
            }
        };
        let source_version = match &artifact["sourceVersion"] {
            Value::String(source_version) => Some(source_version.as_str()),
            Value::Null => None,
            _ => {
                return Err(format!(
                    "{artifact_id} sourceVersion is neither a string nor null"
                ))
            }
        };
        if let Some(source_version) = source_version {
            validate_source_version(source_version, artifact_id)?;
            if !source_version.starts_with("5.00.TEST.") {
                unknown_version_artifacts.insert(artifact_id.to_owned());
            }
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
            require_exact_object_fields(
                &artifact["collectionLimit"],
                &["byteLimit", "limitApplied"],
                &format!("{artifact_id} collectionLimit"),
            )?;
            let byte_limit = artifact["collectionLimit"]["byteLimit"]
                .as_u64()
                .ok_or_else(|| format!("{artifact_id} byteLimit is not an integer"))?;
            if capture_state == "capped" {
                if artifact["collectionLimit"]["limitApplied"] != true
                    || artifact["truncated"] != true
                    || artifact["rotation"]["fragmentComplete"] != false
                    || byte_limit != declared_bytes
                {
                    return Err(format!(
                        "{artifact_id} capped state is not an inclusive exact prefix"
                    ));
                }
            } else if artifact["collectionLimit"]["limitApplied"] != false
                || artifact.get("truncated").is_some()
                || declared_bytes > byte_limit
            {
                return Err(format!(
                    "{artifact_id} {capture_state} state provenance is not uncapped"
                ));
            }
            if capture_state == "parseFailed" && artifact["rotation"]["fragmentComplete"] != false {
                return Err(format!(
                    "{artifact_id} parseFailed artifact is marked complete"
                ));
            }
            let sanitized_path = required_string(artifact, "sanitizedSourcePath", artifact_id)?;
            let fingerprint = required_string(artifact, "pathFingerprint", artifact_id)?;
            if fingerprint.is_empty() || !path_fingerprints.insert(fingerprint.to_owned()) {
                return Err(format!(
                    "{artifact_id} has blank or aliased pathFingerprint"
                ));
            }
            validate_source_topology(
                family,
                artifact_id,
                basename,
                rotation_kind,
                sanitized_path,
                fingerprint,
                Some(relative_path),
            )?;
            let capture_host = required_string(&manifest["bundle"], "captureHost", "bundle")?;
            if !physical_source_identities.insert((
                capture_host.to_owned(),
                sanitized_path.to_owned(),
                rotation_kind.to_owned(),
            )) {
                return Err(format!(
                    "{artifact_id} has duplicate physical source identity"
                ));
            }
            referenced_files.insert(relative_path.to_owned());

            if source_version.is_none() {
                return Err(format!(
                    "{artifact_id} physical source has no sourceVersion"
                ));
            }

            if capture_state == "captured" && artifact["rotation"]["fragmentComplete"] == true {
                let contents = std::str::from_utf8(&bytes).expect("validated UTF-8");
                let evidence = normalize_ccm_artifact(additive_artifact(artifact)?, contents);
                if evidence.iter().any(|record| {
                    record.timestamp.ordering_state == SccmTimeOrderingState::OffsetInvalid
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
                let fingerprint = required_string(artifact, "pathFingerprint", artifact_id)?;
                if fingerprint.is_empty() || !path_fingerprints.insert(fingerprint.to_owned()) {
                    return Err(format!(
                        "{artifact_id} has blank or aliased attempted-path fingerprint"
                    ));
                }
                validate_source_topology(
                    family,
                    artifact_id,
                    basename,
                    rotation_kind,
                    sanitized_path,
                    fingerprint,
                    None,
                )?;
                let capture_host = required_string(&manifest["bundle"], "captureHost", "bundle")?;
                if !physical_source_identities.insert((
                    capture_host.to_owned(),
                    sanitized_path.to_owned(),
                    rotation_kind.to_owned(),
                )) {
                    return Err(format!(
                        "{artifact_id} has duplicate physical source identity"
                    ));
                }
            }
        }
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
            "manifest evidence projection differs: actual {actual_files:?}, referenced {referenced_files:?}"
        ));
    }

    if expected["contractState"] != "proposedPending318And319"
        || expected["scenario"] != scenario
        || expected["workflow"] != family
    {
        return Err("expected contract identity is invalid".to_owned());
    }
    if scenario == "malformed-unknown-profile-invalid-offset" {
        if !expected["productionOutputSha256"].is_null()
            || expected["productionAdmissionError"]
                != "fixture-update-numbered-03: client intake artifact ConfigMgr version is unsafe or too long"
        {
            return Err("rejected production outcome is not the exact committed oracle".to_owned());
        }
    } else {
        let digest = required_string(expected, "productionOutputSha256", "expected")?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !expected["productionAdmissionError"].is_null()
        {
            return Err("admitted production outcome is not a lowercase SHA-256 oracle".to_owned());
        }
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
    require_canonical_string_field_order(coverage, "artifactId", "coverage")?;
    let mut declared_coverage = BTreeMap::new();
    for row in coverage {
        require_exact_object_fields(
            row,
            &["artifactId", "logicalArtifactId", "state"],
            "coverage row",
        )?;
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
    if prohibited_claims.len() != 4
        || expected["prohibitedClaims"]
            != json!([
                "missing or unreadable evidence proves workflow success or failure",
                "same-minute records are causally related without one exact validated key tuple",
                "client evidence alone proves a server-side cause",
                "this preparation corpus is live Windows acceptance"
            ])
    {
        return Err("prohibitedClaims are not the exact non-claim contract".to_owned());
    }

    let observations = expected["sourceLocalObservations"]
        .as_array()
        .ok_or_else(|| "sourceLocalObservations is not an array".to_owned())?;
    require_canonical_string_field_order(observations, "observationId", "observation")?;
    let mut observation_ids = BTreeSet::new();
    let mut observation_memberships = BTreeSet::new();
    let mut observed_artifact_ids = BTreeSet::new();
    let mut unknown_profile_observations = BTreeSet::new();
    let mut invalid_offset_observations = BTreeSet::new();
    for observation in observations {
        require_exact_object_fields(
            observation,
            &[
                "observationId",
                "kind",
                "artifactIds",
                "confidenceCeiling",
                "correlationEligible",
                "claim",
            ],
            "observation",
        )?;
        let observation_id = required_string(observation, "observationId", "observation")?;
        validate_canonical_id(observation_id, "observationId", &format!("{family}-"))?;
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
        if claim != expected_observation_claim(family, kind)? {
            return Err(format!("{observation_id} claim is not canonical"));
        }
        let artifact_ids = observation["artifactIds"]
            .as_array()
            .ok_or_else(|| format!("{observation_id} artifactIds is not an array"))?;
        if artifact_ids.is_empty() {
            return Err(format!(
                "{observation_id} has no bounded artifact references"
            ));
        }
        let mut previous_artifact_id = None;
        let mut observed_states = Vec::new();
        let mut observed_rotations = BTreeSet::new();
        let mut observed_rotation_artifacts = Vec::new();
        for artifact_id in artifact_ids {
            let artifact_id = artifact_id
                .as_str()
                .ok_or_else(|| format!("{observation_id} artifact ID is not a string"))?;
            if previous_artifact_id.is_some_and(|value| value >= artifact_id) {
                return Err(format!(
                    "{observation_id} observation artifact order is not canonical"
                ));
            }
            previous_artifact_id = Some(artifact_id);
            if !artifacts_by_id.contains_key(artifact_id) {
                return Err(format!(
                    "{observation_id} references unknown artifact {artifact_id}"
                ));
            }
            let artifact = artifacts_by_id
                .get(artifact_id)
                .expect("artifact existence checked");
            observed_states.push(effective_state(artifact)?);
            observed_rotations.insert(required_string(&artifact["rotation"], "kind", artifact_id)?);
            if kind == "rotationSplit" {
                observed_rotation_artifacts.push(*artifact);
            }
            observed_artifact_ids.insert(artifact_id.to_owned());
            if !observation_memberships.insert((kind.to_owned(), artifact_id.to_owned())) {
                let kind_label = match kind {
                    "coverageGap" => "coverage-gap",
                    "rotationSplit" => "rotation-split",
                    "malformedRecord" => "malformed-record",
                    "unknownProfile" => "unknown-profile",
                    "invalidOffset" => "invalid-offset",
                    _ => "unsupported",
                };
                return Err(format!(
                    "{observation_id} is a duplicate source-local observation; duplicate {kind_label} observation for {artifact_id}"
                ));
            }
            if kind == "unknownProfile" {
                unknown_profile_observations.insert(artifact_id.to_owned());
            }
            if kind == "invalidOffset" {
                invalid_offset_observations.insert(artifact_id.to_owned());
            }
        }
        if kind == "rotationSplit" {
            if observed_states.len() < 2
                || observed_states.iter().any(|state| state != "partial")
                || observed_rotations != ["current", "lo"].into_iter().collect::<BTreeSet<_>>()
            {
                return Err(format!(
                    "{observation_id} rotationSplit is incompatible with cited artifact coverage/provenance"
                ));
            }
            let observed_rotation_lineages = observed_rotation_artifacts
                .into_iter()
                .map(|artifact| {
                    rotation_lineage_key(family, scenario_root, artifact).map_err(|error| {
                        format!("{observation_id} rotationSplit lineage/key is invalid: {error}")
                    })
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            if observed_rotation_lineages.len() != 1 {
                return Err(format!(
                    "{observation_id} rotationSplit lineage/key is not common"
                ));
            }
        }
        let incompatible = match kind {
            "coverageGap" => observed_states.iter().any(|state| state == "captured"),
            "rotationSplit" => false,
            "malformedRecord" => observed_states.iter().any(|state| state != "parseFailed"),
            "unknownProfile" => artifact_ids.iter().any(|artifact_id| {
                !artifact_id
                    .as_str()
                    .is_some_and(|value| unknown_version_artifacts.contains(value))
            }),
            "invalidOffset" => artifact_ids.iter().any(|artifact_id| {
                !artifact_id
                    .as_str()
                    .is_some_and(|value| invalid_offset_artifacts.contains(value))
            }),
            _ => true,
        };
        if incompatible {
            return Err(format!(
                "{observation_id} {kind} is incompatible with cited artifact coverage/provenance"
            ));
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
    let mut logical_transaction_identities = BTreeSet::new();
    let mut cited_evidence_ranges: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
    let mut previous_transaction_order: Option<(String, u64, u64, String)> = None;
    let mut scenario_semantics = Vec::new();
    for transaction in transactions {
        require_exact_object_fields(
            transaction,
            &[
                "transactionId",
                "workflow",
                "key",
                "phase",
                "state",
                "classification",
                "confidence",
                "lastSuccessfulPhase",
                "evidence",
                "coverageGapArtifactIds",
                "nextArtifact",
            ],
            "transaction",
        )?;
        let transaction_id = required_string(transaction, "transactionId", "transaction")?;
        validate_canonical_id(transaction_id, "transactionId", &format!("{family}-"))?;
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
        let logical_identity = format!(
            "{family}\0{profile}\0{}",
            required_fields
                .iter()
                .map(|field| key[*field].as_str().expect("validated key string"))
                .collect::<Vec<_>>()
                .join("\0")
        );
        if !logical_transaction_identities.insert(logical_identity) {
            return Err(format!(
                "{transaction_id} has duplicate logical transaction identity"
            ));
        }

        let phase = required_string(transaction, "phase", transaction_id)?;
        if !phases.contains(&phase) {
            return Err(format!(
                "{transaction_id} has invalid {family} phase {phase}"
            ));
        }
        let phase_index = phases
            .iter()
            .position(|candidate| *candidate == phase)
            .expect("admitted phase checked above");
        let last_successful_phase =
            if let Some(last_phase) = transaction["lastSuccessfulPhase"].as_str() {
                if !phases.contains(&last_phase) {
                    return Err(format!(
                        "{transaction_id} lastSuccessfulPhase {last_phase} is invalid"
                    ));
                }
                Some(last_phase)
            } else if !transaction["lastSuccessfulPhase"].is_null() {
                return Err(format!(
                    "{transaction_id} lastSuccessfulPhase is neither string nor null"
                ));
            } else {
                None
            };
        if last_successful_phase.is_some_and(|last_phase| {
            phases
                .iter()
                .position(|candidate| *candidate == last_phase)
                .expect("admitted last-success phase checked above")
                > phase_index
        }) {
            return Err(format!(
                "{transaction_id} lastSuccessfulPhase follows the transaction phase"
            ));
        }
        let evidence_refs = transaction["evidence"]
            .as_array()
            .ok_or_else(|| format!("{transaction_id} evidence is not an array"))?;
        if evidence_refs.is_empty() {
            return Err(format!("{transaction_id} has no cited evidence"));
        }
        let mut evidence_order = Vec::new();
        for evidence_ref in evidence_refs {
            require_exact_object_fields(
                evidence_ref,
                &["artifactId", "startLine", "endLine"],
                &format!("{transaction_id} evidence reference"),
            )?;
            let artifact_id =
                required_string(evidence_ref, "artifactId", "evidence reference")?.to_owned();
            let start = evidence_ref["startLine"]
                .as_u64()
                .ok_or_else(|| format!("{transaction_id} evidence startLine is not an integer"))?;
            let end = evidence_ref["endLine"]
                .as_u64()
                .ok_or_else(|| format!("{transaction_id} evidence endLine is not an integer"))?;
            evidence_order.push((artifact_id, start, end));
        }
        if evidence_order.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(format!("{transaction_id} evidence order is not canonical"));
        }
        for (artifact_id, start, end) in &evidence_order {
            if start == &0 || end < start {
                return Err(format!(
                    "{transaction_id} evidence range {start}-{end} is invalid"
                ));
            }
            let prior_ranges = cited_evidence_ranges
                .entry(artifact_id.clone())
                .or_default();
            if prior_ranges
                .iter()
                .any(|(prior_start, prior_end)| start <= prior_end && prior_start <= end)
            {
                return Err(format!(
                    "{transaction_id} has overlapping evidence line identity {artifact_id}:{start}-{end}"
                ));
            }
            prior_ranges.push((*start, *end));
        }
        let first_evidence = evidence_order
            .first()
            .expect("nonempty evidence checked above");
        let transaction_order = (
            first_evidence.0.clone(),
            first_evidence.1,
            first_evidence.2,
            transaction_id.to_owned(),
        );
        if previous_transaction_order
            .as_ref()
            .is_some_and(|previous| previous >= &transaction_order)
        {
            return Err(format!(
                "{transaction_id} transaction order is not canonical"
            ));
        }
        previous_transaction_order = Some(transaction_order);
        let records = evidence_record_texts(scenario_root, &artifacts_by_id, evidence_refs)?;
        for record in &records {
            if !record_field_is(record, "Family", family) {
                return Err(format!(
                    "{transaction_id} Family is not source-record-local and exact"
                ));
            }
            for field in required_fields {
                let value = key[*field].as_str().expect("validated key string");
                if !record_field_is(record, field, value) {
                    return Err(format!(
                        "{transaction_id} {field} is not co-located in every cited CCM record"
                    ));
                }
            }
        }
        if !records
            .iter()
            .any(|record| record_field_is(record, "Phase", phase))
        {
            return Err(format!(
                "{transaction_id} phase {phase} is not bound to cited evidence"
            ));
        }

        let confidence = required_string(transaction, "confidence", transaction_id)?;
        if records
            .iter()
            .any(|record| !record.source_version.starts_with("5.00.TEST."))
        {
            return Err(format!(
                "{transaction_id} exact-key transaction lacks selected profile provenance"
            ));
        }
        let state = required_string(transaction, "state", transaction_id)?;
        let classification = required_string(transaction, "classification", transaction_id)?;
        let has_phase_record = |disposition: &str, terminal: bool| {
            records.iter().any(|record| {
                record_field_is(record, "Phase", phase)
                    && record_field_is(record, "Disposition", disposition)
                    && record_field_is(record, "Terminal", if terminal { "true" } else { "false" })
            })
        };
        let terminal_dispositions = records
            .iter()
            .filter(|record| {
                record_field_is(record, "Phase", phase)
                    && record_field_is(record, "Terminal", "true")
            })
            .filter_map(|record| record.fields.get("Disposition").cloned())
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
                    || !records.iter().any(|record| {
                        record_field_is(record, "Phase", phase)
                            && record_field_is(record, "Disposition", disposition)
                            && record_field_is(record, "Terminal", "true")
                            && record_field_is(record, "ResultType", "Evaluation")
                    })
                {
                    return Err(format!(
                        "{transaction_id} compliance evaluation result is not source-record-local"
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
                    .filter(|record| {
                        record_field_is(record, "Phase", phase)
                            && record_field_is(record, "Disposition", "Failed")
                            && record_field_is(record, "Terminal", "true")
                    })
                    .map(|record| {
                        record
                            .timestamp
                            .utc_millis
                            .expect("normalized timestamp checked during evidence loading")
                    })
                    .max()
                    .expect("terminal failure checked above");
                let earliest_success = records
                    .iter()
                    .filter(|record| {
                        record_field_is(record, "Phase", phase)
                            && record_field_is(record, "Disposition", "Succeeded")
                            && record_field_is(record, "Terminal", "true")
                    })
                    .map(|record| {
                        record
                            .timestamp
                            .utc_millis
                            .expect("normalized timestamp checked during evidence loading")
                    })
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
            "blockedOrDeferred" => {
                if state != "blockedOrDeferred"
                    || confidence != "low"
                    || !(has_phase_record("Pending", false) || has_phase_record("Deferred", false))
                {
                    return Err(format!(
                        "{transaction_id} blocked/deferred state lacks an explicit non-terminal pending or deferred record"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "{transaction_id} has unsupported preparation classification {other}"
                ));
            }
        }
        let evidence_backed_last_success =
            evidence_backed_last_successful_phase(&records, phases, classification);
        if last_successful_phase != evidence_backed_last_success {
            return Err(format!(
                "{transaction_id} lastSuccessfulPhase {last_successful_phase:?} is not evidence-backed as {evidence_backed_last_success:?}"
            ));
        }

        let coverage_gap_ids = transaction["coverageGapArtifactIds"]
            .as_array()
            .ok_or_else(|| format!("{transaction_id} coverageGapArtifactIds is not an array"))?;
        let mut previous_gap_id = None;
        for artifact_id in coverage_gap_ids {
            let artifact_id = artifact_id
                .as_str()
                .ok_or_else(|| format!("{transaction_id} coverage gap ID is not a string"))?;
            if previous_gap_id.is_some_and(|value| value >= artifact_id) {
                return Err(format!(
                    "{transaction_id} coverage gap order is not canonical"
                ));
            }
            previous_gap_id = Some(artifact_id);
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
        let required_next_artifact = expected_next_artifact(family, phase, classification)?;
        match (
            required_next_artifact,
            transaction["nextArtifact"].is_null(),
        ) {
            (Some(_), true) => {
                return Err(format!("{transaction_id} erased required nextArtifact"))
            }
            (None, false) => return Err(format!("{transaction_id} has spurious nextArtifact")),
            (Some(required), false) if transaction["nextArtifact"] != required => {
                return Err(format!(
                    "{transaction_id} nextArtifact differs from required bounded request"
                ))
            }
            _ => {}
        }
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

fn collect_contract_rejection(
    failures: &mut Vec<String>,
    label: &str,
    result: Result<(), String>,
    required_error: &str,
) {
    match result {
        Err(error) if error.contains(required_error) => {}
        Err(error) => failures.push(format!("{label}: wrong rejection: {error}")),
        Ok(()) => failures.push(format!("{label}: unsafe mutation was accepted")),
    }
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
            scenarios: 21,
            artifacts: 55,
            evidence_files: 43,
            evidence_bytes: 17_136,
            capture_states: BTreeMap::from([
                ("absent".to_owned(), 3),
                ("accessDenied".to_owned(), 3),
                ("capped".to_owned(), 3),
                ("captured".to_owned(), 36),
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
fn independent_review_blocker_cited_timestamp_cannot_follow_capture() {
    let (scenario_root, mut manifest, expected) = load_contract("inventory", "success");
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .expect("manifest artifacts are an array")
    {
        artifact["capturedUtc"] = json!("2026-07-30T00:00:00Z");
    }
    assert_rejected_with(
        "complete cited record after capture",
        "inventory",
        "success",
        &scenario_root,
        &manifest,
        &expected,
        "after capturedUtc",
    );
}

#[test]
fn independent_review_blocker_failed_scenarios_require_exact_next_artifacts() {
    let mut failures = Vec::new();
    for family in ["inventory", "compliance", "metering"] {
        let (scenario_root, manifest, expected) = load_contract(family, "terminal-failures");
        for transaction_index in 0..expected["transactions"]
            .as_array()
            .expect("transactions are an array")
            .len()
        {
            let phase = expected["transactions"][transaction_index]["phase"]
                .as_str()
                .expect("phase is a string");
            let mut mutated = expected.clone();
            mutated["transactions"][transaction_index]["nextArtifact"] = Value::Null;
            match validate_contract(
                family,
                "terminal-failures",
                &scenario_root,
                &manifest,
                &mutated,
            ) {
                Err(error) if error.contains("required nextArtifact") => {}
                Err(error) => failures.push(format!("{family}/{phase}: wrong rejection: {error}")),
                Ok(()) => failures.push(format!("{family}/{phase}: erased request was accepted")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn independent_review_blocker_nonfailures_reject_spurious_next_artifacts() {
    let mut failures = Vec::new();
    for (family, scenario) in [
        ("inventory", "success"),
        ("inventory", "recovery-contradictory"),
        ("inventory", "same-minute-collision"),
        ("compliance", "success"),
        ("compliance", "noncompliant-result"),
        ("compliance", "remediation-success"),
        ("compliance", "recovery-contradictory"),
        ("compliance", "same-minute-collision"),
        ("metering", "success"),
        ("metering", "recovery-contradictory"),
        ("metering", "same-minute-collision"),
    ] {
        let (scenario_root, manifest, expected) = load_contract(family, scenario);
        for transaction_index in 0..expected["transactions"]
            .as_array()
            .expect("transactions are an array")
            .len()
        {
            let transaction_id = expected["transactions"][transaction_index]["transactionId"]
                .as_str()
                .expect("transactionId is a string");
            let mut mutated = expected.clone();
            mutated["transactions"][transaction_index]["nextArtifact"] = json!({
                "logicalArtifactId": expected_logical_artifact(family).expect("known family"),
                "sourceBasename": admitted_sources(family).expect("known family")[0],
                "reason": "Inspect the same exact key in this admitted workflow source."
            });
            match validate_contract(family, scenario, &scenario_root, &manifest, &mutated) {
                Err(error) if error.contains("spurious nextArtifact") => {}
                Err(error) => failures.push(format!("{transaction_id}: wrong rejection: {error}")),
                Ok(()) => failures.push(format!("{transaction_id}: spurious request was accepted")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn independent_review_blocker_last_success_respects_family_phase_order() {
    let (scenario_root, manifest, mut expected) = load_contract("inventory", "terminal-failures");
    expected["transactions"][0]["lastSuccessfulPhase"] = json!("Report");
    assert_rejected_with(
        "Collect failure claims later Report success",
        "inventory",
        "terminal-failures",
        &scenario_root,
        &manifest,
        &expected,
        "lastSuccessfulPhase",
    );
}

#[test]
fn independent_review_blocker_recovery_uses_additive_signless_offset_ordering() {
    let (temporary, manifest, expected) = copied_inventory_recovery_with_time_replacements(
        "signless-offset",
        &[
            ("time=\"01:20:00.000+000\"", "time=\"10:00:00.000240\""),
            ("time=\"01:20:01.000+000\"", "time=\"07:00:00.000+000\""),
        ],
    );
    validate_contract(
        "inventory",
        "recovery-contradictory",
        &temporary.root,
        &manifest,
        &expected,
    )
    .unwrap_or_else(|error| {
        panic!("valid signless +240 SCCM provenance must order recovery: {error}")
    });
}

#[test]
fn independent_review_blocker_missing_additive_timestamp_provenance_is_rejected() {
    let (temporary, manifest, expected) = copied_inventory_recovery_with_time_replacements(
        "missing-offset",
        &[
            ("time=\"01:20:00.000+000\"", "time=\"06:00:00.0001234\""),
            ("time=\"01:20:01.000+000\"", "time=\"07:00:00.000+000\""),
        ],
    );
    assert_rejected_with(
        "recovery with missing additive offset",
        "inventory",
        "recovery-contradictory",
        &temporary.root,
        &manifest,
        &expected,
        "normalized additive SCCM timestamp provenance",
    );
}

#[test]
fn independent_review_blocker_invalid_additive_timestamp_provenance_is_rejected() {
    let (temporary, manifest, mut expected) = copied_inventory_recovery_with_time_replacements(
        "invalid-offset",
        &[
            ("time=\"01:20:00.000+000\"", "time=\"06:00:00.000+99999\""),
            ("time=\"01:20:01.000+000\"", "time=\"07:00:00.000+000\""),
        ],
    );
    let artifact_id = manifest["artifacts"][0]["artifactId"]
        .as_str()
        .expect("artifactId is a string");
    expected["sourceLocalObservations"]
        .as_array_mut()
        .expect("sourceLocalObservations are an array")
        .push(json!({
            "observationId": "inventory-recovery-invalid-offset",
            "kind": "invalidOffset",
            "artifactIds": [artifact_id],
            "confidenceCeiling": "low",
            "correlationEligible": false,
            "claim": "Invalid timestamp offset cannot support ordered or high-confidence workflow claims."
        }));
    assert_rejected_with(
        "recovery with invalid additive offset",
        "inventory",
        "recovery-contradictory",
        &temporary.root,
        &manifest,
        &expected,
        "normalized additive SCCM timestamp provenance",
    );
}

#[test]
fn exact_head_review_blocker_structured_fields_are_unique_in_one_ccm_envelope() {
    let cases = [
        (
            "duplicate-report-id",
            "ReportId=INV-REPORT-001",
            "ReportId=INV-REPORT-001 ReportId=INV-REPORT-SHADOW",
            "duplicate structured field",
        ),
        (
            "duplicate-phase",
            "Phase=Report",
            "Phase=Report Phase=Collect",
            "duplicate structured field",
        ),
        (
            "duplicate-terminal",
            "Terminal=true",
            "Terminal=true Terminal=false",
            "duplicate structured field",
        ),
        (
            "duplicate-family",
            "Family=inventory",
            "Family=server Family=inventory",
            "duplicate structured field",
        ),
        (
            "nested-envelope",
            "]LOG]!><time=",
            "]LOG]!><![LOG[SHADOW ENVELOPE]LOG]!><time=",
            "exactly one CCM envelope",
        ),
    ];
    let mut failures = Vec::new();
    for (label, from, to, required_error) in cases {
        let (temporary, manifest, expected) = copied_contract_with_evidence_replacements(
            "inventory",
            "success",
            "inventory-success-report-current",
            label,
            &[(from, to)],
        );
        match validate_contract(
            "inventory",
            "success",
            &temporary.root,
            &manifest,
            &expected,
        ) {
            Err(error) if error.contains(required_error) => {}
            Err(error) => failures.push(format!("{label}: wrong rejection: {error}")),
            Ok(()) => failures.push(format!("{label}: ambiguous record was accepted")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn exact_head_review_blocker_compliance_result_type_is_source_record_local() {
    let (source_root, mut manifest, mut expected) =
        load_contract("compliance", "noncompliant-result");
    let temporary = TemporaryScenario::copy_from(&source_root, "borrowed-result-type");
    let contents = concat!(
        "<![LOG[SYNTHETIC FIXTURE Family=compliance CiId=CI-002 BaselineId=BASELINE-002 ",
        "StateId=STATE-002 ResourceHandle=safe:resource:compliance-002 Phase=Evaluate ",
        "Disposition=NonCompliant Terminal=true]LOG]!><time=\"02:02:00.000+000\" ",
        "date=\"7-30-2026\" component=\"CIAgent\" context=\"\" type=\"1\" thread=\"325\" file=\"\">\n",
        "<![LOG[SYNTHETIC FIXTURE Family=compliance CiId=CI-002 BaselineId=BASELINE-002 ",
        "StateId=STATE-002 ResourceHandle=safe:resource:compliance-002 Phase=Evaluate ",
        "Disposition=Progress Terminal=false ResultType=Evaluation]LOG]!>",
        "<time=\"02:02:01.000+000\" date=\"7-30-2026\" component=\"CIAgent\" ",
        "context=\"\" type=\"1\" thread=\"325\" file=\"\">\n",
    );
    rewrite_artifact_by_id(
        &temporary.root,
        &mut manifest,
        "compliance-noncompliant-result-agent-current",
        contents,
    );
    expected["transactions"][0]["evidence"] = json!([
        {
            "artifactId": "compliance-noncompliant-result-agent-current",
            "startLine": 1,
            "endLine": 1
        },
        {
            "artifactId": "compliance-noncompliant-result-agent-current",
            "startLine": 2,
            "endLine": 2
        }
    ]);
    assert_rejected_with(
        "ResultType borrowed from a nonterminal Report record",
        "compliance",
        "noncompliant-result",
        &temporary.root,
        &manifest,
        &expected,
        "compliance evaluation result is not source-record-local",
    );
}

#[test]
fn exact_head_review_blocker_failed_last_success_is_cited_not_synthesized() {
    let cases = [
        ("inventory", "inventory-provider-failed", "Collect"),
        ("inventory", "inventory-serialize-failed", "Provider"),
        ("inventory", "inventory-queue-failed", "Serialize"),
        ("inventory", "inventory-report-failed", "Queue"),
        ("compliance", "compliance-remediate-failed", "Evaluate"),
        ("compliance", "compliance-report-failed", "Remediate"),
        ("metering", "metering-aggregate-failed", "Collect"),
        ("metering", "metering-report-failed", "Aggregate"),
    ];
    let mut failures = Vec::new();
    for (family, transaction_id, uncited_phase) in cases {
        let (scenario_root, manifest, mut expected) = load_contract(family, "terminal-failures");
        let transaction = expected["transactions"]
            .as_array_mut()
            .expect("transactions are an array")
            .iter_mut()
            .find(|transaction| transaction["transactionId"] == transaction_id)
            .unwrap_or_else(|| panic!("fixture contains transaction {transaction_id}"));
        transaction["lastSuccessfulPhase"] = json!(uncited_phase);
        match validate_contract(
            family,
            "terminal-failures",
            &scenario_root,
            &manifest,
            &expected,
        ) {
            Err(error) if error.contains("not evidence-backed") => {}
            Err(error) => failures.push(format!("{transaction_id}: wrong rejection: {error}")),
            Ok(()) => failures.push(format!(
                "{transaction_id}: uncited predecessor {uncited_phase} was accepted"
            )),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn exact_head_review_blocker_observation_kind_matches_artifact_coverage() {
    let (success_root, success_manifest, mut success_expected) =
        load_contract("inventory", "success");
    success_expected["sourceLocalObservations"] = json!([{
        "observationId": "inventory-captured-as-gap",
        "kind": "coverageGap",
        "artifactIds": ["inventory-success-report-current"],
        "confidenceCeiling": "low",
        "correlationEligible": false,
        "claim": "All non-complete source states remain coverage only; no workflow outcome is inferred."
    }]);
    assert_rejected_with(
        "captured artifact recast as coverage gap",
        "inventory",
        "success",
        &success_root,
        &success_manifest,
        &success_expected,
        "coverageGap is incompatible",
    );

    let (coverage_root, coverage_manifest, mut coverage_expected) =
        load_contract("inventory", "coverage-states");
    coverage_expected["sourceLocalObservations"][0]["kind"] = json!("rotationSplit");
    coverage_expected["sourceLocalObservations"][0]["claim"] = json!(
        "Exact keys split only across incomplete rotation fragments cannot establish a complete workflow."
    );
    assert_rejected_with(
        "all gap states recast as rotation split",
        "inventory",
        "coverage-states",
        &coverage_root,
        &coverage_manifest,
        &coverage_expected,
        "rotationSplit is incompatible",
    );
}

#[test]
fn exact_head_review_blocker_output_schema_and_noncausal_vocabulary_are_closed() {
    let (success_root, success_manifest, success_expected) = load_contract("inventory", "success");
    let mut failures = Vec::new();

    let mut transaction_extension = success_expected.clone();
    transaction_extension["transactions"][0]["serverCause"] = json!("ManagementPoint");
    match validate_contract(
        "inventory",
        "success",
        &success_root,
        &success_manifest,
        &transaction_extension,
    ) {
        Err(error) if error.contains("transaction fields") => {}
        Err(error) => failures.push(format!("transaction extension: wrong rejection: {error}")),
        Ok(()) => failures.push("transaction serverCause was accepted".to_owned()),
    }

    let mut top_level_extension = success_expected.clone();
    top_level_extension["serverCause"] = json!("ManagementPoint");
    match validate_contract(
        "inventory",
        "success",
        &success_root,
        &success_manifest,
        &top_level_extension,
    ) {
        Err(error) if error.contains("expected fields") => {}
        Err(error) => failures.push(format!("top-level extension: wrong rejection: {error}")),
        Ok(()) => failures.push("top-level serverCause was accepted".to_owned()),
    }

    let (coverage_root, coverage_manifest, coverage_expected) =
        load_contract("inventory", "coverage-states");
    let mut observation_extension = coverage_expected.clone();
    observation_extension["sourceLocalObservations"][0]["serverRole"] = json!("managementPoint");
    match validate_contract(
        "inventory",
        "coverage-states",
        &coverage_root,
        &coverage_manifest,
        &observation_extension,
    ) {
        Err(error) if error.contains("observation fields") => {}
        Err(error) => failures.push(format!("observation extension: wrong rejection: {error}")),
        Ok(()) => failures.push("observation serverRole was accepted".to_owned()),
    }

    let mut causal_synonyms = coverage_expected.clone();
    causal_synonyms["sourceLocalObservations"][0]["claim"] =
        json!("A management-point outage triggered and explains the client result.");
    match validate_contract(
        "inventory",
        "coverage-states",
        &coverage_root,
        &coverage_manifest,
        &causal_synonyms,
    ) {
        Err(error) if error.contains("claim is not canonical") => {}
        Err(error) => failures.push(format!("causal synonyms: wrong rejection: {error}")),
        Ok(()) => failures.push("causal triggered/explains claim was accepted".to_owned()),
    }

    let mut rewritten_prohibitions = success_expected.clone();
    rewritten_prohibitions["prohibitedClaims"] = json!([
        "missing evidence proves success",
        "same-time records prove causation",
        "client evidence proves a server outage",
        "this corpus is live Windows acceptance"
    ]);
    match validate_contract(
        "inventory",
        "success",
        &success_root,
        &success_manifest,
        &rewritten_prohibitions,
    ) {
        Err(error) if error.contains("prohibitedClaims") => {}
        Err(error) => failures.push(format!("prohibited claims: wrong rejection: {error}")),
        Ok(()) => failures.push("affirmative prohibitedClaims were accepted".to_owned()),
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn exact_head_review_blocker_transaction_identity_and_collision_topology_are_unique() {
    let (scenario_root, manifest, mut expected) =
        load_contract("inventory", "same-minute-collision");
    expected["transactions"][1]["key"] = expected["transactions"][0]["key"].clone();
    expected["transactions"][1]["evidence"] = expected["transactions"][0]["evidence"].clone();
    assert_rejected_with(
        "different transaction IDs duplicate one exact key and evidence",
        "inventory",
        "same-minute-collision",
        &scenario_root,
        &manifest,
        &expected,
        "duplicate logical transaction identity",
    );

    let (_, mut manifest, expected) = load_contract("inventory", "same-minute-collision");
    manifest["artifacts"][1]["sanitizedSourcePath"] =
        manifest["artifacts"][0]["sanitizedSourcePath"].clone();
    assert_rejected_with(
        "cross-root paths collapse while fingerprints differ",
        "inventory",
        "same-minute-collision",
        &scenario_root,
        &manifest,
        &expected,
        "source topology",
    );
}

#[test]
fn exact_head_review_blocker_all_ordered_arrays_are_canonical() {
    let mut failures = Vec::new();

    let (collision_root, collision_manifest, mut collision_expected) =
        load_contract("inventory", "same-minute-collision");
    collision_expected["transactions"]
        .as_array_mut()
        .expect("transactions are an array")
        .reverse();
    match validate_contract(
        "inventory",
        "same-minute-collision",
        &collision_root,
        &collision_manifest,
        &collision_expected,
    ) {
        Err(error) if error.contains("transaction order is not canonical") => {}
        Err(error) => failures.push(format!("transaction order: wrong rejection: {error}")),
        Ok(()) => failures.push("reversed transaction order was accepted".to_owned()),
    }

    let (recovery_root, recovery_manifest, mut recovery_expected) =
        load_contract("inventory", "recovery-contradictory");
    recovery_expected["transactions"][0]["evidence"]
        .as_array_mut()
        .expect("evidence is an array")
        .reverse();
    match validate_contract(
        "inventory",
        "recovery-contradictory",
        &recovery_root,
        &recovery_manifest,
        &recovery_expected,
    ) {
        Err(error) if error.contains("evidence order is not canonical") => {}
        Err(error) => failures.push(format!("evidence order: wrong rejection: {error}")),
        Ok(()) => failures.push("reversed evidence order was accepted".to_owned()),
    }

    let (success_root, mut success_manifest, mut success_expected) =
        load_contract("inventory", "success");
    success_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .reverse();
    success_expected["coverage"]
        .as_array_mut()
        .expect("coverage is an array")
        .reverse();
    match validate_contract(
        "inventory",
        "success",
        &success_root,
        &success_manifest,
        &success_expected,
    ) {
        Err(error) if error.contains("manifest artifact order is not canonical") => {}
        Err(error) => failures.push(format!("manifest order: wrong rejection: {error}")),
        Ok(()) => failures.push("reversed manifest/coverage order was accepted".to_owned()),
    }

    let (_, success_manifest, mut success_expected) = load_contract("inventory", "success");
    success_expected["coverage"]
        .as_array_mut()
        .expect("coverage is an array")
        .reverse();
    match validate_contract(
        "inventory",
        "success",
        &success_root,
        &success_manifest,
        &success_expected,
    ) {
        Err(error) if error.contains("coverage order is not canonical") => {}
        Err(error) => failures.push(format!("coverage order: wrong rejection: {error}")),
        Ok(()) => failures.push("reversed coverage order was accepted".to_owned()),
    }

    let (profile_root, profile_manifest, mut profile_expected) =
        load_contract("compliance", "malformed-unknown-profile-invalid-offset");
    profile_expected["sourceLocalObservations"]
        .as_array_mut()
        .expect("observations are an array")
        .reverse();
    match validate_contract(
        "compliance",
        "malformed-unknown-profile-invalid-offset",
        &profile_root,
        &profile_manifest,
        &profile_expected,
    ) {
        Err(error) if error.contains("observation order is not canonical") => {}
        Err(error) => failures.push(format!("observation order: wrong rejection: {error}")),
        Ok(()) => failures.push("reversed observation order was accepted".to_owned()),
    }

    let (coverage_root, coverage_manifest, mut coverage_expected) =
        load_contract("inventory", "coverage-states");
    coverage_expected["sourceLocalObservations"][0]["artifactIds"]
        .as_array_mut()
        .expect("artifactIds are an array")
        .reverse();
    match validate_contract(
        "inventory",
        "coverage-states",
        &coverage_root,
        &coverage_manifest,
        &coverage_expected,
    ) {
        Err(error) if error.contains("observation artifact order is not canonical") => {}
        Err(error) => failures.push(format!(
            "observation artifact order: wrong rejection: {error}"
        )),
        Ok(()) => failures.push("reversed observation artifact order was accepted".to_owned()),
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
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
    let complete_record = |payload: &str| {
        format!(
            "<![LOG[{payload}]LOG]!><time=\"01:00:00.000+000\" date=\"7-30-2026\" component=\"Synthetic\" context=\"\" type=\"1\" thread=\"325\" file=\"\">"
        )
    };
    for (field, value) in [
        ("ReportId", "INV-REPORT-001"),
        ("Phase", "Report"),
        ("Disposition", "Succeeded"),
        ("Terminal", "true"),
        ("ResultType", "Evaluation"),
    ] {
        let exact = complete_record(&format!("{field}={value}"));
        let exact_fields =
            strict_ccm_structured_fields(&exact, "exact token").expect("exact record is valid");
        assert_eq!(exact_fields.get(field).map(String::as_str), Some(value));

        for lookalike in [
            complete_record(&format!("Other{field}={value}")),
            complete_record(&format!("Prefix{field}={value}")),
            complete_record(&format!("{field}={value}-suffix")),
            complete_record(&format!("X={field}={value}")),
        ] {
            let fields = strict_ccm_structured_fields(&lookalike, "look-alike token")
                .expect("look-alike is still one complete record");
            assert!(
                fields.get(field).is_none_or(|actual| actual != value),
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
            "claim": "Unknown source version has no selected extraction profile."
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
    promoted_failure["transactions"][0]["lastSuccessfulPhase"] = json!("Queue");
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
        "claim is not canonical",
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

#[test]
fn review_blocker_physical_identity_and_cross_root_topology_are_closed() {
    let mut failures = Vec::new();
    for (family, target_id, source_id) in [
        (
            "inventory",
            "inventory-coverage-states-skipped",
            "inventory-coverage-states-partial",
        ),
        (
            "inventory",
            "inventory-coverage-states-unsupported",
            "inventory-coverage-states-access-denied",
        ),
        (
            "compliance",
            "compliance-coverage-states-access-denied",
            "compliance-coverage-states-partial",
        ),
    ] {
        let (scenario_root, mut manifest, expected) = load_contract(family, "coverage-states");
        let artifacts = manifest["artifacts"]
            .as_array_mut()
            .expect("artifacts are an array");
        let source_path = artifacts
            .iter()
            .find(|artifact| artifact["artifactId"] == source_id)
            .expect("source artifact exists")["sanitizedSourcePath"]
            .clone();
        let source_root = source_path
            .as_str()
            .expect("source path is a string")
            .strip_prefix("SYNTHETIC://")
            .expect("source path is synthetic")
            .split('/')
            .next()
            .expect("source path has a root")
            .to_owned();
        let target = artifacts
            .iter_mut()
            .find(|artifact| artifact["artifactId"] == target_id)
            .expect("target artifact exists");
        target["sanitizedSourcePath"] = source_path;
        target["pathFingerprint"] = json!(format!("synthetic-{target_id}-{source_root}"));
        collect_contract_rejection(
            &mut failures,
            &format!("{family} contradictory physical identity {target_id}/{source_id}"),
            validate_contract(
                family,
                "coverage-states",
                &scenario_root,
                &manifest,
                &expected,
            ),
            "duplicate physical source identity",
        );
    }

    let (scenario_root, mut collapsed_manifest, expected) =
        load_contract("inventory", "same-minute-collision");
    collapsed_manifest["artifacts"][1]["sanitizedSourcePath"] =
        json!("SYNTHETIC://root-a/alternate/CCM/Logs/InventoryAgentProvider.log");
    collect_contract_rejection(
        &mut failures,
        "cross-root source collapsed beneath an alternate root-a path",
        validate_contract(
            "inventory",
            "same-minute-collision",
            &scenario_root,
            &collapsed_manifest,
            &expected,
        ),
        "source topology",
    );

    let (_, mut swapped_manifest, expected) = load_contract("inventory", "same-minute-collision");
    let first_fingerprint = swapped_manifest["artifacts"][0]["pathFingerprint"].clone();
    swapped_manifest["artifacts"][0]["pathFingerprint"] =
        swapped_manifest["artifacts"][1]["pathFingerprint"].clone();
    swapped_manifest["artifacts"][1]["pathFingerprint"] = first_fingerprint;
    collect_contract_rejection(
        &mut failures,
        "cross-root fingerprints swapped between exact source handles",
        validate_contract(
            "inventory",
            "same-minute-collision",
            &scenario_root,
            &swapped_manifest,
            &expected,
        ),
        "source topology",
    );

    let (success_root, mut same_root_manifest, success_expected) =
        load_contract("inventory", "success");
    let first_fingerprint = same_root_manifest["artifacts"][0]["pathFingerprint"].clone();
    same_root_manifest["artifacts"][0]["pathFingerprint"] =
        same_root_manifest["artifacts"][1]["pathFingerprint"].clone();
    same_root_manifest["artifacts"][1]["pathFingerprint"] = first_fingerprint;
    collect_contract_rejection(
        &mut failures,
        "same-root fingerprints swapped between artifact handles",
        validate_contract(
            "inventory",
            "success",
            &success_root,
            &same_root_manifest,
            &success_expected,
        ),
        "source topology",
    );

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn review_blocker_manifest_and_ccm_structured_vocabularies_are_closed() {
    let mut failures = Vec::new();
    for (label, injected_field) in [
        ("server cause", "ServerCause=ManagementPoint"),
        ("server role", "Role=server"),
        ("foreign workflow", "Workflow=compliance"),
    ] {
        let replacement = format!("{injected_field} Phase=Report");
        let (temporary, manifest, expected) = copied_contract_with_evidence_replacements(
            "inventory",
            "success",
            "inventory-success-report-current",
            label,
            &[("Phase=Report", &replacement)],
        );
        collect_contract_rejection(
            &mut failures,
            &format!("unknown CCM field {injected_field}"),
            validate_contract(
                "inventory",
                "success",
                &temporary.root,
                &manifest,
                &expected,
            ),
            "unadmitted structured field",
        );
    }

    let (scenario_root, mut manifest, expected) = load_contract("inventory", "success");
    manifest["artifacts"][0]["serverCause"] = json!("ManagementPoint");
    collect_contract_rejection(
        &mut failures,
        "undeclared SCCM manifest artifact serverCause",
        validate_contract("inventory", "success", &scenario_root, &manifest, &expected),
        "artifact fields",
    );

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn review_blocker_bundle_identity_and_order_descriptors_are_closed() {
    let (scenario_root, manifest, expected) = load_contract("inventory", "success");
    let mutations = [
        (
            "foreign-scenario bundleId",
            "bundleId",
            json!("sccm-325-inventory-terminal-failures"),
        ),
        (
            "arbitrary-suffix bundleId",
            "bundleId",
            json!("sccm-325-inventory-anything"),
        ),
        ("boolean artifactOrder", "artifactOrder", json!(false)),
        (
            "altered artifactOrder",
            "artifactOrder",
            json!("artifactId,originalBasename"),
        ),
        ("boolean rotationOrder", "rotationOrder", json!(false)),
        (
            "altered rotationOrder",
            "rotationOrder",
            json!("timestamp-descending,current"),
        ),
    ];
    let mut failures = Vec::new();

    for (label, field, value) in mutations {
        let mut mutated = manifest.clone();
        mutated["bundle"][field] = value;
        collect_contract_rejection(
            &mut failures,
            label,
            validate_contract("inventory", "success", &scenario_root, &mutated, &expected),
            field,
        );
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn review_blocker_public_identities_are_nonempty_control_free_and_scoped() {
    let mut failures = Vec::new();

    for (label, replacement) in [
        ("blank artifactId", String::new()),
        (
            "control-bearing artifactId",
            "metering-success\nforeign".to_owned(),
        ),
        (
            "foreign-family artifactId",
            "inventory-success-report-current".to_owned(),
        ),
        (
            "overlong artifactId",
            format!("metering-success-{}", "a".repeat(112)),
        ),
    ] {
        let (scenario_root, mut manifest, mut expected) = load_contract("metering", "success");
        manifest["artifacts"][0]["artifactId"] = json!(&replacement);
        manifest["artifacts"][0]["pathFingerprint"] =
            json!(format!("synthetic-{replacement}-root-a"));
        expected["coverage"][0]["artifactId"] = json!(&replacement);
        expected["transactions"][0]["evidence"][0]["artifactId"] = json!(&replacement);
        collect_contract_rejection(
            &mut failures,
            label,
            validate_contract("metering", "success", &scenario_root, &manifest, &expected),
            "artifactId is not canonical",
        );
    }

    for (label, replacement) in [
        ("blank transactionId", String::new()),
        (
            "control-bearing transactionId",
            "metering-success\nforeign".to_owned(),
        ),
        (
            "foreign-family transactionId",
            "inventory-success".to_owned(),
        ),
        (
            "overlong transactionId",
            format!("metering-{}", "a".repeat(120)),
        ),
    ] {
        let (scenario_root, manifest, mut expected) = load_contract("metering", "success");
        expected["transactions"][0]["transactionId"] = json!(&replacement);
        collect_contract_rejection(
            &mut failures,
            label,
            validate_contract("metering", "success", &scenario_root, &manifest, &expected),
            "transactionId is not canonical",
        );
    }

    for (label, replacement) in [
        ("blank observationId", String::new()),
        (
            "control-bearing observationId",
            "metering-coverage-only\nforeign".to_owned(),
        ),
        (
            "foreign-family observationId",
            "inventory-coverage-only".to_owned(),
        ),
        (
            "overlong observationId",
            format!("metering-{}", "a".repeat(120)),
        ),
    ] {
        let (scenario_root, manifest, mut expected) = load_contract("metering", "coverage-states");
        expected["sourceLocalObservations"][0]["observationId"] = json!(&replacement);
        collect_contract_rejection(
            &mut failures,
            label,
            validate_contract(
                "metering",
                "coverage-states",
                &scenario_root,
                &manifest,
                &expected,
            ),
            "observationId is not canonical",
        );
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn review_blocker_sources_own_exact_phases_and_workflow_semantics() {
    let (temporary, manifest, mut expected) = copied_contract_with_evidence_replacements(
        "inventory",
        "success",
        "inventory-success-agent-current",
        "agent-borrows-report-phase",
        &[(
            "Phase=Collect Disposition=Succeeded Terminal=false",
            "Phase=Report Disposition=Succeeded Terminal=true",
        )],
    );
    expected["transactions"][0]["evidence"] = json!([{
        "artifactId": "inventory-success-agent-current",
        "startLine": 1,
        "endLine": 1
    }]);
    assert_rejected_with(
        "InventoryAgent record relabeled as terminal Report success",
        "inventory",
        "success",
        &temporary.root,
        &manifest,
        &expected,
        "does not own phase",
    );
}

#[test]
fn review_blocker_inventory_does_not_borrow_compliance_completion_semantics() {
    let (scenario_root, manifest, _) = load_contract("inventory", "success");
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array");
    let artifacts_by_id = artifacts
        .iter()
        .map(|artifact| {
            (
                artifact["artifactId"]
                    .as_str()
                    .expect("artifactId is a string")
                    .to_owned(),
                artifact,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let evidence = json!([{
        "artifactId": "inventory-success-agent-current",
        "startLine": 1,
        "endLine": 1
    }]);
    let mut records = evidence_record_texts(
        &scenario_root,
        &artifacts_by_id,
        evidence.as_array().expect("evidence is an array"),
    )
    .expect("inventory collect evidence is readable");
    records[0]
        .fields
        .insert("Disposition".to_owned(), "NonCompliant".to_owned());
    records[0]
        .fields
        .insert("Terminal".to_owned(), "true".to_owned());
    records[0]
        .fields
        .insert("ResultType".to_owned(), "Evaluation".to_owned());
    assert_eq!(
        evidence_backed_last_successful_phase(
            &records,
            admitted_phases("inventory").expect("inventory phases"),
            "confirmedFailure",
        ),
        None,
        "inventory must not infer a predecessor from compliance evaluation semantics"
    );
}

#[test]
fn review_blocker_capture_state_provenance_is_closed() {
    let mut failures = Vec::new();

    let (success_root, mut captured_manifest, success_expected) =
        load_contract("inventory", "success");
    captured_manifest["artifacts"][0]["collectionLimit"]["limitApplied"] = json!(true);
    captured_manifest["artifacts"][0]["truncated"] = json!(true);
    collect_contract_rejection(
        &mut failures,
        "captured source claims an applied truncating cap",
        validate_contract(
            "inventory",
            "success",
            &success_root,
            &captured_manifest,
            &success_expected,
        ),
        "captured state provenance",
    );

    let (coverage_root, mut nonphysical_manifest, coverage_expected) =
        load_contract("inventory", "coverage-states");
    let access_denied = nonphysical_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "inventory-coverage-states-access-denied")
        .expect("access-denied artifact exists");
    access_denied["encoding"] = json!("utf-8");
    access_denied["collectionLimit"] = json!({
        "byteLimit": 0,
        "limitApplied": true
    });
    access_denied["truncated"] = json!(true);
    collect_contract_rejection(
        &mut failures,
        "accessDenied source invents encoding cap and truncation",
        validate_contract(
            "inventory",
            "coverage-states",
            &coverage_root,
            &nonphysical_manifest,
            &coverage_expected,
        ),
        "nonphysical state provenance",
    );

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn review_blocker_nonphysical_optional_field_json_types_are_closed() {
    let (scenario_root, manifest, expected) = load_contract("inventory", "coverage-states");
    let mut failures = Vec::new();
    let mutations = vec![
        (
            "accessDenied.relativePath=false",
            "accessDenied",
            "relativePath",
            json!(false),
            "relativePath",
        ),
        (
            "skipped.relativePath=0",
            "skipped",
            "relativePath",
            json!(0),
            "relativePath",
        ),
        (
            "unsupported.relativePath=[]",
            "unsupported",
            "relativePath",
            json!([]),
            "relativePath",
        ),
        (
            "absent.relativePath={}",
            "absent",
            "relativePath",
            json!({}),
            "relativePath",
        ),
        (
            "accessDenied.sourceVersion=false",
            "accessDenied",
            "sourceVersion",
            json!(false),
            "sourceVersion",
        ),
        (
            "skipped.sourceVersion={unexpected:true}",
            "skipped",
            "sourceVersion",
            json!({"unexpected": true}),
            "sourceVersion",
        ),
        (
            "unsupported.sourceVersion=[]",
            "unsupported",
            "sourceVersion",
            json!([]),
            "sourceVersion",
        ),
        (
            "accessDenied.sanitizedSourcePath=false",
            "accessDenied",
            "sanitizedSourcePath",
            json!(false),
            "sanitizedSourcePath",
        ),
        (
            "skipped.pathFingerprint={}",
            "skipped",
            "pathFingerprint",
            json!({}),
            "pathFingerprint",
        ),
    ];

    for (label, capture_state, field, value, required_error) in mutations {
        let mut mutated = manifest.clone();
        let artifact = mutated["artifacts"]
            .as_array_mut()
            .expect("artifacts are an array")
            .iter_mut()
            .find(|artifact| artifact["captureState"] == capture_state)
            .unwrap_or_else(|| panic!("{capture_state} artifact exists"));
        artifact[field] = value;
        collect_contract_rejection(
            &mut failures,
            label,
            validate_contract(
                "inventory",
                "coverage-states",
                &scenario_root,
                &mutated,
                &expected,
            ),
            required_error,
        );
    }

    for capture_state in ["accessDenied", "skipped", "unsupported"] {
        let mut version_unknown = manifest.clone();
        let artifact = version_unknown["artifacts"]
            .as_array_mut()
            .expect("artifacts are an array")
            .iter_mut()
            .find(|artifact| artifact["captureState"] == capture_state)
            .unwrap_or_else(|| panic!("{capture_state} artifact exists"));
        artifact["sourceVersion"] = Value::Null;
        if let Err(error) = validate_contract(
            "inventory",
            "coverage-states",
            &scenario_root,
            &version_unknown,
            &expected,
        ) {
            failures.push(format!(
                "{capture_state}.sourceVersion=null: valid optional version was rejected: {error}"
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn review_blocker_source_versions_are_canonical_before_profile_selection() {
    let (scenario_root, manifest, expected) = load_contract("metering", "success");
    let mut failures = Vec::new();

    for (label, source_version) in [
        ("blank sourceVersion", ""),
        (
            "control-bearing sourceVersion",
            "5.00.TEST.325\n9.99.UNKNOWN",
        ),
        ("whitespace-bearing sourceVersion", "5.00.TEST.325 "),
        ("empty sourceVersion segment", "5.00.TEST..325"),
    ] {
        let mut mutated = manifest.clone();
        mutated["artifacts"][0]["sourceVersion"] = json!(source_version);
        collect_contract_rejection(
            &mut failures,
            label,
            validate_contract("metering", "success", &scenario_root, &mutated, &expected),
            "sourceVersion is not canonical",
        );
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn review_blocker_unknown_versions_are_profile_gaps_for_every_coverage_state() {
    let (scenario_root, manifest, expected) = load_contract("inventory", "coverage-states");
    let mut failures = Vec::new();
    let versioned_artifacts = manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array")
        .iter()
        .filter_map(|artifact| {
            artifact["sourceVersion"].as_str().map(|_| {
                (
                    artifact["artifactId"]
                        .as_str()
                        .expect("artifactId is a string")
                        .to_owned(),
                    artifact["captureState"]
                        .as_str()
                        .expect("captureState is a string")
                        .to_owned(),
                )
            })
        })
        .collect::<Vec<_>>();

    for (artifact_id, capture_state) in versioned_artifacts {
        let mut unknown_manifest = manifest.clone();
        let artifact = unknown_manifest["artifacts"]
            .as_array_mut()
            .expect("artifacts are an array")
            .iter_mut()
            .find(|artifact| artifact["artifactId"] == artifact_id)
            .unwrap_or_else(|| panic!("{artifact_id} exists"));
        artifact["sourceVersion"] = json!("9.99.UNKNOWN");

        collect_contract_rejection(
            &mut failures,
            &format!("{capture_state} unknown version without profile gap"),
            validate_contract(
                "inventory",
                "coverage-states",
                &scenario_root,
                &unknown_manifest,
                &expected,
            ),
            "profile selection",
        );

        let mut gap_expected = expected.clone();
        gap_expected["extractionProfile"]["selectionState"] = json!("mixedKnownAndUnknown");
        gap_expected["sourceLocalObservations"]
            .as_array_mut()
            .expect("sourceLocalObservations are an array")
            .push(json!({
                "observationId": format!(
                    "inventory-coverage-unknown-profile-{artifact_id}"
                ),
                "kind": "unknownProfile",
                "artifactIds": [artifact_id],
                "confidenceCeiling": "low",
                "correlationEligible": false,
                "claim": "Unknown source version has no selected extraction profile."
            }));
        if let Err(error) = validate_contract(
            "inventory",
            "coverage-states",
            &scenario_root,
            &unknown_manifest,
            &gap_expected,
        ) {
            failures.push(format!(
                "{capture_state} unknown version with bounded profile gap was rejected: {error}"
            ));
        }
    }

    let mut absent_version = manifest.clone();
    let absent = absent_version["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["captureState"] == "absent")
        .expect("absent artifact exists");
    absent["sourceVersion"] = json!("9.99.UNKNOWN");
    collect_contract_rejection(
        &mut failures,
        "absent source invents an unknown version",
        validate_contract(
            "inventory",
            "coverage-states",
            &scenario_root,
            &absent_version,
            &expected,
        ),
        "absent source invents path/version identity",
    );

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn review_blocker_source_local_observation_memberships_are_unique_by_kind() {
    let mut failures = Vec::new();

    for (family, scenario, kind) in [
        ("metering", "coverage-states", "coverageGap"),
        (
            "compliance",
            "malformed-unknown-profile-invalid-offset",
            "malformedRecord",
        ),
        (
            "compliance",
            "malformed-unknown-profile-invalid-offset",
            "invalidOffset",
        ),
        ("metering", "rotation-boundary", "rotationSplit"),
    ] {
        let (scenario_root, manifest, mut expected) = load_contract(family, scenario);
        let observations = expected["sourceLocalObservations"]
            .as_array_mut()
            .expect("sourceLocalObservations are an array");
        let mut duplicate = observations
            .iter()
            .find(|observation| observation["kind"] == kind)
            .unwrap_or_else(|| panic!("{family}/{scenario} contains {kind}"))
            .clone();
        let observation_id = duplicate["observationId"]
            .as_str()
            .expect("observationId is a string");
        duplicate["observationId"] = json!(format!("{observation_id}-z"));
        observations.push(duplicate);
        observations.sort_by(|left, right| {
            left["observationId"]
                .as_str()
                .cmp(&right["observationId"].as_str())
        });

        collect_contract_rejection(
            &mut failures,
            &format!("duplicate {kind} membership"),
            validate_contract(family, scenario, &scenario_root, &manifest, &expected),
            "duplicate source-local observation",
        );
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn review_blocker_rotation_split_requires_one_source_lineage_and_exact_key() {
    let mut failures = Vec::new();

    let (inventory_source_root, mut inventory_manifest, inventory_expected) =
        load_contract("inventory", "rotation-boundary");
    let inventory_temporary =
        TemporaryScenario::copy_from(&inventory_source_root, "rotation-basename-mismatch");
    let inventory_artifact = &mut inventory_manifest["artifacts"][0];
    let old_relative_path = inventory_artifact["relativePath"]
        .as_str()
        .expect("current inventory artifact relativePath is a string")
        .to_owned();
    let new_relative_path =
        "evidence/client-inventory/root-a/current/InventoryAgentProvider.log".to_owned();
    let new_full_path = inventory_temporary.root.join(&new_relative_path);
    let provider_contents = "<![LOG[SYNTHETIC FIXTURE Family=inventory InventoryCycleId=INV-CYCLE-025 ResourceHandle=safe:resource:inventory-025 ReportId=INV-REPORT-025 Phase=Report Disposition=Succeeded Terminal=true]LOG]!><time=\"01:25:01.000+000\" date=\"7-30-2026\" component=\"InventoryAgentProvider\" context=\"\" type=\"1\" thread=\"325\" file=\"\">\n";
    std::fs::remove_file(inventory_temporary.root.join(old_relative_path))
        .expect("current inventory evidence can be replaced");
    std::fs::write(&new_full_path, provider_contents)
        .expect("mismatched provider evidence can be written");
    inventory_artifact["originalBasename"] = json!("InventoryAgentProvider.log");
    inventory_artifact["sanitizedSourcePath"] =
        json!("SYNTHETIC://root-a/CCM/Logs/InventoryAgentProvider.log");
    inventory_artifact["relativePath"] = json!(new_relative_path);
    inventory_artifact["bytesCopied"] = json!(provider_contents.len() as u64);
    collect_contract_rejection(
        &mut failures,
        "different canonical basenames form one rotation split",
        validate_contract(
            "inventory",
            "rotation-boundary",
            &inventory_temporary.root,
            &inventory_manifest,
            &inventory_expected,
        ),
        "rotationSplit lineage/key",
    );

    let (metering_root, mut version_manifest, mut version_expected) =
        load_contract("metering", "rotation-boundary");
    let unknown_artifact_id = "metering-rotation-boundary-report-lo";
    version_manifest["artifacts"][1]["sourceVersion"] = json!("9.99.UNKNOWN");
    version_expected["extractionProfile"]["selectionState"] = json!("mixedKnownAndUnknown");
    version_expected["sourceLocalObservations"]
        .as_array_mut()
        .expect("sourceLocalObservations are an array")
        .push(json!({
            "observationId": "metering-rotation-unknown-profile",
            "kind": "unknownProfile",
            "artifactIds": [unknown_artifact_id],
            "confidenceCeiling": "low",
            "correlationEligible": false,
            "claim": "Unknown source version has no selected extraction profile."
        }));
    collect_contract_rejection(
        &mut failures,
        "different source versions form one rotation split",
        validate_contract(
            "metering",
            "rotation-boundary",
            &metering_root,
            &version_manifest,
            &version_expected,
        ),
        "rotationSplit lineage/key",
    );

    let (temporary, key_manifest, key_expected) = copied_contract_with_evidence_replacements(
        "metering",
        "rotation-boundary",
        "metering-rotation-boundary-report-current",
        "rotation-key-mismatch",
        &[("RuleId=RULE-025", "RuleId=RULE-999")],
    );
    collect_contract_rejection(
        &mut failures,
        "different exact keys form one rotation split",
        validate_contract(
            "metering",
            "rotation-boundary",
            &temporary.root,
            &key_manifest,
            &key_expected,
        ),
        "rotationSplit lineage/key",
    );

    let (source_root, mut root_manifest, root_expected) =
        load_contract("metering", "rotation-boundary");
    let temporary = TemporaryScenario::copy_from(&source_root, "rotation-root-mismatch");
    let artifact = &mut root_manifest["artifacts"][1];
    let old_relative_path = artifact["relativePath"]
        .as_str()
        .expect("lo artifact relativePath is a string")
        .to_owned();
    let new_relative_path = "evidence/client-metering/root-b/lo/SWMTRReportGen.log.lo".to_owned();
    let new_full_path = temporary.root.join(&new_relative_path);
    std::fs::create_dir_all(
        new_full_path
            .parent()
            .expect("root-mismatch destination has a parent"),
    )
    .expect("root-mismatch destination can be created");
    std::fs::rename(temporary.root.join(old_relative_path), &new_full_path)
        .expect("lo evidence can move to a distinct synthetic root");
    artifact["sanitizedSourcePath"] = json!("SYNTHETIC://root-b/CCM/Logs/SWMTRReportGen.log.lo");
    artifact["pathFingerprint"] = json!("synthetic-metering-rotation-boundary-report-lo-root-b");
    artifact["relativePath"] = json!(new_relative_path);
    collect_contract_rejection(
        &mut failures,
        "different synthetic roots form one rotation split",
        validate_contract(
            "metering",
            "rotation-boundary",
            &temporary.root,
            &root_manifest,
            &root_expected,
        ),
        "rotationSplit lineage/key",
    );

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn review_blocker_unknown_profile_observation_is_unique_per_artifact() {
    let (scenario_root, mut manifest, mut expected) = load_contract("inventory", "coverage-states");
    let artifact_id = "inventory-coverage-states-access-denied";
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == artifact_id)
        .expect("accessDenied artifact exists");
    artifact["sourceVersion"] = json!("9.99.UNKNOWN");
    expected["extractionProfile"]["selectionState"] = json!("mixedKnownAndUnknown");
    for suffix in ["a", "b"] {
        expected["sourceLocalObservations"]
            .as_array_mut()
            .expect("sourceLocalObservations are an array")
            .push(json!({
                "observationId": format!(
                    "inventory-coverage-unknown-profile-{suffix}"
                ),
                "kind": "unknownProfile",
                "artifactIds": [artifact_id],
                "confidenceCeiling": "low",
                "correlationEligible": false,
                "claim": "Unknown source version has no selected extraction profile."
            }));
    }

    assert_rejected_with(
        "two canonical unknownProfile observations cite one artifact",
        "inventory",
        "coverage-states",
        &scenario_root,
        &manifest,
        &expected,
        "duplicate unknown-profile observation",
    );
}

#[test]
fn review_blocker_evidence_line_identity_is_unique_and_nonoverlapping() {
    let (scenario_root, manifest, expected) = load_contract("inventory", "recovery-contradictory");

    let mut overlapping = expected.clone();
    overlapping["transactions"][0]["evidence"][0]["endLine"] = json!(2);
    assert_rejected_with(
        "recovery cites ranges 1-2 and 2-2",
        "inventory",
        "recovery-contradictory",
        &scenario_root,
        &manifest,
        &overlapping,
        "overlapping evidence line",
    );

    let mut duplicated = expected;
    duplicated["transactions"][0]["evidence"][1] =
        duplicated["transactions"][0]["evidence"][0].clone();
    assert_rejected(
        "recovery duplicates the same physical evidence range",
        "inventory",
        "recovery-contradictory",
        &scenario_root,
        &manifest,
        &duplicated,
    );
}

#[test]
fn review_blocker_windows_evidence_paths_use_manifest_separators() {
    assert_eq!(
        normalize_manifest_relative_path(
            r"evidence\client-inventory\root-a\current\InventoryAgent.log"
        ),
        "evidence/client-inventory/root-a/current/InventoryAgent.log",
        "actual evidence files must compare to manifest relativePath on Windows"
    );
}
