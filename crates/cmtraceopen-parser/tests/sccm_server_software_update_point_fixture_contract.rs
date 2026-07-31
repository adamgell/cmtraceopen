use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, NaiveDateTime};
use cmtraceopen_parser::sccm::{
    normalize_ccm_artifact, SccmArtifact, SccmCoverageState, SccmEvidence, SccmRole, SccmRotation,
    SccmTimeOrderingState,
};
use serde_json::{json, Value};

const SCENARIOS: &[&str] = &[
    "incomplete",
    "metadata-failure",
    "rotation-boundary",
    "sup-setup-failure",
    "supplemental-wsus-skipped",
    "sync-retry",
    "sync-success",
    "unrelated-update-key",
    "wcm-configuration-failure",
    "wsus-health-failure",
];

const STATE_CHAIN: &[&str] = &[
    "configure",
    "synchronize",
    "importOrProcessMetadata",
    "validateWsus",
    "publishAvailability",
    "healthyOrTerminal",
];

const EXACT_PROFILE: &str = "sup-server-5.00.test-v1";
const EXACT_SITE: &str = "LAB";
const EXACT_SUP: &str = "safe:sup:lab-sup-01";
const EXACT_WSUS: &str = "safe:wsus:lab-wsus-01";
const EXACT_SITE_SERVER: &str = "safe:server:lab-pri-01";
const EXACT_CLIENT: &str = "safe:client:lab-client-01";

fn expected_observation_signature(
    scenario: &str,
) -> &'static [(&'static str, &'static str, &'static str, bool)] {
    match scenario {
        "incomplete" => &[("sync-10-01-configure", "configure", "succeeded", false)],
        "metadata-failure" => &[
            ("sync-05-01-configure", "configure", "succeeded", false),
            ("sync-05-02-synchronize", "synchronize", "succeeded", false),
            (
                "sync-05-03-import",
                "importOrProcessMetadata",
                "failed",
                true,
            ),
        ],
        "rotation-boundary" => &[],
        "sup-setup-failure" => &[("sync-06-01-configure", "configure", "failed", true)],
        "supplemental-wsus-skipped" => &[
            ("sync-07-01-configure", "configure", "succeeded", false),
            ("sync-07-02-synchronize", "synchronize", "succeeded", false),
            (
                "sync-07-03-import",
                "importOrProcessMetadata",
                "succeeded",
                false,
            ),
            ("sync-07-04-validate", "validateWsus", "succeeded", false),
            (
                "sync-07-05-publish",
                "publishAvailability",
                "succeeded",
                false,
            ),
            (
                "sync-07-06-terminal",
                "healthyOrTerminal",
                "succeeded",
                true,
            ),
        ],
        "sync-retry" => &[
            ("sync-04-01-configure", "configure", "succeeded", false),
            ("sync-04-02-retry", "synchronize", "retrying", false),
        ],
        "sync-success" => &[
            ("sync-01-01-configure", "configure", "succeeded", false),
            ("sync-01-02-synchronize", "synchronize", "succeeded", false),
            (
                "sync-01-03-import",
                "importOrProcessMetadata",
                "succeeded",
                false,
            ),
            ("sync-01-04-validate", "validateWsus", "succeeded", false),
            (
                "sync-01-05-publish",
                "publishAvailability",
                "succeeded",
                false,
            ),
            (
                "sync-01-06-terminal",
                "healthyOrTerminal",
                "succeeded",
                true,
            ),
        ],
        "unrelated-update-key" => &[
            ("sync-08-01-configure", "configure", "succeeded", false),
            ("sync-08-02-synchronize", "synchronize", "succeeded", false),
            (
                "sync-08-03-import",
                "importOrProcessMetadata",
                "succeeded",
                false,
            ),
            ("sync-08-04-validate", "validateWsus", "succeeded", false),
            (
                "sync-08-05-publish",
                "publishAvailability",
                "succeeded",
                false,
            ),
            (
                "sync-08-06-terminal",
                "healthyOrTerminal",
                "succeeded",
                true,
            ),
        ],
        "wcm-configuration-failure" => &[("sync-02-01-configure", "configure", "failed", true)],
        "wsus-health-failure" => &[
            ("sync-03-01-configure", "configure", "succeeded", false),
            ("sync-03-02-synchronize", "synchronize", "succeeded", false),
            (
                "sync-03-03-import",
                "importOrProcessMetadata",
                "succeeded",
                false,
            ),
            ("sync-03-04-validate", "validateWsus", "failed", true),
        ],
        _ => &[],
    }
}

fn expected_source_local_signature(scenario: &str) -> &'static [(&'static str, &'static str)] {
    match scenario {
        "rotation-boundary" => &[
            ("rotation-01-split", "rotationSplit"),
            ("rotation-02-malformed", "malformedEvidence"),
        ],
        "unrelated-update-key" => &[("unrelated-client-01", "ignoredClientEvidence")],
        _ => &[],
    }
}

fn corpus_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/software_update_point")
}

fn mutation_asset_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/software_update_point_mutation_assets")
}

fn relative_fixture_files(root: &std::path::Path) -> Result<BTreeSet<String>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("{} is readable: {error}", directory.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("{} has a readable entry: {error}", directory.display()))?
                .path();
            if path.is_dir() {
                pending.push(path);
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|error| {
                        format!("{} is beneath {}: {error}", path.display(), root.display())
                    })?
                    .to_str()
                    .ok_or_else(|| format!("{} is valid UTF-8", path.display()))?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                files.insert(relative);
            }
        }
    }
    Ok(files)
}

fn read_json(scenario: &str, filename: &str) -> Result<Value, String> {
    let path = corpus_root().join(scenario).join(filename);
    let contents = std::fs::read_to_string(&path)
        .map_err(|error| format!("{} is readable: {error}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("{} contains valid JSON: {error}", path.display()))
}

fn required_string<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{context}.{field} must be a string"))
}

fn required_array<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a [Value], String> {
    value[field]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{context}.{field} must be an array"))
}

fn required_bool(value: &Value, field: &str, context: &str) -> Result<bool, String> {
    value[field]
        .as_bool()
        .ok_or_else(|| format!("{context}.{field} must be a boolean"))
}

fn index_by_identifier(array: &Value, field: &str, identifier: &str, context: &str) -> usize {
    array
        .as_array()
        .unwrap_or_else(|| panic!("{context} is an array"))
        .iter()
        .position(|value| value[field] == identifier)
        .unwrap_or_else(|| panic!("{context} contains {field}={identifier}"))
}

fn artifact_index(manifest: &Value, artifact_id: &str) -> usize {
    index_by_identifier(
        &manifest["artifacts"],
        "artifactId",
        artifact_id,
        "manifest.artifacts",
    )
}

fn transaction_index(expected: &Value, transaction_id: &str) -> usize {
    index_by_identifier(
        &expected["transactions"],
        "transactionId",
        transaction_id,
        "expected.transactions",
    )
}

fn observation_index(expected: &Value, transaction_id: &str, observation_id: &str) -> usize {
    let transaction = transaction_index(expected, transaction_id);
    index_by_identifier(
        &expected["transactions"][transaction]["observations"],
        "observationId",
        observation_id,
        "transaction.observations",
    )
}

fn source_local_index(expected: &Value, observation_id: &str) -> usize {
    index_by_identifier(
        &expected["sourceLocalObservations"],
        "observationId",
        observation_id,
        "expected.sourceLocalObservations",
    )
}

fn reject_unknown_fields(
    value: &Value,
    allowed: &[&str],
    context: &str,
    failures: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        failures.push(format!("{context} must be an object"));
        return;
    };
    for field in object.keys() {
        if !allowed.contains(&field.as_str()) {
            failures.push(format!("{context} contains unsupported field {field}"));
        }
    }
}

fn role_from_manifest(role: &str) -> Result<SccmRole, String> {
    match role {
        "client" => Ok(SccmRole::Client),
        "siteServer" => Ok(SccmRole::SiteServer),
        "softwareUpdatePoint" => Ok(SccmRole::SoftwareUpdatePoint),
        "wsUs" => Ok(SccmRole::WsUs),
        other => Err(format!("unsupported fixture producer role {other}")),
    }
}

fn coverage_from_manifest(state: &str) -> Result<SccmCoverageState, String> {
    match state {
        "captured" => Ok(SccmCoverageState::Captured),
        "absent" => Ok(SccmCoverageState::Absent),
        "accessDenied" => Ok(SccmCoverageState::AccessDenied),
        "capped" => Ok(SccmCoverageState::Capped),
        "skipped" => Ok(SccmCoverageState::Skipped),
        "unsupported" => Ok(SccmCoverageState::Unsupported),
        "parseFailed" => Ok(SccmCoverageState::ParseFailed),
        other => Err(format!("unsupported fixture capture state {other}")),
    }
}

fn rotation_from_manifest(rotation: &Value) -> Result<SccmRotation, String> {
    match required_string(rotation, "kind", "rotation")? {
        "current" => Ok(SccmRotation::Current),
        "lo_" => Ok(SccmRotation::LoUnderscore),
        "numbered" => rotation["value"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value != 0)
            .map(SccmRotation::Numbered)
            .ok_or_else(|| "numbered rotation requires a nonzero u32 value".to_owned()),
        "timestamped" => {
            let value = required_string(rotation, "value", "rotation")?;
            if value.len() == "YYYYMMDD-HHMMSS".len()
                && NaiveDateTime::parse_from_str(value, "%Y%m%d-%H%M%S")
                    .is_ok_and(|timestamp| timestamp.format("%Y%m%d-%H%M%S").to_string() == value)
            {
                Ok(SccmRotation::Timestamped(value.to_owned()))
            } else {
                Err("timestamped rotation requires canonical YYYYMMDD-HHMMSS".to_owned())
            }
        }
        other => Err(format!("unsupported fixture rotation {other}")),
    }
}

fn allowed_source(source_id: &str, role: &str, basename: &str, source_kind: &str) -> bool {
    matches!(
        (source_id, role, basename, source_kind),
        ("server-sup-sync", "siteServer", "WCM.log", "ccmLog")
            | ("server-sup-sync", "siteServer", "wsyncmgr.log", "ccmLog")
            | (
                "server-sup-sync",
                "softwareUpdatePoint",
                "SUPSetup.log",
                "ccmLog"
            )
            | (
                "server-sup-sync",
                "softwareUpdatePoint",
                "WSUSCtrl.log",
                "ccmLog"
            )
            | (
                "server-sup-wsus",
                "wsUs",
                "WsusHealth.json",
                "profileDefined"
            )
            | (
                "client-updates-control",
                "client",
                "WUAHandler.log",
                "ccmLog"
            )
    )
}

fn phase_allowed_for_artifact(artifact: &ParsedArtifact, phase: &str) -> bool {
    matches!(
        (artifact.basename.as_str(), phase),
        ("WCM.log", "configure")
            | (
                "wsyncmgr.log",
                "synchronize"
                    | "importOrProcessMetadata"
                    | "publishAvailability"
                    | "healthyOrTerminal"
            )
            | ("SUPSetup.log", "configure" | "healthyOrTerminal")
            | ("WSUSCtrl.log", "validateWsus" | "healthyOrTerminal")
            | ("WsusHealth.json", "validateWsus" | "healthyOrTerminal")
    )
}

fn parse_fixture_fields(message: &str) -> Result<BTreeMap<String, String>, String> {
    let message = message
        .strip_prefix("[sccm-public-message-v1] ")
        .ok_or_else(|| "normalized evidence lacks the public projection profile".to_owned())?;
    let mut segments = message.split(';').map(str::trim);
    if segments.next() != Some("SYNTHETIC FIXTURE") {
        return Err("CCM evidence lacks the semantic SYNTHETIC FIXTURE marker".to_owned());
    }

    let allowed = [
        "Phase",
        "Disposition",
        "Terminal",
        "SyncRunId",
        "SiteCode",
        "SupHandle",
        "ProfileId",
        "UpdateId",
        "KbId",
        "ClientHandle",
    ];
    let mut fields = BTreeMap::new();
    for segment in segments {
        let (name, value) = segment
            .split_once('=')
            .ok_or_else(|| format!("fixture field is not Name=Value: {segment}"))?;
        if !allowed.contains(&name) {
            return Err(format!("unsupported fixture field {name}"));
        }
        if value.is_empty() {
            return Err(format!("fixture field {name} is empty"));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
        {
            return Err(format!("fixture field {name} contains unsupported syntax"));
        }
        if fields.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate fixture field {name}"));
        }
    }
    Ok(fields)
}

fn source_path_is_bounded(relative_path: &str, basename: &str) -> bool {
    !relative_path.is_empty()
        && relative_path.starts_with("evidence/")
        && !relative_path.starts_with('/')
        && !relative_path.contains('\\')
        && relative_path.split('/').all(|segment| {
            !segment.is_empty()
                && !matches!(segment, "." | "..")
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
        && relative_path
            .rsplit('/')
            .next()
            .is_some_and(|candidate| candidate == basename)
}

fn sanitized_source_path_is_safe(value: &str) -> bool {
    value.strip_prefix("SYNTHETIC://").is_some_and(|suffix| {
        !suffix.is_empty()
            && !suffix.contains('\\')
            && suffix.split('/').all(|segment| {
                !segment.is_empty()
                    && !matches!(segment, "." | "..")
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
    })
}

fn rotation_source_basename(basename: &str, rotation: &SccmRotation) -> Option<String> {
    match rotation {
        SccmRotation::Current => Some(basename.to_owned()),
        SccmRotation::LoUnderscore => basename
            .strip_suffix(".log")
            .map(|stem| format!("{stem}.lo_")),
        SccmRotation::Numbered(value) => basename
            .ends_with(".log")
            .then(|| format!("{basename}.{value}")),
        SccmRotation::Timestamped(value) => basename
            .ends_with(".log")
            .then(|| format!("{basename}.{value}")),
        SccmRotation::Unknown(_) => None,
    }
}

fn rotation_destination_segment(rotation: &SccmRotation) -> Option<String> {
    match rotation {
        SccmRotation::Current => Some("current".to_owned()),
        SccmRotation::LoUnderscore => Some("lo_".to_owned()),
        SccmRotation::Numbered(value) => Some(format!("numbered-{value}")),
        SccmRotation::Timestamped(value) => Some(format!("timestamped-{value}")),
        SccmRotation::Unknown(_) => None,
    }
}

fn bounded_token_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .next_back()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn prefixed_token_is_nonempty(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
}

#[derive(Debug)]
struct ParsedArtifact {
    state: String,
    source_id: String,
    role: String,
    producer_host: String,
    workflow_subject_role: String,
    workflow_subject_handle: String,
    source_version: String,
    basename: String,
    rotation_kind: String,
    rotation_lineage: String,
    fragment_complete: Option<bool>,
}

#[derive(Debug)]
struct ParsedScenario {
    artifacts: BTreeMap<String, ParsedArtifact>,
    evidence: BTreeMap<(String, u32, u32), SccmEvidence>,
}

fn validate_manifest(
    scenario: &str,
    scenario_root: &std::path::Path,
    manifest: &Value,
    fixture_overrides: &BTreeMap<String, Vec<u8>>,
) -> Result<ParsedScenario, Vec<String>> {
    let mut failures = Vec::new();
    reject_unknown_fields(
        manifest,
        &[
            "sccmManifestVersion",
            "proposalOnly",
            "syntheticFixture",
            "scenario",
            "bundle",
            "topology",
            "artifacts",
        ],
        "manifest",
        &mut failures,
    );
    reject_unknown_fields(
        &manifest["bundle"],
        &["bundleRole", "workflow", "capturedUtc"],
        "bundle",
        &mut failures,
    );
    reject_unknown_fields(
        &manifest["topology"],
        &["siteCode", "supHandle", "wsusHandle", "rolesObserved"],
        "topology",
        &mut failures,
    );
    if manifest["sccmManifestVersion"] != 1
        || manifest["proposalOnly"] != true
        || manifest["syntheticFixture"] != true
        || manifest["scenario"] != scenario
        || manifest["bundle"]["bundleRole"] != "server"
        || manifest["bundle"]["workflow"] != "softwareUpdatePoint"
    {
        failures
            .push("manifest does not retain the versioned synthetic server boundary".to_owned());
    }
    if manifest["topology"]["siteCode"] != EXACT_SITE
        || manifest["topology"]["supHandle"] != EXACT_SUP
        || manifest["topology"]["wsusHandle"] != EXACT_WSUS
    {
        failures.push("manifest topology is not the exact synthetic LAB SUP/WSUS scope".to_owned());
    }

    let role_values = manifest["topology"]["rolesObserved"].as_array();
    let roles = role_values
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut sorted_roles = roles.clone();
    sorted_roles.sort_unstable();
    sorted_roles.dedup();
    if role_values.is_none_or(|values| values.len() != roles.len())
        || roles != sorted_roles
        || !roles.contains(&"siteServer")
        || !roles.contains(&"softwareUpdatePoint")
        || roles
            .iter()
            .any(|role| !matches!(*role, "siteServer" | "softwareUpdatePoint" | "wsUs"))
    {
        failures.push(
            "rolesObserved must be sorted, unique, catalogued, and retain site/SUP observations"
                .to_owned(),
        );
    }

    let captured_utc =
        match required_string(&manifest["bundle"], "capturedUtc", "bundle").and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|parsed| parsed.timestamp_millis())
                .map_err(|error| format!("bundle.capturedUtc is RFC3339: {error}"))
        }) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                i64::MAX
            }
        };

    let artifacts = match required_array(manifest, "artifacts", "manifest") {
        Ok(artifacts) => artifacts,
        Err(error) => {
            failures.push(error);
            return Err(failures);
        }
    };
    let artifact_order = artifacts
        .iter()
        .filter_map(|artifact| artifact["artifactId"].as_str())
        .collect::<Vec<_>>();
    let mut sorted_artifact_order = artifact_order.clone();
    sorted_artifact_order.sort_unstable();
    if artifact_order != sorted_artifact_order {
        failures.push("manifest artifacts are not sorted by artifactId".to_owned());
    }

    let mut parsed_artifacts = BTreeMap::new();
    let mut evidence_by_reference = BTreeMap::new();
    let mut relative_paths = BTreeSet::new();
    let mut physical_identities = BTreeSet::new();
    let mut path_fingerprints = BTreeSet::new();
    for artifact in artifacts {
        let artifact_id = match required_string(artifact, "artifactId", "artifact") {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let context = format!("artifact {artifact_id}");
        reject_unknown_fields(
            artifact,
            &[
                "artifactId",
                "sourceId",
                "producerRole",
                "producerHostHandle",
                "workflowSubjectRole",
                "workflowSubjectHandle",
                "sourceKind",
                "originalBasename",
                "sanitizedSourcePath",
                "pathFingerprint",
                "rotation",
                "captureState",
                "sourceVersion",
                "collectedUtc",
                "encoding",
                "collectionLimit",
                "bytesCopied",
                "relativePath",
            ],
            &context,
            &mut failures,
        );
        reject_unknown_fields(
            &artifact["rotation"],
            &["kind", "value", "lineageId", "fragmentComplete"],
            &format!("{context}.rotation"),
            &mut failures,
        );
        if artifact.get("collectionLimit").is_some() {
            reject_unknown_fields(
                &artifact["collectionLimit"],
                &["byteLimit", "limitApplied"],
                &format!("{context}.collectionLimit"),
                &mut failures,
            );
        }

        let source_id = required_string(artifact, "sourceId", &context).unwrap_or("invalid");
        let role = required_string(artifact, "producerRole", &context).unwrap_or("invalid");
        let producer_host =
            required_string(artifact, "producerHostHandle", &context).unwrap_or("invalid");
        let workflow_subject_role =
            required_string(artifact, "workflowSubjectRole", &context).unwrap_or("invalid");
        let workflow_subject_handle =
            required_string(artifact, "workflowSubjectHandle", &context).unwrap_or("invalid");
        let basename = required_string(artifact, "originalBasename", &context).unwrap_or("invalid");
        let source_kind = required_string(artifact, "sourceKind", &context).unwrap_or("invalid");
        let state = required_string(artifact, "captureState", &context).unwrap_or("invalid");
        let source_version =
            required_string(artifact, "sourceVersion", &context).unwrap_or("invalid");
        if !allowed_source(source_id, role, basename, source_kind) {
            failures.push(format!(
                "{artifact_id} has an uncatalogued source/producer/basename/grammar tuple"
            ));
        }
        if workflow_subject_role != "softwareUpdatePoint" || workflow_subject_handle != EXACT_SUP {
            failures.push(format!(
                "{artifact_id} loses the exact SUP workflow subject"
            ));
        }
        let expected_producer = match role {
            "siteServer" => Some(EXACT_SITE_SERVER),
            "softwareUpdatePoint" => Some(EXACT_SUP),
            "wsUs" => Some(EXACT_WSUS),
            "client" => Some(EXACT_CLIENT),
            _ => None,
        };
        if Some(producer_host) != expected_producer {
            failures.push(format!(
                "{artifact_id} producer handle is not exact for its declared role"
            ));
        }
        let path_fingerprint = artifact["pathFingerprint"].as_str();
        if !path_fingerprint.is_some_and(|value| prefixed_token_is_nonempty(value, "synthetic:"))
            || !artifact["sanitizedSourcePath"]
                .as_str()
                .is_some_and(sanitized_source_path_is_safe)
        {
            failures.push(format!("{artifact_id} leaks or omits path provenance"));
        }
        if path_fingerprint
            .map(str::to_ascii_lowercase)
            .is_some_and(|value| !path_fingerprints.insert(value))
        {
            failures.push(format!("{artifact_id} reuses a physical path fingerprint"));
        }
        if !prefixed_token_is_nonempty(source_version, "5.00.TEST.") {
            failures.push(format!(
                "{artifact_id} is outside the synthetic version profile"
            ));
        }

        let rotation_kind = artifact["rotation"]["kind"]
            .as_str()
            .unwrap_or("invalid")
            .to_owned();
        let rotation_lineage = artifact["rotation"]["lineageId"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let rotation_value_shape_valid = match rotation_kind.as_str() {
            "current" | "lo_" => artifact["rotation"].get("value").is_none(),
            "numbered" => artifact["rotation"]["value"].as_u64().is_some(),
            "timestamped" => artifact["rotation"]["value"].as_str().is_some(),
            _ => false,
        };
        let rotation_model = rotation_from_manifest(&artifact["rotation"]);
        if !bounded_token_is_safe(&rotation_lineage)
            || !rotation_value_shape_valid
            || rotation_model.is_err()
        {
            failures.push(format!(
                "{artifact_id} has incomplete or incoherent rotation provenance"
            ));
        }
        if let Ok(rotation) = &rotation_model {
            let source_basename = artifact["sanitizedSourcePath"]
                .as_str()
                .and_then(|value| value.rsplit('/').next());
            if rotation_source_basename(basename, rotation).as_deref() != source_basename {
                failures.push(format!(
                    "{artifact_id} rotation is not bound to its sanitized source path"
                ));
            }
        }
        let identity = (
            artifact["producerHostHandle"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            artifact["sanitizedSourcePath"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase(),
        );
        if !physical_identities.insert(identity) {
            failures.push(format!(
                "{artifact_id} duplicates one physical source identity"
            ));
        }

        let artifact_collected_utc = match required_string(artifact, "collectedUtc", &context)
            .and_then(|value| {
                DateTime::parse_from_rfc3339(value)
                    .map(|parsed| parsed.timestamp_millis())
                    .map_err(|error| format!("{context}.collectedUtc is RFC3339: {error}"))
            }) {
            Ok(value) if value <= captured_utc => Some(value),
            Ok(_) => {
                failures.push(format!("{artifact_id} was collected after its bundle"));
                None
            }
            Err(error) => {
                failures.push(error);
                None
            }
        };

        let role_model = match role_from_manifest(role) {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!("{artifact_id}: {error}"));
                continue;
            }
        };
        let coverage_model = match coverage_from_manifest(state) {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!("{artifact_id}: {error}"));
                continue;
            }
        };
        let rotation_model = match rotation_model {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!("{artifact_id}: {error}"));
                continue;
            }
        };

        if matches!(state, "captured" | "capped" | "parseFailed") {
            if artifact["rotation"]["fragmentComplete"].as_bool().is_none() {
                failures.push(format!(
                    "{artifact_id} physical capture lacks fragment completeness"
                ));
            }
            let relative_path = match required_string(artifact, "relativePath", &context) {
                Ok(value) => value,
                Err(error) => {
                    failures.push(error);
                    continue;
                }
            };
            if !source_path_is_bounded(relative_path, basename) {
                failures.push(format!(
                    "{artifact_id} has an unsafe or mismatched evidence path"
                ));
            }
            if rotation_destination_segment(&rotation_model).as_deref()
                != relative_path.rsplit('/').nth(1)
            {
                failures.push(format!(
                    "{artifact_id} rotation is not bound to its evidence destination"
                ));
            }
            if !relative_paths.insert(relative_path.to_ascii_lowercase()) {
                failures.push(format!(
                    "{artifact_id} collides with an evidence destination"
                ));
            }
            let fixture_path = scenario_root.join(relative_path);
            let bytes = match fixture_overrides.get(relative_path) {
                Some(value) => value.clone(),
                None => match std::fs::read(&fixture_path) {
                    Ok(value) => value,
                    Err(error) => {
                        failures.push(format!(
                            "{} is readable for {artifact_id}: {error}",
                            fixture_path.display()
                        ));
                        continue;
                    }
                },
            };
            if artifact["bytesCopied"].as_u64() != Some(bytes.len() as u64) {
                failures.push(format!(
                    "{artifact_id}.bytesCopied does not match its physical fixture"
                ));
            }
            let byte_limit = artifact["collectionLimit"]["byteLimit"].as_u64();
            let limit_applied = artifact["collectionLimit"]["limitApplied"].as_bool();
            if artifact["encoding"] != "utf-8"
                || byte_limit.is_none()
                || limit_applied.is_none()
                || state == "capped"
                    && (limit_applied != Some(true) || byte_limit != Some(bytes.len() as u64))
                || state != "capped"
                    && (limit_applied != Some(false)
                        || byte_limit.is_some_and(|limit| limit < bytes.len() as u64))
            {
                failures.push(format!(
                    "{artifact_id} has incoherent raw-byte collection provenance"
                ));
            }
            if !String::from_utf8_lossy(&bytes).contains("SYNTHETIC FIXTURE") {
                failures.push(format!("{artifact_id} lacks a synthetic fixture marker"));
            }

            if source_kind == "ccmLog" {
                let content = String::from_utf8_lossy(&bytes);
                let artifact_model = SccmArtifact {
                    artifact_id: artifact_id.to_owned(),
                    display_name: basename.to_owned(),
                    original_path: None,
                    host: artifact["producerHostHandle"].as_str().map(str::to_owned),
                    role: role_model.clone(),
                    configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
                    collected_at_utc: artifact["collectedUtc"].as_str().map(str::to_owned),
                    rotation: rotation_model,
                    coverage: coverage_model,
                    encoding: artifact["encoding"].as_str().map(str::to_owned),
                };
                let normalized = normalize_ccm_artifact(artifact_model, &content);
                if state == "parseFailed" {
                    if !normalized.is_empty() {
                        failures.push(format!(
                            "{artifact_id} is parseFailed but contains usable normalized CCM evidence"
                        ));
                    }
                } else {
                    if artifact["rotation"]["fragmentComplete"] == false && !normalized.is_empty() {
                        failures.push(format!(
                            "{artifact_id} exposes a logical record from an incomplete fragment"
                        ));
                    }
                    for record in normalized {
                        if record.role != role_model {
                            failures.push(format!("{artifact_id} loses producer-role provenance"));
                        }
                        if record.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
                            || record.timestamp.offset_minutes != Some(0)
                            || record.timestamp.utc_millis.is_none()
                            || artifact_collected_utc.is_none()
                            || record
                                .timestamp
                                .utc_millis
                                .zip(artifact_collected_utc)
                                .is_some_and(|(evidence_utc, collected_utc)| {
                                    evidence_utc > collected_utc
                                })
                        {
                            failures.push(format!(
                                "{artifact_id} has unusable evidence/artifact/capture chronology"
                            ));
                        }
                        if record
                            .ccm_source_file
                            .as_deref()
                            .is_none_or(|value| !value.contains(".cpp:"))
                        {
                            failures.push(format!(
                                "{artifact_id} loses distinct CCM code-origin provenance"
                            ));
                        }
                        match parse_fixture_fields(&record.message) {
                            Ok(fields) => {
                                if fields.get("SupHandle").map(String::as_str) != Some(EXACT_SUP) {
                                    failures.push(format!(
                                        "{artifact_id} record escapes the exact SUP subject"
                                    ));
                                }
                            }
                            Err(error) => failures.push(format!("{artifact_id}: {error}")),
                        }
                        let Some(line_start) = record.reference.line_start else {
                            failures.push(format!("{artifact_id} evidence lacks lineStart"));
                            continue;
                        };
                        let Some(line_end) = record.reference.line_end else {
                            failures.push(format!("{artifact_id} evidence lacks lineEnd"));
                            continue;
                        };
                        let key = (artifact_id.to_owned(), line_start, line_end);
                        if evidence_by_reference.insert(key, record).is_some() {
                            failures
                                .push(format!("{artifact_id} has duplicate line-range evidence"));
                        }
                    }
                }
            }
        } else if artifact.get("relativePath").is_some()
            || artifact.get("bytesCopied").is_some()
            || artifact.get("encoding").is_some()
            || artifact.get("collectionLimit").is_some()
            || artifact["rotation"].get("fragmentComplete").is_some()
        {
            failures.push(format!(
                "{artifact_id} invents physical capture facts for state {state}"
            ));
        }

        if parsed_artifacts
            .insert(
                artifact_id.to_owned(),
                ParsedArtifact {
                    state: state.to_owned(),
                    source_id: source_id.to_owned(),
                    role: role.to_owned(),
                    producer_host: producer_host.to_owned(),
                    workflow_subject_role: workflow_subject_role.to_owned(),
                    workflow_subject_handle: workflow_subject_handle.to_owned(),
                    source_version: source_version.to_owned(),
                    basename: basename.to_owned(),
                    rotation_kind,
                    rotation_lineage,
                    fragment_complete: artifact["rotation"]["fragmentComplete"].as_bool(),
                },
            )
            .is_some()
        {
            failures.push(format!("duplicate artifactId {artifact_id}"));
        }
    }

    if failures.is_empty() {
        Ok(ParsedScenario {
            artifacts: parsed_artifacts,
            evidence: evidence_by_reference,
        })
    } else {
        Err(failures)
    }
}

fn evidence_for<'a>(
    parsed: &'a ParsedScenario,
    reference: &Value,
    context: &str,
) -> Result<&'a SccmEvidence, String> {
    let artifact_id = required_string(reference, "artifactId", context)?;
    let line_start = reference["startLine"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| format!("{context}.startLine must be a u32"))?;
    let line_end = reference["endLine"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| format!("{context}.endLine must be a u32"))?;
    parsed
        .evidence
        .get(&(artifact_id.to_owned(), line_start, line_end))
        .ok_or_else(|| {
            format!(
                "{context} does not cite a physical logical record: {artifact_id}:{line_start}-{line_end}"
            )
        })
}

fn exact_key_fields(key: &Value, context: &str) -> Result<BTreeMap<&'static str, String>, String> {
    let mut fields = BTreeMap::from([
        (
            "SyncRunId",
            required_string(key, "syncRunId", context)?.to_owned(),
        ),
        (
            "SiteCode",
            required_string(key, "siteCode", context)?.to_owned(),
        ),
        (
            "SupHandle",
            required_string(key, "supHandle", context)?.to_owned(),
        ),
        (
            "ProfileId",
            required_string(key, "extractionProfileId", context)?.to_owned(),
        ),
    ]);
    match (key["updateId"].as_str(), key["kbId"].as_str()) {
        (Some(update_id), Some(kb_id)) => {
            fields.insert("UpdateId", update_id.to_owned());
            fields.insert("KbId", kb_id.to_owned());
        }
        (None, None) if key["updateId"].is_null() && key["kbId"].is_null() => {}
        _ => return Err(format!("{context} has a partial update/KB identity")),
    }
    if fields["SiteCode"] != EXACT_SITE
        || fields["SupHandle"] != EXACT_SUP
        || fields["ProfileId"] != EXACT_PROFILE
        || key["confidence"] != "exact"
    {
        return Err(format!("{context} is outside the exact synthetic profile"));
    }
    Ok(fields)
}

fn validate_expected(
    scenario: &str,
    manifest: &Value,
    expected: &Value,
    parsed: &ParsedScenario,
) -> Result<(), Vec<String>> {
    let mut failures = Vec::new();
    reject_unknown_fields(
        expected,
        &[
            "contractState",
            "workflow",
            "scenario",
            "stateChain",
            "analysisContract",
            "extractionProfile",
            "roleAssessment",
            "coverage",
            "transactions",
            "sourceLocalObservations",
            "artifactRequests",
            "clientCausalClaims",
            "correlationHandoff",
        ],
        "expected",
        &mut failures,
    );
    for (value, allowed, context) in [
        (
            &expected["analysisContract"],
            &[
                "independentReducer",
                "consumesClientOutput",
                "crossSideCorrelationPerformed",
            ][..],
            "analysisContract",
        ),
        (
            &expected["extractionProfile"],
            &["selectionState", "profileId", "validatedRole"][..],
            "extractionProfile",
        ),
        (
            &expected["roleAssessment"],
            &[
                "softwareUpdatePointObserved",
                "roleAbsentInferred",
                "missingDefaultPathInterpretation",
            ][..],
            "roleAssessment",
        ),
        (
            &expected["correlationHandoff"],
            &["issue", "performed", "timeOnlyEligible"][..],
            "correlationHandoff",
        ),
    ] {
        reject_unknown_fields(value, allowed, context, &mut failures);
    }
    if expected["contractState"] != "proposedPendingReviewed318And335"
        || expected["workflow"] != "softwareUpdatePoint"
        || expected["scenario"] != scenario
        || expected["analysisContract"]["independentReducer"] != true
        || expected["analysisContract"]["consumesClientOutput"] != false
        || expected["analysisContract"]["crossSideCorrelationPerformed"] != false
    {
        failures.push("expected output loses the preparation/dependency boundary".to_owned());
    }
    let state_values = expected["stateChain"].as_array();
    let state_chain = state_values
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if state_values.is_none_or(|values| values.len() != state_chain.len())
        || state_chain != STATE_CHAIN
    {
        failures.push("expected state chain does not match the #330 contract".to_owned());
    }
    if expected["extractionProfile"]["profileId"] != EXACT_PROFILE
        || expected["extractionProfile"]["selectionState"] != "selectedSynthetic"
        || expected["extractionProfile"]["validatedRole"] != "softwareUpdatePoint"
        || expected["roleAssessment"]["roleAbsentInferred"] != false
        || expected["roleAssessment"]["missingDefaultPathInterpretation"] != "sourceCoverageOnly"
    {
        failures.push("expected output loses profile or conservative role semantics".to_owned());
    }

    let expected_coverage = parsed
        .artifacts
        .iter()
        .map(|(artifact_id, artifact)| (artifact_id.clone(), artifact.state.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut declared_coverage = BTreeMap::new();
    let mut coverage_order = Vec::new();
    match required_array(expected, "coverage", "expected") {
        Ok(rows) => {
            for row in rows {
                reject_unknown_fields(row, &["artifactId", "state"], "coverage", &mut failures);
                let artifact_id =
                    required_string(row, "artifactId", "coverage").unwrap_or("invalid");
                let state = required_string(row, "state", "coverage").unwrap_or("invalid");
                coverage_order.push(artifact_id);
                if declared_coverage
                    .insert(artifact_id.to_owned(), state.to_owned())
                    .is_some()
                {
                    failures.push(format!("duplicate coverage row {artifact_id}"));
                }
            }
        }
        Err(error) => failures.push(error),
    }
    let mut sorted_coverage = coverage_order.clone();
    sorted_coverage.sort_unstable();
    if coverage_order != sorted_coverage || declared_coverage != expected_coverage {
        failures.push("coverage is not the exact sorted manifest projection".to_owned());
    }

    let transactions = match required_array(expected, "transactions", "expected") {
        Ok(value) => value,
        Err(error) => {
            failures.push(error);
            &[]
        }
    };
    let transaction_order = transactions
        .iter()
        .filter_map(|transaction| transaction["transactionId"].as_str())
        .collect::<Vec<_>>();
    let mut sorted_transaction_order = transaction_order.clone();
    sorted_transaction_order.sort_unstable();
    if transaction_order != sorted_transaction_order {
        failures.push("transactions are not deterministically sorted".to_owned());
    }

    let mut seen_transaction_ids = BTreeSet::new();
    let mut seen_transaction_keys = BTreeSet::new();
    for transaction in transactions {
        let transaction_id =
            required_string(transaction, "transactionId", "transaction").unwrap_or("invalid");
        if !seen_transaction_ids.insert(transaction_id) {
            failures.push(format!("duplicate transactionId {transaction_id}"));
        }
        reject_unknown_fields(
            transaction,
            &[
                "transactionId",
                "key",
                "topologyCompatibility",
                "correlationEligible",
                "state",
                "classification",
                "confidence",
                "confidenceCeiling",
                "lastSuccessfulPhase",
                "nextSourceId",
                "coverageGapArtifactIds",
                "observations",
            ],
            transaction_id,
            &mut failures,
        );
        reject_unknown_fields(
            &transaction["key"],
            &[
                "syncRunId",
                "siteCode",
                "supHandle",
                "updateId",
                "kbId",
                "confidence",
                "extractionProfileId",
            ],
            &format!("{transaction_id}.key"),
            &mut failures,
        );
        let key_fields = match exact_key_fields(&transaction["key"], transaction_id) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let expected_id = if let Some(update_id) = key_fields.get("UpdateId") {
            format!(
                "sup:{}:{}:{}:{}",
                key_fields["SyncRunId"], key_fields["SiteCode"], key_fields["SupHandle"], update_id
            )
        } else {
            format!(
                "sup:{}:{}:{}",
                key_fields["SyncRunId"], key_fields["SiteCode"], key_fields["SupHandle"]
            )
        };
        if transaction_id != expected_id || !seen_transaction_keys.insert(expected_id) {
            failures.push(format!(
                "{transaction_id} is not unique and derived from its exact immutable key"
            ));
        }
        if transaction["topologyCompatibility"] != "exact"
            || transaction["correlationEligible"] != true
        {
            failures.push(format!("{transaction_id} is not exact/topology-gated"));
        }

        let observations = match required_array(transaction, "observations", transaction_id) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let actual_signature = observations
            .iter()
            .map(|observation| {
                (
                    observation["observationId"].as_str(),
                    observation["phase"].as_str(),
                    observation["disposition"].as_str(),
                    observation["terminal"].as_bool(),
                )
            })
            .collect::<Vec<_>>();
        let expected_signature = expected_observation_signature(scenario)
            .iter()
            .map(|(observation_id, phase, disposition, terminal)| {
                (
                    Some(*observation_id),
                    Some(*phase),
                    Some(*disposition),
                    Some(*terminal),
                )
            })
            .collect::<Vec<_>>();
        if actual_signature != expected_signature {
            failures.push(format!(
                "{scenario} does not retain its exact required observation chain"
            ));
        }
        let observation_order = observations
            .iter()
            .filter_map(|observation| observation["observationId"].as_str())
            .collect::<Vec<_>>();
        let mut sorted_observation_order = observation_order.clone();
        sorted_observation_order.sort_unstable();
        if observation_order != sorted_observation_order {
            failures.push(format!("{transaction_id} observations are not sorted"));
        }

        let mut latest_success = None;
        let mut terminal_success = false;
        let mut terminal_failure = false;
        let mut deferred_seen = false;
        let mut previous_utc = i64::MIN;
        let mut previous_phase = 0usize;
        let mut seen_observation_ids = BTreeSet::new();
        let mut seen_transaction_evidence = BTreeSet::new();
        for observation in observations {
            let observation_id =
                required_string(observation, "observationId", transaction_id).unwrap_or("invalid");
            if !seen_observation_ids.insert(observation_id) {
                failures.push(format!("duplicate observationId {observation_id}"));
            }
            let phase = required_string(observation, "phase", observation_id).unwrap_or("invalid");
            let disposition =
                required_string(observation, "disposition", observation_id).unwrap_or("invalid");
            let terminal = required_bool(observation, "terminal", observation_id).unwrap_or(false);
            reject_unknown_fields(
                observation,
                &[
                    "observationId",
                    "phase",
                    "disposition",
                    "terminal",
                    "evidence",
                ],
                observation_id,
                &mut failures,
            );
            let phase_index = STATE_CHAIN.iter().position(|candidate| *candidate == phase);
            if phase_index.is_none() || phase_index.is_some_and(|index| index < previous_phase) {
                failures.push(format!(
                    "{transaction_id} has an unsupported/backward phase"
                ));
            }
            if let Some(index) = phase_index {
                previous_phase = index;
            }
            let references = match required_array(observation, "evidence", observation_id) {
                Ok(value) if !value.is_empty() => value,
                Ok(_) => {
                    failures.push(format!("{observation_id} has no cited evidence"));
                    continue;
                }
                Err(error) => {
                    failures.push(error);
                    continue;
                }
            };
            for reference in references {
                reject_unknown_fields(
                    reference,
                    &["artifactId", "startLine", "endLine"],
                    &format!("{observation_id}.evidence"),
                    &mut failures,
                );
                let artifact_id =
                    required_string(reference, "artifactId", observation_id).unwrap_or("invalid");
                match parsed.artifacts.get(artifact_id) {
                    Some(artifact)
                        if artifact.role != "client"
                            && phase_allowed_for_artifact(artifact, phase) => {}
                    _ => failures.push(format!(
                        "{observation_id} cites an artifact that cannot own phase {phase}"
                    )),
                }
                let record = match evidence_for(parsed, reference, observation_id) {
                    Ok(value) => value,
                    Err(error) => {
                        failures.push(error);
                        continue;
                    }
                };
                let evidence_identity = (
                    artifact_id.to_owned(),
                    reference["startLine"].as_u64(),
                    reference["endLine"].as_u64(),
                );
                if !seen_transaction_evidence.insert(evidence_identity) {
                    failures.push(format!(
                        "{transaction_id} cites one physical logical record more than once"
                    ));
                }
                let fields = match parse_fixture_fields(&record.message) {
                    Ok(value) => value,
                    Err(error) => {
                        failures.push(format!("{observation_id}: {error}"));
                        continue;
                    }
                };
                for (field, expected_value) in &key_fields {
                    if fields.get(*field) != Some(expected_value) {
                        failures.push(format!(
                            "{observation_id} evidence does not repeat exact {field}"
                        ));
                    }
                }
                for optional in ["UpdateId", "KbId"] {
                    if !key_fields.contains_key(optional) && fields.contains_key(optional) {
                        failures.push(format!(
                            "{observation_id} invents an unkeyed {optional} identity"
                        ));
                    }
                }
                if fields.get("Phase").map(String::as_str) != Some(phase)
                    || fields.get("Disposition").map(String::as_str) != Some(disposition)
                    || fields.get("Terminal").map(String::as_str)
                        != Some(if terminal { "true" } else { "false" })
                {
                    failures.push(format!(
                        "{observation_id} phase/disposition/terminal is not cited exactly"
                    ));
                }
                let utc = record.timestamp.utc_millis.unwrap_or(i64::MIN);
                if utc < previous_utc {
                    failures.push(format!("{transaction_id} evidence is not UTC-ordered"));
                }
                previous_utc = utc;
            }
            match (disposition, terminal) {
                ("succeeded", true) => {
                    latest_success = latest_success.max(phase_index);
                    terminal_success = true;
                }
                ("succeeded", false) => latest_success = latest_success.max(phase_index),
                ("failed", true) => terminal_failure = true,
                ("deferred" | "retrying", false) => deferred_seen = true,
                _ => failures.push(format!(
                    "{observation_id} uses an incoherent disposition/terminal pair"
                )),
            }
        }

        let computed_last_success = latest_success.map(|index| STATE_CHAIN[index]);
        if transaction["lastSuccessfulPhase"].as_str() != computed_last_success
            || computed_last_success.is_none() && !transaction["lastSuccessfulPhase"].is_null()
        {
            failures.push(format!(
                "{transaction_id}.lastSuccessfulPhase is not evidence-derived"
            ));
        }
        let state = required_string(transaction, "state", transaction_id).unwrap_or("invalid");
        let classification =
            required_string(transaction, "classification", transaction_id).unwrap_or("invalid");
        let confidence =
            required_string(transaction, "confidence", transaction_id).unwrap_or("invalid");
        let confidence_ceiling =
            required_string(transaction, "confidenceCeiling", transaction_id).unwrap_or("invalid");

        let gap_values = transaction["coverageGapArtifactIds"].as_array();
        let gap_ids = gap_values
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut sorted_gap_ids = gap_ids.clone();
        sorted_gap_ids.sort_unstable();
        sorted_gap_ids.dedup();
        if gap_values.is_none_or(|values| values.len() != gap_ids.len())
            || gap_ids != sorted_gap_ids
        {
            failures.push(format!(
                "{transaction_id} coverage gaps are not exact sorted strings"
            ));
        }
        let expected_gap_ids = parsed
            .artifacts
            .iter()
            .filter(|(_, artifact)| {
                artifact.role != "client"
                    && (artifact.state != "captured" || artifact.fragment_complete != Some(true))
            })
            .map(|(artifact_id, _)| artifact_id.as_str())
            .collect::<Vec<_>>();
        if gap_ids != expected_gap_ids {
            failures.push(format!(
                "{transaction_id} does not disclose every noncomplete server artifact"
            ));
        }
        let optional_only_gap = !gap_ids.is_empty()
            && gap_ids.iter().all(|artifact_id| {
                parsed.artifacts.get(*artifact_id).is_some_and(|artifact| {
                    artifact.source_id == "server-sup-wsus"
                        && matches!(
                            artifact.state.as_str(),
                            "skipped" | "unsupported" | "capped"
                        )
                })
            });
        for artifact_id in &gap_ids {
            match parsed.artifacts.get(*artifact_id) {
                Some(artifact)
                    if artifact.state != "captured" || artifact.fragment_complete != Some(true) => {
                }
                _ => failures.push(format!(
                    "{transaction_id} coverage gap {artifact_id} is absent or complete"
                )),
            }
        }
        match (state, classification) {
            ("succeeded", "success")
                if terminal_success
                    && computed_last_success == Some("healthyOrTerminal")
                    && !terminal_failure
                    && ((!optional_only_gap
                        && gap_ids.is_empty()
                        && confidence == "high"
                        && confidence_ceiling == "high")
                        || (optional_only_gap
                            && confidence == "medium"
                            && confidence_ceiling == "medium")) => {}
            ("failed", "confirmedFailure")
                if terminal_failure
                    && !terminal_success
                    && gap_ids.is_empty()
                    && confidence == "high"
                    && confidence_ceiling == "high" => {}
            ("failed", "confirmedFailure")
                if terminal_failure
                    && !terminal_success
                    && optional_only_gap
                    && confidence == "medium"
                    && confidence_ceiling == "medium" => {}
            ("deferred", "blockedOrDeferred")
                if deferred_seen
                    && !terminal_failure
                    && !terminal_success
                    && confidence == "medium"
                    && confidence_ceiling == "medium" => {}
            ("incomplete", "insufficientEvidence")
                if !terminal_failure
                    && !terminal_success
                    && confidence == "low"
                    && confidence_ceiling == "low" => {}
            _ => failures.push(format!(
                "{transaction_id} state/classification lacks required evidence/coverage"
            )),
        }

        if state == "incomplete" {
            let next_source = transaction["nextSourceId"].as_str();
            if next_source.is_none()
                || !parsed.artifacts.values().any(|artifact| {
                    Some(artifact.source_id.as_str()) == next_source && artifact.state != "captured"
                })
            {
                failures.push(format!(
                    "{transaction_id} incomplete state lacks a bounded noncomplete next source"
                ));
            }
        } else if !transaction["nextSourceId"].is_null() {
            failures.push(format!("{transaction_id} invents a next source"));
        }
    }

    let expected_transaction = match scenario {
        "incomplete" => Some(("incomplete", "insufficientEvidence", Some("configure"))),
        "metadata-failure" => Some(("failed", "confirmedFailure", Some("synchronize"))),
        "rotation-boundary" => None,
        "sup-setup-failure" => Some(("failed", "confirmedFailure", None)),
        "supplemental-wsus-skipped" => Some(("succeeded", "success", Some("healthyOrTerminal"))),
        "sync-retry" => Some(("deferred", "blockedOrDeferred", Some("configure"))),
        "sync-success" | "unrelated-update-key" => {
            Some(("succeeded", "success", Some("healthyOrTerminal")))
        }
        "wcm-configuration-failure" => Some(("failed", "confirmedFailure", None)),
        "wsus-health-failure" => Some((
            "failed",
            "confirmedFailure",
            Some("importOrProcessMetadata"),
        )),
        _ => {
            failures.push(format!("unknown scenario outcome contract {scenario}"));
            None
        }
    };
    match (expected_transaction, transactions) {
        (None, []) => {}
        (Some((state, classification, last_success)), [transaction])
            if transaction["state"] == state
                && transaction["classification"] == classification
                && (transaction["lastSuccessfulPhase"].as_str() == last_success
                    || last_success.is_none() && transaction["lastSuccessfulPhase"].is_null()) => {}
        _ => failures.push(format!(
            "{scenario} does not contain its one exact role-local outcome"
        )),
    }

    let source_local = match required_array(expected, "sourceLocalObservations", "expected") {
        Ok(value) => value,
        Err(error) => {
            failures.push(error);
            &[]
        }
    };
    let source_local_order = source_local
        .iter()
        .filter_map(|observation| observation["observationId"].as_str())
        .collect::<Vec<_>>();
    let mut sorted_source_local_order = source_local_order.clone();
    sorted_source_local_order.sort_unstable();
    if source_local_order != sorted_source_local_order {
        failures.push("source-local observations are not sorted".to_owned());
    }
    let actual_source_local_signature = source_local
        .iter()
        .map(|observation| {
            (
                observation["observationId"].as_str(),
                observation["classification"].as_str(),
            )
        })
        .collect::<Vec<_>>();
    let expected_source_local_signature = expected_source_local_signature(scenario)
        .iter()
        .map(|(observation_id, classification)| (Some(*observation_id), Some(*classification)))
        .collect::<Vec<_>>();
    if actual_source_local_signature != expected_source_local_signature {
        failures.push(format!(
            "{scenario} does not retain its exact source-local observation identities"
        ));
    }
    let mut seen_source_local_ids = BTreeSet::new();
    for observation in source_local {
        let observation_id =
            required_string(observation, "observationId", "sourceLocal").unwrap_or("invalid");
        if !seen_source_local_ids.insert(observation_id) {
            failures.push(format!(
                "duplicate source-local observationId {observation_id}"
            ));
        }
        reject_unknown_fields(
            observation,
            &[
                "observationId",
                "classification",
                "confidence",
                "confidenceCeiling",
                "correlationEligible",
                "artifactIds",
                "evidence",
            ],
            observation_id,
            &mut failures,
        );
        let classification = observation["classification"].as_str();
        if !matches!(
            classification,
            Some("ignoredClientEvidence" | "rotationSplit" | "malformedEvidence")
        ) || observation["confidence"] != "low"
            || observation["confidenceCeiling"] != "low"
            || observation["correlationEligible"] != false
        {
            failures.push(format!("{observation_id} is not safely source-local"));
        }
        let artifact_id_values = observation["artifactIds"].as_array();
        let artifact_ids = artifact_id_values
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut sorted_artifact_ids = artifact_ids.clone();
        sorted_artifact_ids.sort_unstable();
        sorted_artifact_ids.dedup();
        if artifact_id_values.is_none_or(|values| values.len() != artifact_ids.len())
            || artifact_ids.is_empty()
            || artifact_ids != sorted_artifact_ids
        {
            failures.push(format!(
                "{observation_id} artifact IDs are not exact sorted strings"
            ));
        }
        for artifact_id in &artifact_ids {
            if !parsed.artifacts.contains_key(*artifact_id) {
                failures.push(format!(
                    "{observation_id} cites unknown artifact ID {artifact_id}"
                ));
            }
        }
        let artifacts = artifact_ids
            .iter()
            .filter_map(|artifact_id| parsed.artifacts.get(*artifact_id))
            .collect::<Vec<_>>();
        let references = match required_array(observation, "evidence", observation_id) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                &[]
            }
        };
        let mut cited_ids = BTreeSet::new();
        let mut seen_source_local_evidence = BTreeSet::new();
        for reference in references {
            reject_unknown_fields(
                reference,
                &["artifactId", "startLine", "endLine"],
                &format!("{observation_id}.evidence"),
                &mut failures,
            );
            if let Ok(artifact_id) = required_string(reference, "artifactId", observation_id) {
                cited_ids.insert(artifact_id);
                let identity = (
                    artifact_id,
                    reference["startLine"].as_u64(),
                    reference["endLine"].as_u64(),
                );
                if !seen_source_local_evidence.insert(identity) {
                    failures.push(format!(
                        "{observation_id} cites one physical logical record more than once"
                    ));
                }
                if !artifact_ids.contains(&artifact_id) {
                    failures.push(format!("{observation_id} evidence escapes artifactIds"));
                }
            }
            if let Err(error) = evidence_for(parsed, reference, observation_id) {
                failures.push(error);
            }
        }
        let semantics_match = match classification {
            Some("ignoredClientEvidence") => {
                !references.is_empty()
                    && cited_ids == artifact_ids.iter().copied().collect::<BTreeSet<_>>()
                    && artifacts.iter().all(|artifact| {
                        artifact.role == "client"
                            && artifact.source_id == "client-updates-control"
                            && matches!(artifact.state.as_str(), "captured" | "capped")
                    })
            }
            Some("rotationSplit") => {
                let sources = artifacts
                    .iter()
                    .map(|artifact| artifact.source_id.as_str())
                    .collect::<BTreeSet<_>>();
                let roles = artifacts
                    .iter()
                    .map(|artifact| artifact.role.as_str())
                    .collect::<BTreeSet<_>>();
                let producer_hosts = artifacts
                    .iter()
                    .map(|artifact| artifact.producer_host.as_str())
                    .collect::<BTreeSet<_>>();
                let workflow_subject_roles = artifacts
                    .iter()
                    .map(|artifact| artifact.workflow_subject_role.as_str())
                    .collect::<BTreeSet<_>>();
                let workflow_subject_handles = artifacts
                    .iter()
                    .map(|artifact| artifact.workflow_subject_handle.as_str())
                    .collect::<BTreeSet<_>>();
                let source_versions = artifacts
                    .iter()
                    .map(|artifact| artifact.source_version.as_str())
                    .collect::<BTreeSet<_>>();
                let basenames = artifacts
                    .iter()
                    .map(|artifact| artifact.basename.to_ascii_lowercase())
                    .collect::<BTreeSet<_>>();
                let lineages = artifacts
                    .iter()
                    .map(|artifact| artifact.rotation_lineage.as_str())
                    .collect::<BTreeSet<_>>();
                let rotations = artifacts
                    .iter()
                    .map(|artifact| artifact.rotation_kind.as_str())
                    .collect::<BTreeSet<_>>();
                references.is_empty()
                    && artifacts.len() >= 2
                    && sources.len() == 1
                    && roles.len() == 1
                    && producer_hosts.len() == 1
                    && workflow_subject_roles.len() == 1
                    && workflow_subject_handles.len() == 1
                    && source_versions.len() == 1
                    && basenames.len() == 1
                    && lineages.len() == 1
                    && lineages.first().is_some_and(|lineage| !lineage.is_empty())
                    && rotations.len() >= 2
                    && artifacts.iter().all(|artifact| {
                        artifact.role != "client"
                            && matches!(artifact.state.as_str(), "captured" | "capped")
                            && artifact.fragment_complete == Some(false)
                    })
            }
            Some("malformedEvidence") => {
                references.is_empty()
                    && !artifacts.is_empty()
                    && artifacts.iter().all(|artifact| {
                        artifact.role != "client" && artifact.state == "parseFailed"
                    })
            }
            _ => false,
        };
        if !semantics_match {
            failures.push(format!(
                "{observation_id} classification is detached from physical semantics"
            ));
        }
    }
    let requests = match required_array(expected, "artifactRequests", "expected") {
        Ok(value) => value,
        Err(error) => {
            failures.push(error);
            &[]
        }
    };
    let mut request_order = Vec::new();
    for request in requests {
        reject_unknown_fields(
            request,
            &["sourceId", "reasonCode"],
            "artifactRequest",
            &mut failures,
        );
        let source_id =
            required_string(request, "sourceId", "artifactRequest").unwrap_or("invalid");
        let reason_code =
            required_string(request, "reasonCode", "artifactRequest").unwrap_or("invalid");
        request_order.push((source_id, reason_code));
        let matching_coverage = parsed.artifacts.values().any(|artifact| {
            artifact.source_id == source_id
                && match reason_code {
                    "coverageAbsent" => artifact.state == "absent",
                    "coverageAccessDenied" => artifact.state == "accessDenied",
                    "coverageCapped" => artifact.state == "capped",
                    "coverageMalformed" => artifact.state == "parseFailed",
                    "coverageRotationSplit" => {
                        matches!(artifact.state.as_str(), "captured" | "capped")
                            && artifact.fragment_complete == Some(false)
                    }
                    _ => false,
                }
        });
        if !matches!(source_id, "server-sup-sync" | "server-sup-wsus")
            || !matches!(
                reason_code,
                "coverageAbsent"
                    | "coverageAccessDenied"
                    | "coverageCapped"
                    | "coverageMalformed"
                    | "coverageRotationSplit"
            )
            || !matching_coverage
        {
            failures.push(format!(
                "artifact request {source_id}/{reason_code} is not bounded by coverage"
            ));
        }
    }
    let mut sorted_requests = request_order.clone();
    sorted_requests.sort_unstable();
    sorted_requests.dedup();
    if request_order != sorted_requests {
        failures.push("artifact requests are not sorted/unique".to_owned());
    }
    let expected_requests: &[(&str, &str)] = match scenario {
        "incomplete" => &[
            ("server-sup-sync", "coverageAbsent"),
            ("server-sup-sync", "coverageAccessDenied"),
        ],
        "rotation-boundary" => &[
            ("server-sup-sync", "coverageMalformed"),
            ("server-sup-sync", "coverageRotationSplit"),
        ],
        _ => &[],
    };
    if request_order != expected_requests {
        failures.push(format!(
            "{scenario} does not retain its exact bounded coverage requests"
        ));
    }

    if expected["clientCausalClaims"] != json!([])
        || expected["correlationHandoff"]["issue"] != "#333"
        || expected["correlationHandoff"]["performed"] != false
        || expected["correlationHandoff"]["timeOnlyEligible"] != false
    {
        failures.push("expected output enables a premature client/SUP causal claim".to_owned());
    }
    let sup_observed = manifest["topology"]["rolesObserved"]
        .as_array()
        .is_some_and(|roles| roles.iter().any(|role| role == "softwareUpdatePoint"));
    if expected["roleAssessment"]["softwareUpdatePointObserved"].as_bool() != Some(sup_observed) {
        failures.push("role assessment is not an exact topology projection".to_owned());
    }
    if scenario == "rotation-boundary" && !transactions.is_empty() {
        failures.push("rotation fragments formed a SUP transaction".to_owned());
    }
    if scenario == "unrelated-update-key"
        && (transactions.len() != 1
            || !parsed
                .artifacts
                .values()
                .any(|artifact| artifact.role == "client"))
    {
        failures
            .push("unrelated client update did not stay outside one server transaction".to_owned());
    }
    if scenario == "supplemental-wsus-skipped"
        && transactions.first().is_none_or(|transaction| {
            transaction["confidence"] != "medium" || transaction["classification"] != "success"
        })
    {
        failures.push("skipped optional WSUS evidence did not lower confidence only".to_owned());
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

fn validate_scenario_values(
    scenario: &str,
    manifest: &Value,
    expected: &Value,
) -> Result<(), Vec<String>> {
    validate_scenario_values_with_overrides(scenario, manifest, expected, &BTreeMap::new())
}

fn validate_scenario_values_with_overrides(
    scenario: &str,
    manifest: &Value,
    expected: &Value,
    fixture_overrides: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Vec<String>> {
    let scenario_root = corpus_root().join(scenario);
    let parsed = validate_manifest(scenario, &scenario_root, manifest, fixture_overrides)?;
    validate_expected(scenario, manifest, expected, &parsed)
}

fn mutation_was_accepted(scenario: &str, manifest: &Value, expected: &Value) -> bool {
    validate_scenario_values(scenario, manifest, expected).is_ok()
}

fn mutation_was_accepted_with_asset(
    scenario: &str,
    manifest: &Value,
    expected: &Value,
    evidence_path: &str,
    mutation_asset: &str,
) -> bool {
    let asset_path = mutation_asset_root().join(mutation_asset);
    let bytes = std::fs::read(&asset_path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", asset_path.display()));
    let overrides = BTreeMap::from([(evidence_path.to_owned(), bytes)]);
    validate_scenario_values_with_overrides(scenario, manifest, expected, &overrides).is_ok()
}

#[test]
fn software_update_point_scenario_matrix_is_complete_and_loadable() {
    let root = corpus_root();
    let mut actual = std::fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", root.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            path.is_dir().then(|| {
                path.file_name()
                    .expect("scenario directory has a name")
                    .to_string_lossy()
                    .into_owned()
            })
        })
        .collect::<Vec<_>>();
    actual.sort();
    assert_eq!(actual, SCENARIOS, "the #330 scenario matrix changed");

    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        validate_scenario_values(scenario, &manifest, &expected)
            .unwrap_or_else(|failures| panic!("{scenario}:\n{}", failures.join("\n")));
    }
}

#[test]
fn every_scenario_evidence_asset_is_manifest_and_coverage_closed() {
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json").expect("manifest loads");
        let expected = read_json(scenario, "expected.json").expect("expected loads");
        let scenario_root = corpus_root().join(scenario);
        let evidence_files = relative_fixture_files(&scenario_root.join("evidence"))
            .unwrap_or_else(|error| panic!("{scenario}: {error}"))
            .into_iter()
            .map(|path| format!("evidence/{path}"))
            .collect::<BTreeSet<_>>();
        let physical_artifacts = manifest["artifacts"]
            .as_array()
            .expect("manifest.artifacts is an array")
            .iter()
            .filter(|artifact| {
                matches!(
                    artifact["captureState"].as_str(),
                    Some("captured" | "capped" | "parseFailed")
                )
            })
            .map(|artifact| {
                (
                    artifact["relativePath"]
                        .as_str()
                        .expect("physical artifact has relativePath")
                        .to_owned(),
                    artifact["artifactId"]
                        .as_str()
                        .expect("physical artifact has artifactId")
                        .to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let coverage_ids = expected["coverage"]
            .as_array()
            .expect("expected.coverage is an array")
            .iter()
            .map(|coverage| {
                coverage["artifactId"]
                    .as_str()
                    .expect("coverage has artifactId")
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(
            evidence_files,
            physical_artifacts.keys().cloned().collect(),
            "{scenario} has physical fixture assets outside its manifest"
        );
        assert!(
            physical_artifacts
                .values()
                .all(|artifact_id| coverage_ids.contains(artifact_id)),
            "{scenario} has a physical manifest artifact outside expected coverage"
        );
    }
}

#[test]
fn mutation_assets_have_an_explicit_separate_test_contract() {
    let root = mutation_asset_root();
    let manifest_path = root.join("manifest.json");
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .unwrap_or_else(|error| panic!("{} is readable: {error}", manifest_path.display())),
    )
    .unwrap_or_else(|error| panic!("{} contains valid JSON: {error}", manifest_path.display()));
    assert_eq!(manifest["contractVersion"], 1);
    assert_eq!(manifest["syntheticFixture"], true);
    assert_eq!(manifest["testOnly"], true);

    let assets = manifest["assets"]
        .as_array()
        .expect("mutation assets are an array");
    let actual_asset_files = relative_fixture_files(&root)
        .expect("mutation asset directory is readable")
        .into_iter()
        .filter(|path| path != "manifest.json")
        .collect::<BTreeSet<_>>();
    let declared_asset_files = assets
        .iter()
        .map(|asset| {
            asset["relativePath"]
                .as_str()
                .expect("mutation asset has relativePath")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_asset_files, declared_asset_files,
        "mutation-only bytes must not exist outside their explicit test contract"
    );

    let actual_contract = assets
        .iter()
        .map(|asset| {
            let relative_path = asset["relativePath"]
                .as_str()
                .expect("mutation asset has relativePath");
            let bytes = std::fs::read(root.join(relative_path))
                .unwrap_or_else(|error| panic!("{relative_path} is readable: {error}"));
            assert_eq!(
                asset["bytesCopied"].as_u64(),
                Some(bytes.len() as u64),
                "{relative_path} retains an exact byte count"
            );
            assert!(
                String::from_utf8_lossy(&bytes).contains("SYNTHETIC FIXTURE"),
                "{relative_path} retains its synthetic marker"
            );
            (
                asset["assetId"]
                    .as_str()
                    .expect("mutation asset has assetId"),
                relative_path,
                asset["testPurpose"]
                    .as_str()
                    .expect("mutation asset has testPurpose"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_contract,
        [
            (
                "cross-family-lo-wcm",
                "cross-family-lo-wcm.log",
                "rejectCrossFamilyRotationGrouping"
            ),
            (
                "incomplete-required-numbered-wsyncmgr",
                "incomplete-required-numbered-wsyncmgr.log",
                "rejectIncompleteRequiredRotationSuccess"
            ),
            (
                "parse-failed-valid-numbered-wsusctrl",
                "parse-failed-valid-numbered-wsusctrl.log",
                "rejectParseFailedUsableCcm"
            ),
        ],
        "the bounded mutation-asset contract changed"
    );
}

#[test]
fn structured_fields_are_unique_closed_and_not_nested_ccm() {
    let valid = "[sccm-public-message-v1] SYNTHETIC FIXTURE; Phase=synchronize; Disposition=succeeded; Terminal=false; SyncRunId=sync-01; SiteCode=LAB; SupHandle=safe:sup:lab-sup-01; ProfileId=sup-server-5.00.test-v1";
    assert!(parse_fixture_fields(valid).is_ok());
    for invalid in [
        "[sccm-public-message-v1] SYNTHETIC FIXTURE; Phase=synchronize; Phase=validateWsus; Disposition=succeeded; Terminal=false",
        "[sccm-public-message-v1] SYNTHETIC FIXTURE; Phase=synchronize; Disposition=succeeded; Terminal=false; Terminal=true",
        "[sccm-public-message-v1] SYNTHETIC FIXTURE; Phase=synchronize; Disposition=succeeded; Terminal=false; ServerCause=network",
        "[sccm-public-message-v1] SYNTHETIC FIXTURE; Phase=synchronize]LOG]!>; Disposition=succeeded; Terminal=false",
    ] {
        assert!(
            parse_fixture_fields(invalid).is_err(),
            "ambiguous or unsupported fields were accepted: {invalid}"
        );
    }
}

#[test]
fn rotation_metadata_must_bind_to_source_and_evidence_paths() {
    let success_manifest = read_json("sync-success", "manifest.json").expect("manifest loads");
    let success_expected = read_json("sync-success", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let wcm = artifact_index(&success_manifest, "sync-success-01-wcm");
    let lo = artifact_index(&rotation_manifest, "rotation-02-lo");
    let current = artifact_index(&rotation_manifest, "rotation-01-current");
    let mut accepted = Vec::new();

    let mut unbound_kind = success_manifest.clone();
    unbound_kind["artifacts"][wcm]["rotation"]["kind"] = json!("lo_");
    if mutation_was_accepted("sync-success", &unbound_kind, &success_expected) {
        accepted.push("lo_ rotation retained current source and destination paths");
    }

    let mut unbound_source = success_manifest.clone();
    unbound_source["artifacts"][wcm]["rotation"]["kind"] = json!("lo_");
    unbound_source["artifacts"][wcm]["relativePath"] =
        json!("evidence/server-sup-sync/site/lo_/WCM.log");
    let current_wcm_path = corpus_root()
        .join("sync-success")
        .join("evidence/server-sup-sync/site/current/WCM.log");
    let current_wcm_bytes = std::fs::read(&current_wcm_path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", current_wcm_path.display()));
    let unbound_source_overrides = BTreeMap::from([(
        "evidence/server-sup-sync/site/lo_/WCM.log".to_owned(),
        current_wcm_bytes,
    )]);
    if validate_scenario_values_with_overrides(
        "sync-success",
        &unbound_source,
        &success_expected,
        &unbound_source_overrides,
    )
    .is_ok()
    {
        accepted.push("lo_ rotation retained a current sanitized source path");
    }

    let mut unbound_number = success_manifest.clone();
    unbound_number["artifacts"][wcm]["rotation"]["kind"] = json!("numbered");
    unbound_number["artifacts"][wcm]["rotation"]["value"] = json!(1);
    unbound_number["artifacts"][wcm]["sanitizedSourcePath"] =
        json!("SYNTHETIC://configured-root/Site/Logs/WCM.log.1");
    if mutation_was_accepted("sync-success", &unbound_number, &success_expected) {
        accepted.push("numbered rotation value was absent from its evidence destination");
    }

    let mut duplicate_physical_source = rotation_manifest.clone();
    duplicate_physical_source["artifacts"][lo]["sanitizedSourcePath"] =
        duplicate_physical_source["artifacts"][current]["sanitizedSourcePath"].clone();
    if mutation_was_accepted(
        "rotation-boundary",
        &duplicate_physical_source,
        &rotation_expected,
    ) {
        accepted.push("self-declared rotation metadata disguised one physical source collision");
    }

    let mut unsafe_timestamp = success_manifest.clone();
    unsafe_timestamp["artifacts"][wcm]["rotation"]["kind"] = json!("timestamped");
    unsafe_timestamp["artifacts"][wcm]["rotation"]["value"] = json!("20260730-150060");
    unsafe_timestamp["artifacts"][wcm]["sanitizedSourcePath"] =
        json!("SYNTHETIC://configured-root/Site/Logs/WCM.log.20260730-150060");
    unsafe_timestamp["artifacts"][wcm]["relativePath"] =
        json!("evidence/server-sup-sync/site/timestamped-20260730-150060/WCM.log");
    if mutation_was_accepted("sync-success", &unsafe_timestamp, &success_expected) {
        accepted.push("noncanonical rotation timestamp");
    }

    let mut path_like_timestamp = success_manifest.clone();
    path_like_timestamp["artifacts"][wcm]["rotation"]["kind"] = json!("timestamped");
    path_like_timestamp["artifacts"][wcm]["rotation"]["value"] =
        json!("../../Users/Real/secret.log");
    if mutation_was_accepted("sync-success", &path_like_timestamp, &success_expected) {
        accepted.push("path-like rotation timestamp");
    }

    let mut unsafe_lineage = success_manifest.clone();
    unsafe_lineage["artifacts"][wcm]["rotation"]["lineageId"] = json!("C:\\Users\\Real\\WCM.log");
    if mutation_was_accepted("sync-success", &unsafe_lineage, &success_expected) {
        accepted.push("unsafe rotation lineage syntax");
    }

    assert!(
        accepted.is_empty(),
        "unbound or unsafe rotation provenance was accepted: {accepted:?}"
    );
}

#[test]
fn canonical_numbered_and_timestamped_rotation_bindings_remain_loadable() {
    let manifest = read_json("sync-success", "manifest.json").expect("manifest loads");
    let expected = read_json("sync-success", "expected.json").expect("expected loads");
    let wcm = artifact_index(&manifest, "sync-success-01-wcm");
    let current_path = corpus_root()
        .join("sync-success")
        .join("evidence/server-sup-sync/site/current/WCM.log");
    let bytes = std::fs::read(&current_path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", current_path.display()));

    for (kind, value, source_path, evidence_path) in [
        (
            "numbered",
            json!(1),
            "SYNTHETIC://configured-root/Site/Logs/WCM.log.1",
            "evidence/server-sup-sync/site/numbered-1/WCM.log",
        ),
        (
            "timestamped",
            json!("20260730-150000"),
            "SYNTHETIC://configured-root/Site/Logs/WCM.log.20260730-150000",
            "evidence/server-sup-sync/site/timestamped-20260730-150000/WCM.log",
        ),
    ] {
        let mut rotated = manifest.clone();
        rotated["artifacts"][wcm]["rotation"]["kind"] = json!(kind);
        rotated["artifacts"][wcm]["rotation"]["value"] = value;
        rotated["artifacts"][wcm]["sanitizedSourcePath"] = json!(source_path);
        rotated["artifacts"][wcm]["relativePath"] = json!(evidence_path);
        let overrides = BTreeMap::from([(evidence_path.to_owned(), bytes.clone())]);
        validate_scenario_values_with_overrides("sync-success", &rotated, &expected, &overrides)
            .unwrap_or_else(|failures| {
                panic!("{kind} canonical binding:\n{}", failures.join("\n"))
            });
    }
}

#[test]
fn exact_keys_terminal_evidence_and_client_causality_fail_closed() {
    let manifest = read_json("sync-success", "manifest.json").expect("manifest loads");
    let expected = read_json("sync-success", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();
    let transaction_id = "sup:sync-01:LAB:safe:sup:lab-sup-01";
    let transaction = transaction_index(&expected, transaction_id);

    let mut key_alias = expected.clone();
    key_alias["transactions"][transaction]["key"]["syncRunId"] = json!("sync-other");
    if mutation_was_accepted("sync-success", &manifest, &key_alias) {
        accepted.push("transaction key diverged from every cited record");
    }
    let mut terminal_removed = expected.clone();
    let terminal_observation = observation_index(&expected, transaction_id, "sync-01-06-terminal");
    terminal_removed["transactions"][transaction]["observations"][terminal_observation]
        ["terminal"] = json!(false);
    if mutation_was_accepted("sync-success", &manifest, &terminal_removed) {
        accepted.push("success survived without cited terminal evidence");
    }
    let mut time_only = expected.clone();
    time_only["clientCausalClaims"] =
        json!(["A same-time client scan proves the SUP caused the failure."]);
    if mutation_was_accepted("sync-success", &manifest, &time_only) {
        accepted.push("time-only client/SUP causality was admitted");
    }

    assert!(
        accepted.is_empty(),
        "key/terminal/causality mutations were accepted: {accepted:?}"
    );
}

#[test]
fn coverage_role_nonphysical_and_capture_time_fail_closed() {
    let manifest = read_json("incomplete", "manifest.json").expect("manifest loads");
    let expected = read_json("incomplete", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();
    let wcm = artifact_index(&manifest, "incomplete-01-wcm");
    let denied = artifact_index(&manifest, "incomplete-02-wsync-denied");

    let mut role_inferred = expected.clone();
    role_inferred["roleAssessment"]["softwareUpdatePointObserved"] = json!(false);
    role_inferred["roleAssessment"]["roleAbsentInferred"] = json!(true);
    if mutation_was_accepted("incomplete", &manifest, &role_inferred) {
        accepted.push("missing sources erased an observed SUP role");
    }
    let mut host_alias = manifest.clone();
    host_alias["artifacts"][wcm]["producerHostHandle"] = json!(EXACT_SUP);
    if mutation_was_accepted("incomplete", &host_alias, &expected) {
        accepted.push("site-server producer collapsed onto the SUP subject");
    }
    let mut physical_invention = manifest.clone();
    physical_invention["artifacts"][denied]["collectionLimit"] =
        json!({"byteLimit": 4096, "limitApplied": false});
    if mutation_was_accepted("incomplete", &physical_invention, &expected) {
        accepted.push("access-denied artifact invented physical collection provenance");
    }
    let mut early_capture = manifest.clone();
    early_capture["bundle"]["capturedUtc"] = json!("2026-07-30T00:00:00Z");
    if mutation_was_accepted("incomplete", &early_capture, &expected) {
        accepted.push("evidence after the bundle capture was accepted");
    }

    assert!(
        accepted.is_empty(),
        "coverage/role/provenance mutations were accepted: {accepted:?}"
    );
}

#[test]
fn source_local_semantics_ordering_and_transaction_uniqueness_fail_closed() {
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let unrelated_manifest =
        read_json("unrelated-update-key", "manifest.json").expect("manifest loads");
    let unrelated_expected =
        read_json("unrelated-update-key", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();
    let rotation_split = source_local_index(&rotation_expected, "rotation-01-split");
    let malformed = source_local_index(&rotation_expected, "rotation-02-malformed");
    let ignored_client = source_local_index(&unrelated_expected, "unrelated-client-01");
    let unrelated_transaction_id = "sup:sync-08:LAB:safe:sup:lab-sup-01:update-server-a";
    let unrelated_transaction = transaction_index(&unrelated_expected, unrelated_transaction_id);

    let mut split_as_client = rotation_expected.clone();
    split_as_client["sourceLocalObservations"][rotation_split]["classification"] =
        json!("ignoredClientEvidence");
    if mutation_was_accepted("rotation-boundary", &rotation_manifest, &split_as_client) {
        accepted.push("server rotation split was relabeled as client evidence");
    }
    let mut malformed_as_split = rotation_expected.clone();
    malformed_as_split["sourceLocalObservations"][malformed]["classification"] =
        json!("rotationSplit");
    if mutation_was_accepted("rotation-boundary", &rotation_manifest, &malformed_as_split) {
        accepted.push("parse-failed evidence was relabeled as rotation split");
    }
    let mut client_as_malformed = unrelated_expected.clone();
    client_as_malformed["sourceLocalObservations"][ignored_client]["classification"] =
        json!("malformedEvidence");
    if mutation_was_accepted(
        "unrelated-update-key",
        &unrelated_manifest,
        &client_as_malformed,
    ) {
        accepted.push("client evidence was relabeled as malformed server evidence");
    }
    let mut reversed = unrelated_expected.clone();
    reversed["transactions"][unrelated_transaction]["observations"]
        .as_array_mut()
        .expect("observations are mutable")
        .reverse();
    if mutation_was_accepted("unrelated-update-key", &unrelated_manifest, &reversed) {
        accepted.push("reversed observations were accepted");
    }
    let mut duplicated = unrelated_expected.clone();
    let duplicate = duplicated["transactions"][unrelated_transaction].clone();
    duplicated["transactions"]
        .as_array_mut()
        .expect("transactions are mutable")
        .push(duplicate);
    if mutation_was_accepted("unrelated-update-key", &unrelated_manifest, &duplicated) {
        accepted.push("duplicate exact transaction was accepted");
    }

    assert!(
        accepted.is_empty(),
        "source-local/order/identity mutations were accepted: {accepted:?}"
    );
}

#[test]
fn physical_collisions_unknown_fields_and_update_key_borrowing_fail_closed() {
    let manifest = read_json("unrelated-update-key", "manifest.json").expect("manifest loads");
    let expected = read_json("unrelated-update-key", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let current = artifact_index(&rotation_manifest, "rotation-01-current");
    let lo = artifact_index(&rotation_manifest, "rotation-02-lo");
    let mut collision = rotation_manifest.clone();
    collision["artifacts"][lo]["relativePath"] =
        collision["artifacts"][current]["relativePath"].clone();
    collision["artifacts"][lo]["bytesCopied"] =
        collision["artifacts"][current]["bytesCopied"].clone();
    if mutation_was_accepted("rotation-boundary", &collision, &rotation_expected) {
        accepted.push("physical evidence destination collision");
    }
    let mut unknown_cause = expected.clone();
    unknown_cause["serverCause"] = json!("SUP caused the client scan failure");
    if mutation_was_accepted("unrelated-update-key", &manifest, &unknown_cause) {
        accepted.push("unknown causal field");
    }
    let mut borrowed_update = expected.clone();
    let transaction = transaction_index(
        &expected,
        "sup:sync-08:LAB:safe:sup:lab-sup-01:update-server-a",
    );
    borrowed_update["transactions"][transaction]["key"]["updateId"] = json!("update-client-b");
    if mutation_was_accepted("unrelated-update-key", &manifest, &borrowed_update) {
        accepted.push("client update identity was borrowed into the server transaction");
    }

    assert!(
        accepted.is_empty(),
        "collision/schema/update-key mutations were accepted: {accepted:?}"
    );
}

#[test]
fn scenario_cardinality_rotation_shape_and_provenance_fail_closed() {
    let incomplete_manifest = read_json("incomplete", "manifest.json").expect("manifest loads");
    let incomplete_expected = read_json("incomplete", "expected.json").expect("expected loads");
    let success_manifest = read_json("sync-success", "manifest.json").expect("manifest loads");
    let success_expected = read_json("sync-success", "expected.json").expect("expected loads");
    let supplemental_manifest =
        read_json("supplemental-wsus-skipped", "manifest.json").expect("manifest loads");
    let supplemental_expected =
        read_json("supplemental-wsus-skipped", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let unrelated_manifest =
        read_json("unrelated-update-key", "manifest.json").expect("manifest loads");
    let unrelated_expected =
        read_json("unrelated-update-key", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();
    let success_transaction_id = "sup:sync-01:LAB:safe:sup:lab-sup-01";
    let success_transaction = transaction_index(&success_expected, success_transaction_id);

    let mut missing_transaction = success_expected.clone();
    missing_transaction["transactions"] = json!([]);
    if mutation_was_accepted("sync-success", &success_manifest, &missing_transaction) {
        accepted.push("required scenario transaction was deleted");
    }
    let mut duplicate_evidence = success_expected.clone();
    let configure_observation = observation_index(
        &success_expected,
        success_transaction_id,
        "sync-01-01-configure",
    );
    let duplicate_reference = duplicate_evidence["transactions"][success_transaction]
        ["observations"][configure_observation]["evidence"][0]
        .clone();
    duplicate_evidence["transactions"][success_transaction]["observations"][configure_observation]
        ["evidence"]
        .as_array_mut()
        .expect("evidence is mutable")
        .push(duplicate_reference);
    if mutation_was_accepted("sync-success", &success_manifest, &duplicate_evidence) {
        accepted.push("one physical logical record was cited twice");
    }
    let mut omitted_gap = supplemental_expected.clone();
    let supplemental_transaction = transaction_index(
        &supplemental_expected,
        "sup:sync-07:LAB:safe:sup:lab-sup-01",
    );
    omitted_gap["transactions"][supplemental_transaction]["coverageGapArtifactIds"] = json!([]);
    omitted_gap["transactions"][supplemental_transaction]["confidence"] = json!("high");
    omitted_gap["transactions"][supplemental_transaction]["confidenceCeiling"] = json!("high");
    if mutation_was_accepted(
        "supplemental-wsus-skipped",
        &supplemental_manifest,
        &omitted_gap,
    ) {
        accepted.push("optional skipped coverage disappeared from the transaction");
    }
    let mut unexpected_role = success_manifest.clone();
    unexpected_role["topology"]["rolesObserved"] =
        json!(["siteServer", "softwareUpdatePoint", "unknownRole", "wsUs"]);
    if mutation_was_accepted("sync-success", &unexpected_role, &success_expected) {
        accepted.push("uncatalogued topology role was accepted");
    }
    let mut duplicate_fingerprint = success_manifest.clone();
    let wcm = artifact_index(&success_manifest, "sync-success-01-wcm");
    let wsync = artifact_index(&success_manifest, "sync-success-02-wsync");
    duplicate_fingerprint["artifacts"][wsync]["pathFingerprint"] =
        duplicate_fingerprint["artifacts"][wcm]["pathFingerprint"].clone();
    if mutation_was_accepted("sync-success", &duplicate_fingerprint, &success_expected) {
        accepted.push("two physical artifacts shared one path fingerprint");
    }
    let mut shaped_current = success_manifest.clone();
    shaped_current["artifacts"][wcm]["rotation"]["value"] = json!("lo_");
    if mutation_was_accepted("sync-success", &shaped_current, &success_expected) {
        accepted.push("current rotation accepted an incompatible value");
    }
    let mut missing_fragment_state = success_manifest.clone();
    missing_fragment_state["artifacts"][wcm]["rotation"]
        .as_object_mut()
        .expect("rotation is mutable")
        .remove("fragmentComplete");
    if mutation_was_accepted("sync-success", &missing_fragment_state, &success_expected) {
        accepted.push("physical artifact omitted fragment completeness");
    }
    let mut late_parse_failure = rotation_manifest.clone();
    let malformed = artifact_index(&rotation_manifest, "rotation-03-malformed");
    late_parse_failure["artifacts"][malformed]["collectedUtc"] = json!("2026-07-30T20:00:00Z");
    if mutation_was_accepted("rotation-boundary", &late_parse_failure, &rotation_expected) {
        accepted.push("parse-failed artifact was collected after its bundle");
    }
    let mut missing_rotation_observations = rotation_expected.clone();
    missing_rotation_observations["sourceLocalObservations"] = json!([]);
    if mutation_was_accepted(
        "rotation-boundary",
        &rotation_manifest,
        &missing_rotation_observations,
    ) {
        accepted.push("rotation and malformed source-local observations were deleted");
    }
    let mut missing_client_observation = unrelated_expected.clone();
    missing_client_observation["sourceLocalObservations"] = json!([]);
    if mutation_was_accepted(
        "unrelated-update-key",
        &unrelated_manifest,
        &missing_client_observation,
    ) {
        accepted.push("ignored client observation was deleted");
    }
    let mut missing_requests = incomplete_expected.clone();
    missing_requests["artifactRequests"] = json!([]);
    if mutation_was_accepted("incomplete", &incomplete_manifest, &missing_requests) {
        accepted.push("bounded incomplete-coverage requests were deleted");
    }

    assert!(
        accepted.is_empty(),
        "scenario/rotation/provenance mutations were accepted: {accepted:?}"
    );
}

#[test]
fn terminal_failure_with_optional_gap_has_a_medium_confidence_ceiling() {
    let mut manifest =
        read_json("wcm-configuration-failure", "manifest.json").expect("manifest loads");
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are mutable")
        .push(json!({
            "artifactId": "wcm-failure-02-wsus-health",
            "sourceId": "server-sup-wsus",
            "producerRole": "wsUs",
            "producerHostHandle": EXACT_WSUS,
            "workflowSubjectRole": "softwareUpdatePoint",
            "workflowSubjectHandle": EXACT_SUP,
            "sourceKind": "profileDefined",
            "originalBasename": "WsusHealth.json",
            "sanitizedSourcePath": "SYNTHETIC://configured-root/WSUS/WsusHealth.json",
            "pathFingerprint": "synthetic:wcm-failure-wsus-health",
            "rotation": {
                "kind": "current",
                "lineageId": "wcm-failure-wsus-health"
            },
            "captureState": "skipped",
            "sourceVersion": "5.00.TEST.0001",
            "collectedUtc": "2026-07-30T18:00:00Z"
        }));

    let mut expected =
        read_json("wcm-configuration-failure", "expected.json").expect("expected loads");
    expected["coverage"]
        .as_array_mut()
        .expect("coverage is mutable")
        .push(json!({
            "artifactId": "wcm-failure-02-wsus-health",
            "state": "skipped"
        }));
    let transaction = transaction_index(&expected, "sup:sync-02:LAB:safe:sup:lab-sup-01");
    expected["transactions"][transaction]["coverageGapArtifactIds"] =
        json!(["wcm-failure-02-wsus-health"]);

    assert!(
        validate_scenario_values("wcm-configuration-failure", &manifest, &expected).is_err(),
        "high-confidence terminal failure survived an explicit optional coverage gap"
    );

    expected["transactions"][transaction]["confidence"] = json!("medium");
    expected["transactions"][transaction]["confidenceCeiling"] = json!("medium");
    validate_scenario_values("wcm-configuration-failure", &manifest, &expected)
        .unwrap_or_else(|failures| panic!("{}", failures.join("\n")));
}

#[test]
fn required_phase_identity_and_manifest_strings_fail_closed() {
    let success_manifest = read_json("sync-success", "manifest.json").expect("manifest loads");
    let success_expected = read_json("sync-success", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();
    let transaction_id = "sup:sync-01:LAB:safe:sup:lab-sup-01";
    let transaction = transaction_index(&success_expected, transaction_id);

    let mut missing_required_phase = success_expected.clone();
    let synchronize =
        observation_index(&success_expected, transaction_id, "sync-01-02-synchronize");
    missing_required_phase["transactions"][transaction]["observations"]
        .as_array_mut()
        .expect("observations are mutable")
        .remove(synchronize);
    if mutation_was_accepted("sync-success", &success_manifest, &missing_required_phase) {
        accepted.push("sync-success survived without its required synchronize phase");
    }

    let mut renamed_observation = success_expected.clone();
    let terminal = observation_index(&success_expected, transaction_id, "sync-01-06-terminal");
    renamed_observation["transactions"][transaction]["observations"][terminal]["observationId"] =
        json!("sync-01-06-terminal-renamed");
    if mutation_was_accepted("sync-success", &success_manifest, &renamed_observation) {
        accepted.push("a scenario observation identity was renamed");
    }

    let current = artifact_index(&rotation_manifest, "rotation-01-current");
    let lo = artifact_index(&rotation_manifest, "rotation-02-lo");
    let mut dot_alias = rotation_manifest.clone();
    dot_alias["artifacts"][lo]["relativePath"] =
        json!("evidence/server-sup-sync/site/current/./wsyncmgr.log");
    dot_alias["artifacts"][lo]["bytesCopied"] =
        dot_alias["artifacts"][current]["bytesCopied"].clone();
    if mutation_was_accepted("rotation-boundary", &dot_alias, &rotation_expected) {
        accepted.push("dot-segment path alias reused a physical evidence destination");
    }

    let wcm = artifact_index(&success_manifest, "sync-success-01-wcm");
    let mut unsafe_source_path = success_manifest.clone();
    unsafe_source_path["artifacts"][wcm]["sanitizedSourcePath"] =
        json!("SYNTHETIC://configured-root/Site/Logs/../secrets.txt");
    if mutation_was_accepted("sync-success", &unsafe_source_path, &success_expected) {
        accepted.push("sanitized source path accepted traversal syntax");
    }

    let mut empty_fingerprint = success_manifest.clone();
    empty_fingerprint["artifacts"][wcm]["pathFingerprint"] = json!("synthetic:");
    if mutation_was_accepted("sync-success", &empty_fingerprint, &success_expected) {
        accepted.push("empty synthetic path fingerprint");
    }

    let mut empty_version = success_manifest.clone();
    empty_version["artifacts"][wcm]["sourceVersion"] = json!("5.00.TEST.");
    if mutation_was_accepted("sync-success", &empty_version, &success_expected) {
        accepted.push("empty synthetic source-version suffix");
    }

    let mut non_string_role = success_manifest.clone();
    non_string_role["topology"]["rolesObserved"] =
        json!(["siteServer", "softwareUpdatePoint", 7, "wsUs"]);
    if mutation_was_accepted("sync-success", &non_string_role, &success_expected) {
        accepted.push("non-string topology role");
    }

    let mut non_string_state = success_expected.clone();
    non_string_state["stateChain"]
        .as_array_mut()
        .expect("state chain is mutable")
        .push(json!(7));
    if mutation_was_accepted("sync-success", &success_manifest, &non_string_state) {
        accepted.push("non-string state-chain entry");
    }

    let mut non_string_gap = success_expected.clone();
    non_string_gap["transactions"][transaction]["coverageGapArtifactIds"]
        .as_array_mut()
        .expect("coverage gaps are mutable")
        .push(json!(7));
    if mutation_was_accepted("sync-success", &success_manifest, &non_string_gap) {
        accepted.push("non-string transaction coverage-gap ID");
    }

    let mut non_string_source_local_artifact = rotation_expected.clone();
    let rotation_split = source_local_index(&rotation_expected, "rotation-01-split");
    non_string_source_local_artifact["sourceLocalObservations"][rotation_split]["artifactIds"]
        .as_array_mut()
        .expect("source-local artifact IDs are mutable")
        .push(json!(7));
    if mutation_was_accepted(
        "rotation-boundary",
        &rotation_manifest,
        &non_string_source_local_artifact,
    ) {
        accepted.push("non-string source-local artifact ID");
    }

    assert!(
        accepted.is_empty(),
        "required-phase/schema/path mutations were accepted: {accepted:?}"
    );
}

#[test]
fn source_local_schema_identity_and_provenance_fail_closed() {
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let unrelated_manifest =
        read_json("unrelated-update-key", "manifest.json").expect("manifest loads");
    let unrelated_expected =
        read_json("unrelated-update-key", "expected.json").expect("expected loads");
    let rotation_split = source_local_index(&rotation_expected, "rotation-01-split");
    let malformed = source_local_index(&rotation_expected, "rotation-02-malformed");
    let ignored_client = source_local_index(&unrelated_expected, "unrelated-client-01");
    let mut accepted = Vec::new();

    let mut renamed_observation = rotation_expected.clone();
    renamed_observation["sourceLocalObservations"][rotation_split]["observationId"] =
        json!("rotation-01-arbitrary");
    if mutation_was_accepted(
        "rotation-boundary",
        &rotation_manifest,
        &renamed_observation,
    ) {
        accepted.push("source-local observation identity was renamed");
    }

    let mut duplicate_observation_id = rotation_expected.clone();
    duplicate_observation_id["sourceLocalObservations"][rotation_split]["observationId"] =
        duplicate_observation_id["sourceLocalObservations"][malformed]["observationId"].clone();
    if mutation_was_accepted(
        "rotation-boundary",
        &rotation_manifest,
        &duplicate_observation_id,
    ) {
        accepted.push("source-local observation identity was duplicated");
    }

    let mut unknown_artifact = rotation_expected.clone();
    unknown_artifact["sourceLocalObservations"][rotation_split]["artifactIds"]
        .as_array_mut()
        .expect("source-local artifact IDs are mutable")
        .insert(0, json!("aaa-unknown-artifact"));
    if mutation_was_accepted("rotation-boundary", &rotation_manifest, &unknown_artifact) {
        accepted.push("source-local observation cited an unknown artifact ID");
    }

    let mut non_array_evidence = rotation_expected.clone();
    non_array_evidence["sourceLocalObservations"][rotation_split]["evidence"] =
        json!("not-an-array");
    if mutation_was_accepted("rotation-boundary", &rotation_manifest, &non_array_evidence) {
        accepted.push("source-local evidence accepted a non-array value");
    }

    let mut duplicate_evidence = unrelated_expected.clone();
    let duplicate_reference =
        duplicate_evidence["sourceLocalObservations"][ignored_client]["evidence"][0].clone();
    duplicate_evidence["sourceLocalObservations"][ignored_client]["evidence"]
        .as_array_mut()
        .expect("source-local evidence is mutable")
        .push(duplicate_reference);
    if mutation_was_accepted(
        "unrelated-update-key",
        &unrelated_manifest,
        &duplicate_evidence,
    ) {
        accepted.push("source-local observation cited one logical record twice");
    }

    assert!(
        accepted.is_empty(),
        "source-local schema/identity/provenance mutations were accepted: {accepted:?}"
    );
}

#[test]
fn partial_capture_malformed_bytes_and_rotation_family_fail_closed() {
    let success_manifest = read_json("sync-success", "manifest.json").expect("manifest loads");
    let success_expected = read_json("sync-success", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut incomplete_required_rotation = success_manifest.clone();
    incomplete_required_rotation["artifacts"]
        .as_array_mut()
        .expect("manifest artifacts are mutable")
        .push(json!({
            "artifactId": "sync-success-04-wsync-partial",
            "sourceId": "server-sup-sync",
            "producerRole": "siteServer",
            "producerHostHandle": EXACT_SITE_SERVER,
            "workflowSubjectRole": "softwareUpdatePoint",
            "workflowSubjectHandle": EXACT_SUP,
            "sourceKind": "ccmLog",
            "originalBasename": "wsyncmgr.log",
            "sanitizedSourcePath": "SYNTHETIC://configured-root/Site/Logs/wsyncmgr.log.1",
            "pathFingerprint": "synthetic:sync-success-wsync-partial",
            "rotation": {
                "kind": "numbered",
                "value": 1,
                "lineageId": "sync-success-wsync",
                "fragmentComplete": false
            },
            "captureState": "captured",
            "sourceVersion": "5.00.TEST.0001",
            "collectedUtc": "2026-07-30T18:00:00Z",
            "encoding": "utf-8",
            "collectionLimit": {
                "byteLimit": 4096,
                "limitApplied": false
            },
            "bytesCopied": 182,
            "relativePath": "evidence/server-sup-sync/site/numbered-1/wsyncmgr.log"
        }));
    let mut incomplete_required_expected = success_expected.clone();
    incomplete_required_expected["coverage"]
        .as_array_mut()
        .expect("coverage is mutable")
        .push(json!({
            "artifactId": "sync-success-04-wsync-partial",
            "state": "captured"
        }));
    if mutation_was_accepted_with_asset(
        "sync-success",
        &incomplete_required_rotation,
        &incomplete_required_expected,
        "evidence/server-sup-sync/site/numbered-1/wsyncmgr.log",
        "incomplete-required-numbered-wsyncmgr.log",
    ) {
        accepted.push("captured incomplete required rotation retained high-confidence success");
    }

    let malformed = artifact_index(&rotation_manifest, "rotation-03-malformed");
    let mut parse_failed_valid_ccm = rotation_manifest.clone();
    parse_failed_valid_ccm["artifacts"][malformed]["sanitizedSourcePath"] =
        json!("SYNTHETIC://configured-root/SUP/Logs/WSUSCtrl.log.1");
    parse_failed_valid_ccm["artifacts"][malformed]["rotation"]["kind"] = json!("numbered");
    parse_failed_valid_ccm["artifacts"][malformed]["rotation"]["value"] = json!(1);
    parse_failed_valid_ccm["artifacts"][malformed]["bytesCopied"] = json!(326);
    parse_failed_valid_ccm["artifacts"][malformed]["relativePath"] =
        json!("evidence/server-sup-sync/sup/numbered-1/WSUSCtrl.log");
    if mutation_was_accepted_with_asset(
        "rotation-boundary",
        &parse_failed_valid_ccm,
        &rotation_expected,
        "evidence/server-sup-sync/sup/numbered-1/WSUSCtrl.log",
        "parse-failed-valid-numbered-wsusctrl.log",
    ) {
        accepted.push("parse-failed artifact contained usable normalized CCM evidence");
    }

    let lo = artifact_index(&rotation_manifest, "rotation-02-lo");
    let mut cross_family_rotation = rotation_manifest.clone();
    cross_family_rotation["artifacts"][lo]["originalBasename"] = json!("WCM.log");
    cross_family_rotation["artifacts"][lo]["sanitizedSourcePath"] =
        json!("SYNTHETIC://configured-root/Site/Logs/WCM.lo_");
    cross_family_rotation["artifacts"][lo]["relativePath"] =
        json!("evidence/server-sup-sync/site/lo_/WCM.log");
    if mutation_was_accepted_with_asset(
        "rotation-boundary",
        &cross_family_rotation,
        &rotation_expected,
        "evidence/server-sup-sync/site/lo_/WCM.log",
        "cross-family-lo-wcm.log",
    ) {
        accepted.push("rotation split grouped different canonical log families");
    }

    assert!(
        accepted.is_empty(),
        "partial/malformed/rotation-family mutations were accepted: {accepted:?}"
    );
}

#[test]
fn bounded_request_documentation_includes_nonphysical_manifest_coverage() {
    let contract =
        include_str!("../../../docs/sccm/preparation/issue-330-software-update-point-corpus.md");
    assert!(
        contract.contains("backed by matching noncomplete manifest coverage"),
        "bounded request prose must include absent/access-denied manifest states"
    );
    assert!(
        !contract.contains("backed by matching noncomplete physical coverage"),
        "bounded request prose must not require physical evidence for nonphysical states"
    );
    assert!(
        !contract.contains("incomplete physical coverage"),
        "coverage prose must include nonphysical manifest states"
    );
}
