use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use cmtraceopen_parser::sccm::{
    normalize_ccm_artifact, SccmArtifact, SccmCoverageState, SccmEvidence, SccmRole, SccmRotation,
    SccmTimeOrderingState,
};
use serde_json::{json, Value};

const SCENARIOS: &[&str] = &[
    "absent-dp",
    "client-only-looking-request",
    "content-version-mismatch",
    "distribution-failure",
    "healthy-package",
    "incomplete",
    "rotation-boundary",
    "serve-observed",
    "transfer-retry",
    "validation-failure",
];

const STATE_CHAIN: &[&str] = &[
    "receiveContent",
    "distribute",
    "transfer",
    "validate",
    "makeAvailable",
    "serveOrReport",
];

const EXACT_PROFILE: &str = "dp-server-5.00.test-v1";
const EXACT_SITE: &str = "LAB";
const EXACT_DP: &str = "safe:dp:lab-dp-01";
const EXACT_SITE_SERVER: &str = "safe:server:lab-pri-01";
const EXACT_CLIENT: &str = "safe:client:lab-client-01";

fn corpus_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/distribution_point")
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
        "distributionPoint" => Ok(SccmRole::DistributionPoint),
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
            .map(SccmRotation::Numbered)
            .ok_or_else(|| "numbered rotation requires a u32 value".to_owned()),
        "timestamped" => required_string(rotation, "value", "rotation")
            .map(str::to_owned)
            .map(SccmRotation::Timestamped),
        other => Err(format!("unsupported fixture rotation {other}")),
    }
}

fn allowed_source(source_id: &str, role: &str, basename: &str) -> bool {
    matches!(
        (source_id, role, basename),
        ("server-dp-distribution", "siteServer", "distmgr.log")
            | ("server-dp-distribution", "siteServer", "PkgXferMgr.log")
            | (
                "server-dp-distribution",
                "distributionPoint",
                "SMSDPProv.log"
            )
            | ("server-dp-distribution", "distributionPoint", "PullDP.log")
            | ("server-dp-serve", "distributionPoint", "SMSdpmon.log")
            | (
                "client-content-control",
                "client",
                "DataTransferService.log"
            )
    )
}

fn phase_allowed_for_artifact(artifact: &ParsedArtifact, phase: &str) -> bool {
    matches!(
        (
            artifact.source_id.as_str(),
            artifact.basename.as_str(),
            phase
        ),
        (
            "server-dp-distribution",
            "distmgr.log",
            "receiveContent" | "distribute"
        ) | ("server-dp-distribution", "PkgXferMgr.log", "transfer")
            | (
                "server-dp-distribution",
                "PullDP.log",
                "receiveContent" | "transfer"
            )
            | (
                "server-dp-distribution",
                "SMSDPProv.log",
                "validate" | "makeAvailable" | "serveOrReport"
            )
            | ("server-dp-serve", "SMSdpmon.log", "serveOrReport")
    )
}

#[derive(Debug)]
struct ParsedArtifact {
    state: String,
    source_id: String,
    role: String,
    basename: String,
    workflow_subject_handle: Option<String>,
    rotation_kind: String,
    rotation_lineage: String,
    fragment_complete: Option<bool>,
}

#[derive(Debug)]
struct ParsedScenario {
    artifacts: BTreeMap<String, ParsedArtifact>,
    evidence: BTreeMap<(String, u32, u32), SccmEvidence>,
    distribution_point_handles: BTreeSet<String>,
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
        "PackageId",
        "ContentId",
        "ContentVersion",
        "SiteCode",
        "DpHandle",
        "ProfileId",
        "ClientHandle",
        "RequestId",
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
        && !relative_path.split('/').any(|segment| segment == "..")
        && relative_path
            .rsplit('/')
            .next()
            .is_some_and(|candidate| candidate == basename)
}

fn validate_manifest(
    scenario_root: &std::path::Path,
    manifest: &Value,
) -> Result<ParsedScenario, Vec<String>> {
    let mut failures = Vec::new();
    reject_unknown_fields(
        manifest,
        &[
            "sccmManifestVersion",
            "proposalOnly",
            "syntheticFixture",
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
        &[
            "siteCode",
            "distributionPointHandle",
            "distributionPointHandles",
            "rolesObserved",
        ],
        "topology",
        &mut failures,
    );
    if manifest["sccmManifestVersion"] != 1
        || manifest["proposalOnly"] != true
        || manifest["syntheticFixture"] != true
        || manifest["bundle"]["bundleRole"] != "server"
        || manifest["bundle"]["workflow"] != "distributionPoint"
    {
        failures
            .push("manifest does not retain the versioned synthetic server boundary".to_owned());
    }
    if manifest["topology"]["siteCode"] != EXACT_SITE
        || manifest["topology"]["distributionPointHandle"] != EXACT_DP
    {
        failures.push("manifest topology is not the exact synthetic LAB DP".to_owned());
    }
    let mut distribution_point_handles = manifest["topology"]["distributionPointHandles"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![EXACT_DP.to_owned()]);
    let original_handle_order = distribution_point_handles.clone();
    distribution_point_handles.sort();
    distribution_point_handles.dedup();
    if distribution_point_handles != original_handle_order
        || !distribution_point_handles
            .iter()
            .any(|handle| handle == EXACT_DP)
        || distribution_point_handles
            .iter()
            .any(|handle| !handle.starts_with("safe:dp:"))
    {
        failures.push(
            "distributionPointHandles must be sorted, unique, opaque, and include the primary DP"
                .to_owned(),
        );
    }
    let distribution_point_handles = distribution_point_handles
        .into_iter()
        .collect::<BTreeSet<_>>();

    let roles = manifest["topology"]["rolesObserved"]
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut sorted_roles = roles.clone();
    sorted_roles.sort_unstable();
    sorted_roles.dedup();
    if roles != sorted_roles || !roles.contains(&"siteServer") {
        failures
            .push("rolesObserved must be sorted, unique, and retain the site server".to_owned());
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
        failures
            .push("manifest artifacts are not deterministically sorted by artifactId".to_owned());
    }

    let mut parsed_artifacts = BTreeMap::new();
    let mut evidence_by_reference = BTreeMap::new();
    let mut relative_paths = BTreeSet::new();
    let mut physical_source_identities = BTreeSet::new();
    for artifact in artifacts {
        let artifact_id = match required_string(artifact, "artifactId", "artifact") {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let context = format!("artifact {artifact_id}");
        let source_id = match required_string(artifact, "sourceId", &context) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let role = match required_string(artifact, "producerRole", &context) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let basename = match required_string(artifact, "originalBasename", &context) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let state = match required_string(artifact, "captureState", &context) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        reject_unknown_fields(
            artifact,
            &[
                "artifactId",
                "sourceId",
                "producerRole",
                "producerHostHandle",
                "workflowSubjectRole",
                "workflowSubjectHandle",
                "workflowSubjectBasis",
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
        if !allowed_source(source_id, role, basename) {
            failures.push(format!(
                "{artifact_id} has an uncatalogued source/producer/basename combination"
            ));
        }
        let workflow_subject_handle = artifact["workflowSubjectHandle"].as_str();
        let workflow_subject_basis = artifact["workflowSubjectBasis"].as_str();
        if artifact["workflowSubjectRole"] != "distributionPoint"
            || match (workflow_subject_handle, workflow_subject_basis) {
                (Some(handle), None) => !distribution_point_handles.contains(handle),
                (None, Some("manifestTopology")) => {
                    role != "siteServer" || distribution_point_handles.len() < 2
                }
                _ => true,
            }
        {
            failures.push(format!(
                "{artifact_id} loses the distribution-point workflow subject"
            ));
        }
        let producer_host_handle = artifact["producerHostHandle"].as_str();
        let producer_matches_role = match role {
            "siteServer" => producer_host_handle == Some(EXACT_SITE_SERVER),
            "client" => producer_host_handle == Some(EXACT_CLIENT),
            "distributionPoint" => {
                producer_host_handle.is_some_and(|value| distribution_point_handles.contains(value))
            }
            _ => false,
        };
        if !producer_matches_role {
            failures.push(format!(
                "{artifact_id} producer handle is not in the exact role-specific namespace"
            ));
        }
        if role == "distributionPoint"
            && (workflow_subject_handle.is_none()
                || artifact["producerHostHandle"] != artifact["workflowSubjectHandle"])
        {
            failures.push(format!(
                "{artifact_id} DP producer does not match its exact workflow subject"
            ));
        }
        let path_fingerprint = artifact["pathFingerprint"].as_str();
        let sanitized_source_path = artifact["sanitizedSourcePath"].as_str();
        if !path_fingerprint.is_some_and(|value| value.starts_with("synthetic:"))
            || !sanitized_source_path.is_some_and(|value| value.starts_with("SYNTHETIC://"))
        {
            failures.push(format!("{artifact_id} leaks or omits path provenance"));
        }
        let rotation_kind = artifact["rotation"]["kind"].as_str();
        let rotation_value = artifact["rotation"]["value"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| {
                artifact["rotation"]["value"]
                    .as_u64()
                    .map(|value| value.to_string())
            })
            .unwrap_or_default();
        if let (Some(producer), Some(source_path), Some(rotation_kind)) = (
            artifact["producerHostHandle"].as_str(),
            sanitized_source_path,
            rotation_kind,
        ) {
            let physical_identity = (
                producer.to_owned(),
                source_path.to_owned(),
                basename.to_owned(),
                rotation_kind.to_owned(),
                rotation_value,
            );
            if !physical_source_identities.insert(physical_identity) {
                failures.push(format!(
                    "{artifact_id} duplicates one physical source for another workflow subject"
                ));
            }
        }
        if artifact["sourceKind"] != "ccmLog"
            || !artifact["sourceVersion"]
                .as_str()
                .is_some_and(|value| value.starts_with("5.00.TEST."))
        {
            failures.push(format!(
                "{artifact_id} is outside the synthetic CCM/profile source boundary"
            ));
        }

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
        let rotation_model = match rotation_from_manifest(&artifact["rotation"]) {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!("{artifact_id}: {error}"));
                continue;
            }
        };

        if matches!(state, "captured" | "capped" | "parseFailed") {
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
            if !relative_paths.insert(relative_path.to_owned()) {
                failures.push(format!(
                    "{artifact_id} collides with another physical evidence destination"
                ));
            }
            let fixture_path = scenario_root.join(relative_path);
            let bytes = match std::fs::read(&fixture_path) {
                Ok(value) => value,
                Err(error) => {
                    failures.push(format!(
                        "{} is readable for {artifact_id}: {error}",
                        fixture_path.display()
                    ));
                    continue;
                }
            };
            if artifact["bytesCopied"].as_u64() != Some(bytes.len() as u64) {
                failures.push(format!(
                    "{artifact_id}.bytesCopied does not match its physical fixture"
                ));
            }
            let byte_limit = artifact["collectionLimit"]["byteLimit"].as_u64();
            let limit_applied = artifact["collectionLimit"]["limitApplied"].as_bool();
            if byte_limit.is_none()
                || limit_applied.is_none()
                || (state == "capped"
                    && (limit_applied != Some(true) || byte_limit != Some(bytes.len() as u64)))
                || (state != "capped"
                    && (limit_applied != Some(false)
                        || byte_limit.is_some_and(|limit| limit < bytes.len() as u64)))
            {
                failures.push(format!(
                    "{artifact_id} has incoherent raw-byte collection-limit provenance"
                ));
            }
            if !String::from_utf8_lossy(&bytes).contains("SYNTHETIC FIXTURE") {
                failures.push(format!("{artifact_id} lacks a synthetic fixture marker"));
            }
            if matches!(state, "captured" | "capped") {
                let content = String::from_utf8_lossy(&bytes);
                let artifact_model = SccmArtifact {
                    artifact_id: artifact_id.to_owned(),
                    display_name: basename.to_owned(),
                    original_path: None,
                    host: artifact["producerHostHandle"].as_str().map(str::to_owned),
                    role: role_model.clone(),
                    configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
                    collected_at_utc: Some(
                        required_string(artifact, "collectedUtc", &context)
                            .unwrap_or_default()
                            .to_owned(),
                    ),
                    rotation: rotation_model.clone(),
                    coverage: coverage_model.clone(),
                    encoding: artifact["encoding"].as_str().map(str::to_owned),
                };
                let normalized = normalize_ccm_artifact(artifact_model, &content);
                if artifact["rotation"]["fragmentComplete"] == false && !normalized.is_empty() {
                    failures.push(format!(
                        "{artifact_id} exposes a logical record from an incomplete rotation fragment"
                    ));
                }
                for record in &normalized {
                    if record.role != role_model {
                        failures.push(format!("{artifact_id} loses producer-role provenance"));
                    }
                    if record.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
                        || record.timestamp.offset_minutes != Some(0)
                        || record.timestamp.utc_millis.is_none()
                    {
                        failures.push(format!(
                            "{artifact_id} has unusable timestamp provenance in a transaction-capable record"
                        ));
                    } else if record
                        .timestamp
                        .utc_millis
                        .is_some_and(|value| value > captured_utc)
                    {
                        failures.push(format!(
                            "{artifact_id} cites evidence later than the canonical bundle capture"
                        ));
                    }
                    let artifact_collected_utc = artifact["collectedUtc"]
                        .as_str()
                        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                        .map(|value| value.timestamp_millis());
                    if artifact_collected_utc.is_none()
                        || artifact_collected_utc.is_some_and(|value| value > captured_utc)
                        || record
                            .timestamp
                            .utc_millis
                            .zip(artifact_collected_utc)
                            .is_some_and(|(evidence_utc, collected_utc)| {
                                evidence_utc > collected_utc
                            })
                    {
                        failures.push(format!(
                            "{artifact_id} has incoherent evidence/artifact/bundle chronology"
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
                            let record_dp_handle = fields.get("DpHandle").map(String::as_str);
                            if workflow_subject_handle
                                .is_some_and(|handle| record_dp_handle != Some(handle))
                                || workflow_subject_basis == Some("manifestTopology")
                                    && record_dp_handle.is_none_or(|handle| {
                                        !distribution_point_handles.contains(handle)
                                    })
                            {
                                failures.push(format!(
                                    "{artifact_id} record escapes its declared workflow-subject scope"
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
                    if evidence_by_reference.insert(key, record.clone()).is_some() {
                        failures.push(format!("{artifact_id} has duplicate line-range evidence"));
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
                    basename: basename.to_owned(),
                    workflow_subject_handle: workflow_subject_handle.map(str::to_owned),
                    rotation_kind: artifact["rotation"]["kind"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    rotation_lineage: artifact["rotation"]["lineageId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
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
            distribution_point_handles,
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

fn exact_key_fields(
    key: &Value,
    context: &str,
    distribution_point_handles: &BTreeSet<String>,
) -> Result<BTreeMap<&'static str, String>, String> {
    let mut fields = BTreeMap::new();
    for (json_field, record_field) in [
        ("packageId", "PackageId"),
        ("contentId", "ContentId"),
        ("contentVersion", "ContentVersion"),
        ("siteCode", "SiteCode"),
        ("distributionPointHandle", "DpHandle"),
        ("extractionProfileId", "ProfileId"),
    ] {
        let value = if json_field == "contentVersion" {
            key[json_field]
                .as_u64()
                .map(|value| value.to_string())
                .ok_or_else(|| format!("{context}.{json_field} must be a u64"))?
        } else {
            required_string(key, json_field, context)?.to_owned()
        };
        fields.insert(record_field, value);
    }
    if fields["SiteCode"] != EXACT_SITE
        || !distribution_point_handles.contains(&fields["DpHandle"])
        || fields["ProfileId"] != EXACT_PROFILE
        || key["confidence"] != "exact"
    {
        return Err(format!(
            "{context} is outside the exact synthetic key profile"
        ));
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
    reject_unknown_fields(
        &expected["analysisContract"],
        &[
            "independentReducer",
            "consumesClientOutput",
            "crossSideCorrelationPerformed",
        ],
        "analysisContract",
        &mut failures,
    );
    reject_unknown_fields(
        &expected["extractionProfile"],
        &["selectionState", "profileId", "validatedRole"],
        "extractionProfile",
        &mut failures,
    );
    reject_unknown_fields(
        &expected["roleAssessment"],
        &[
            "distributionPointObserved",
            "roleAbsentInferred",
            "missingDefaultPathInterpretation",
        ],
        "roleAssessment",
        &mut failures,
    );
    reject_unknown_fields(
        &expected["correlationHandoff"],
        &["issue", "performed", "timeOnlyEligible"],
        "correlationHandoff",
        &mut failures,
    );
    if expected["contractState"] != "proposedPendingReviewed318And335"
        || expected["workflow"] != "distributionPoint"
        || expected["scenario"] != scenario
        || expected["analysisContract"]["independentReducer"] != true
        || expected["analysisContract"]["consumesClientOutput"] != false
        || expected["analysisContract"]["crossSideCorrelationPerformed"] != false
    {
        failures.push("expected output loses the preparation/dependency boundary".to_owned());
    }
    if expected["stateChain"]
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .as_deref()
        != Some(STATE_CHAIN)
    {
        failures.push("expected state chain does not match Task 5".to_owned());
    }
    if expected["extractionProfile"]["profileId"] != EXACT_PROFILE
        || expected["extractionProfile"]["selectionState"] != "selectedSynthetic"
        || expected["extractionProfile"]["validatedRole"] != "distributionPoint"
    {
        failures
            .push("expected output lacks the versioned synthetic extraction profile".to_owned());
    }
    if expected["roleAssessment"]["roleAbsentInferred"] != false
        || expected["roleAssessment"]["missingDefaultPathInterpretation"] != "sourceCoverageOnly"
    {
        failures.push("expected output infers role state from source coverage".to_owned());
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
                reject_unknown_fields(row, &["artifactId", "state"], "coverage row", &mut failures);
                let Ok(artifact_id) = required_string(row, "artifactId", "coverage row") else {
                    failures.push("coverage row lacks artifactId".to_owned());
                    continue;
                };
                let Ok(state) = required_string(row, "state", "coverage row") else {
                    failures.push(format!("{artifact_id} coverage row lacks state"));
                    continue;
                };
                coverage_order.push(artifact_id.to_owned());
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
    sorted_coverage.sort();
    if coverage_order != sorted_coverage {
        failures.push("coverage rows are not deterministically sorted".to_owned());
    }
    if declared_coverage != expected_coverage {
        failures.push(format!(
            "coverage is not the exact physical manifest projection: {declared_coverage:?} != {expected_coverage:?}"
        ));
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
    for transaction in transactions {
        let transaction_id = match required_string(transaction, "transactionId", "transaction") {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
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
                "packageId",
                "contentId",
                "contentVersion",
                "siteCode",
                "distributionPointHandle",
                "confidence",
                "extractionProfileId",
            ],
            &format!("{transaction_id}.key"),
            &mut failures,
        );
        let key_fields = match exact_key_fields(
            &transaction["key"],
            &format!("{transaction_id}.key"),
            &parsed.distribution_point_handles,
        ) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let expected_id = format!(
            "dp:{}:{}:v{}:{}",
            key_fields["PackageId"],
            key_fields["ContentId"],
            key_fields["ContentVersion"],
            key_fields["DpHandle"]
        );
        if transaction_id != expected_id {
            failures.push(format!(
                "{transaction_id} is not derived from its exact immutable key"
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
        let observation_order = observations
            .iter()
            .filter_map(|observation| observation["observationId"].as_str())
            .collect::<Vec<_>>();
        let mut sorted_observation_order = observation_order.clone();
        sorted_observation_order.sort_unstable();
        if observation_order != sorted_observation_order {
            failures.push(format!(
                "{transaction_id} observations are not deterministically sorted"
            ));
        }

        let mut latest_success: Option<usize> = None;
        let mut terminal_success = false;
        let mut terminal_failure = false;
        let mut terminal_deferred = false;
        let mut previous_utc = i64::MIN;
        let mut previous_phase = 0usize;
        for observation in observations {
            let observation_id =
                required_string(observation, "observationId", transaction_id).unwrap_or("invalid");
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
            if phase_index.is_none() {
                failures.push(format!("{observation_id} uses unsupported phase {phase}"));
            }
            if phase_index.is_some_and(|index| index < previous_phase) {
                failures.push(format!(
                    "{transaction_id} phases move backward despite increasing evidence time"
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
                let cited_artifact_id =
                    required_string(reference, "artifactId", observation_id).unwrap_or("invalid");
                match parsed.artifacts.get(cited_artifact_id) {
                    Some(artifact)
                        if artifact.role != "client"
                            && phase_allowed_for_artifact(artifact, phase)
                            && artifact
                                .workflow_subject_handle
                                .as_deref()
                                .is_none_or(|handle| handle == key_fields["DpHandle"]) => {}
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
                            "{observation_id} evidence does not repeat exact {field}={expected_value}"
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
                    failures.push(format!(
                        "{transaction_id} evidence is not ordered by normalized UTC provenance"
                    ));
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
                ("deferred" | "retrying", false) => terminal_deferred = true,
                _ => failures.push(format!(
                    "{observation_id} uses an incoherent disposition/terminal pair"
                )),
            }
        }

        let computed_last_success = latest_success.map(|index| STATE_CHAIN[index]);
        if transaction["lastSuccessfulPhase"].as_str() != computed_last_success
            || (computed_last_success.is_none() && !transaction["lastSuccessfulPhase"].is_null())
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
        match (state, classification) {
            ("succeeded", "success")
                if terminal_success
                    && computed_last_success == Some("serveOrReport")
                    && !terminal_failure
                    && confidence == "high"
                    && confidence_ceiling == "high" => {}
            ("failed", "confirmedFailure")
                if terminal_failure
                    && !terminal_success
                    && confidence == "high"
                    && confidence_ceiling == "high" => {}
            ("deferred", "blockedOrDeferred")
                if terminal_deferred
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
                "{transaction_id} state/classification lacks the required terminal evidence"
            )),
        }

        let gap_ids = transaction["coverageGapArtifactIds"]
            .as_array()
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut sorted_gap_ids = gap_ids.clone();
        sorted_gap_ids.sort_unstable();
        if gap_ids != sorted_gap_ids {
            failures.push(format!("{transaction_id} coverage gaps are not sorted"));
        }
        for artifact_id in gap_ids {
            match parsed.artifacts.get(artifact_id) {
                Some(artifact) if artifact.state != "captured" => {}
                _ => failures.push(format!(
                    "{transaction_id} coverage gap {artifact_id} is absent or complete"
                )),
            }
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
            failures.push(format!(
                "{transaction_id} terminal/deferred state invents a next source"
            ));
        }
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
        failures.push("source-local observations are not deterministically sorted".to_owned());
    }
    for observation in source_local {
        let observation_id =
            required_string(observation, "observationId", "sourceLocalObservation")
                .unwrap_or("invalid");
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
        ) || observation.get("key").is_some()
            || observation["correlationEligible"] != false
            || observation["confidence"] != "low"
            || observation["confidenceCeiling"] != "low"
        {
            failures.push(format!(
                "{observation_id} is not an explicitly noncorrelatable source-local observation"
            ));
        }
        let artifact_ids = observation["artifactIds"]
            .as_array()
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut sorted_artifact_ids = artifact_ids.clone();
        sorted_artifact_ids.sort_unstable();
        let unique_artifact_ids = artifact_ids.iter().copied().collect::<BTreeSet<_>>();
        if artifact_ids.is_empty()
            || artifact_ids != sorted_artifact_ids
            || unique_artifact_ids.len() != artifact_ids.len()
        {
            failures.push(format!(
                "{observation_id} lacks sorted physical artifact provenance"
            ));
        }
        for artifact_id in &artifact_ids {
            if !parsed.artifacts.contains_key(*artifact_id) {
                failures.push(format!(
                    "{observation_id} cites unknown physical artifact {artifact_id}"
                ));
            }
        }
        let references = observation["evidence"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut cited_artifact_ids = BTreeSet::new();
        for reference in references {
            reject_unknown_fields(
                reference,
                &["artifactId", "startLine", "endLine"],
                &format!("{observation_id}.evidence"),
                &mut failures,
            );
            if let Ok(artifact_id) = required_string(
                reference,
                "artifactId",
                &format!("{observation_id}.evidence"),
            ) {
                cited_artifact_ids.insert(artifact_id);
                if !unique_artifact_ids.contains(artifact_id) {
                    failures.push(format!(
                        "{observation_id} cites evidence outside its physical artifact set"
                    ));
                }
            }
            if let Err(error) = evidence_for(parsed, reference, observation_id) {
                failures.push(error);
            }
        }
        let artifacts = artifact_ids
            .iter()
            .filter_map(|artifact_id| parsed.artifacts.get(*artifact_id))
            .collect::<Vec<_>>();
        let semantic_match = match classification {
            Some("ignoredClientEvidence") => {
                !references.is_empty()
                    && cited_artifact_ids == unique_artifact_ids
                    && artifacts.iter().all(|artifact| {
                        artifact.role == "client"
                            && artifact.source_id == "client-content-control"
                            && matches!(artifact.state.as_str(), "captured" | "capped")
                    })
            }
            Some("rotationSplit") => {
                let source_ids = artifacts
                    .iter()
                    .map(|artifact| artifact.source_id.as_str())
                    .collect::<BTreeSet<_>>();
                let lineages = artifacts
                    .iter()
                    .map(|artifact| artifact.rotation_lineage.as_str())
                    .collect::<BTreeSet<_>>();
                let rotation_kinds = artifacts
                    .iter()
                    .map(|artifact| artifact.rotation_kind.as_str())
                    .collect::<BTreeSet<_>>();
                references.is_empty()
                    && artifacts.len() >= 2
                    && source_ids.len() == 1
                    && lineages.len() == 1
                    && lineages.first().is_some_and(|lineage| !lineage.is_empty())
                    && rotation_kinds.len() >= 2
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
        if !semantic_match {
            failures.push(format!(
                "{observation_id} classification is detached from exact physical coverage semantics"
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
        let source_id =
            required_string(request, "sourceId", "artifactRequest").unwrap_or("invalid");
        let reason_code =
            required_string(request, "reasonCode", "artifactRequest").unwrap_or("invalid");
        reject_unknown_fields(
            request,
            &["sourceId", "reasonCode"],
            "artifactRequest",
            &mut failures,
        );
        request_order.push((source_id, reason_code));
        if !matches!(source_id, "server-dp-distribution" | "server-dp-serve")
            || !matches!(
                reason_code,
                "coverageAbsent"
                    | "coverageAccessDenied"
                    | "coverageCapped"
                    | "coverageMalformed"
                    | "coverageRotationSplit"
            )
            || request.get("reason").is_some()
        {
            failures.push(format!(
                "artifact request is not a bounded versioned source/reason code: {source_id}/{reason_code}"
            ));
        }
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
        if !matching_coverage {
            failures.push(format!(
                "artifact request {source_id}/{reason_code} lacks matching noncomplete coverage"
            ));
        }
    }
    let mut sorted_request_order = request_order.clone();
    sorted_request_order.sort_unstable();
    if request_order != sorted_request_order {
        failures.push("artifact requests are not deterministically sorted".to_owned());
    }

    if expected["clientCausalClaims"] != json!([])
        || expected["correlationHandoff"]["issue"] != "#333"
        || expected["correlationHandoff"]["performed"] != false
        || expected["correlationHandoff"]["timeOnlyEligible"] != false
    {
        failures.push(
            "expected output makes or enables a premature cross-side causal claim".to_owned(),
        );
    }

    if scenario == "absent-dp"
        && (expected["roleAssessment"]["distributionPointObserved"] != true
            || !transactions.is_empty())
    {
        failures.push("absent-dp must retain the observed role without a diagnosis".to_owned());
    }
    if scenario == "client-only-looking-request"
        && (!transactions.is_empty()
            || !parsed
                .artifacts
                .values()
                .any(|artifact| artifact.role == "client"))
    {
        failures.push("client-only evidence entered a DP transaction".to_owned());
    }
    if scenario == "rotation-boundary" && !transactions.is_empty() {
        failures.push("rotation fragments formed a DP transaction".to_owned());
    }
    if scenario == "content-version-mismatch" {
        let versions = transactions
            .iter()
            .filter_map(|transaction| transaction["key"]["contentVersion"].as_u64())
            .collect::<BTreeSet<_>>();
        let dp_handles = transactions
            .iter()
            .filter_map(|transaction| {
                transaction["key"]["distributionPointHandle"]
                    .as_str()
                    .map(str::to_owned)
            })
            .collect::<BTreeSet<_>>();
        if versions != BTreeSet::from([1, 2])
            || dp_handles
                != BTreeSet::from([
                    "safe:dp:lab-dp-01".to_owned(),
                    "safe:dp:lab-dp-02".to_owned(),
                ])
            || transactions.len() != 3
        {
            failures.push(
                "content/version/DP topology did not remain three exact transactions".to_owned(),
            );
        }
    }

    if manifest["topology"]["rolesObserved"]
        .as_array()
        .is_some_and(|roles| roles.iter().any(|role| role == "distributionPoint"))
        != expected["roleAssessment"]["distributionPointObserved"]
            .as_bool()
            .unwrap_or(false)
    {
        failures.push("role assessment is not an exact topology projection".to_owned());
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
    let scenario_root = corpus_root().join(scenario);
    let parsed = validate_manifest(&scenario_root, manifest)?;
    validate_expected(scenario, manifest, expected, &parsed)
}

#[test]
fn distribution_point_scenario_matrix_is_complete_and_loadable() {
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

    assert_eq!(actual, SCENARIOS, "the Task 5 scenario matrix changed");
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        validate_scenario_values(scenario, &manifest, &expected)
            .unwrap_or_else(|failures| panic!("{scenario}:\n{}", failures.join("\n")));
    }
}

fn mutation_was_accepted(scenario: &str, manifest: &Value, expected: &Value) -> bool {
    validate_scenario_values(scenario, manifest, expected).is_ok()
}

#[test]
fn exact_content_version_dp_topology_and_terminal_evidence_fail_closed() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut version_alias = healthy_expected.clone();
    version_alias["transactions"][0]["key"]["contentVersion"] = json!(2);
    if mutation_was_accepted("healthy-package", &healthy_manifest, &version_alias) {
        accepted.push("transaction content version diverged from cited evidence");
    }

    let mut dp_alias = healthy_expected.clone();
    dp_alias["transactions"][0]["key"]["distributionPointHandle"] = json!("safe:dp:lab-dp-02");
    if mutation_was_accepted("healthy-package", &healthy_manifest, &dp_alias) {
        accepted.push("transaction DP topology diverged from cited evidence");
    }

    let mut time_only_cause = healthy_expected.clone();
    time_only_cause["clientCausalClaims"] =
        json!(["A same-time client request proves the DP caused the failure."]);
    if mutation_was_accepted("healthy-package", &healthy_manifest, &time_only_cause) {
        accepted.push("time-only client/DP causality was admitted");
    }

    let failure_manifest =
        read_json("distribution-failure", "manifest.json").expect("manifest loads");
    let mut failure_expected =
        read_json("distribution-failure", "expected.json").expect("expected loads");
    failure_expected["transactions"][0]["observations"][1]["terminal"] = json!(false);
    if mutation_was_accepted("distribution-failure", &failure_manifest, &failure_expected) {
        accepted.push("confirmed failure survived without cited terminal evidence");
    }

    assert!(
        accepted.is_empty(),
        "exact key/causality/terminal mutations were accepted: {accepted:?}"
    );
}

#[test]
fn coverage_role_and_rotation_states_fail_closed() {
    let absent_manifest = read_json("absent-dp", "manifest.json").expect("manifest loads");
    let absent_expected = read_json("absent-dp", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut promoted_coverage = absent_expected.clone();
    promoted_coverage["coverage"][0]["state"] = json!("captured");
    if mutation_was_accepted("absent-dp", &absent_manifest, &promoted_coverage) {
        accepted.push("absent source coverage was promoted to captured");
    }

    let mut missing_role = absent_expected.clone();
    missing_role["roleAssessment"]["distributionPointObserved"] = json!(false);
    missing_role["roleAssessment"]["roleAbsentInferred"] = json!(true);
    if mutation_was_accepted("absent-dp", &absent_manifest, &missing_role) {
        accepted.push("missing source path was promoted to missing DP role");
    }

    let mut role_alias_manifest = absent_manifest.clone();
    role_alias_manifest["artifacts"][0]["producerRole"] = json!("distributionPoint");
    if mutation_was_accepted("absent-dp", &role_alias_manifest, &absent_expected) {
        accepted.push("basename reclassified the site-server producer as a DP");
    }

    let mut host_alias_manifest = absent_manifest.clone();
    host_alias_manifest["artifacts"][0]["producerHostHandle"] = json!(EXACT_DP);
    if mutation_was_accepted("absent-dp", &host_alias_manifest, &absent_expected) {
        accepted.push("site-server producer host collapsed onto its DP workflow subject");
    }

    let mut nonphysical_limit_manifest = absent_manifest.clone();
    nonphysical_limit_manifest["artifacts"][0]["collectionLimit"] =
        json!({"byteLimit": 4096, "limitApplied": false});
    if mutation_was_accepted("absent-dp", &nonphysical_limit_manifest, &absent_expected) {
        accepted.push("absent artifact invented a physical collection-limit policy");
    }

    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut invented_transaction = rotation_expected.clone();
    invented_transaction["transactions"] = healthy_expected["transactions"].clone();
    if mutation_was_accepted(
        "rotation-boundary",
        &rotation_manifest,
        &invented_transaction,
    ) {
        accepted.push("split rotation fragments formed a transaction");
    }

    assert!(
        accepted.is_empty(),
        "coverage/role/rotation mutations were accepted: {accepted:?}"
    );
}

#[test]
fn client_only_and_version_mismatch_controls_stay_independent() {
    let client_manifest =
        read_json("client-only-looking-request", "manifest.json").expect("manifest loads");
    let client_expected =
        read_json("client-only-looking-request", "expected.json").expect("expected loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut server_transaction = client_expected.clone();
    server_transaction["transactions"] = healthy_expected["transactions"].clone();
    if mutation_was_accepted(
        "client-only-looking-request",
        &client_manifest,
        &server_transaction,
    ) {
        accepted.push("client-only record entered the server DP reducer");
    }

    let mismatch_manifest =
        read_json("content-version-mismatch", "manifest.json").expect("manifest loads");
    let mismatch_expected =
        read_json("content-version-mismatch", "expected.json").expect("expected loads");
    let mut merged_versions = mismatch_expected.clone();
    merged_versions["transactions"]
        .as_array_mut()
        .expect("transactions are mutable")
        .pop();
    if mutation_was_accepted(
        "content-version-mismatch",
        &mismatch_manifest,
        &merged_versions,
    ) {
        accepted.push("same content across two versions collapsed into one transaction");
    }

    assert!(
        accepted.is_empty(),
        "client/version separation mutations were accepted: {accepted:?}"
    );
}

#[test]
fn structured_fixture_fields_are_unique_closed_and_record_local() {
    let valid = "[sccm-public-message-v1] SYNTHETIC FIXTURE; Phase=transfer; Disposition=succeeded; Terminal=false; PackageId=LAB00001; ContentId=content-alpha; ContentVersion=1; SiteCode=LAB; DpHandle=safe:dp:lab-dp-01; ProfileId=dp-server-5.00.test-v1";
    assert!(parse_fixture_fields(valid).is_ok());

    for invalid in [
        "[sccm-public-message-v1] SYNTHETIC FIXTURE; Phase=transfer; Phase=validate; Disposition=succeeded; Terminal=false",
        "[sccm-public-message-v1] SYNTHETIC FIXTURE; Phase=transfer; Disposition=succeeded; Terminal=false; Terminal=true",
        "[sccm-public-message-v1] SYNTHETIC FIXTURE; Phase=transfer; Disposition=succeeded; Terminal=false; ServerCause=network",
        "[sccm-public-message-v1] SYNTHETIC FIXTURE; Phase=transfer]LOG]!>; Disposition=succeeded; Terminal=false",
    ] {
        assert!(
            parse_fixture_fields(invalid).is_err(),
            "ambiguous or unsupported fields were accepted: {invalid}"
        );
    }
}

#[test]
fn unknown_semantics_collisions_and_output_reordering_fail_closed() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut injected_cause = healthy_expected.clone();
    injected_cause["serverCause"] = json!("The DP triggered the client failure.");
    if mutation_was_accepted("healthy-package", &healthy_manifest, &injected_cause) {
        accepted.push("unknown server-cause field");
    }

    let mut reversed_observations = healthy_expected.clone();
    reversed_observations["transactions"][0]["observations"]
        .as_array_mut()
        .expect("observations are mutable")
        .reverse();
    if mutation_was_accepted("healthy-package", &healthy_manifest, &reversed_observations) {
        accepted.push("reversed observation output");
    }

    let mismatch_manifest =
        read_json("content-version-mismatch", "manifest.json").expect("manifest loads");
    let mut mismatch_expected =
        read_json("content-version-mismatch", "expected.json").expect("expected loads");
    mismatch_expected["transactions"]
        .as_array_mut()
        .expect("transactions are mutable")
        .reverse();
    if mutation_was_accepted(
        "content-version-mismatch",
        &mismatch_manifest,
        &mismatch_expected,
    ) {
        accepted.push("reversed transaction output");
    }

    let mut collided_manifest = healthy_manifest.clone();
    collided_manifest["artifacts"][1]["relativePath"] =
        collided_manifest["artifacts"][0]["relativePath"].clone();
    collided_manifest["artifacts"][1]["originalBasename"] =
        collided_manifest["artifacts"][0]["originalBasename"].clone();
    if mutation_was_accepted("healthy-package", &collided_manifest, &healthy_expected) {
        accepted.push("colliding physical evidence destination");
    }

    assert!(
        accepted.is_empty(),
        "closed-schema/collision/order mutations were accepted: {accepted:?}"
    );
}

#[test]
fn one_physical_site_log_is_not_duplicated_per_distribution_point_subject() {
    let manifest = read_json("content-version-mismatch", "manifest.json").expect("manifest loads");
    let mut physical_sources = BTreeSet::new();
    let mut duplicates = Vec::new();

    for artifact in manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array")
    {
        let identity = (
            artifact["producerHostHandle"]
                .as_str()
                .expect("producer handle"),
            artifact["sanitizedSourcePath"]
                .as_str()
                .expect("sanitized source path"),
            artifact["originalBasename"].as_str().expect("basename"),
            artifact["rotation"]["kind"]
                .as_str()
                .expect("rotation kind"),
        );
        if !physical_sources.insert(identity) {
            duplicates.push(identity);
        }
    }

    assert!(
        duplicates.is_empty(),
        "one physical capture was duplicated to attach multiple workflow subjects: {duplicates:?}"
    );

    let mut falsely_narrowed = manifest.clone();
    falsely_narrowed["artifacts"][0]
        .as_object_mut()
        .expect("artifact is an object")
        .remove("workflowSubjectBasis");
    falsely_narrowed["artifacts"][0]["workflowSubjectHandle"] = json!(EXACT_DP);
    assert!(
        validate_manifest(
            &corpus_root().join("content-version-mismatch"),
            &falsely_narrowed
        )
        .is_err(),
        "a shared physical site log was falsely narrowed to one DP despite containing another"
    );
}

#[test]
fn source_local_classifications_are_bound_to_physical_coverage_semantics() {
    let client_manifest =
        read_json("client-only-looking-request", "manifest.json").expect("manifest loads");
    let client_expected =
        read_json("client-only-looking-request", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut client_as_malformed = client_expected.clone();
    client_as_malformed["sourceLocalObservations"][0]["classification"] =
        json!("malformedEvidence");
    if mutation_was_accepted(
        "client-only-looking-request",
        &client_manifest,
        &client_as_malformed,
    ) {
        accepted.push("captured client evidence relabeled as malformed server evidence");
    }

    let mut split_as_client = rotation_expected.clone();
    split_as_client["sourceLocalObservations"][0]["classification"] =
        json!("ignoredClientEvidence");
    if mutation_was_accepted("rotation-boundary", &rotation_manifest, &split_as_client) {
        accepted.push("split server rotation relabeled as ignored client evidence");
    }

    let mut malformed_as_split = rotation_expected.clone();
    malformed_as_split["sourceLocalObservations"][1]["classification"] = json!("rotationSplit");
    if mutation_was_accepted("rotation-boundary", &rotation_manifest, &malformed_as_split) {
        accepted.push("parse-failed source relabeled as a rotation split");
    }

    assert!(
        accepted.is_empty(),
        "source-local classifications were detached from physical coverage: {accepted:?}"
    );
}
