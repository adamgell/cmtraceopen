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
const EXACT_SOURCE_VERSION: &str = "5.00.TEST.0001";
const EXACT_SITE: &str = "LAB";
const EXACT_DP: &str = "safe:dp:lab-dp-01";
const EXACT_DP_02: &str = "safe:dp:lab-dp-02";
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

fn required_nonempty_string<'a>(
    value: &'a Value,
    field: &str,
    context: &str,
) -> Result<&'a str, String> {
    required_string(value, field, context).and_then(|candidate| {
        if candidate.is_empty() {
            Err(format!("{context}.{field} must not be empty"))
        } else {
            Ok(candidate)
        }
    })
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
        "current" if rotation.get("value").is_none() => Ok(SccmRotation::Current),
        "current" => Err("current rotation must not contain a value".to_owned()),
        "lo_" if rotation.get("value").is_none() => Ok(SccmRotation::LoUnderscore),
        "lo_" => Err("lo_ rotation must not contain a value".to_owned()),
        "numbered" => serde_json::from_value(json!({
            "kind": "numbered",
            "value": rotation["value"].clone(),
        }))
        .map_err(|error| format!("numbered rotation is noncanonical: {error}")),
        "timestamped" => serde_json::from_value(json!({
            "kind": "timestamped",
            "value": rotation["value"].clone(),
        }))
        .map_err(|error| format!("timestamped rotation is noncanonical: {error}")),
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
    physical_evidence: BTreeSet<(String, u32, u32)>,
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

fn path_segment_is_safe(segment: &str) -> bool {
    !segment.is_empty()
        && !matches!(segment, "." | "..")
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn segmented_path_is_safe(path: &str) -> bool {
    !path.is_empty() && !path.contains('\\') && path.split('/').all(path_segment_is_safe)
}

fn source_path_is_bounded(relative_path: &str, basename: &str) -> bool {
    relative_path
        .strip_prefix("evidence/")
        .is_some_and(segmented_path_is_safe)
        && relative_path
            .rsplit('/')
            .next()
            .is_some_and(|candidate| candidate == basename)
}

fn sanitized_source_path_is_bounded(source_path: &str, basename: &str, rotation: &Value) -> bool {
    let Some(suffix) = source_path.strip_prefix("SYNTHETIC://") else {
        return false;
    };
    if !segmented_path_is_safe(suffix) {
        return false;
    }
    let segments = suffix.split('/').collect::<Vec<_>>();
    if segments.len() != 3
        || !matches!(
            segments[0],
            "client-control"
                | "default-dp-root"
                | "default-site-root"
                | "dp-02-root"
                | "dp-root"
                | "site-root"
        )
        || segments[1] != "Logs"
    {
        return false;
    }

    let expected_basename = match rotation["kind"].as_str() {
        Some("current") => Some(basename.to_owned()),
        Some("lo_") => basename
            .strip_suffix(".log")
            .map(|stem| format!("{stem}.lo_")),
        Some("numbered") => rotation["value"]
            .as_u64()
            .map(|value| format!("{basename}.{value}")),
        Some("timestamped") => rotation["value"]
            .as_str()
            .map(|value| format!("{basename}.{value}")),
        _ => None,
    };
    expected_basename.is_some_and(|expected| segments[2].eq_ignore_ascii_case(&expected))
}

fn path_fingerprint_is_safe(path_fingerprint: &str) -> bool {
    path_fingerprint
        .strip_prefix("synthetic:")
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn artifact_id_is_safe(artifact_id: &str) -> bool {
    artifact_id.len() <= 128 && path_segment_is_safe(artifact_id)
}

fn request_id_is_safe(request_id: &str) -> bool {
    request_id
        .strip_prefix("client-request-")
        .is_some_and(|suffix| suffix.len() <= 64 && path_segment_is_safe(suffix))
}

fn coverage_request_reason(artifact: &ParsedArtifact) -> Option<&'static str> {
    match artifact.state.as_str() {
        "absent" => Some("coverageAbsent"),
        "accessDenied" => Some("coverageAccessDenied"),
        "capped" => Some("coverageCapped"),
        "parseFailed" => Some("coverageMalformed"),
        _ if artifact.fragment_complete == Some(false) => Some("coverageRotationSplit"),
        _ => None,
    }
}

fn artifact_has_incomplete_coverage(artifact: &ParsedArtifact) -> bool {
    artifact.state != "captured" || artifact.fragment_complete == Some(false)
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
    let mut distribution_point_handles = Vec::new();
    match required_array(
        &manifest["topology"],
        "distributionPointHandles",
        "topology",
    ) {
        Ok(values) => {
            for value in values {
                match value.as_str() {
                    Some(handle)
                        if !handle.is_empty() && matches!(handle, EXACT_DP | EXACT_DP_02) =>
                    {
                        distribution_point_handles.push(handle.to_owned());
                    }
                    Some(handle) => failures.push(format!(
                        "distributionPointHandles contains unknown handle {handle}"
                    )),
                    None => failures.push(
                        "distributionPointHandles entries must be nonempty strings".to_owned(),
                    ),
                }
            }
        }
        Err(error) => failures.push(error),
    }
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

    let mut roles = Vec::new();
    match required_array(&manifest["topology"], "rolesObserved", "topology") {
        Ok(values) => {
            for value in values {
                match value.as_str() {
                    Some(role) if matches!(role, "distributionPoint" | "siteServer") => {
                        roles.push(role);
                    }
                    Some(role) => {
                        failures.push(format!("rolesObserved contains unsupported role {role}"))
                    }
                    None => failures.push(
                        "rolesObserved entries must be strings in the allowed role set".to_owned(),
                    ),
                }
            }
        }
        Err(error) => failures.push(error),
    }
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
    let mut physical_evidence_by_reference = BTreeSet::new();
    let mut relative_paths = BTreeSet::new();
    let mut physical_source_identities = BTreeSet::new();
    let mut path_fingerprints = BTreeSet::new();
    for artifact in artifacts {
        let artifact_id = match required_nonempty_string(artifact, "artifactId", "artifact") {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        if !artifact_id_is_safe(artifact_id) {
            failures.push(format!(
                "artifact {artifact_id} does not use a bounded stable artifact ID"
            ));
        }
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
        let rotation_kind = artifact["rotation"]["kind"].as_str();
        let rotation_lineage =
            match required_nonempty_string(&artifact["rotation"], "lineageId", &context) {
                Ok(value) => value.to_owned(),
                Err(error) => {
                    failures.push(error);
                    String::new()
                }
            };
        let physical_capture = matches!(state, "captured" | "capped" | "parseFailed");
        let artifact_collected_utc = match required_string(artifact, "collectedUtc", &context)
            .and_then(|value| {
                DateTime::parse_from_rfc3339(value)
                    .map(|parsed| parsed.timestamp_millis())
                    .map_err(|error| format!("{context}.collectedUtc is RFC3339: {error}"))
            }) {
            Ok(value) => {
                if value > captured_utc {
                    failures.push(format!(
                        "{artifact_id} was collected after the canonical bundle capture"
                    ));
                }
                Some(value)
            }
            Err(error) => {
                failures.push(error);
                None
            }
        };
        let encoding = artifact["encoding"].as_str();
        if physical_capture && encoding.is_none_or(str::is_empty) {
            failures.push(format!(
                "{artifact_id} physical capture lacks encoding provenance"
            ));
        }
        let fragment_complete = if physical_capture {
            match required_bool(&artifact["rotation"], "fragmentComplete", &context) {
                Ok(value) => Some(value),
                Err(error) => {
                    failures.push(error);
                    None
                }
            }
        } else {
            None
        };
        let path_fingerprint = artifact["pathFingerprint"].as_str();
        let sanitized_source_path = artifact["sanitizedSourcePath"].as_str();
        if !path_fingerprint.is_some_and(path_fingerprint_is_safe)
            || !sanitized_source_path.is_some_and(|value| {
                sanitized_source_path_is_bounded(value, basename, &artifact["rotation"])
            })
        {
            failures.push(format!("{artifact_id} leaks or omits path provenance"));
        }
        if path_fingerprint
            .map(str::to_ascii_lowercase)
            .is_some_and(|value| !path_fingerprints.insert(value))
        {
            failures.push(format!(
                "{artifact_id} duplicates another physical path fingerprint"
            ));
        }
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
                source_path.to_ascii_lowercase(),
                basename.to_ascii_lowercase(),
                rotation_kind.to_owned(),
                rotation_value.to_ascii_lowercase(),
            );
            if !physical_source_identities.insert(physical_identity) {
                failures.push(format!(
                    "{artifact_id} duplicates one physical source for another workflow subject"
                ));
            }
        }
        if artifact["sourceKind"] != "ccmLog"
            || artifact["sourceVersion"].as_str() != Some(EXACT_SOURCE_VERSION)
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

        if physical_capture {
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
            if !relative_paths.insert(relative_path.to_ascii_lowercase()) {
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
            let content = String::from_utf8_lossy(&bytes);
            if !content.contains("SYNTHETIC FIXTURE") {
                failures.push(format!("{artifact_id} lacks a synthetic fixture marker"));
            }
            for (line_index, _) in content.lines().enumerate() {
                let Ok(line_number) = u32::try_from(line_index + 1) else {
                    failures.push(format!(
                        "{artifact_id} has more physical lines than an evidence reference can address"
                    ));
                    break;
                };
                physical_evidence_by_reference.insert((
                    artifact_id.to_owned(),
                    line_number,
                    line_number,
                ));
            }
            if matches!(state, "captured" | "capped") {
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
                    encoding: encoding.map(str::to_owned),
                };
                let normalized = normalize_ccm_artifact(artifact_model, &content);
                if fragment_complete == Some(false) && !normalized.is_empty() {
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
                            let identity_fields_are_safe = match role {
                                "client" => {
                                    fields.get("ClientHandle").map(String::as_str)
                                        == Some(EXACT_CLIENT)
                                        && fields
                                            .get("RequestId")
                                            .is_some_and(|value| request_id_is_safe(value))
                                }
                                "siteServer" | "distributionPoint" => {
                                    !fields.contains_key("ClientHandle")
                                        && !fields.contains_key("RequestId")
                                }
                                _ => false,
                            };
                            if !identity_fields_are_safe {
                                failures.push(format!(
                                    "{artifact_id} exposes identity-bearing fields outside the approved opaque role namespace"
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
                    rotation_lineage,
                    fragment_complete,
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
            physical_evidence: physical_evidence_by_reference,
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
    let key = evidence_reference_key(reference, context)?;
    parsed.evidence.get(&key).ok_or_else(|| {
        format!(
            "{context} does not cite a physical logical record: {}:{}-{}",
            key.0, key.1, key.2
        )
    })
}

fn physical_evidence_for(
    parsed: &ParsedScenario,
    reference: &Value,
    context: &str,
) -> Result<(), String> {
    let key = evidence_reference_key(reference, context)?;
    if parsed.physical_evidence.contains(&key) {
        Ok(())
    } else {
        Err(format!(
            "{context} does not cite an exact physical line: {}:{}-{}",
            key.0, key.1, key.2
        ))
    }
}

fn evidence_reference_key(reference: &Value, context: &str) -> Result<(String, u32, u32), String> {
    let artifact_id = required_string(reference, "artifactId", context)?;
    let line_start = reference["startLine"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| format!("{context}.startLine must be a u32"))?;
    let line_end = reference["endLine"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| format!("{context}.endLine must be a u32"))?;
    Ok((artifact_id.to_owned(), line_start, line_end))
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
        .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
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
    let mut seen_observation_ids = BTreeSet::new();
    let mut consumed_evidence = BTreeSet::new();
    let mut required_incomplete_requests = BTreeSet::new();
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
        if observations.is_empty() {
            failures.push(format!(
                "{transaction_id} has an exact correlation-eligible key without cited logical records"
            ));
        }
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
        let mut terminal_success_phase = None;
        let mut terminal_failure = false;
        let mut terminal_deferred = false;
        let mut cites_capped_evidence = false;
        let mut previous_utc = i64::MIN;
        let mut previous_phase = 0usize;
        for observation in observations {
            let observation_id =
                match required_nonempty_string(observation, "observationId", transaction_id) {
                    Ok(value) => value,
                    Err(error) => {
                        failures.push(error);
                        continue;
                    }
                };
            if !seen_observation_ids.insert(observation_id) {
                failures.push(format!(
                    "{transaction_id} contains duplicate observationId {observation_id}"
                ));
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
                if evidence_reference_key(reference, observation_id)
                    .is_ok_and(|key| !consumed_evidence.insert(key))
                {
                    failures.push(format!(
                        "{transaction_id} consumes one physical evidence reference more than once"
                    ));
                }
                let cited_artifact_id =
                    required_string(reference, "artifactId", observation_id).unwrap_or("invalid");
                match parsed.artifacts.get(cited_artifact_id) {
                    Some(artifact)
                        if artifact.role != "client"
                            && phase_allowed_for_artifact(artifact, phase)
                            && artifact
                                .workflow_subject_handle
                                .as_deref()
                                .is_none_or(|handle| handle == key_fields["DpHandle"]) =>
                    {
                        cites_capped_evidence |= artifact.state == "capped";
                    }
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
                    if terminal_success_phase.is_some() {
                        failures.push(format!(
                            "{transaction_id} contains more than one terminal success"
                        ));
                    }
                    terminal_success_phase = phase_index;
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
                    && terminal_success_phase
                        == STATE_CHAIN
                            .iter()
                            .position(|phase| *phase == "serveOrReport")
                    && computed_last_success == Some("serveOrReport")
                    && !terminal_failure
                    && !cites_capped_evidence
                    && confidence == "high"
                    && confidence_ceiling == "high" => {}
            ("failed", "confirmedFailure")
                if terminal_failure
                    && !terminal_success
                    && !cites_capped_evidence
                    && confidence == "high"
                    && confidence_ceiling == "high" => {}
            ("deferred", "blockedOrDeferred")
                if terminal_deferred
                    && !terminal_failure
                    && !terminal_success
                    && !cites_capped_evidence
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

        let mut gap_ids = Vec::new();
        match required_array(transaction, "coverageGapArtifactIds", transaction_id) {
            Ok(values) => {
                for value in values {
                    match value.as_str() {
                        Some(artifact_id) if !artifact_id.is_empty() => gap_ids.push(artifact_id),
                        Some(_) => failures.push(format!(
                            "{transaction_id} coverage gap artifact ID must not be empty"
                        )),
                        None => failures.push(format!(
                            "{transaction_id} coverage gap artifact IDs must be strings"
                        )),
                    }
                }
            }
            Err(error) => failures.push(error),
        }
        let mut sorted_gap_ids = gap_ids.clone();
        sorted_gap_ids.sort_unstable();
        sorted_gap_ids.dedup();
        if gap_ids != sorted_gap_ids {
            failures.push(format!(
                "{transaction_id} coverage gaps must be sorted and unique"
            ));
        }
        for artifact_id in &gap_ids {
            match parsed.artifacts.get(*artifact_id) {
                Some(artifact) if artifact_has_incomplete_coverage(artifact) => {}
                _ => failures.push(format!(
                    "{transaction_id} coverage gap {artifact_id} is absent or complete"
                )),
            }
        }
        if state == "incomplete" {
            let next_source = transaction["nextSourceId"].as_str();
            if next_source.is_none()
                || !parsed.artifacts.values().any(|artifact| {
                    Some(artifact.source_id.as_str()) == next_source
                        && artifact_has_incomplete_coverage(artifact)
                })
            {
                failures.push(format!(
                    "{transaction_id} incomplete state lacks a bounded noncomplete next source"
                ));
            }
            let declared_gap_ids = gap_ids.iter().copied().collect::<BTreeSet<_>>();
            let expected_gap_ids = parsed
                .artifacts
                .iter()
                .filter(|(_, artifact)| {
                    Some(artifact.source_id.as_str()) == next_source
                        && artifact_has_incomplete_coverage(artifact)
                })
                .map(|(artifact_id, _)| artifact_id.as_str())
                .collect::<BTreeSet<_>>();
            if declared_gap_ids.is_empty() || declared_gap_ids != expected_gap_ids {
                failures.push(format!(
                    "{transaction_id} incomplete state lacks the exact physical coverage gaps"
                ));
            }
            for artifact_id in declared_gap_ids {
                let Some(artifact) = parsed.artifacts.get(artifact_id) else {
                    continue;
                };
                match coverage_request_reason(artifact) {
                    Some(reason_code) => {
                        required_incomplete_requests
                            .insert((artifact.source_id.clone(), reason_code.to_owned()));
                    }
                    None => failures.push(format!(
                        "{transaction_id} gap {artifact_id} has no bounded artifact-request reason"
                    )),
                }
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
        let observation_id = match required_nonempty_string(
            observation,
            "observationId",
            "sourceLocalObservation",
        ) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        if !seen_observation_ids.insert(observation_id) {
            failures.push(format!(
                "source-local observations contain duplicate observationId {observation_id}"
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
        ) || observation.get("key").is_some()
            || observation["correlationEligible"] != false
            || observation["confidence"] != "low"
            || observation["confidenceCeiling"] != "low"
        {
            failures.push(format!(
                "{observation_id} is not an explicitly noncorrelatable source-local observation"
            ));
        }
        let mut artifact_ids = Vec::new();
        match required_array(observation, "artifactIds", observation_id) {
            Ok(values) => {
                for value in values {
                    match value.as_str() {
                        Some(artifact_id) if !artifact_id.is_empty() => {
                            artifact_ids.push(artifact_id);
                        }
                        Some(_) => {
                            failures.push(format!("{observation_id} artifact ID must not be empty"))
                        }
                        None => {
                            failures.push(format!("{observation_id} artifact IDs must be strings"))
                        }
                    }
                }
            }
            Err(error) => failures.push(error),
        }
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
        let references = match required_array(observation, "evidence", observation_id) {
            Ok(values) if !values.is_empty() => values,
            Ok(_) => {
                failures.push(format!(
                    "{observation_id} has no cited physical source-local evidence"
                ));
                &[]
            }
            Err(error) => {
                failures.push(error);
                &[]
            }
        };
        let mut cited_artifact_ids = BTreeSet::new();
        let mut reference_order = Vec::new();
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
            if let Ok(key) = evidence_reference_key(reference, observation_id) {
                reference_order.push(key.clone());
                if !consumed_evidence.insert(key) {
                    failures.push(format!(
                        "{observation_id} consumes one physical evidence reference more than once"
                    ));
                }
            }
            if let Err(error) = physical_evidence_for(parsed, reference, observation_id) {
                failures.push(error);
            }
        }
        let mut sorted_reference_order = reference_order.clone();
        sorted_reference_order.sort();
        if reference_order != sorted_reference_order {
            failures.push(format!(
                "{observation_id} physical evidence is not canonically ordered"
            ));
        }
        let artifacts = artifact_ids
            .iter()
            .filter_map(|artifact_id| parsed.artifacts.get(*artifact_id))
            .collect::<Vec<_>>();
        let semantic_match = match classification {
            Some("ignoredClientEvidence") => {
                cited_artifact_ids == unique_artifact_ids
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
                cited_artifact_ids == unique_artifact_ids
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
                cited_artifact_ids == unique_artifact_ids
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
        let source_id = required_string(request, "sourceId", "artifactRequest")
            .unwrap_or("invalid")
            .to_owned();
        let reason_code = required_string(request, "reasonCode", "artifactRequest")
            .unwrap_or("invalid")
            .to_owned();
        reject_unknown_fields(
            request,
            &["sourceId", "reasonCode"],
            "artifactRequest",
            &mut failures,
        );
        request_order.push((source_id.clone(), reason_code.clone()));
        if !matches!(
            source_id.as_str(),
            "server-dp-distribution" | "server-dp-serve"
        ) || !matches!(
            reason_code.as_str(),
            "coverageAbsent"
                | "coverageAccessDenied"
                | "coverageCapped"
                | "coverageMalformed"
                | "coverageRotationSplit"
        ) || request.get("reason").is_some()
        {
            failures.push(format!(
                "artifact request is not a bounded versioned source/reason code: {source_id}/{reason_code}"
            ));
        }
        let matching_coverage = parsed.artifacts.values().any(|artifact| {
            artifact.source_id == source_id
                && match reason_code.as_str() {
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
    let declared_requests = request_order.iter().cloned().collect::<BTreeSet<_>>();
    if request_order != sorted_request_order || declared_requests.len() != request_order.len() {
        failures.push("artifact requests are not sorted and unique".to_owned());
    }
    let expected_requests = parsed
        .artifacts
        .values()
        .filter(|artifact| artifact.role != "client")
        .filter_map(|artifact| {
            coverage_request_reason(artifact)
                .map(|reason| (artifact.source_id.clone(), reason.to_owned()))
        })
        .collect::<BTreeSet<_>>();
    if declared_requests != expected_requests {
        failures.push(format!(
            "artifact requests are not the exact bounded coverage projection: {declared_requests:?} != {expected_requests:?}"
        ));
    }
    if !required_incomplete_requests.is_subset(&declared_requests) {
        failures.push(
            "incomplete transactions lack requests matching their exact physical gaps".to_owned(),
        );
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

struct TemporaryScenario {
    root: std::path::PathBuf,
}

impl Drop for TemporaryScenario {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn copy_fixture_tree(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::create_dir_all(destination).expect("temporary fixture directory is created");
    for entry in std::fs::read_dir(source).expect("fixture directory is readable") {
        let entry = entry.expect("fixture directory entry is readable");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_fixture_tree(&source_path, &destination_path);
        } else {
            std::fs::copy(&source_path, &destination_path)
                .expect("fixture file is copied into the temporary scenario");
        }
    }
}

fn temporary_scenario(scenario: &str) -> TemporaryScenario {
    static NEXT_TEMP_SCENARIO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT_TEMP_SCENARIO.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "cmtraceopen-sccm-329-{}-{scenario}-{sequence}",
        std::process::id()
    ));
    copy_fixture_tree(&corpus_root().join(scenario), &root);
    TemporaryScenario { root }
}

fn mutation_at_root_was_accepted(
    scenario: &str,
    scenario_root: &std::path::Path,
    manifest: &Value,
    expected: &Value,
) -> bool {
    validate_manifest(scenario_root, manifest)
        .and_then(|parsed| validate_expected(scenario, manifest, expected, &parsed))
        .is_ok()
}

fn replace_fixture_text(
    scenario_root: &std::path::Path,
    relative_path: &str,
    original: &str,
    replacement: &str,
) {
    let path = scenario_root.join(relative_path);
    let contents = std::fs::read_to_string(&path).expect("temporary fixture is readable");
    assert_eq!(
        contents.matches(original).count(),
        1,
        "fixture mutation must identify exactly one raw marker"
    );
    std::fs::write(&path, contents.replacen(original, replacement, 1))
        .expect("temporary fixture mutation is written");
}

fn refresh_artifact_bytes(
    manifest: &mut Value,
    artifact_index: usize,
    scenario_root: &std::path::Path,
) {
    let relative_path = manifest["artifacts"][artifact_index]["relativePath"]
        .as_str()
        .expect("physical artifact has a relative path");
    let byte_count = std::fs::metadata(scenario_root.join(relative_path))
        .expect("mutated physical artifact is readable")
        .len();
    manifest["artifacts"][artifact_index]["bytesCopied"] = json!(byte_count);
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

#[test]
fn path_provenance_aliases_fail_closed() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut duplicate_fingerprint = healthy_manifest.clone();
    duplicate_fingerprint["artifacts"][1]["pathFingerprint"] =
        duplicate_fingerprint["artifacts"][0]["pathFingerprint"].clone();
    if mutation_was_accepted("healthy-package", &duplicate_fingerprint, &healthy_expected) {
        accepted.push("duplicate path fingerprint");
    }

    let mut dot_segment_alias = healthy_manifest.clone();
    dot_segment_alias["artifacts"][1]["relativePath"] =
        json!("evidence/server-dp-distribution/site/current/./PkgXferMgr.log");
    if mutation_was_accepted("healthy-package", &dot_segment_alias, &healthy_expected) {
        accepted.push("dot-segment physical evidence alias");
    }

    let mut unsafe_source_path = healthy_manifest.clone();
    unsafe_source_path["artifacts"][2]["sanitizedSourcePath"] =
        json!("SYNTHETIC://../../Users/RealUser/SMSDPProv.log");
    if mutation_was_accepted("healthy-package", &unsafe_source_path, &healthy_expected) {
        accepted.push("unsafe sanitized source path");
    }

    assert!(
        accepted.is_empty(),
        "unsafe or colliding path provenance was accepted: {accepted:?}"
    );
}

#[test]
fn exact_profile_requires_the_pinned_synthetic_source_version() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut missing_version = healthy_manifest.clone();
    missing_version["artifacts"][0]
        .as_object_mut()
        .expect("artifact is an object")
        .remove("sourceVersion");
    if mutation_was_accepted("healthy-package", &missing_version, &healthy_expected) {
        accepted.push("missing source version retained Exact");
    }

    for (label, version) in [
        ("unknown source version retained Exact", "5.00.TEST.UNKNOWN"),
        ("malformed source version retained Exact", "5.00.TEST."),
        (
            "prefix-collision source version retained Exact",
            "5.00.TEST.0001-extra",
        ),
    ] {
        let mut mutated = healthy_manifest.clone();
        mutated["artifacts"][0]["sourceVersion"] = json!(version);
        if mutation_was_accepted("healthy-package", &mutated, &healthy_expected) {
            accepted.push(label);
        }
    }

    assert!(
        accepted.is_empty(),
        "unvalidated source versions selected the Exact profile: {accepted:?}"
    );
}

#[test]
fn topology_roles_are_typed_and_known() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut non_string_role = healthy_manifest.clone();
    non_string_role["topology"]["rolesObserved"]
        .as_array_mut()
        .expect("roles are an array")
        .push(json!(7));
    if mutation_was_accepted("healthy-package", &non_string_role, &healthy_expected) {
        accepted.push("non-string observed role");
    }

    let mut unknown_role = healthy_manifest.clone();
    unknown_role["topology"]["rolesObserved"]
        .as_array_mut()
        .expect("roles are an array")
        .push(json!("unknownRole"));
    if mutation_was_accepted("healthy-package", &unknown_role, &healthy_expected) {
        accepted.push("unknown observed role");
    }

    assert!(
        accepted.is_empty(),
        "malformed role topology was accepted: {accepted:?}"
    );
}

#[test]
fn rotation_shapes_match_the_shared_canonical_contract() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut current_with_value = healthy_manifest.clone();
    current_with_value["artifacts"][0]["rotation"]["value"] = json!("unexpected");
    if mutation_was_accepted("healthy-package", &current_with_value, &healthy_expected) {
        accepted.push("current rotation with value");
    }

    let mut lo_with_value = rotation_manifest.clone();
    lo_with_value["artifacts"][1]["rotation"]["value"] = json!("unexpected");
    if mutation_was_accepted("rotation-boundary", &lo_with_value, &rotation_expected) {
        accepted.push("lo_ rotation with value");
    }

    let mut numbered_zero = healthy_manifest.clone();
    numbered_zero["artifacts"][0]["rotation"]["kind"] = json!("numbered");
    numbered_zero["artifacts"][0]["rotation"]["value"] = json!(0);
    if mutation_was_accepted("healthy-package", &numbered_zero, &healthy_expected) {
        accepted.push("numbered rotation with zero value");
    }

    let mut malformed_timestamp = healthy_manifest.clone();
    malformed_timestamp["artifacts"][0]["rotation"]["kind"] = json!("timestamped");
    malformed_timestamp["artifacts"][0]["rotation"]["value"] = json!("20260730_122000");
    if mutation_was_accepted("healthy-package", &malformed_timestamp, &healthy_expected) {
        accepted.push("timestamped rotation with noncanonical value");
    }

    assert!(
        accepted.is_empty(),
        "noncanonical rotation shapes were accepted: {accepted:?}"
    );
}

#[test]
fn transaction_observation_ids_and_evidence_are_single_use() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut duplicate_observation_id = healthy_expected.clone();
    duplicate_observation_id["transactions"][0]["observations"][1]["observationId"] =
        json!("01-receive");
    if mutation_was_accepted(
        "healthy-package",
        &healthy_manifest,
        &duplicate_observation_id,
    ) {
        accepted.push("duplicate observation ID");
    }

    let mut reused_evidence = healthy_expected.clone();
    let mut repeated = reused_evidence["transactions"][0]["observations"][5].clone();
    repeated["observationId"] = json!("07-report-copy");
    reused_evidence["transactions"][0]["observations"]
        .as_array_mut()
        .expect("observations are an array")
        .push(repeated);
    if mutation_was_accepted("healthy-package", &healthy_manifest, &reused_evidence) {
        accepted.push("one physical evidence reference consumed twice");
    }

    assert!(
        accepted.is_empty(),
        "duplicate observations or reused evidence were accepted: {accepted:?}"
    );
}

#[test]
fn physical_path_provenance_is_case_folded_bounded_and_basename_bound() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut case_folded_fingerprint = healthy_manifest.clone();
    case_folded_fingerprint["artifacts"][1]["pathFingerprint"] = json!("synthetic:HEALTHY-DISTMGR");
    if mutation_was_accepted(
        "healthy-package",
        &case_folded_fingerprint,
        &healthy_expected,
    ) {
        accepted.push("case-folded duplicate path fingerprint");
    }

    let mut basename_detached = healthy_manifest.clone();
    basename_detached["artifacts"][1]["sanitizedSourcePath"] =
        basename_detached["artifacts"][0]["sanitizedSourcePath"].clone();
    if mutation_was_accepted("healthy-package", &basename_detached, &healthy_expected) {
        accepted.push("sanitized source path detached from its original basename");
    }

    let mut identity_bearing_path = healthy_manifest.clone();
    identity_bearing_path["artifacts"][2]["sanitizedSourcePath"] =
        json!("SYNTHETIC://Users/RealUser/SMSDPProv.log");
    if mutation_was_accepted("healthy-package", &identity_bearing_path, &healthy_expected) {
        accepted.push("identity-bearing sanitized source root");
    }

    assert!(
        accepted.is_empty(),
        "unbounded or colliding physical path provenance was accepted: {accepted:?}"
    );
}

#[test]
fn distribution_point_handles_are_typed_known_unique_and_complete() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut non_string_handle = healthy_manifest.clone();
    non_string_handle["topology"]["distributionPointHandles"] = json!([EXACT_DP, 7]);
    if mutation_was_accepted("healthy-package", &non_string_handle, &healthy_expected) {
        accepted.push("non-string distribution-point topology handle");
    }

    let mut unknown_handle = healthy_manifest.clone();
    unknown_handle["topology"]["distributionPointHandles"] = json!([EXACT_DP, "safe:dp:lab-dp-99"]);
    if mutation_was_accepted("healthy-package", &unknown_handle, &healthy_expected) {
        accepted.push("unknown distribution-point topology handle");
    }

    let mut duplicate_handle = healthy_manifest.clone();
    duplicate_handle["topology"]["distributionPointHandles"] = json!([EXACT_DP, EXACT_DP]);
    if mutation_was_accepted("healthy-package", &duplicate_handle, &healthy_expected) {
        accepted.push("duplicate distribution-point topology handle");
    }

    let mut missing_primary = healthy_manifest.clone();
    missing_primary["topology"]["distributionPointHandles"] = json!(["safe:dp:lab-dp-02"]);
    if mutation_was_accepted("healthy-package", &missing_primary, &healthy_expected) {
        accepted.push("distribution-point topology omitted its primary handle");
    }

    let mut missing_handle_array = healthy_manifest.clone();
    missing_handle_array["topology"]
        .as_object_mut()
        .expect("topology is an object")
        .remove("distributionPointHandles");
    if mutation_was_accepted("healthy-package", &missing_handle_array, &healthy_expected) {
        accepted.push("distribution-point topology omitted its exact handle array");
    }

    assert!(
        accepted.is_empty(),
        "malformed distribution-point topology handles were accepted: {accepted:?}"
    );
}

#[test]
fn physical_rotation_provenance_is_typed_and_complete() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut non_boolean_fragment = healthy_manifest.clone();
    non_boolean_fragment["artifacts"][0]["rotation"]["fragmentComplete"] = json!("true");
    if mutation_was_accepted("healthy-package", &non_boolean_fragment, &healthy_expected) {
        accepted.push("non-boolean physical fragment completeness");
    }

    let mut non_string_lineage = healthy_manifest.clone();
    non_string_lineage["artifacts"][0]["rotation"]["lineageId"] = json!(7);
    if mutation_was_accepted("healthy-package", &non_string_lineage, &healthy_expected) {
        accepted.push("non-string rotation lineage");
    }

    let mut missing_lineage = healthy_manifest.clone();
    missing_lineage["artifacts"][0]["rotation"]
        .as_object_mut()
        .expect("rotation is an object")
        .remove("lineageId");
    if mutation_was_accepted("healthy-package", &missing_lineage, &healthy_expected) {
        accepted.push("missing rotation lineage");
    }

    let mut missing_fragment = healthy_manifest.clone();
    missing_fragment["artifacts"][0]["rotation"]
        .as_object_mut()
        .expect("rotation is an object")
        .remove("fragmentComplete");
    if mutation_was_accepted("healthy-package", &missing_fragment, &healthy_expected) {
        accepted.push("missing physical fragment completeness");
    }

    assert_eq!(
        rotation_from_manifest(&json!({"kind": "numbered", "value": 3}))
            .expect("canonical numbered rotation"),
        SccmRotation::Numbered(3)
    );
    assert_eq!(
        rotation_from_manifest(&json!({"kind": "timestamped", "value": "20260730-150000"}))
            .expect("canonical timestamped rotation"),
        SccmRotation::Timestamped("20260730-150000".to_owned())
    );

    assert!(
        accepted.is_empty(),
        "malformed or incomplete rotation provenance was accepted: {accepted:?}"
    );
}

#[test]
fn observation_ids_and_physical_evidence_are_unique_across_classes() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let client_manifest =
        read_json("client-only-looking-request", "manifest.json").expect("manifest loads");
    let client_expected =
        read_json("client-only-looking-request", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut empty_transaction_observation = healthy_expected.clone();
    empty_transaction_observation["transactions"][0]["observations"][0]["observationId"] =
        json!("");
    if mutation_was_accepted(
        "healthy-package",
        &healthy_manifest,
        &empty_transaction_observation,
    ) {
        accepted.push("empty transaction observation ID");
    }

    let mut duplicate_source_local_id = rotation_expected.clone();
    duplicate_source_local_id["sourceLocalObservations"][1]["observationId"] =
        duplicate_source_local_id["sourceLocalObservations"][0]["observationId"].clone();
    if mutation_was_accepted(
        "rotation-boundary",
        &rotation_manifest,
        &duplicate_source_local_id,
    ) {
        accepted.push("duplicate source-local observation ID");
    }

    let mut reused_source_local_evidence = client_expected.clone();
    let repeated =
        reused_source_local_evidence["sourceLocalObservations"][0]["evidence"][0].clone();
    reused_source_local_evidence["sourceLocalObservations"][0]["evidence"]
        .as_array_mut()
        .expect("source-local evidence is an array")
        .push(repeated);
    if mutation_was_accepted(
        "client-only-looking-request",
        &client_manifest,
        &reused_source_local_evidence,
    ) {
        accepted.push("source-local physical evidence consumed twice");
    }

    assert!(
        accepted.is_empty(),
        "observation identity or evidence single-use violations were accepted: {accepted:?}"
    );
}

#[test]
fn source_local_artifact_ids_are_strict_strings_across_classifications() {
    let client_manifest =
        read_json("client-only-looking-request", "manifest.json").expect("manifest loads");
    let client_expected =
        read_json("client-only-looking-request", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let surfaces = [
        (
            "ignoredClientEvidence",
            "client-only-looking-request",
            &client_manifest,
            &client_expected,
            0usize,
        ),
        (
            "rotationSplit",
            "rotation-boundary",
            &rotation_manifest,
            &rotation_expected,
            0usize,
        ),
        (
            "malformedEvidence",
            "rotation-boundary",
            &rotation_manifest,
            &rotation_expected,
            1usize,
        ),
    ];
    let invalid_entries = [
        ("numeric", json!(7)),
        ("null", Value::Null),
        ("boolean", json!(true)),
        ("object", json!({"unexpected": "value"})),
        ("empty string", json!("")),
    ];
    let mut accepted = Vec::new();

    for (surface, scenario, manifest, expected, observation_index) in surfaces {
        for (shape, invalid_entry) in &invalid_entries {
            let mut mutated = expected.clone();
            mutated["sourceLocalObservations"][observation_index]["artifactIds"]
                .as_array_mut()
                .expect("source-local artifact IDs are an array")
                .push(invalid_entry.clone());
            if mutation_was_accepted(scenario, manifest, &mutated) {
                accepted.push(format!("{surface} accepted appended {shape} artifact ID"));
            }
        }

        let mut mixed_array = expected.clone();
        mixed_array["sourceLocalObservations"][observation_index]["artifactIds"]
            .as_array_mut()
            .expect("source-local artifact IDs are an array")
            .extend([
                json!(7),
                Value::Null,
                json!(true),
                json!({"unexpected": "value"}),
            ]);
        if mutation_was_accepted(scenario, manifest, &mixed_array) {
            accepted.push(format!("{surface} accepted a mixed-type artifact ID array"));
        }
    }

    assert!(
        accepted.is_empty(),
        "malformed source-local physical artifact IDs were accepted: {accepted:?}"
    );
}

#[test]
fn source_local_evidence_is_typed_nonempty_closed_and_physical() {
    let client_manifest =
        read_json("client-only-looking-request", "manifest.json").expect("manifest loads");
    let client_expected =
        read_json("client-only-looking-request", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let surfaces = [
        (
            "ignoredClientEvidence",
            "client-only-looking-request",
            &client_manifest,
            &client_expected,
            0usize,
            json!([{
                "artifactId": "dp-client-control-01-data-transfer",
                "startLine": 1,
                "endLine": 1
            }]),
        ),
        (
            "rotationSplit",
            "rotation-boundary",
            &rotation_manifest,
            &rotation_expected,
            0usize,
            json!([
                {
                    "artifactId": "dp-rotation-01-current-fragment",
                    "startLine": 1,
                    "endLine": 1
                },
                {
                    "artifactId": "dp-rotation-02-lo-fragment",
                    "startLine": 1,
                    "endLine": 1
                }
            ]),
        ),
        (
            "malformedEvidence",
            "rotation-boundary",
            &rotation_manifest,
            &rotation_expected,
            1usize,
            json!([{
                "artifactId": "dp-rotation-03-malformed",
                "startLine": 1,
                "endLine": 1
            }]),
        ),
    ];
    let non_array_shapes = [
        ("null", Value::Null),
        ("boolean", json!(true)),
        ("numeric", json!(7)),
        ("string", json!("not-an-evidence-array")),
        ("object", json!({"unexpected": "value"})),
    ];
    let mut accepted = Vec::new();

    for (surface, scenario, manifest, expected, observation_index, valid_evidence) in surfaces {
        for (shape, invalid_evidence) in &non_array_shapes {
            let mut mutated = expected.clone();
            mutated["sourceLocalObservations"][observation_index]["evidence"] =
                invalid_evidence.clone();
            if mutation_was_accepted(scenario, manifest, &mutated) {
                accepted.push(format!("{surface} accepted {shape} evidence"));
            }
        }

        let mut empty = expected.clone();
        empty["sourceLocalObservations"][observation_index]["evidence"] = json!([]);
        if mutation_was_accepted(scenario, manifest, &empty) {
            accepted.push(format!("{surface} accepted an empty evidence array"));
        }

        let mut mixed = expected.clone();
        let mut mixed_entries = valid_evidence
            .as_array()
            .expect("valid source-local evidence is an array")
            .clone();
        mixed_entries.extend([
            Value::Null,
            json!(true),
            json!(7),
            json!("not-an-evidence-reference"),
            json!({"unexpected": "value"}),
        ]);
        mixed["sourceLocalObservations"][observation_index]["evidence"] =
            Value::Array(mixed_entries);
        if mutation_was_accepted(scenario, manifest, &mixed) {
            accepted.push(format!("{surface} accepted a mixed evidence array"));
        }

        let mut open_reference = expected.clone();
        open_reference["sourceLocalObservations"][observation_index]["evidence"] =
            valid_evidence.clone();
        open_reference["sourceLocalObservations"][observation_index]["evidence"][0]["unexpected"] =
            json!("value");
        if mutation_was_accepted(scenario, manifest, &open_reference) {
            accepted.push(format!(
                "{surface} accepted an open evidence-reference object"
            ));
        }

        let mut missing_line = expected.clone();
        missing_line["sourceLocalObservations"][observation_index]["evidence"] =
            valid_evidence.clone();
        missing_line["sourceLocalObservations"][observation_index]["evidence"][0]
            .as_object_mut()
            .expect("evidence reference is an object")
            .remove("endLine");
        if mutation_was_accepted(scenario, manifest, &missing_line) {
            accepted.push(format!(
                "{surface} accepted an incomplete evidence reference"
            ));
        }

        let mut unbound_line = expected.clone();
        unbound_line["sourceLocalObservations"][observation_index]["evidence"] =
            valid_evidence.clone();
        unbound_line["sourceLocalObservations"][observation_index]["evidence"][0]["startLine"] =
            json!(99);
        unbound_line["sourceLocalObservations"][observation_index]["evidence"][0]["endLine"] =
            json!(99);
        if mutation_was_accepted(scenario, manifest, &unbound_line) {
            accepted.push(format!("{surface} accepted an unbound physical line"));
        }
    }

    assert!(
        accepted.is_empty(),
        "malformed source-local evidence was accepted: {accepted:?}"
    );
}

#[test]
fn coverage_gap_ids_are_typed_nonempty_unique_and_physical() {
    let incomplete_manifest = read_json("incomplete", "manifest.json").expect("manifest loads");
    let incomplete_expected = read_json("incomplete", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut non_string_gap = incomplete_expected.clone();
    non_string_gap["transactions"][0]["coverageGapArtifactIds"]
        .as_array_mut()
        .expect("coverage gaps are an array")
        .push(json!(7));
    if mutation_was_accepted("incomplete", &incomplete_manifest, &non_string_gap) {
        accepted.push("non-string coverage-gap artifact ID");
    }

    let mut empty_gap = incomplete_expected.clone();
    empty_gap["transactions"][0]["coverageGapArtifactIds"][0] = json!("");
    if mutation_was_accepted("incomplete", &incomplete_manifest, &empty_gap) {
        accepted.push("empty coverage-gap artifact ID");
    }

    let mut duplicate_gap = incomplete_expected.clone();
    let repeated = duplicate_gap["transactions"][0]["coverageGapArtifactIds"][1].clone();
    duplicate_gap["transactions"][0]["coverageGapArtifactIds"]
        .as_array_mut()
        .expect("coverage gaps are an array")
        .push(repeated);
    if mutation_was_accepted("incomplete", &incomplete_manifest, &duplicate_gap) {
        accepted.push("duplicate coverage-gap artifact ID");
    }

    assert!(
        accepted.is_empty(),
        "malformed coverage-gap artifact IDs were accepted: {accepted:?}"
    );
}

#[test]
fn capped_transaction_evidence_cannot_retain_high_confidence_terminal_health() {
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    for (label, artifact_index) in [("earlier phase", 0usize), ("terminal phase", 2usize)] {
        let mut manifest = healthy_manifest.clone();
        let mut expected = healthy_expected.clone();
        let artifact_id = manifest["artifacts"][artifact_index]["artifactId"].clone();
        let bytes_copied = manifest["artifacts"][artifact_index]["bytesCopied"].clone();
        manifest["artifacts"][artifact_index]["captureState"] = json!("capped");
        manifest["artifacts"][artifact_index]["collectionLimit"] =
            json!({"byteLimit": bytes_copied, "limitApplied": true});
        expected["coverage"][artifact_index]["state"] = json!("capped");
        expected["transactions"][0]["coverageGapArtifactIds"] = json!([artifact_id]);
        expected["artifactRequests"] = json!([{
            "sourceId": "server-dp-distribution",
            "reasonCode": "coverageCapped"
        }]);

        if mutation_was_accepted("healthy-package", &manifest, &expected) {
            accepted.push(label);
        }
    }

    assert!(
        accepted.is_empty(),
        "capped transaction evidence retained high-confidence success: {accepted:?}"
    );
}

#[test]
fn terminal_success_is_bound_to_the_cited_serve_or_report_record() {
    let temporary = temporary_scenario("healthy-package");
    let mut manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let mut expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let relative_path = manifest["artifacts"][2]["relativePath"]
        .as_str()
        .expect("provider artifact has a path")
        .to_owned();

    replace_fixture_text(
        &temporary.root,
        &relative_path,
        "Phase=validate; Disposition=succeeded; Terminal=false;",
        "Phase=validate; Disposition=succeeded; Terminal=true;",
    );
    replace_fixture_text(
        &temporary.root,
        &relative_path,
        "Phase=serveOrReport; Disposition=succeeded; Terminal=true;",
        "Phase=serveOrReport; Disposition=succeeded; Terminal=false;",
    );
    refresh_artifact_bytes(&mut manifest, 2, &temporary.root);
    expected["transactions"][0]["observations"][3]["terminal"] = json!(true);
    expected["transactions"][0]["observations"][5]["terminal"] = json!(false);

    assert!(
        !mutation_at_root_was_accepted("healthy-package", &temporary.root, &manifest, &expected,),
        "an earlier terminal success survived later nonterminal ServeOrReport evidence"
    );
}

#[test]
fn correlation_eligible_incomplete_output_requires_evidence_gaps_and_requests() {
    let manifest = read_json("incomplete", "manifest.json").expect("manifest loads");
    let expected = read_json("incomplete", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut uncited_key = expected.clone();
    uncited_key["transactions"][0]["observations"] = json!([]);
    uncited_key["transactions"][0]["lastSuccessfulPhase"] = Value::Null;
    if mutation_was_accepted("incomplete", &manifest, &uncited_key) {
        accepted.push("correlation-eligible exact key with zero cited logical records");
    }

    let mut no_gaps = expected.clone();
    no_gaps["transactions"][0]["coverageGapArtifactIds"] = json!([]);
    if mutation_was_accepted("incomplete", &manifest, &no_gaps) {
        accepted.push("insufficientEvidence transaction with no physical gaps");
    }

    let mut no_requests = expected.clone();
    no_requests["artifactRequests"] = json!([]);
    if mutation_was_accepted("incomplete", &manifest, &no_requests) {
        accepted.push("insufficientEvidence transaction with no bounded request");
    }

    assert!(
        accepted.is_empty(),
        "incomplete output escaped evidence-first coverage requirements: {accepted:?}"
    );
}

#[test]
fn identity_bearing_fixture_fields_are_bounded_role_local_and_not_public() {
    let client_expected =
        read_json("client-only-looking-request", "expected.json").expect("expected loads");
    let public_json = serde_json::to_string(&client_expected).expect("public output serializes");
    for forbidden in ["ClientHandle", "RequestId", "RealUser", "RealRequest"] {
        assert!(
            !public_json.contains(forbidden),
            "public expected JSON exposes raw identity marker {forbidden}"
        );
    }

    let mut accepted = Vec::new();
    for (label, original, replacement) in [
        (
            "unbounded client handle",
            "ClientHandle=safe:client:lab-client-01",
            "ClientHandle=RealUser",
        ),
        (
            "unbounded request ID",
            "RequestId=client-request-01",
            "RequestId=RealRequest",
        ),
    ] {
        let temporary = temporary_scenario("client-only-looking-request");
        let mut manifest =
            read_json("client-only-looking-request", "manifest.json").expect("manifest loads");
        let relative_path = manifest["artifacts"][0]["relativePath"]
            .as_str()
            .expect("client artifact has a path")
            .to_owned();
        replace_fixture_text(&temporary.root, &relative_path, original, replacement);
        refresh_artifact_bytes(&mut manifest, 0, &temporary.root);
        if mutation_at_root_was_accepted(
            "client-only-looking-request",
            &temporary.root,
            &manifest,
            &client_expected,
        ) {
            accepted.push(label);
        }
    }

    let temporary = temporary_scenario("healthy-package");
    let mut manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let relative_path = manifest["artifacts"][2]["relativePath"]
        .as_str()
        .expect("provider artifact has a path")
        .to_owned();
    replace_fixture_text(
        &temporary.root,
        &relative_path,
        "ProfileId=dp-server-5.00.test-v1]LOG]!><time=\"12:00:03",
        "ProfileId=dp-server-5.00.test-v1; ClientHandle=safe:client:lab-client-01; RequestId=client-request-01]LOG]!><time=\"12:00:03",
    );
    refresh_artifact_bytes(&mut manifest, 2, &temporary.root);
    if mutation_at_root_was_accepted("healthy-package", &temporary.root, &manifest, &expected) {
        accepted.push("identity-bearing fields on a server transaction record");
    }

    assert!(
        accepted.is_empty(),
        "identity-bearing fixture fields escaped their safe role boundary: {accepted:?}"
    );
}

#[test]
fn state_chain_rejects_lossy_non_string_projection() {
    let manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let invalid_entries = [
        ("null", Value::Null),
        ("boolean", json!(true)),
        ("number", json!(7)),
        ("object", json!({"unexpected": "value"})),
    ];
    let mut accepted = Vec::new();

    for (shape, invalid) in &invalid_entries {
        let mut mutated = expected.clone();
        mutated["stateChain"]
            .as_array_mut()
            .expect("state chain is an array")
            .push(invalid.clone());
        if mutation_was_accepted("healthy-package", &manifest, &mutated) {
            accepted.push(format!("{shape} state-chain entry"));
        }
    }

    let mut mixed = expected.clone();
    mixed["stateChain"]
        .as_array_mut()
        .expect("state chain is an array")
        .extend(invalid_entries.iter().map(|(_, value)| value.clone()));
    if mutation_was_accepted("healthy-package", &manifest, &mixed) {
        accepted.push("mixed-type state-chain array".to_owned());
    }

    assert!(
        accepted.is_empty(),
        "malformed state-chain entries were projected away: {accepted:?}"
    );
}

#[test]
fn artifact_identity_collection_time_and_encoding_are_mandatory() {
    let absent_manifest = read_json("absent-dp", "manifest.json").expect("manifest loads");
    let absent_expected = read_json("absent-dp", "expected.json").expect("expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let healthy_manifest = read_json("healthy-package", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-package", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut empty_artifact_id = absent_manifest.clone();
    empty_artifact_id["artifacts"][0]["artifactId"] = json!("");
    let mut empty_artifact_id_expected = absent_expected.clone();
    empty_artifact_id_expected["coverage"][0]["artifactId"] = json!("");
    if mutation_was_accepted("absent-dp", &empty_artifact_id, &empty_artifact_id_expected) {
        accepted.push("empty stable artifact ID");
    }

    let mut absent_without_collection_time = absent_manifest.clone();
    absent_without_collection_time["artifacts"][0]
        .as_object_mut()
        .expect("artifact is an object")
        .remove("collectedUtc");
    if mutation_was_accepted(
        "absent-dp",
        &absent_without_collection_time,
        &absent_expected,
    ) {
        accepted.push("absent artifact without collectedUtc");
    }

    let mut malformed_without_collection_time = rotation_manifest.clone();
    malformed_without_collection_time["artifacts"][2]
        .as_object_mut()
        .expect("artifact is an object")
        .remove("collectedUtc");
    if mutation_was_accepted(
        "rotation-boundary",
        &malformed_without_collection_time,
        &rotation_expected,
    ) {
        accepted.push("parseFailed artifact without collectedUtc");
    }

    let mut captured_without_encoding = healthy_manifest.clone();
    captured_without_encoding["artifacts"][0]
        .as_object_mut()
        .expect("artifact is an object")
        .remove("encoding");
    if mutation_was_accepted(
        "healthy-package",
        &captured_without_encoding,
        &healthy_expected,
    ) {
        accepted.push("captured CCM artifact without encoding");
    }

    assert!(
        accepted.is_empty(),
        "mandatory artifact provenance was omitted: {accepted:?}"
    );
}

#[test]
fn source_local_evidence_and_artifact_requests_are_canonical_and_unique() {
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("expected loads");
    let incomplete_manifest = read_json("incomplete", "manifest.json").expect("manifest loads");
    let incomplete_expected = read_json("incomplete", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut reversed_evidence = rotation_expected.clone();
    reversed_evidence["sourceLocalObservations"][0]["evidence"]
        .as_array_mut()
        .expect("source-local evidence is an array")
        .reverse();
    if mutation_was_accepted("rotation-boundary", &rotation_manifest, &reversed_evidence) {
        accepted.push("reordered source-local evidence");
    }

    let mut duplicate_request = incomplete_expected.clone();
    let repeated = duplicate_request["artifactRequests"][0].clone();
    duplicate_request["artifactRequests"]
        .as_array_mut()
        .expect("artifact requests are an array")
        .insert(1, repeated);
    if mutation_was_accepted("incomplete", &incomplete_manifest, &duplicate_request) {
        accepted.push("duplicate sorted artifact request");
    }

    assert!(
        accepted.is_empty(),
        "nondeterministic source-local output was accepted: {accepted:?}"
    );
}

#[test]
fn client_control_coverage_does_not_create_a_server_artifact_request() {
    let mut manifest =
        read_json("client-only-looking-request", "manifest.json").expect("manifest loads");
    let mut expected =
        read_json("client-only-looking-request", "expected.json").expect("expected loads");
    let bytes_copied = manifest["artifacts"][0]["bytesCopied"].clone();
    manifest["artifacts"][0]["captureState"] = json!("capped");
    manifest["artifacts"][0]["collectionLimit"] =
        json!({"byteLimit": bytes_copied, "limitApplied": true});
    expected["coverage"][0]["state"] = json!("capped");

    let validation = validate_scenario_values("client-only-looking-request", &manifest, &expected);
    assert!(
        validation.is_ok(),
        "ignored capped client control invented a server artifact request: {validation:?}"
    );
}

#[test]
fn captured_incomplete_fragments_satisfy_the_bounded_next_source() {
    let temporary = temporary_scenario("incomplete");
    let mut manifest = read_json("incomplete", "manifest.json").expect("manifest loads");
    let mut expected = read_json("incomplete", "expected.json").expect("expected loads");
    let fragments = [
        (
            1usize,
            "evidence/server-dp-distribution/site/current/PkgXferMgr.log",
            "SYNTHETIC FIXTURE CURRENT FRAGMENT ONLY <![LOG[Phase=transfer; PackageId=LAB00007\n",
        ),
        (
            2usize,
            "evidence/server-dp-distribution/dp/current/SMSDPProv.log",
            "SYNTHETIC FIXTURE CURRENT FRAGMENT ONLY <![LOG[Phase=validate; PackageId=LAB00007\n",
        ),
    ];

    for (artifact_index, relative_path, contents) in fragments {
        let fixture_path = temporary.root.join(relative_path);
        std::fs::create_dir_all(
            fixture_path
                .parent()
                .expect("temporary fixture has a parent directory"),
        )
        .expect("temporary fixture parent is created");
        std::fs::write(&fixture_path, contents).expect("temporary fragment is written");
        manifest["artifacts"][artifact_index]["captureState"] = json!("captured");
        manifest["artifacts"][artifact_index]["rotation"]["fragmentComplete"] = json!(false);
        manifest["artifacts"][artifact_index]["encoding"] = json!("utf-8");
        manifest["artifacts"][artifact_index]["collectionLimit"] =
            json!({"byteLimit": 4096, "limitApplied": false});
        manifest["artifacts"][artifact_index]["bytesCopied"] = json!(contents.len());
        manifest["artifacts"][artifact_index]["relativePath"] = json!(relative_path);
        expected["coverage"][artifact_index]["state"] = json!("captured");
    }
    expected["artifactRequests"] = json!([{
        "sourceId": "server-dp-distribution",
        "reasonCode": "coverageRotationSplit"
    }]);

    let validation = validate_manifest(&temporary.root, &manifest)
        .and_then(|parsed| validate_expected("incomplete", &manifest, &expected, &parsed));
    assert!(
        validation.is_ok(),
        "captured incomplete fragments were not usable as bounded coverage gaps: {validation:?}"
    );
}
