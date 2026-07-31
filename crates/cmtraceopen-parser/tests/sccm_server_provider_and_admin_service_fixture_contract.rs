use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use chrono::DateTime;
use cmtraceopen_parser::sccm::{
    classify_artifact_name, normalize_ccm_artifact, SccmArtifact, SccmArtifactFamily,
    SccmCoverageState, SccmEvidence, SccmRole, SccmRotation, SccmTimeOrderingState,
};
use serde_json::Value;

const SCENARIOS: [&str; 13] = [
    "admin-service-auth-failure",
    "admin-service-backend-failure",
    "admin-service-success",
    "contradictory-evidence",
    "iis-supplemental",
    "incomplete",
    "privacy-redaction",
    "provider-authz-denied",
    "provider-query-failure",
    "provider-retry",
    "provider-success",
    "provider-timeout",
    "rotation-boundary",
];

const PROVIDER_CHAIN: [&str; 5] = [
    "receive",
    "authenticateOrAuthorize",
    "executeProviderOperation",
    "respond",
    "recordOutcome",
];

const ADMIN_SERVICE_CHAIN: [&str; 6] = [
    "receive",
    "authenticateOrAuthorize",
    "route",
    "executeBackendOperation",
    "respond",
    "recordOutcome",
];

const PROVIDER_PROFILE: &str = "provider-server-5.00.test-v1";
const ADMIN_SERVICE_PROFILE: &str = "admin-service-server-5.00.test-v1";

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/provider_and_admin_service")
}

fn read_json(scenario: &str, filename: &str) -> Result<Value, String> {
    let path = corpus_root().join(scenario).join(filename);
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("{} is readable: {error}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("{} contains valid JSON: {error}", path.display()))
}

fn actual_scenarios() -> Result<BTreeSet<String>, String> {
    let root = corpus_root();
    let scenarios = fs::read_dir(&root)
        .map_err(|error| format!("{} is readable: {error}", root.display()))?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            path.is_dir().then(|| {
                path.file_name()
                    .expect("scenario directory has a name")
                    .to_string_lossy()
                    .into_owned()
            })
        })
        .collect::<BTreeSet<_>>();
    Ok(scenarios)
}

fn safe_segmented_path(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
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

fn safe_opaque_token(value: &str, prefix: &str, max_suffix_len: usize) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix.len() <= max_suffix_len
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn safe_synthetic_lineage(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn safe_endpoint_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn expected_sanitized_source_path(
    source_id: Option<&str>,
    rotation: &Value,
) -> Option<&'static str> {
    match (source_id, rotation["kind"].as_str()) {
        (Some("server-provider"), Some("current")) => {
            Some("SYNTHETIC://configured-root/LAB/Logs/Smsprov.log")
        }
        (Some("server-provider"), Some("lo_")) => {
            Some("SYNTHETIC://configured-root/LAB/Logs/Smsprov.lo_")
        }
        (Some("server-admin-service"), Some("current")) => {
            Some("SYNTHETIC://configured-root/LAB/Logs/AdminService.log")
        }
        (Some("server-admin-service-iis"), Some("current")) => {
            Some("SYNTHETIC://scoped-export/LAB/IIS/u_ex_synthetic.log")
        }
        _ => None,
    }
}

fn expected_relative_path(
    source_id: Option<&str>,
    endpoint_id: Option<&str>,
    rotation: &Value,
) -> Option<String> {
    let endpoint_id = endpoint_id.filter(|value| safe_endpoint_id(value))?;
    match (source_id, rotation["kind"].as_str()) {
        (Some("server-provider"), Some("current")) => Some(format!(
            "evidence/server-provider/{endpoint_id}/current/Smsprov.log"
        )),
        (Some("server-provider"), Some("lo_")) => Some(format!(
            "evidence/server-provider/{endpoint_id}/lo_/Smsprov.lo_"
        )),
        (Some("server-admin-service"), Some("current")) => Some(format!(
            "evidence/server-admin-service/{endpoint_id}/current/AdminService.log"
        )),
        (Some("server-admin-service-iis"), Some("current")) => Some(format!(
            "evidence/server-admin-service-iis/{endpoint_id}/current/u_ex_synthetic.log"
        )),
        _ => None,
    }
}

fn exported_projection_contains_private_shape(value: &Value) -> bool {
    match value {
        Value::String(value) => {
            let value = value.to_ascii_lowercase();
            value.chars().any(char::is_control)
                || value.contains('@')
                || value.contains('\\')
                || [
                    "bearer ",
                    "select ",
                    "delete ",
                    "insert ",
                    "update ",
                    "drop ",
                    "http://",
                    "https://",
                    "ghp_",
                    "github_pat_",
                    "eyj",
                ]
                .iter()
                .any(|term| value.contains(term))
        }
        Value::Array(values) => values
            .iter()
            .any(exported_projection_contains_private_shape),
        Value::Object(values) => values
            .values()
            .any(exported_projection_contains_private_shape),
        _ => false,
    }
}

fn physical_line_count(scenario: &str, relative_path: &str) -> Option<u64> {
    if !safe_segmented_path(relative_path, "evidence/") {
        return None;
    }
    fs::read_to_string(corpus_root().join(scenario).join(relative_path))
        .ok()
        .map(|content| content.lines().count() as u64)
}

fn coverage_state(value: &str) -> Option<SccmCoverageState> {
    match value {
        "captured" => Some(SccmCoverageState::Captured),
        "absent" => Some(SccmCoverageState::Absent),
        "accessDenied" => Some(SccmCoverageState::AccessDenied),
        "capped" => Some(SccmCoverageState::Capped),
        "skipped" => Some(SccmCoverageState::Skipped),
        "unsupported" => Some(SccmCoverageState::Unsupported),
        "parseFailed" => Some(SccmCoverageState::ParseFailed),
        _ => None,
    }
}

fn rotation(value: &Value) -> Option<SccmRotation> {
    match value["kind"].as_str()? {
        "current" if value.get("value").is_none() => Some(SccmRotation::Current),
        "lo_" if value.get("value").is_none() => Some(SccmRotation::LoUnderscore),
        "numbered" => value["value"]
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .map(SccmRotation::Numbered),
        "timestamped" => value["value"]
            .as_str()
            .map(str::to_owned)
            .map(SccmRotation::Timestamped),
        _ => None,
    }
}

fn object_has_only(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.keys().all(|field| fields.contains(&field.as_str())))
}

fn parse_fixture_fields(message: &str) -> Result<BTreeMap<String, String>, String> {
    let message = message
        .strip_prefix("[sccm-public-message-v1] ")
        .ok_or_else(|| "record lacks the public SCCM projection".to_owned())?;
    let mut segments = message.split(';').map(str::trim);
    if segments.next() != Some("SYNTHETIC FIXTURE") {
        return Err("record lacks the semantic synthetic marker".to_owned());
    }
    let allowed = [
        "Phase",
        "Disposition",
        "Terminal",
        "RequestId",
        "OperationHandle",
        "EndpointId",
        "Layer",
        "ProfileId",
        "CallerHandle",
        "QueryHandle",
        "Authorization",
    ];
    let mut fields = BTreeMap::new();
    for segment in segments {
        if segment.starts_with("[redacted:") && segment.ends_with(']') {
            continue;
        }
        let (name, value) = segment
            .split_once('=')
            .ok_or_else(|| format!("fixture field is not Name=Value: {segment}"))?;
        if !allowed.contains(&name) || value.is_empty() {
            return Err(format!("unsupported or empty fixture field {name}"));
        }
        if matches!(name, "CallerHandle" | "QueryHandle" | "Authorization") {
            if value != "[redacted:sccm-public-message-v1]" {
                return Err(format!("raw sensitive fixture field {name}"));
            }
            continue;
        }
        if fields.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate fixture field {name}"));
        }
    }
    Ok(fields)
}

fn normalized_records(
    scenario: &str,
    manifest: &Value,
) -> BTreeMap<(String, u32, u32), SccmEvidence> {
    let mut records = BTreeMap::new();
    for artifact in manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts are an array")
    {
        if artifact["diagnosticUse"] != "primary"
            || !matches!(
                artifact["captureState"].as_str(),
                Some("captured" | "capped")
            )
        {
            continue;
        }
        let artifact_id = artifact["artifactId"]
            .as_str()
            .expect("artifact ID is a string");
        let relative_path = artifact["relativePath"]
            .as_str()
            .expect("physical artifact has a relative path");
        let content = fs::read_to_string(corpus_root().join(scenario).join(relative_path))
            .expect("fixture evidence is readable UTF-8");
        let model = SccmArtifact {
            artifact_id: artifact_id.to_owned(),
            display_name: artifact["originalBasename"]
                .as_str()
                .expect("artifact basename is a string")
                .to_owned(),
            original_path: None,
            host: artifact["producerHostHandle"].as_str().map(str::to_owned),
            role: SccmRole::Provider,
            configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
            collected_at_utc: artifact["collectedUtc"].as_str().map(str::to_owned),
            rotation: rotation(&artifact["rotation"]).expect("rotation is valid"),
            coverage: coverage_state(artifact["captureState"].as_str().unwrap_or_default())
                .expect("coverage is valid"),
            encoding: artifact["encoding"].as_str().map(str::to_owned),
        };
        for record in normalize_ccm_artifact(model, &content) {
            let start = record
                .reference
                .line_start
                .expect("normalized evidence has a start line");
            let end = record
                .reference
                .line_end
                .expect("normalized evidence has an end line");
            assert!(
                records
                    .insert((artifact_id.to_owned(), start, end), record)
                    .is_none(),
                "{scenario}: duplicate logical evidence"
            );
        }
    }
    records
}

fn expected_transaction_ids(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "admin-service-auth-failure" => &[
            "adminService:66666666-6666-6666-6666-666666666666:safe-operation-admin-auth:admin-service-lab",
        ],
        "admin-service-backend-failure" => &[
            "adminService:77777777-7777-7777-7777-777777777777:safe-operation-admin-backend:admin-service-lab",
        ],
        "admin-service-success" => &[
            "adminService:55555555-5555-5555-5555-555555555555:safe-operation-admin-read:admin-service-lab",
        ],
        "contradictory-evidence" => &[
            "provider:dddddddd-dddd-dddd-dddd-dddddddddddd:safe-operation-contradictory:provider-local",
        ],
        "iis-supplemental" => &[
            "adminService:88888888-8888-8888-8888-888888888888:safe-operation-admin-iis:admin-service-lab",
        ],
        "incomplete" => &[
            "adminService:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:safe-operation-admin-incomplete:admin-service-lab",
        ],
        "privacy-redaction" => &[
            "adminService:99999999-9999-9999-9999-999999999999:safe-operation-admin-privacy:admin-service-lab",
            "provider:99999999-9999-9999-9999-999999999999:safe-operation-provider-privacy:provider-local",
        ],
        "provider-authz-denied" => &[
            "provider:22222222-2222-2222-2222-222222222222:safe-operation-update-device:provider-local",
        ],
        "provider-query-failure" => &[
            "provider:33333333-3333-3333-3333-333333333333:safe-operation-query-device:provider-local",
        ],
        "provider-retry" => &[
            "provider:cccccccc-cccc-cccc-cccc-cccccccccccc:safe-operation-provider-retry:provider-local",
        ],
        "provider-success" => &[
            "provider:11111111-1111-1111-1111-111111111111:safe-operation-read-device:provider-local",
        ],
        "provider-timeout" => &[
            "provider:44444444-4444-4444-4444-444444444444:safe-operation-provider-timeout:provider-local",
        ],
        "rotation-boundary" => &[],
        _ => &[],
    }
}

fn expected_outcomes(
    scenario: &str,
) -> &'static [(&'static str, &'static str, &'static str, &'static str)] {
    match scenario {
        "admin-service-auth-failure" | "admin-service-backend-failure" => {
            &[("failed", "confirmedFailure", "high", "high")]
        }
        "admin-service-success" | "iis-supplemental" | "provider-success" => {
            &[("succeeded", "success", "high", "high")]
        }
        "provider-retry" => &[("succeeded", "success", "high", "high")],
        "contradictory-evidence" => &[("incomplete", "insufficientEvidence", "low", "low")],
        "privacy-redaction" => &[
            ("succeeded", "success", "high", "high"),
            ("succeeded", "success", "high", "high"),
        ],
        "provider-authz-denied" | "provider-query-failure" => {
            &[("failed", "confirmedFailure", "high", "high")]
        }
        "provider-timeout" | "incomplete" => {
            &[("incomplete", "insufficientEvidence", "low", "low")]
        }
        "rotation-boundary" => &[],
        _ => &[],
    }
}

fn expected_public_summaries(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "admin-service-auth-failure" => &["Admin Service authentication was explicitly rejected."],
        "admin-service-backend-failure" => {
            &["Admin Service recorded an explicit backend operation failure."]
        }
        "admin-service-success" => {
            &["Admin Service request completed with explicit terminal evidence."]
        }
        "contradictory-evidence" => &[
            "Provider evidence contains contradictory terminal outcomes for one exact request key.",
        ],
        "iis-supplemental" => &["Admin Service evidence independently records a terminal success."],
        "incomplete" => {
            &["Admin Service evidence stops before an explicit response or terminal outcome."]
        }
        "privacy-redaction" => &[
            "Admin Service privacy fixture completed with redacted public evidence.",
            "Provider privacy fixture completed with redacted public evidence.",
        ],
        "provider-authz-denied" => &["Provider authorization was explicitly denied."],
        "provider-query-failure" => &["Provider operation recorded an explicit terminal failure."],
        "provider-retry" => &["Provider retry completed with explicit terminal recovery evidence."],
        "provider-success" => &["Provider operation completed with explicit terminal evidence."],
        "provider-timeout" => &["Provider evidence stops before an explicit terminal outcome."],
        "rotation-boundary" => &[],
        _ => &[],
    }
}

fn expected_artifact_ids(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "admin-service-auth-failure" => &["admin-auth-current"],
        "admin-service-backend-failure" => &["admin-backend-current"],
        "admin-service-success" => &["admin-success-current"],
        "contradictory-evidence" => &["contradictory-provider-current"],
        "iis-supplemental" => &["admin-iis-current", "iis-supplemental-current"],
        "incomplete" => &["incomplete-admin-current"],
        "privacy-redaction" => &["privacy-admin-current", "privacy-provider-current"],
        "provider-authz-denied" => &["provider-authz-current"],
        "provider-query-failure" => &["provider-query-current"],
        "provider-retry" => &["provider-retry-current"],
        "provider-success" => &["provider-success-current"],
        "provider-timeout" => &["provider-timeout-current"],
        "rotation-boundary" => &["rotation-01-current", "rotation-02-lo"],
        _ => &[],
    }
}

fn expected_observation_ids(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "admin-service-auth-failure" => &[
            "admin-auth-01-receive",
            "admin-auth-02-rejected",
            "admin-auth-03-outcome",
        ],
        "admin-service-backend-failure" => &[
            "admin-backend-01-receive",
            "admin-backend-02-authorize",
            "admin-backend-03-route",
            "admin-backend-04-execute",
            "admin-backend-05-outcome",
        ],
        "admin-service-success" => &[
            "admin-success-01-receive",
            "admin-success-02-authorize",
            "admin-success-03-route",
            "admin-success-04-backend",
            "admin-success-05-respond",
            "admin-success-06-outcome",
        ],
        "contradictory-evidence" => &[
            "contradictory-01-receive",
            "contradictory-02-authorize",
            "contradictory-03-execute",
            "contradictory-04-respond",
            "contradictory-05-success",
            "contradictory-06-failure",
        ],
        "iis-supplemental" => &[
            "admin-iis-01-receive",
            "admin-iis-02-route",
            "admin-iis-03-respond",
            "admin-iis-04-outcome",
        ],
        "incomplete" => &["incomplete-admin-01-receive", "incomplete-admin-02-route"],
        "privacy-redaction" => &[
            "privacy-admin-01-receive",
            "privacy-admin-02-outcome",
            "privacy-provider-01-receive",
            "privacy-provider-02-outcome",
        ],
        "provider-authz-denied" => &[
            "provider-authz-01-receive",
            "provider-authz-02-denied",
            "provider-authz-03-outcome",
        ],
        "provider-query-failure" => &[
            "provider-query-01-receive",
            "provider-query-02-authorize",
            "provider-query-03-execute",
            "provider-query-04-outcome",
        ],
        "provider-retry" => &[
            "provider-retry-01-receive",
            "provider-retry-02-authorize",
            "provider-retry-03-retryable",
            "provider-retry-04-recovered",
            "provider-retry-05-respond",
            "provider-retry-06-outcome",
        ],
        "provider-success" => &[
            "provider-success-01-receive",
            "provider-success-02-authorize",
            "provider-success-03-execute",
            "provider-success-04-respond",
            "provider-success-05-outcome",
        ],
        "provider-timeout" => &[
            "provider-timeout-01-receive",
            "provider-timeout-02-authorize",
            "provider-timeout-03-execute",
        ],
        "rotation-boundary" => &[],
        _ => &[],
    }
}

fn expected_source_local_ids(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "iis-supplemental" => &["iis-supplemental-01"],
        "privacy-redaction" => &["privacy-redaction-admin", "privacy-redaction-provider"],
        "rotation-boundary" => &["rotation-fragment-01"],
        _ => &[],
    }
}

fn expected_source_local_reasons(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "iis-supplemental" => &[
            "Scoped IIS evidence is optional context and cannot create an Admin Service transaction.",
        ],
        "privacy-redaction" => &[
            "Caller and endpoint details remain outside public keys and summaries.",
            "Caller, authorization, and query details remain outside public keys and summaries.",
        ],
        "rotation-boundary" => {
            &["Split rotation fragments and an unknown version cannot form an exact request key."]
        }
        _ => &[],
    }
}

fn expected_artifact_requests(scenario: &str) -> &'static [(&'static str, &'static str)] {
    match scenario {
        "incomplete" => &[(
            "server-admin-service",
            "Capture the bounded Admin Service source lineage for the exact request key and terminal outcome.",
        )],
        "provider-timeout" => &[(
            "server-provider",
            "Capture the bounded Provider source lineage for the exact request key and terminal outcome.",
        )],
        "contradictory-evidence" => &[(
            "server-provider",
            "Capture the bounded Provider source lineage for the exact request key and reconcile contradictory terminal outcomes.",
        )],
        "rotation-boundary" => &[(
            "server-provider",
            "Capture one bounded complete Provider rotation with known version provenance.",
        )],
        _ => &[],
    }
}

fn expected_profile_layers(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "admin-service-auth-failure"
        | "admin-service-backend-failure"
        | "admin-service-success"
        | "iis-supplemental"
        | "incomplete" => &["adminService"],
        "privacy-redaction" => &["adminService", "provider"],
        "provider-authz-denied"
        | "contradictory-evidence"
        | "provider-query-failure"
        | "provider-retry"
        | "provider-success"
        | "provider-timeout"
        | "rotation-boundary" => &["provider"],
        _ => &[],
    }
}

fn known_test_version(value: &str) -> bool {
    value
        .strip_prefix("5.00.TEST.")
        .is_some_and(|suffix| suffix.len() == 4 && suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

fn safe_version(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let segments = value.split('.').collect::<Vec<_>>();
    let digits =
        |segment: &str| !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit());
    match segments.as_slice() {
        ["IIS", "TEST", suffix] => suffix.len() == 4 && digits(suffix),
        [major, minor, "UNKNOWN"] => digits(major) && digits(minor),
        [major, minor, "TEST", suffix] => {
            digits(major) && digits(minor) && suffix.len() == 4 && digits(suffix)
        }
        [major, minor, build, revision] => {
            digits(major) && digits(minor) && digits(build) && digits(revision)
        }
        _ => false,
    }
}

fn state_chain(layer: &str) -> Option<&'static [&'static str]> {
    match layer {
        "provider" => Some(&PROVIDER_CHAIN),
        "adminService" => Some(&ADMIN_SERVICE_CHAIN),
        _ => None,
    }
}

fn profile_for(layer: &str) -> Option<&'static str> {
    match layer {
        "provider" => Some(PROVIDER_PROFILE),
        "adminService" => Some(ADMIN_SERVICE_PROFILE),
        _ => None,
    }
}

fn schema_failures(scenario: &str, manifest: &Value, expected: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    if !object_has_only(
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
    ) || manifest["sccmManifestVersion"] != 1
        || manifest["proposalOnly"] != true
        || manifest["syntheticFixture"] != true
        || manifest["scenario"] != scenario
        || !object_has_only(
            &manifest["bundle"],
            &["bundleRole", "workflow", "capturedUtc"],
        )
        || manifest["bundle"]["bundleRole"] != "server"
        || manifest["bundle"]["workflow"] != "providerAndAdminService"
        || DateTime::parse_from_rfc3339(
            manifest["bundle"]["capturedUtc"]
                .as_str()
                .unwrap_or_default(),
        )
        .is_err()
    {
        failures.push("manifest identity or bundle contract changed".to_owned());
    }

    if !object_has_only(
        &manifest["topology"],
        &["siteCode", "rolesObserved", "endpoints"],
    ) || manifest["topology"]["siteCode"] != "LAB"
    {
        failures.push("manifest topology contains an unsupported shape".to_owned());
    }
    let roles = manifest["topology"]["rolesObserved"].as_array();
    if roles.is_none_or(|roles| {
        roles.len() != 1 || roles.iter().any(|role| role.as_str() != Some("provider"))
    }) {
        failures.push("topology roles are not exact strings".to_owned());
    }

    let endpoints = manifest["topology"]["endpoints"].as_array();
    let mut endpoint_layers = BTreeMap::new();
    let mut endpoint_hosts = BTreeMap::new();
    let mut endpoint_ids = Vec::new();
    for endpoint in endpoints.into_iter().flatten() {
        if !object_has_only(
            endpoint,
            &["endpointId", "layer", "hostHandle", "producerRole"],
        ) {
            failures.push("endpoint contains unsupported fields".to_owned());
        }
        let Some(endpoint_id) = endpoint["endpointId"].as_str() else {
            failures.push("endpoint ID is not a string".to_owned());
            continue;
        };
        let Some(layer) = endpoint["layer"].as_str() else {
            failures.push(format!("{endpoint_id}: endpoint layer is not a string"));
            continue;
        };
        let host_handle = endpoint["hostHandle"].as_str();
        if !safe_endpoint_id(endpoint_id)
            || !matches!(layer, "provider" | "adminService")
            || endpoint["producerRole"] != "provider"
            || host_handle.is_none_or(|value| !safe_opaque_token(value, "safe:server:", 64))
            || endpoint_layers
                .insert(endpoint_id.to_owned(), layer.to_owned())
                .is_some()
        {
            failures.push(format!("{endpoint_id}: invalid endpoint topology"));
        }
        if let Some(host_handle) = host_handle {
            endpoint_hosts.insert(endpoint_id.to_owned(), host_handle.to_owned());
        }
        endpoint_ids.push(endpoint_id);
    }
    let mut sorted_endpoint_ids = endpoint_ids.clone();
    sorted_endpoint_ids.sort_unstable();
    sorted_endpoint_ids.dedup();
    if endpoints.is_none()
        || endpoint_ids.is_empty()
        || endpoint_ids != sorted_endpoint_ids
        || endpoint_layers.len() != endpoint_ids.len()
    {
        failures.push("endpoint identities are not exact sorted unique strings".to_owned());
    }

    let artifacts = manifest["artifacts"].as_array();
    let mut artifact_ids = Vec::new();
    let mut artifact_sources = BTreeMap::new();
    let mut artifact_physical_state = BTreeMap::new();
    let mut fingerprints = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    let mut sanitized_sources = BTreeSet::new();
    let mut artifact_endpoint_ids = BTreeSet::new();
    let mut physical_line_counts = BTreeMap::new();
    let mut artifact_rotation_provenance = BTreeMap::new();
    for artifact in artifacts.into_iter().flatten() {
        if !object_has_only(
            artifact,
            &[
                "artifactId",
                "sourceId",
                "producerRole",
                "layer",
                "producerHostHandle",
                "endpointId",
                "diagnosticUse",
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
        ) || !object_has_only(
            &artifact["rotation"],
            &["kind", "value", "lineageId", "fragmentComplete"],
        ) || artifact.get("collectionLimit").is_some()
            && !object_has_only(&artifact["collectionLimit"], &["byteLimit", "limitApplied"])
        {
            failures.push("artifact contains unsupported fields".to_owned());
        }
        let Some(artifact_id) = artifact["artifactId"].as_str() else {
            failures.push("artifact ID is not a string".to_owned());
            continue;
        };
        if artifact_id.is_empty() {
            failures.push("artifact ID is empty".to_owned());
        }
        artifact_ids.push(artifact_id);
        let source_id = artifact["sourceId"].as_str();
        let layer = artifact["layer"].as_str();
        let basename = artifact["originalBasename"].as_str();
        let diagnostic_use = artifact["diagnosticUse"].as_str();
        let endpoint_id = artifact["endpointId"].as_str();
        let producer_host = artifact["producerHostHandle"].as_str();
        let sanitized_source_path = artifact["sanitizedSourcePath"].as_str();
        let path_fingerprint = artifact["pathFingerprint"].as_str();
        let source_tuple = (layer, source_id, basename, diagnostic_use);
        if !matches!(
            source_tuple,
            (
                Some("provider"),
                Some("server-provider"),
                Some("Smsprov.log"),
                Some("primary")
            ) | (
                Some("adminService"),
                Some("server-admin-service"),
                Some("AdminService.log"),
                Some("primary")
            ) | (
                Some("supplementalIis"),
                Some("server-admin-service-iis"),
                Some("u_ex_synthetic.log"),
                Some("supplementalOnly")
            )
        ) {
            failures.push(format!("{artifact_id}: unsupported source/layer tuple"));
        }
        if artifact["producerRole"] != "provider"
            || producer_host.is_none_or(|value| !safe_opaque_token(value, "safe:server:", 64))
            || endpoint_id
                .and_then(|id| endpoint_hosts.get(id))
                .map(String::as_str)
                != producer_host
            || DateTime::parse_from_rfc3339(artifact["collectedUtc"].as_str().unwrap_or_default())
                .is_err()
            || sanitized_source_path
                != expected_sanitized_source_path(source_id, &artifact["rotation"])
            || sanitized_source_path
                .map(str::to_ascii_lowercase)
                .is_none_or(|value| !sanitized_sources.insert(value))
            || path_fingerprint.is_none_or(|value| !safe_opaque_token(value, "synthetic:", 96))
            || path_fingerprint
                .map(str::to_ascii_lowercase)
                .is_none_or(|value| !fingerprints.insert(value))
            || rotation(&artifact["rotation"]).is_none()
            || artifact["rotation"]["lineageId"]
                .as_str()
                .is_none_or(|value| !safe_synthetic_lineage(value))
            || coverage_state(artifact["captureState"].as_str().unwrap_or_default()).is_none()
        {
            failures.push(format!("{artifact_id}: invalid typed provenance"));
        }
        if let Some(endpoint_id) = endpoint_id {
            artifact_endpoint_ids.insert(endpoint_id);
        }
        let expected_endpoint_layer = endpoint_id.and_then(|id| endpoint_layers.get(id));
        let endpoint_matches = match layer {
            Some("supplementalIis") => {
                expected_endpoint_layer.map(String::as_str) == Some("adminService")
            }
            Some(layer) => expected_endpoint_layer.map(String::as_str) == Some(layer),
            None => false,
        };
        if !endpoint_matches {
            failures.push(format!("{artifact_id}: incompatible endpoint topology"));
        }
        let state = artifact["captureState"].as_str();
        match state {
            Some("captured" | "capped" | "parseFailed") => {
                let relative_path = artifact["relativePath"].as_str();
                let byte_limit = artifact["collectionLimit"]["byteLimit"].as_u64();
                let limit_applied = artifact["collectionLimit"]["limitApplied"].as_bool();
                let bytes_copied = artifact["bytesCopied"].as_u64();
                let limit_matches_state = match state {
                    Some("captured") => limit_applied == Some(false),
                    Some("capped") => {
                        limit_applied == Some(true)
                            && bytes_copied.is_some()
                            && bytes_copied == byte_limit
                    }
                    Some("parseFailed") => limit_applied == Some(false),
                    _ => false,
                };
                if relative_path.is_none_or(|value| !safe_segmented_path(value, "evidence/"))
                    || relative_path
                        != expected_relative_path(source_id, endpoint_id, &artifact["rotation"])
                            .as_deref()
                    || relative_path
                        .map(str::to_ascii_lowercase)
                        .is_none_or(|value| !destinations.insert(value))
                    || bytes_copied.is_none()
                    || artifact["encoding"] != "utf-8"
                    || byte_limit.is_none_or(|limit| limit == 0)
                    || bytes_copied
                        .zip(byte_limit)
                        .is_none_or(|(copied, limit)| copied > limit)
                    || !limit_matches_state
                    || artifact["rotation"]["fragmentComplete"].as_bool().is_none()
                    || artifact["sourceVersion"]
                        .as_str()
                        .is_none_or(|value| !safe_version(value))
                {
                    failures.push(format!("{artifact_id}: invalid physical provenance"));
                }
                if let Some(line_count) =
                    relative_path.and_then(|path| physical_line_count(scenario, path))
                {
                    physical_line_counts.insert(artifact_id.to_owned(), line_count);
                }
            }
            Some("absent" | "accessDenied" | "skipped" | "unsupported") => {
                if artifact.get("relativePath").is_some()
                    || artifact.get("bytesCopied").is_some()
                    || artifact.get("encoding").is_some()
                    || artifact.get("collectionLimit").is_some()
                    || artifact["rotation"].get("fragmentComplete").is_some()
                {
                    failures.push(format!(
                        "{artifact_id}: nonphysical coverage invents file provenance"
                    ));
                }
            }
            _ => {}
        }
        if let (Some(source_id), Some(layer)) = (source_id, layer) {
            artifact_sources.insert(
                artifact_id.to_owned(),
                (source_id.to_owned(), layer.to_owned()),
            );
        }
        if let (
            Some(source_id),
            Some(endpoint_id),
            Some(producer_host),
            Some(lineage_id),
            Some(kind),
        ) = (
            source_id,
            endpoint_id,
            producer_host,
            artifact["rotation"]["lineageId"].as_str(),
            artifact["rotation"]["kind"].as_str(),
        ) {
            artifact_rotation_provenance.insert(
                artifact_id.to_owned(),
                (
                    source_id.to_owned(),
                    endpoint_id.to_owned(),
                    producer_host.to_owned(),
                    lineage_id.to_owned(),
                    kind.to_owned(),
                ),
            );
        }
        artifact_physical_state.insert(
            artifact_id.to_owned(),
            (
                state.unwrap_or_default().to_owned(),
                artifact["rotation"]["fragmentComplete"].as_bool(),
            ),
        );
    }
    let mut sorted_artifact_ids = artifact_ids.clone();
    sorted_artifact_ids.sort_unstable();
    sorted_artifact_ids.dedup();
    if artifacts.is_none()
        || artifact_ids.is_empty()
        || artifact_ids != sorted_artifact_ids
        || artifact_ids != expected_artifact_ids(scenario)
        || artifact_sources.len() != artifact_ids.len()
        || artifact_endpoint_ids != endpoint_ids.iter().copied().collect::<BTreeSet<_>>()
    {
        failures.push("artifact IDs are not exact sorted unique strings".to_owned());
    }

    if !object_has_only(
        expected,
        &[
            "contractState",
            "workflow",
            "scenario",
            "profiles",
            "coverage",
            "transactions",
            "sourceLocalObservations",
            "artifactRequests",
            "crossSideCausalClaims",
        ],
    ) || expected["contractState"] != "proposedPendingReviewed318And335"
        || expected["workflow"] != "providerAndAdminService"
        || expected["scenario"] != scenario
        || expected["crossSideCausalClaims"] != Value::Array(Vec::new())
    {
        failures.push("expected output loses its preparation boundary".to_owned());
    }
    if exported_projection_contains_private_shape(manifest)
        || exported_projection_contains_private_shape(expected)
    {
        failures.push("exported projection contains a private raw shape".to_owned());
    }

    let profiles = expected["profiles"].as_array();
    let mut profile_layers = Vec::new();
    for profile in profiles.into_iter().flatten() {
        if !object_has_only(profile, &["layer", "selectionState", "profileId"]) {
            failures.push("profile contains unsupported fields".to_owned());
        }
        let layer = profile["layer"].as_str();
        let selection = profile["selectionState"].as_str();
        let profile_id = profile["profileId"].as_str();
        let versions = manifest["artifacts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|artifact| {
                artifact["layer"].as_str() == layer && artifact["diagnosticUse"] == "primary"
            })
            .filter_map(|artifact| artifact["sourceVersion"].as_str())
            .collect::<Vec<_>>();
        let versions_are_known =
            !versions.is_empty() && versions.iter().all(|version| known_test_version(version));
        let versions_are_unknown = !versions.is_empty() && !versions_are_known;
        if layer.is_none()
            || !matches!(selection, Some("selectedSynthetic" | "unknownVersion"))
            || match selection {
                Some("selectedSynthetic") => {
                    layer.and_then(profile_for) != profile_id || !versions_are_known
                }
                Some("unknownVersion") => profile_id.is_some() || !versions_are_unknown,
                _ => true,
            }
        {
            failures.push("profile selection is not exact and versioned".to_owned());
        }
        if let Some(layer) = layer {
            profile_layers.push(layer);
        }
    }
    let mut sorted_profile_layers = profile_layers.clone();
    sorted_profile_layers.sort_unstable();
    sorted_profile_layers.dedup();
    if profiles.is_none()
        || profile_layers.is_empty()
        || profile_layers != sorted_profile_layers
        || profile_layers != expected_profile_layers(scenario)
        || profile_layers
            .iter()
            .any(|layer| !matches!(*layer, "provider" | "adminService" | "supplementalIis"))
    {
        failures.push("profile layers are not exact sorted unique strings".to_owned());
    }

    let coverage = expected["coverage"].as_array();
    let mut coverage_projection = Vec::new();
    for row in coverage.into_iter().flatten() {
        if !object_has_only(row, &["artifactId", "state", "sourceId", "layer"]) {
            failures.push("coverage row contains unsupported fields".to_owned());
        }
        let artifact_id = row["artifactId"].as_str();
        let state = row["state"].as_str();
        let source_id = row["sourceId"].as_str();
        let layer = row["layer"].as_str();
        if artifact_id.is_none()
            || state.and_then(coverage_state).is_none()
            || artifact_id
                .and_then(|id| artifact_sources.get(id))
                .is_none_or(|(expected_source, expected_layer)| {
                    Some(expected_source.as_str()) != source_id
                        || Some(expected_layer.as_str()) != layer
                })
        {
            failures.push("coverage row is not bound to a manifest artifact".to_owned());
        }
        if let Some(artifact_id) = artifact_id {
            coverage_projection.push(artifact_id);
        }
    }
    let manifest_coverage = manifest["artifacts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|artifact| {
            Some((
                artifact["artifactId"].as_str()?,
                artifact["captureState"].as_str()?,
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let expected_coverage = coverage
        .into_iter()
        .flatten()
        .filter_map(|row| Some((row["artifactId"].as_str()?, row["state"].as_str()?)))
        .collect::<BTreeMap<_, _>>();
    if coverage.is_none()
        || coverage_projection != artifact_ids
        || manifest_coverage != expected_coverage
    {
        failures.push("coverage is not the exact sorted manifest projection".to_owned());
    }

    let transactions = expected["transactions"].as_array();
    let mut transaction_ids = Vec::new();
    let mut all_observation_ids = Vec::new();
    let mut outcomes = Vec::new();
    let mut public_summaries = Vec::new();
    for transaction in transactions.into_iter().flatten() {
        if !object_has_only(
            transaction,
            &[
                "transactionId",
                "layer",
                "key",
                "topologyCompatibility",
                "timestampOrdering",
                "state",
                "classification",
                "confidence",
                "confidenceCeiling",
                "terminalEvidence",
                "coverageGapArtifactIds",
                "publicSummary",
                "observations",
            ],
        ) || !object_has_only(
            &transaction["key"],
            &[
                "requestId",
                "operationHandle",
                "endpointId",
                "confidence",
                "extractionProfileId",
            ],
        ) {
            failures.push("transaction contains unsupported fields".to_owned());
        }
        let transaction_id = transaction["transactionId"].as_str().unwrap_or_default();
        transaction_ids.push(transaction_id);
        outcomes.push((
            transaction["state"].as_str().unwrap_or_default(),
            transaction["classification"].as_str().unwrap_or_default(),
            transaction["confidence"].as_str().unwrap_or_default(),
            transaction["confidenceCeiling"]
                .as_str()
                .unwrap_or_default(),
        ));
        public_summaries.push(transaction["publicSummary"].as_str().unwrap_or_default());
        let layer = transaction["layer"].as_str().unwrap_or_default();
        let key = &transaction["key"];
        let request_id = key["requestId"].as_str();
        let operation = key["operationHandle"].as_str();
        let endpoint_id = key["endpointId"].as_str();
        let derived_id = format!(
            "{layer}:{}:{}:{}",
            request_id.unwrap_or_default().to_ascii_lowercase(),
            operation.unwrap_or_default(),
            endpoint_id.unwrap_or_default()
        );
        if state_chain(layer).is_none()
            || request_id.is_none_or(str::is_empty)
            || operation.is_none_or(|value| !value.starts_with("safe-operation-"))
            || endpoint_id.is_none_or(str::is_empty)
            || key["confidence"] != "exact"
            || key["extractionProfileId"].as_str() != profile_for(layer)
            || transaction_id != derived_id
            || endpoint_id
                .and_then(|id| endpoint_layers.get(id))
                .map(String::as_str)
                != Some(layer)
            || transaction["topologyCompatibility"] != "exact"
            || !matches!(
                transaction["timestampOrdering"].as_str(),
                Some("usable" | "unusableInvalidOffset")
            )
            || !matches!(
                transaction["confidenceCeiling"].as_str(),
                Some("high" | "medium" | "low")
            )
        {
            failures.push("transaction identity/key/topology is not exact".to_owned());
        }
        let gap_values = transaction["coverageGapArtifactIds"].as_array();
        let gap_ids = gap_values
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut sorted_gap_ids = gap_ids.clone();
        sorted_gap_ids.sort_unstable();
        sorted_gap_ids.dedup();
        if gap_values.is_none_or(|values| values.len() != gap_ids.len())
            || gap_ids != sorted_gap_ids
            || gap_ids.iter().any(|id| !artifact_sources.contains_key(*id))
        {
            failures.push("coverage gaps are not exact sorted manifest artifact IDs".to_owned());
        }
        if transaction["confidence"] == "high"
            && (transaction["confidenceCeiling"] != "high"
                || transaction["timestampOrdering"] != "usable"
                || transaction["terminalEvidence"] != true
                || !gap_ids.is_empty())
        {
            failures.push("high confidence bypasses time/terminal/coverage gates".to_owned());
        }
        let evidence_confidence_ceiling = if transaction["timestampOrdering"] == "usable"
            && transaction["terminalEvidence"] == true
            && gap_ids.is_empty()
            && transaction["state"] != "incomplete"
        {
            "high"
        } else {
            "low"
        };
        if transaction["confidenceCeiling"] != evidence_confidence_ceiling {
            failures.push(
                "confidence ceiling diverges from time/terminal/coverage/completeness gates"
                    .to_owned(),
            );
        }
        if transaction["publicSummary"].as_str().is_none_or(|summary| {
            summary.is_empty()
                || [
                    "@",
                    "bearer",
                    "select ",
                    "http://",
                    "https://",
                    "/adminservice",
                ]
                .iter()
                .any(|term| summary.to_ascii_lowercase().contains(term))
        }) {
            failures.push("public transaction summary is unsafe or empty".to_owned());
        }

        let observations = transaction["observations"].as_array();
        let mut observation_ids = Vec::new();
        let mut prior_phase = 0usize;
        let mut cited_terminal = false;
        let mut terminal_dispositions = BTreeSet::new();
        let mut phase_dispositions = Vec::new();
        let mut cited_references = BTreeSet::new();
        for observation in observations.into_iter().flatten() {
            if !object_has_only(
                observation,
                &[
                    "observationId",
                    "phase",
                    "disposition",
                    "terminal",
                    "evidence",
                ],
            ) {
                failures.push("transaction observation contains unsupported fields".to_owned());
            }
            let observation_id = observation["observationId"].as_str();
            let phase = observation["phase"].as_str();
            let disposition = observation["disposition"].as_str();
            let chain = state_chain(layer).unwrap_or_default();
            let phase_index = phase.and_then(|phase| chain.iter().position(|item| *item == phase));
            if observation_id.is_none_or(str::is_empty)
                || phase_index.is_none()
                || phase_index.is_some_and(|index| index < prior_phase)
                || !matches!(
                    disposition,
                    Some("succeeded" | "failed" | "retryableFailure" | "pending")
                )
                || observation["terminal"].as_bool().is_none()
            {
                failures.push("transaction observation is not exact/monotonic".to_owned());
            }
            if let Some(index) = phase_index {
                prior_phase = index;
            }
            let terminal = observation["terminal"].as_bool().unwrap_or(false);
            if terminal && phase != Some("recordOutcome") {
                failures.push(
                    "terminal evidence is not bound to the source-specific outcome phase"
                        .to_owned(),
                );
            }
            if terminal && phase == Some("recordOutcome") {
                cited_terminal = true;
                if let Some(disposition) = observation["disposition"].as_str() {
                    terminal_dispositions.insert(disposition);
                }
            }
            if let (Some(phase), Some(disposition)) = (phase, disposition) {
                phase_dispositions.push((phase, disposition, terminal));
            }
            if let Some(observation_id) = observation_id {
                observation_ids.push(observation_id);
                all_observation_ids.push(observation_id);
            }
            let references = observation["evidence"].as_array();
            if references.is_none_or(Vec::is_empty) {
                failures.push("transaction observation lacks cited evidence".to_owned());
            }
            for reference in references.into_iter().flatten() {
                let start = reference["startLine"]
                    .as_u64()
                    .and_then(|line| u32::try_from(line).ok());
                let end = reference["endLine"]
                    .as_u64()
                    .and_then(|line| u32::try_from(line).ok());
                let physical_range_is_valid = reference["artifactId"]
                    .as_str()
                    .zip(start)
                    .zip(end)
                    .is_some_and(|((artifact_id, start), end)| {
                        start > 0
                            && end >= start
                            && physical_line_counts
                                .get(artifact_id)
                                .is_some_and(|line_count| u64::from(end) <= *line_count)
                    });
                if !object_has_only(reference, &["artifactId", "startLine", "endLine"])
                    || reference["artifactId"]
                        .as_str()
                        .is_none_or(|id| !artifact_sources.contains_key(id))
                    || reference["artifactId"].as_str().is_some_and(|id| {
                        artifact_sources
                            .get(id)
                            .is_none_or(|(_, artifact_layer)| artifact_layer != layer)
                    })
                    || reference["artifactId"].as_str().is_some_and(|id| {
                        artifact_physical_state
                            .get(id)
                            .is_none_or(|(state, complete)| {
                                state != "captured" || *complete != Some(true)
                            })
                    })
                    || !physical_range_is_valid
                {
                    failures.push("transaction evidence reference is malformed".to_owned());
                }
                if let (Some(artifact_id), Some(start), Some(end)) =
                    (reference["artifactId"].as_str(), start, end)
                {
                    if !cited_references.insert((artifact_id, start, end)) {
                        failures.push("transaction evidence reference is duplicated".to_owned());
                    }
                }
            }
        }
        let mut sorted_observation_ids = observation_ids.clone();
        sorted_observation_ids.sort_unstable();
        sorted_observation_ids.dedup();
        if observations.is_none()
            || observation_ids.is_empty()
            || observation_ids != sorted_observation_ids
        {
            failures
                .push("transaction observation identities are not sorted and unique".to_owned());
        }
        if transaction["terminalEvidence"].as_bool() != Some(cited_terminal) {
            failures.push("transaction terminality is not citation-derived".to_owned());
        }
        let terminal_outcome_matches = match transaction["state"].as_str() {
            Some("succeeded") => {
                terminal_dispositions == BTreeSet::from(["succeeded"])
                    && transaction["classification"] == "success"
            }
            Some("failed") => {
                terminal_dispositions == BTreeSet::from(["failed"])
                    && transaction["classification"] == "confirmedFailure"
            }
            Some("incomplete") if cited_terminal => {
                terminal_dispositions.len() > 1
                    && transaction["classification"] == "insufficientEvidence"
            }
            Some("incomplete") => {
                terminal_dispositions.is_empty()
                    && transaction["classification"] == "insufficientEvidence"
            }
            _ => false,
        };
        if !terminal_outcome_matches {
            failures.push(
                "terminal outcome disposition does not agree with conservative state/classification"
                    .to_owned(),
            );
        }
        if phase_dispositions
            .iter()
            .any(|(_, disposition, terminal)| *disposition == "failed" && !terminal)
            && transaction["state"] != "failed"
        {
            failures.push("nonterminal failure does not agree with the declared state".to_owned());
        }
        if phase_dispositions.iter().any(|(_, disposition, terminal)| {
            *disposition == "retryableFailure" && (scenario != "provider-retry" || *terminal)
        }) {
            failures.push("retryable failure is outside the closed recovery contract".to_owned());
        }
        if phase_dispositions.iter().any(|(_, disposition, terminal)| {
            *disposition == "pending"
                && (*terminal || transaction["state"].as_str() != Some("incomplete"))
        }) {
            failures.push("pending disposition is outside an incomplete transaction".to_owned());
        }
        if scenario == "provider-retry" {
            let retry_sequence = phase_dispositions
                .iter()
                .filter_map(|(phase, disposition, _)| {
                    (*phase == "executeProviderOperation").then_some(*disposition)
                })
                .collect::<Vec<_>>();
            if retry_sequence != ["retryableFailure", "succeeded"] {
                failures.push(
                    "provider retry lacks one explicit retryable failure followed by recovery"
                        .to_owned(),
                );
            }
        }
    }
    let mut sorted_transaction_ids = transaction_ids.clone();
    sorted_transaction_ids.sort_unstable();
    sorted_transaction_ids.dedup();
    if transactions.is_none()
        || transaction_ids != sorted_transaction_ids
        || transaction_ids != expected_transaction_ids(scenario)
        || all_observation_ids != expected_observation_ids(scenario)
        || outcomes != expected_outcomes(scenario)
        || public_summaries != expected_public_summaries(scenario)
    {
        failures.push("transaction identity/cardinality matrix changed".to_owned());
    }

    let source_local = expected["sourceLocalObservations"].as_array();
    let mut source_local_ids = Vec::new();
    let mut source_local_reasons = Vec::new();
    for observation in source_local.into_iter().flatten() {
        if !object_has_only(
            observation,
            &[
                "observationId",
                "kind",
                "layer",
                "reason",
                "correlationEligible",
                "evidence",
            ],
        ) || !matches!(
            observation["kind"].as_str(),
            Some("supplementalOnly" | "privacyRedacted" | "rotationFragment")
        ) || !matches!(
            observation["layer"].as_str(),
            Some("provider" | "adminService" | "supplementalIis")
        ) || observation["reason"].as_str().is_none_or(str::is_empty)
            || observation["correlationEligible"] != false
        {
            failures.push("source-local observation is not closed and noncorrelatable".to_owned());
        }
        if let Some(reason) = observation["reason"].as_str() {
            source_local_reasons.push(reason);
        }
        if let Some(id) = observation["observationId"].as_str() {
            if id.is_empty() {
                failures.push("source-local observation ID is empty".to_owned());
            }
            source_local_ids.push(id);
        } else {
            failures.push("source-local observation ID is not a string".to_owned());
        }
        let references = observation["evidence"].as_array();
        if references.is_none_or(Vec::is_empty) {
            failures.push("source-local observation lacks evidence".to_owned());
        }
        let mut cited_references = BTreeSet::new();
        let mut cited_artifact_ids = Vec::new();
        for reference in references.into_iter().flatten() {
            let artifact_id = reference["artifactId"].as_str();
            let start = reference["startLine"].as_u64();
            let end = reference["endLine"].as_u64();
            let physical_range_is_valid =
                artifact_id
                    .zip(start)
                    .zip(end)
                    .is_some_and(|((artifact_id, start), end)| {
                        start > 0
                            && end >= start
                            && physical_line_counts
                                .get(artifact_id)
                                .is_some_and(|line_count| end <= *line_count)
                    });
            if !object_has_only(reference, &["artifactId", "startLine", "endLine"])
                || artifact_id.is_none_or(|id| !artifact_sources.contains_key(id))
                || artifact_id.is_some_and(|id| {
                    let observation_layer = observation["layer"].as_str().unwrap_or_default();
                    artifact_sources
                        .get(id)
                        .is_none_or(|(_, artifact_layer)| artifact_layer != observation_layer)
                })
                || !physical_range_is_valid
            {
                failures.push("source-local evidence reference is malformed".to_owned());
            }
            if let (Some(artifact_id), Some(start), Some(end)) = (artifact_id, start, end) {
                cited_artifact_ids.push(artifact_id);
                if !cited_references.insert((artifact_id, start, end)) {
                    failures.push("source-local evidence reference is duplicated".to_owned());
                }
            }
        }
        if observation["kind"] == "rotationFragment" {
            let mut shared_lineage = BTreeSet::new();
            let mut rotation_kinds = BTreeSet::new();
            for artifact_id in &cited_artifact_ids {
                if let Some((source_id, endpoint_id, host, lineage_id, kind)) =
                    artifact_rotation_provenance.get(*artifact_id)
                {
                    shared_lineage.insert((source_id, endpoint_id, host, lineage_id));
                    rotation_kinds.insert(kind.as_str());
                }
            }
            if cited_artifact_ids.len() != 2
                || shared_lineage.len() != 1
                || rotation_kinds.len() != 2
                || !rotation_kinds.contains("current")
                || !rotation_kinds.contains("lo_")
            {
                failures.push(
                    "split rotation evidence does not share source/endpoint/host/lineage"
                        .to_owned(),
                );
            }
        }
    }
    let mut sorted_source_local_ids = source_local_ids.clone();
    sorted_source_local_ids.sort_unstable();
    sorted_source_local_ids.dedup();
    if source_local.is_none()
        || source_local_ids != sorted_source_local_ids
        || source_local_ids != expected_source_local_ids(scenario)
        || source_local_reasons != expected_source_local_reasons(scenario)
    {
        failures.push("source-local observation IDs are not sorted and unique".to_owned());
    }

    let requests = expected["artifactRequests"].as_array();
    let mut requested_artifacts = Vec::new();
    for request in requests.into_iter().flatten() {
        if !object_has_only(request, &["logicalArtifactId", "reason"])
            || !matches!(
                request["logicalArtifactId"].as_str(),
                Some("server-provider" | "server-admin-service" | "server-admin-service-iis")
            )
            || request["reason"].as_str().is_none_or(str::is_empty)
        {
            failures.push("artifact request is not exact and bounded".to_owned());
        }
        if let (Some(source), Some(reason)) = (
            request["logicalArtifactId"].as_str(),
            request["reason"].as_str(),
        ) {
            requested_artifacts.push((source, reason));
        }
    }
    let mut sorted_requested_artifacts = requested_artifacts.clone();
    sorted_requested_artifacts.sort_unstable();
    sorted_requested_artifacts.dedup();
    if requests.is_none()
        || requested_artifacts != sorted_requested_artifacts
        || requested_artifacts != expected_artifact_requests(scenario)
    {
        failures.push("artifact requests are not exact sorted bounded contracts".to_owned());
    }

    failures
}

fn schema_failures_with_records(
    scenario: &str,
    manifest: &Value,
    expected: &Value,
    records: &BTreeMap<(String, u32, u32), SccmEvidence>,
) -> Vec<String> {
    let mut failures = schema_failures(scenario, manifest, expected);
    failures.extend(uncited_transaction_record_failures(expected, records));
    failures
}

fn uncited_transaction_record_failures(
    expected: &Value,
    records: &BTreeMap<(String, u32, u32), SccmEvidence>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for transaction in expected["transactions"].as_array().into_iter().flatten() {
        let layer = transaction["layer"].as_str();
        let key = &transaction["key"];
        let cited = transaction["observations"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|observation| observation["evidence"].as_array().into_iter().flatten())
            .filter_map(|reference| {
                Some((
                    reference["artifactId"].as_str()?.to_owned(),
                    u32::try_from(reference["startLine"].as_u64()?).ok()?,
                    u32::try_from(reference["endLine"].as_u64()?).ok()?,
                ))
            })
            .collect::<BTreeSet<_>>();

        for (record_key, record) in records {
            let Ok(fields) = parse_fixture_fields(&record.message) else {
                continue;
            };
            let matches_exact_key = [
                ("RequestId", key["requestId"].as_str()),
                ("OperationHandle", key["operationHandle"].as_str()),
                ("EndpointId", key["endpointId"].as_str()),
                ("Layer", layer),
                ("ProfileId", key["extractionProfileId"].as_str()),
            ]
            .iter()
            .all(|(field, value)| fields.get(*field).map(String::as_str) == *value);
            if matches_exact_key && !cited.contains(record_key) {
                failures.push(format!(
                    "{}: admitted exact-key logical record {}:{}-{} is uncited",
                    transaction["transactionId"].as_str().unwrap_or("<invalid>"),
                    record_key.0,
                    record_key.1,
                    record_key.2
                ));
            }
        }
    }
    failures
}

#[test]
fn provider_and_admin_service_scenario_matrix_is_exact() {
    let actual = actual_scenarios().expect("provider/Admin Service fixture root exists");
    let expected = SCENARIOS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();

    assert_eq!(actual, expected);
}

#[test]
fn provider_and_admin_service_sources_are_layered_and_role_exact() {
    let provider = classify_artifact_name("Smsprov.log", SccmRole::Provider);
    assert_eq!(provider.family, SccmArtifactFamily::Provider);
    assert!(provider.uses_ccm_records);
    assert!(provider.supported_for_diagnosis);

    let admin_service = classify_artifact_name("AdminService.log", SccmRole::Provider);
    assert_eq!(admin_service.family, SccmArtifactFamily::AdminService);
    assert!(admin_service.uses_ccm_records);
    assert!(admin_service.supported_for_diagnosis);

    for role in [
        SccmRole::SiteServer,
        SccmRole::ManagementPoint,
        SccmRole::AdminService,
    ] {
        let wrong_provider = classify_artifact_name("Smsprov.log", role.clone());
        let wrong_admin = classify_artifact_name("AdminService.log", role);
        assert!(matches!(
            wrong_provider.family,
            SccmArtifactFamily::Unknown(_)
        ));
        assert!(!wrong_provider.supported_for_diagnosis);
        assert!(matches!(wrong_admin.family, SccmArtifactFamily::Unknown(_)));
        assert!(!wrong_admin.supported_for_diagnosis);
    }

    let iis = classify_artifact_name("u_ex_synthetic.log", SccmRole::Provider);
    assert!(matches!(iis.family, SccmArtifactFamily::Unknown(_)));
    assert!(!iis.uses_ccm_records);
    assert!(!iis.supported_for_diagnosis);
}

#[test]
fn provider_and_admin_service_contracts_are_closed_and_coverage_exact() {
    let mut failures = Vec::new();
    for scenario in SCENARIOS {
        let manifest =
            read_json(scenario, "manifest.json").unwrap_or_else(|error| panic!("{error}"));
        let expected =
            read_json(scenario, "expected.json").unwrap_or_else(|error| panic!("{error}"));
        for failure in schema_failures(scenario, &manifest, &expected) {
            failures.push(format!("{scenario}: {failure}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn physical_evidence_is_synthetic_bounded_and_byte_exact() {
    let mut failures = Vec::new();
    for scenario in SCENARIOS {
        let manifest =
            read_json(scenario, "manifest.json").unwrap_or_else(|error| panic!("{error}"));
        for artifact in manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
        {
            let Some(relative_path) = artifact["relativePath"].as_str() else {
                continue;
            };
            let artifact_id = artifact["artifactId"].as_str().unwrap_or("<invalid>");
            let path = corpus_root().join(scenario).join(relative_path);
            let content = match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(error) => {
                    failures.push(format!("{scenario}/{artifact_id}: {error}"));
                    continue;
                }
            };
            if artifact["bytesCopied"].as_u64() != Some(content.len() as u64) {
                failures.push(format!(
                    "{scenario}/{artifact_id}: bytesCopied does not match physical bytes"
                ));
            }
            if content.is_empty()
                || !content.contains("SYNTHETIC")
                || content.contains("C:\\")
                || content.contains("\\\\")
                || content.contains(".local")
                || content.contains(".com")
            {
                failures.push(format!(
                    "{scenario}/{artifact_id}: evidence is empty or not safely synthetic"
                ));
            }
            let byte_limit = artifact["collectionLimit"]["byteLimit"]
                .as_u64()
                .unwrap_or_default();
            if content.len() as u64 > byte_limit {
                failures.push(format!(
                    "{scenario}/{artifact_id}: evidence exceeds collection cap"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn request_transactions_are_exact_cited_ordered_and_layer_local() {
    let mut failures = Vec::new();
    for scenario in SCENARIOS {
        let manifest =
            read_json(scenario, "manifest.json").unwrap_or_else(|error| panic!("{error}"));
        let expected =
            read_json(scenario, "expected.json").unwrap_or_else(|error| panic!("{error}"));
        let records = normalized_records(scenario, &manifest);
        let artifact_layers = manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
            .iter()
            .filter_map(|artifact| {
                Some((
                    artifact["artifactId"].as_str()?.to_owned(),
                    artifact["layer"].as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeMap<_, _>>();

        let transactions = expected["transactions"]
            .as_array()
            .expect("transactions are an array");
        let outcomes = transactions
            .iter()
            .map(|transaction| {
                (
                    transaction["state"].as_str().unwrap_or_default(),
                    transaction["classification"].as_str().unwrap_or_default(),
                    transaction["confidence"].as_str().unwrap_or_default(),
                    transaction["confidenceCeiling"]
                        .as_str()
                        .unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        if outcomes != expected_outcomes(scenario) {
            failures.push(format!("{scenario}: outcome matrix changed"));
        }

        for transaction in transactions {
            let transaction_id = transaction["transactionId"].as_str().unwrap_or("<invalid>");
            let layer = transaction["layer"].as_str().unwrap_or_default();
            let key = &transaction["key"];
            let mut prior_utc = i64::MIN;
            let mut cited_terminal = false;
            let mut cited_records = BTreeSet::new();
            for observation in transaction["observations"]
                .as_array()
                .expect("transaction observations are an array")
            {
                let observation_id = observation["observationId"].as_str().unwrap_or("<invalid>");
                let phase = observation["phase"].as_str().unwrap_or_default();
                let disposition = observation["disposition"].as_str().unwrap_or_default();
                let terminal = observation["terminal"].as_bool().unwrap_or(false);
                cited_terminal |= terminal;
                for reference in observation["evidence"]
                    .as_array()
                    .expect("evidence is an array")
                {
                    let artifact_id = reference["artifactId"].as_str().unwrap_or_default();
                    let Some(start_line) = reference["startLine"]
                        .as_u64()
                        .and_then(|line| u32::try_from(line).ok())
                    else {
                        failures.push(format!(
                            "{scenario}/{observation_id}: citation start line exceeds u32"
                        ));
                        continue;
                    };
                    let Some(end_line) = reference["endLine"]
                        .as_u64()
                        .and_then(|line| u32::try_from(line).ok())
                    else {
                        failures.push(format!(
                            "{scenario}/{observation_id}: citation end line exceeds u32"
                        ));
                        continue;
                    };
                    let record_key = (artifact_id.to_owned(), start_line, end_line);
                    let Some(record) = records.get(&record_key) else {
                        failures.push(format!(
                            "{scenario}/{observation_id}: citation is not one logical CCM record"
                        ));
                        continue;
                    };
                    if !cited_records.insert(record_key)
                        || artifact_layers.get(artifact_id).map(String::as_str) != Some(layer)
                    {
                        failures.push(format!(
                            "{scenario}/{transaction_id}: evidence is reused or cross-layer"
                        ));
                    }
                    let fields = match parse_fixture_fields(&record.message) {
                        Ok(fields) => fields,
                        Err(error) => {
                            failures.push(format!("{scenario}/{observation_id}: {error}"));
                            continue;
                        }
                    };
                    for (field, value) in [
                        ("RequestId", key["requestId"].as_str()),
                        ("OperationHandle", key["operationHandle"].as_str()),
                        ("EndpointId", key["endpointId"].as_str()),
                        ("Layer", Some(layer)),
                        ("ProfileId", key["extractionProfileId"].as_str()),
                    ] {
                        if fields.get(field).map(String::as_str) != value {
                            failures.push(format!(
                                "{scenario}/{observation_id}: evidence key {field} diverges"
                            ));
                        }
                    }
                    if fields.get("Phase").map(String::as_str) != Some(phase)
                        || fields.get("Disposition").map(String::as_str) != Some(disposition)
                        || fields.get("Terminal").map(String::as_str)
                            != Some(if terminal { "true" } else { "false" })
                    {
                        failures.push(format!(
                            "{scenario}/{observation_id}: evidence semantics diverge"
                        ));
                    }
                    match transaction["timestampOrdering"].as_str() {
                        Some("usable") => {
                            if record.timestamp.ordering_state
                                != SccmTimeOrderingState::NormalizedUtc
                                || record.timestamp.utc_millis.is_none()
                                || record
                                    .timestamp
                                    .utc_millis
                                    .is_some_and(|utc| utc < prior_utc)
                            {
                                failures.push(format!(
                                    "{scenario}/{transaction_id}: time is unusable or reversed"
                                ));
                            }
                            if let Some(utc) = record.timestamp.utc_millis {
                                prior_utc = utc;
                            }
                        }
                        Some("unusableInvalidOffset") => {
                            if record.timestamp.ordering_state
                                != SccmTimeOrderingState::OffsetInvalid
                            {
                                failures.push(format!(
                                    "{scenario}/{transaction_id}: invalid offset became usable"
                                ));
                            }
                        }
                        _ => failures.push(format!(
                            "{scenario}/{transaction_id}: unknown timestamp ordering"
                        )),
                    }
                }
            }
            if transaction["terminalEvidence"].as_bool() != Some(cited_terminal) {
                failures.push(format!(
                    "{scenario}/{transaction_id}: terminality is not citation-derived"
                ));
            }
        }

        for failure in uncited_transaction_record_failures(&expected, &records) {
            failures.push(format!("{scenario}: {failure}"));
        }

        if scenario == "rotation-boundary" && !records.is_empty() {
            failures.push(
                "rotation-boundary: partial rotation fragments formed logical evidence".to_owned(),
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn privacy_iis_and_missing_source_controls_stay_conservative() {
    let privacy_manifest = read_json("privacy-redaction", "manifest.json").unwrap();
    let privacy_expected = read_json("privacy-redaction", "expected.json").unwrap();
    let privacy_public = serde_json::to_string(&privacy_expected)
        .expect("privacy expected output serializes")
        .to_ascii_lowercase();
    for raw in [
        "synthetic.user@example.invalid",
        "synthetic-raw-bearer-do-not-export",
        "select * from sms_r_system",
        "/adminservice/v1.0/device",
    ] {
        assert!(
            !privacy_public.contains(raw),
            "public output leaked synthetic sensitive shape {raw}"
        );
    }
    let privacy_raw = privacy_manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|artifact| artifact["relativePath"].as_str())
        .map(|path| fs::read_to_string(corpus_root().join("privacy-redaction").join(path)).unwrap())
        .collect::<String>()
        .to_ascii_lowercase();
    assert!(privacy_raw.contains("synthetic.user@example.invalid"));
    assert!(privacy_raw.contains("synthetic-raw-bearer-do-not-export"));
    assert!(privacy_raw.contains("select * from sms_r_system"));
    assert!(privacy_raw.contains("/adminservice/v1.0/device"));

    let privacy_transactions = privacy_expected["transactions"].as_array().unwrap();
    assert_eq!(privacy_transactions.len(), 2);
    assert_eq!(
        privacy_transactions[0]["key"]["requestId"],
        privacy_transactions[1]["key"]["requestId"]
    );
    assert_ne!(
        privacy_transactions[0]["transactionId"],
        privacy_transactions[1]["transactionId"]
    );
    assert_ne!(
        privacy_transactions[0]["layer"],
        privacy_transactions[1]["layer"]
    );

    let iis_expected = read_json("iis-supplemental", "expected.json").unwrap();
    let iis_transaction_evidence = serde_json::to_string(&iis_expected["transactions"]).unwrap();
    assert!(!iis_transaction_evidence.contains("iis-supplemental-current"));
    assert_eq!(
        iis_expected["sourceLocalObservations"][0]["kind"],
        "supplementalOnly"
    );
    assert_eq!(
        iis_expected["sourceLocalObservations"][0]["correlationEligible"],
        false
    );

    let provider_timeout = read_json("provider-timeout", "expected.json").unwrap();
    assert_eq!(
        provider_timeout["artifactRequests"][0]["logicalArtifactId"],
        "server-provider"
    );
    let incomplete = read_json("incomplete", "expected.json").unwrap();
    assert_eq!(
        incomplete["artifactRequests"][0]["logicalArtifactId"],
        "server-admin-service"
    );
}

#[test]
fn schema_and_identity_mutations_fail_closed() {
    let manifest = read_json("provider-success", "manifest.json").unwrap();
    let expected = read_json("provider-success", "expected.json").unwrap();
    let iis_manifest = read_json("iis-supplemental", "manifest.json").unwrap();
    let iis_expected = read_json("iis-supplemental", "expected.json").unwrap();
    let timeout_manifest = read_json("provider-timeout", "manifest.json").unwrap();
    let timeout_expected = read_json("provider-timeout", "expected.json").unwrap();
    let mut accepted = Vec::new();

    let mut extra_field = manifest.clone();
    extra_field["unexpected"] = Value::Bool(true);
    if schema_failures("provider-success", &extra_field, &expected).is_empty() {
        accepted.push("unknown manifest field");
    }

    let mut wrong_role = manifest.clone();
    wrong_role["artifacts"][0]["producerRole"] = Value::String("adminService".to_owned());
    if schema_failures("provider-success", &wrong_role, &expected).is_empty() {
        accepted.push("wrong producer role");
    }

    let mut unknown_version = manifest.clone();
    unknown_version["artifacts"][0]["sourceVersion"] = Value::String("9.99.UNKNOWN".to_owned());
    if schema_failures("provider-success", &unknown_version, &expected).is_empty() {
        accepted.push("unknown version retained selected profile");
    }

    let mut control_version = manifest.clone();
    control_version["artifacts"][0]["sourceVersion"] =
        Value::String("5.00.TEST.0001\n9.99.UNKNOWN".to_owned());
    if schema_failures("provider-success", &control_version, &expected).is_empty() {
        accepted.push("control-character source version retained selected profile");
    }

    let mut blank_artifact = manifest.clone();
    blank_artifact["artifacts"][0]["artifactId"] = Value::String(String::new());
    let mut blank_artifact_expected = expected.clone();
    blank_artifact_expected["coverage"][0]["artifactId"] = Value::String(String::new());
    for observation in blank_artifact_expected["transactions"][0]["observations"]
        .as_array_mut()
        .unwrap()
    {
        observation["evidence"][0]["artifactId"] = Value::String(String::new());
    }
    if schema_failures(
        "provider-success",
        &blank_artifact,
        &blank_artifact_expected,
    )
    .is_empty()
    {
        accepted.push("blank artifact identity with internally rewritten references");
    }

    let mut unsafe_path = manifest.clone();
    unsafe_path["artifacts"][0]["relativePath"] =
        Value::String("evidence/../outside/Smsprov.log".to_owned());
    if schema_failures("provider-success", &unsafe_path, &expected).is_empty() {
        accepted.push("unsafe relative path");
    }

    let mut endpoint_only = expected.clone();
    endpoint_only["transactions"][0]["key"]["requestId"] = Value::String(String::new());
    if schema_failures("provider-success", &manifest, &endpoint_only).is_empty() {
        accepted.push("endpoint-only key");
    }

    let mut time_only = expected.clone();
    time_only["transactions"][0]["key"]["requestId"] = Value::String("same-minute-only".to_owned());
    time_only["transactions"][0]["key"]["operationHandle"] =
        Value::String("safe-operation-time-only".to_owned());
    time_only["transactions"][0]["transactionId"] = Value::String(
        "provider:same-minute-only:safe-operation-time-only:provider-local".to_owned(),
    );
    if schema_failures("provider-success", &manifest, &time_only).is_empty() {
        accepted.push("time-like arbitrary key replaced profile fixture identity");
    }

    let mut non_array_evidence = expected.clone();
    non_array_evidence["transactions"][0]["observations"][0]["evidence"] = Value::Bool(false);
    if schema_failures("provider-success", &manifest, &non_array_evidence).is_empty() {
        accepted.push("non-array transaction evidence");
    }

    let mut duplicate_observation = expected.clone();
    let first = duplicate_observation["transactions"][0]["observations"][0].clone();
    duplicate_observation["transactions"][0]["observations"]
        .as_array_mut()
        .unwrap()
        .push(first);
    if schema_failures("provider-success", &manifest, &duplicate_observation).is_empty() {
        accepted.push("duplicate transaction observation");
    }

    let mut arbitrary_observation = expected.clone();
    arbitrary_observation["transactions"][0]["observations"][0]["observationId"] =
        Value::String("arbitrary-observation".to_owned());
    if schema_failures("provider-success", &manifest, &arbitrary_observation).is_empty() {
        accepted.push("arbitrary transaction observation identity");
    }

    let mut incomplete_high = manifest.clone();
    incomplete_high["artifacts"][0]["rotation"]["fragmentComplete"] = Value::Bool(false);
    if schema_failures("provider-success", &incomplete_high, &expected).is_empty() {
        accepted.push("incomplete physical fragment retained high confidence");
    }

    let mut altered_outcome = expected.clone();
    altered_outcome["transactions"][0]["state"] = Value::String("unknown".to_owned());
    if schema_failures("provider-success", &manifest, &altered_outcome).is_empty() {
        accepted.push("arbitrary transaction outcome");
    }

    let mut iis_as_primary = iis_expected.clone();
    iis_as_primary["transactions"][0]["observations"][0]["evidence"][0]["artifactId"] =
        Value::String("iis-supplemental-current".to_owned());
    if schema_failures("iis-supplemental", &iis_manifest, &iis_as_primary).is_empty() {
        accepted.push("supplemental IIS evidence became an Admin Service transaction");
    }

    let mut arbitrary_source_local = iis_expected.clone();
    arbitrary_source_local["sourceLocalObservations"][0]["observationId"] =
        Value::String("arbitrary-source-local".to_owned());
    if schema_failures("iis-supplemental", &iis_manifest, &arbitrary_source_local).is_empty() {
        accepted.push("arbitrary source-local observation identity");
    }

    let mut missing_request = timeout_expected.clone();
    missing_request["artifactRequests"] = Value::Array(Vec::new());
    if schema_failures("provider-timeout", &timeout_manifest, &missing_request).is_empty() {
        accepted.push("required bounded follow-up request omitted");
    }

    let mut unsafe_summary = expected.clone();
    unsafe_summary["transactions"][0]["publicSummary"] =
        Value::String("SELECT * FROM SMS_R_System for user@example.invalid".to_owned());
    if schema_failures("provider-success", &manifest, &unsafe_summary).is_empty() {
        accepted.push("sensitive public summary");
    }

    let mut broad_request = expected.clone();
    broad_request["artifactRequests"] = serde_json::json!([{
        "logicalArtifactId": "server-provider",
        "reason": "Collect all logs from the entire drive."
    }]);
    if schema_failures("provider-success", &manifest, &broad_request).is_empty() {
        accepted.push("broad artifact request");
    }

    let mut cross_side_claim = expected.clone();
    cross_side_claim["crossSideCausalClaims"] =
        serde_json::json!(["same-time client failure was caused"]);
    if schema_failures("provider-success", &manifest, &cross_side_claim).is_empty() {
        accepted.push("cross-side causal claim");
    }

    assert!(accepted.is_empty(), "accepted mutations: {accepted:#?}");
}

#[test]
fn review_privacy_topology_profile_and_citation_mutations_fail_closed() {
    let manifest = read_json("provider-success", "manifest.json").unwrap();
    let expected = read_json("provider-success", "expected.json").unwrap();
    let privacy_manifest = read_json("privacy-redaction", "manifest.json").unwrap();
    let privacy_expected = read_json("privacy-redaction", "expected.json").unwrap();
    let iis_manifest = read_json("iis-supplemental", "manifest.json").unwrap();
    let iis_expected = read_json("iis-supplemental", "expected.json").unwrap();
    let timeout_manifest = read_json("provider-timeout", "manifest.json").unwrap();
    let timeout_expected = read_json("provider-timeout", "expected.json").unwrap();
    let mut accepted = Vec::new();

    let mut noncanonical_known_version = manifest.clone();
    noncanonical_known_version["artifacts"][0]["sourceVersion"] =
        Value::String("5.00.TEST.1".to_owned());
    if schema_failures("provider-success", &noncanonical_known_version, &expected).is_empty() {
        accepted.push("noncanonical synthetic source version selected an exact profile");
    }

    let mut overlong_known_version = manifest.clone();
    overlong_known_version["artifacts"][0]["sourceVersion"] =
        Value::String("5.00.TEST.00010".to_owned());
    if schema_failures("provider-success", &overlong_known_version, &expected).is_empty() {
        accepted.push("overlong synthetic source version selected an exact profile");
    }

    let mut topology_host_mismatch = manifest.clone();
    topology_host_mismatch["artifacts"][0]["producerHostHandle"] =
        Value::String("safe:server:different-host".to_owned());
    if schema_failures("provider-success", &topology_host_mismatch, &expected).is_empty() {
        accepted.push("artifact producer host diverged from its endpoint host");
    }

    let mut identity_bearing_host = manifest.clone();
    identity_bearing_host["topology"]["endpoints"][0]["hostHandle"] =
        Value::String("safe:server:synthetic.user@example.invalid".to_owned());
    identity_bearing_host["artifacts"][0]["producerHostHandle"] =
        Value::String("safe:server:synthetic.user@example.invalid".to_owned());
    if schema_failures("provider-success", &identity_bearing_host, &expected).is_empty() {
        accepted.push("identity-bearing host provenance");
    }

    let mut identity_bearing_source_path = manifest.clone();
    identity_bearing_source_path["artifacts"][0]["sanitizedSourcePath"] =
        Value::String("SYNTHETIC://Users/Adam.Gell/LAB/Logs/Smsprov.log".to_owned());
    if schema_failures("provider-success", &identity_bearing_source_path, &expected).is_empty() {
        accepted.push("identity-bearing sanitized source path");
    }

    let mut identity_bearing_fingerprint = manifest.clone();
    identity_bearing_fingerprint["artifacts"][0]["pathFingerprint"] =
        Value::String("synthetic:synthetic.user@example.invalid".to_owned());
    if schema_failures("provider-success", &identity_bearing_fingerprint, &expected).is_empty() {
        accepted.push("identity-bearing path fingerprint");
    }

    let mut basename_mismatch = manifest.clone();
    basename_mismatch["artifacts"][0]["sanitizedSourcePath"] =
        Value::String("SYNTHETIC://configured-root/LAB/Logs/AdminService.log".to_owned());
    if schema_failures("provider-success", &basename_mismatch, &expected).is_empty() {
        accepted.push("sanitized source path basename diverged from source identity");
    }

    let mut duplicate_sanitized_physical_identity = privacy_manifest.clone();
    duplicate_sanitized_physical_identity["artifacts"][1]["sanitizedSourcePath"] =
        duplicate_sanitized_physical_identity["artifacts"][0]["sanitizedSourcePath"].clone();
    if schema_failures(
        "privacy-redaction",
        &duplicate_sanitized_physical_identity,
        &privacy_expected,
    )
    .is_empty()
    {
        accepted.push("duplicate sanitized physical identity hidden by distinct fingerprints");
    }

    let mut out_of_range_source_local_citation = iis_expected.clone();
    out_of_range_source_local_citation["sourceLocalObservations"][0]["evidence"][0]["startLine"] =
        Value::from(9999_u64);
    out_of_range_source_local_citation["sourceLocalObservations"][0]["evidence"][0]["endLine"] =
        Value::from(9999_u64);
    if schema_failures(
        "iis-supplemental",
        &iis_manifest,
        &out_of_range_source_local_citation,
    )
    .is_empty()
    {
        accepted.push("source-local citation points outside physical evidence");
    }

    let mut reversed_source_local_citation = iis_expected.clone();
    reversed_source_local_citation["sourceLocalObservations"][0]["evidence"][0]["startLine"] =
        Value::from(2_u64);
    reversed_source_local_citation["sourceLocalObservations"][0]["evidence"][0]["endLine"] =
        Value::from(1_u64);
    if schema_failures(
        "iis-supplemental",
        &iis_manifest,
        &reversed_source_local_citation,
    )
    .is_empty()
    {
        accepted.push("source-local citation has a reversed line range");
    }

    let mut private_source_local_reason = privacy_expected.clone();
    private_source_local_reason["sourceLocalObservations"][0]["reason"] =
        Value::String("Caller synthetic.user@example.invalid used a raw token".to_owned());
    if schema_failures(
        "privacy-redaction",
        &privacy_manifest,
        &private_source_local_reason,
    )
    .is_empty()
    {
        accepted.push("source-local public reason leaks caller identity");
    }

    let mut private_request_reason = timeout_expected.clone();
    private_request_reason["artifactRequests"][0]["reason"] =
        Value::String("Capture caller synthetic.user@example.invalid bearer token".to_owned());
    if schema_failures(
        "provider-timeout",
        &timeout_manifest,
        &private_request_reason,
    )
    .is_empty()
    {
        accepted.push("artifact request public reason leaks caller and token material");
    }

    let mut extra_unobserved_endpoint = manifest.clone();
    extra_unobserved_endpoint["topology"]["endpoints"]
        .as_array_mut()
        .unwrap()
        .insert(
            0,
            serde_json::json!({
                "endpointId": "aaa-unobserved",
                "layer": "provider",
                "hostHandle": "safe:server:unused",
                "producerRole": "provider"
            }),
        );
    if schema_failures("provider-success", &extra_unobserved_endpoint, &expected).is_empty() {
        accepted.push("unobserved extra endpoint entered exact topology");
    }

    assert!(accepted.is_empty(), "accepted mutations: {accepted:#?}");
}

#[test]
fn overflowing_transaction_citation_lines_fail_closed() {
    let manifest = read_json("provider-success", "manifest.json").unwrap();
    let mut expected = read_json("provider-success", "expected.json").unwrap();
    let wrapped_line = u64::from(u32::MAX) + 2;
    expected["transactions"][0]["observations"][0]["evidence"][0]["startLine"] =
        Value::from(wrapped_line);
    expected["transactions"][0]["observations"][0]["evidence"][0]["endLine"] =
        Value::from(wrapped_line);

    assert!(
        !schema_failures("provider-success", &manifest, &expected).is_empty(),
        "u64 citation lines that wrap to a different u32 logical record were accepted"
    );
}

#[test]
fn exported_manifest_and_expected_strings_fail_closed_on_private_shapes() {
    let manifest = read_json("provider-success", "manifest.json").unwrap();
    let expected = read_json("provider-success", "expected.json").unwrap();
    let mut accepted = Vec::new();

    let mut private_manifest = manifest.clone();
    private_manifest["artifacts"][0]["rotation"]["lineageId"] =
        Value::String("synthetic.user@example.invalid".to_owned());
    if schema_failures("provider-success", &private_manifest, &expected).is_empty() {
        accepted.push("manifest rotation lineage containing an email identity");
    }

    let mut private_expected = expected.clone();
    private_expected["transactions"][0]["publicSummary"] = Value::String(
        r"CONTOSO\alice issued DELETE FROM SMS_R_System with ghp_abcdefghijklmnopqrstuvwxyz0123456789"
            .to_owned(),
    );
    if schema_failures("provider-success", &manifest, &private_expected).is_empty() {
        accepted.push("public summary containing identity, query, and token shapes");
    }

    assert!(accepted.is_empty(), "accepted mutations: {accepted:#?}");
}

#[test]
fn split_rotation_members_with_divergent_lineage_fail_closed() {
    let mut manifest = read_json("rotation-boundary", "manifest.json").unwrap();
    let expected = read_json("rotation-boundary", "expected.json").unwrap();
    manifest["artifacts"][1]["rotation"]["lineageId"] =
        Value::String("different-lineage".to_owned());

    assert!(
        !schema_failures("rotation-boundary", &manifest, &expected).is_empty(),
        "one source-local split rotation accepted divergent lineage provenance"
    );
}

#[test]
fn incomplete_invalid_offset_transaction_cannot_claim_high_ceiling() {
    let manifest = read_json("provider-timeout", "manifest.json").unwrap();
    let mut expected = read_json("provider-timeout", "expected.json").unwrap();
    expected["transactions"][0]["confidenceCeiling"] = Value::String("high".to_owned());

    assert!(
        !schema_failures("provider-timeout", &manifest, &expected).is_empty(),
        "incomplete invalid-offset evidence accepted a high confidence ceiling"
    );
}

#[test]
fn generic_artifact_request_reason_fails_closed() {
    let manifest = read_json("provider-timeout", "manifest.json").unwrap();
    let mut expected = read_json("provider-timeout", "expected.json").unwrap();
    expected["artifactRequests"][0]["reason"] = Value::String("Collect logs.".to_owned());

    assert!(
        !schema_failures("provider-timeout", &manifest, &expected).is_empty(),
        "generic request prose lost the exact unresolved request and terminal basis"
    );
}

#[test]
fn later_uncited_same_key_terminal_failure_invalidates_high_success() {
    let manifest = read_json("provider-success", "manifest.json").unwrap();
    let expected = read_json("provider-success", "expected.json").unwrap();
    let mut records = normalized_records("provider-success", &manifest);
    let artifact = SccmArtifact {
        artifact_id: "provider-success-current".to_owned(),
        display_name: "Smsprov.log".to_owned(),
        original_path: None,
        host: Some("safe:server:lab-provider-01".to_owned()),
        role: SccmRole::Provider,
        configmgr_version: Some("5.00.TEST.0001".to_owned()),
        collected_at_utc: Some("2026-07-30T21:00:00Z".to_owned()),
        rotation: SccmRotation::Current,
        coverage: SccmCoverageState::Captured,
        encoding: Some("utf-8".to_owned()),
    };
    let raw = "<![LOG[SYNTHETIC FIXTURE; Phase=recordOutcome; Disposition=failed; Terminal=true; RequestId=11111111-1111-1111-1111-111111111111; OperationHandle=safe-operation-read-device; EndpointId=provider-local; Layer=provider; ProfileId=provider-server-5.00.test-v1]LOG]!><time=\"21:00:05.000+000\" date=\"7-30-2026\" component=\"SMS_PROVIDER\" context=\"\" type=\"3\" thread=\"1101\" file=\"synthetic-provider.cc:60\">";
    let mut later_failure = normalize_ccm_artifact(artifact, raw)
        .into_iter()
        .next()
        .expect("adversarial terminal record normalizes");
    later_failure.evidence_id = "provider-success-current:6-6".to_owned();
    later_failure.reference.entry_id = "provider-success-current:6-6".to_owned();
    later_failure.reference.line_start = Some(6);
    later_failure.reference.line_end = Some(6);
    records.insert(("provider-success-current".to_owned(), 6, 6), later_failure);

    assert!(
        !schema_failures_with_records("provider-success", &manifest, &expected, &records)
            .is_empty(),
        "an uncited later terminal failure for the exact transaction key retained high success"
    );
}

#[test]
fn terminal_marker_cannot_move_from_record_outcome_to_receive() {
    let manifest = read_json("provider-success", "manifest.json").unwrap();
    let mut expected = read_json("provider-success", "expected.json").unwrap();
    expected["transactions"][0]["observations"][0]["terminal"] = Value::Bool(true);
    expected["transactions"][0]["observations"][4]["terminal"] = Value::Bool(false);

    assert!(
        !schema_failures("provider-success", &manifest, &expected).is_empty(),
        "a receive marker satisfied terminal evidence after recordOutcome became nonterminal"
    );
}

#[test]
fn applied_collection_limit_cannot_remain_captured_or_high() {
    let mut manifest = read_json("provider-success", "manifest.json").unwrap();
    let expected = read_json("provider-success", "expected.json").unwrap();
    manifest["artifacts"][0]["collectionLimit"]["limitApplied"] = Value::Bool(true);

    assert!(
        !schema_failures("provider-success", &manifest, &expected).is_empty(),
        "limitApplied=true retained captured coverage and high-confidence success"
    );
}

#[test]
fn relative_path_must_match_declared_source_rotation_and_basename() {
    let mut manifest = read_json("rotation-boundary", "manifest.json").unwrap();
    let expected = read_json("rotation-boundary", "expected.json").unwrap();
    let current_path = manifest["artifacts"][0]["relativePath"].clone();
    let current_bytes = manifest["artifacts"][0]["bytesCopied"].clone();
    manifest["artifacts"][0]["relativePath"] = manifest["artifacts"][1]["relativePath"].clone();
    manifest["artifacts"][0]["bytesCopied"] = manifest["artifacts"][1]["bytesCopied"].clone();
    manifest["artifacts"][1]["relativePath"] = current_path;
    manifest["artifacts"][1]["bytesCopied"] = current_bytes;

    assert!(
        !schema_failures("rotation-boundary", &manifest, &expected).is_empty(),
        "current and lo_ artifacts accepted each other's physical paths"
    );
}

#[test]
fn unknown_source_version_requires_canonical_public_grammar() {
    let manifest = read_json("rotation-boundary", "manifest.json").unwrap();
    let expected = read_json("rotation-boundary", "expected.json").unwrap();

    for unsafe_version in ["SyntheticCaller", "1.2.SYNTHETICCALLER"] {
        let mut mutated = manifest.clone();
        for artifact in mutated["artifacts"].as_array_mut().unwrap() {
            artifact["sourceVersion"] = Value::String(unsafe_version.to_owned());
        }
        assert!(
            !schema_failures("rotation-boundary", &mutated, &expected).is_empty(),
            "caller-shaped text {unsafe_version} was exported as unknown source-version provenance"
        );
    }
}

#[test]
fn exact_rotation_topology_rejects_an_empty_endpoint() {
    let mut manifest = read_json("rotation-boundary", "manifest.json").unwrap();
    let expected = read_json("rotation-boundary", "expected.json").unwrap();
    manifest["topology"]["endpoints"][0]["endpointId"] = Value::String(String::new());
    for artifact in manifest["artifacts"].as_array_mut().unwrap() {
        artifact["endpointId"] = Value::String(String::new());
    }

    assert!(
        !schema_failures("rotation-boundary", &manifest, &expected).is_empty(),
        "an empty endpoint retained exact topology when no transaction was emitted"
    );
}

#[test]
fn provider_sensitive_fields_never_enter_public_or_candidate_projections() {
    const REDACTED: &str = "[redacted:sccm-public-message-v1]";
    let prefix = "[sccm-public-message-v1] ";
    let core = "Phase=receive; Disposition=succeeded; Terminal=false; RequestId=11111111-1111-1111-1111-111111111111; OperationHandle=safe-operation-read-device; EndpointId=provider-local; Layer=provider; ProfileId=provider-server-5.00.test-v1";
    let raw_fields = [
        (
            "CallerHandle=opaque-private-caller",
            "opaque-private-caller",
        ),
        (
            "CallerHandle=private-caller-middle",
            "private-caller-middle",
        ),
        ("CallerHandle=private-caller-tail", "private-caller-tail"),
        (
            "QueryHandle=/AdminService/v1.0/device",
            "/AdminService/v1.0/device",
        ),
        (
            "QueryHandle=SELECT * FROM SMS_R_System",
            "SELECT * FROM SMS_R_System",
        ),
        ("QueryHandle=opaque-private-query", "opaque-private-query"),
        (
            "Authorization=Bearer private-auth-start",
            "private-auth-start",
        ),
        (
            "Authorization=Custom private-auth-middle",
            "private-auth-middle",
        ),
        ("Authorization=Basic private-auth-tail", "private-auth-tail"),
    ];

    for (index, (raw_field, sensitive)) in raw_fields.into_iter().enumerate() {
        let message = match index % 3 {
            0 => format!("{prefix}SYNTHETIC FIXTURE; {raw_field}; {core}"),
            1 => format!(
                "{prefix}SYNTHETIC FIXTURE; Phase=receive; {raw_field}; Disposition=succeeded; Terminal=false; RequestId=11111111-1111-1111-1111-111111111111; OperationHandle=safe-operation-read-device; EndpointId=provider-local; Layer=provider; ProfileId=provider-server-5.00.test-v1"
            ),
            _ => format!("{prefix}SYNTHETIC FIXTURE; {core}; {raw_field}"),
        };
        let error = parse_fixture_fields(&message)
            .expect_err("a raw sensitive fixture field must fail closed");
        assert!(
            !error.contains(sensitive),
            "candidate error leaked {sensitive}"
        );
    }

    for field in ["CallerHandle", "QueryHandle", "Authorization"] {
        let message = format!("{prefix}SYNTHETIC FIXTURE; {core}; {field}={REDACTED}");
        let fields = parse_fixture_fields(&message)
            .unwrap_or_else(|error| panic!("{field} redaction marker was rejected: {error}"));
        assert!(
            !fields.contains_key(field),
            "{field} entered exact facts after redaction"
        );
    }

    let manifest = read_json("privacy-redaction", "manifest.json").unwrap();
    let records = normalized_records("privacy-redaction", &manifest);
    let public_json = serde_json::to_string(&records.values().collect::<Vec<_>>()).unwrap();
    for sensitive in [
        "synthetic.user@example.invalid",
        "SYNTHETIC-RAW-BEARER-DO-NOT-EXPORT",
        "SELECT * FROM SMS_R_System",
        "/AdminService/v1.0/device",
    ] {
        assert!(
            !public_json.contains(sensitive),
            "public evidence leaked {sensitive}"
        );
    }
    for record in records.values() {
        let fields = parse_fixture_fields(&record.message)
            .unwrap_or_else(|error| panic!("projected fixture field is invalid: {error}"));
        for field in ["CallerHandle", "QueryHandle", "Authorization"] {
            assert!(
                !fields.contains_key(field),
                "{field} entered an exact-key correlation candidate"
            );
        }
    }
}

#[test]
fn nonterminal_disposition_and_recovery_vocabulary_is_closed() {
    let manifest = read_json("provider-success", "manifest.json").unwrap();
    let expected = read_json("provider-success", "expected.json").unwrap();
    let records = normalized_records("provider-success", &manifest);
    let mut accepted = Vec::new();

    for disposition in ["manufacturedRecovery", "failed", "retryableFailure"] {
        let mut paired_expected = expected.clone();
        let observation = &mut paired_expected["transactions"][0]["observations"][2];
        observation["disposition"] = Value::String(disposition.to_owned());
        let artifact_id = observation["evidence"][0]["artifactId"]
            .as_str()
            .unwrap()
            .to_owned();
        let start_line =
            u32::try_from(observation["evidence"][0]["startLine"].as_u64().unwrap()).unwrap();
        let end_line =
            u32::try_from(observation["evidence"][0]["endLine"].as_u64().unwrap()).unwrap();
        let mut paired_records = records.clone();
        let record = paired_records
            .get_mut(&(artifact_id, start_line, end_line))
            .expect("paired evidence record exists");
        record.message = record.message.replacen(
            "Disposition=succeeded",
            &format!("Disposition={disposition}"),
            1,
        );

        if schema_failures_with_records(
            "provider-success",
            &manifest,
            &paired_expected,
            &paired_records,
        )
        .is_empty()
        {
            accepted.push(disposition);
        }
    }

    assert!(
        accepted.is_empty(),
        "paired high-success mutations accepted nonterminal dispositions: {accepted:#?}"
    );
}

#[test]
fn provider_retry_requires_an_explicit_retryable_failure_then_recovery() {
    let manifest = read_json("provider-retry", "manifest.json").unwrap();
    let mut expected = read_json("provider-retry", "expected.json").unwrap();
    expected["transactions"][0]["observations"][2]["disposition"] =
        Value::String("succeeded".to_owned());

    assert!(
        !schema_failures("provider-retry", &manifest, &expected).is_empty(),
        "a nominal success sequence replaced the explicit retryable failure"
    );
}

#[test]
fn provider_retry_scenario_is_explicit() {
    read_json("provider-retry", "manifest.json").expect("provider retry manifest exists");
    read_json("provider-retry", "expected.json").expect("provider retry expectation exists");
}

#[test]
fn contradictory_evidence_scenario_is_explicit() {
    read_json("contradictory-evidence", "manifest.json")
        .expect("contradictory evidence manifest exists");
    read_json("contradictory-evidence", "expected.json")
        .expect("contradictory evidence expectation exists");
}
