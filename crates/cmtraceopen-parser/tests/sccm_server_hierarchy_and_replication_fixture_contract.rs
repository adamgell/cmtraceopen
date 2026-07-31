use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use cmtraceopen_parser::sccm::{
    classify_artifact_name, normalize_ccm_artifact, SccmArtifact, SccmArtifactFamily,
    SccmCoverageState, SccmEvidence, SccmRole, SccmRotation, SccmTimeOrderingState,
};
use serde_json::Value;

const SCENARIOS: &[&str] = &[
    "absent-remote-source",
    "backlog-retry",
    "clock-offset-unknown",
    "generic-site-token",
    "healthy-link",
    "incomplete",
    "receiver-processing-failure",
    "recovery",
    "rotation-boundary",
    "sender-failure",
    "topology-mismatch",
];

const STATE_CHAIN: &[&str] = &[
    "initiate",
    "queueOrSerialize",
    "send",
    "receive",
    "process",
    "acknowledge",
    "healthyOrTerminal",
];

const EXACT_PROFILE: &str = "hierarchy-server-5.00.test-v1";
const EXACT_SOURCE_VERSION: &str = "5.00.TEST.0001";

fn corpus_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/hierarchy_and_replication")
}

fn read_json(scenario: &str, filename: &str) -> Result<Value, String> {
    let path = corpus_root().join(scenario).join(filename);
    let contents = std::fs::read_to_string(&path)
        .map_err(|error| format!("{} is readable: {error}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("{} contains valid JSON: {error}", path.display()))
}

fn actual_scenarios() -> Result<Vec<String>, String> {
    let root = corpus_root();
    let mut scenarios = std::fs::read_dir(&root)
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
        .collect::<Vec<_>>();
    scenarios.sort();
    Ok(scenarios)
}

fn required_string<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{context}.{field} must be a string"))
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

fn safe_server_handle(value: &str) -> bool {
    value.strip_prefix("safe:server:").is_some_and(|payload| {
        !payload.is_empty()
            && payload
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
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
        "loUnderscore" if value.get("value").is_none() => Some(SccmRotation::LoUnderscore),
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
        "MessageId",
        "LinkId",
        "OriginSite",
        "TargetSite",
        "ProfileId",
    ];
    let mut fields = BTreeMap::new();
    for segment in segments {
        let (name, value) = segment
            .split_once('=')
            .ok_or_else(|| format!("fixture field is not Name=Value: {segment}"))?;
        if !allowed.contains(&name) || value.is_empty() {
            return Err(format!("unsupported or empty fixture field {name}"));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(format!("fixture field {name} contains unsupported syntax"));
        }
        if fields.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate fixture field {name}"));
        }
    }
    Ok(fields)
}

fn exact_source_tuple(source_id: &str, basename: &str, direction: &str, role: &str) -> bool {
    role == "siteServer"
        && matches!(
            (source_id, basename, direction),
            ("server-hierarchy-control", "replmgr.log", "origin")
                | ("server-hierarchy-control", "rcmctrl.log", "target")
                | (
                    "server-hierarchy-transfer",
                    "sender.log" | "sender.lo_",
                    "origin"
                )
                | ("server-hierarchy-transfer", "despool.log", "target")
        )
}

fn artifact_has_exact_source_tuple(artifact: &Value) -> bool {
    artifact["sourceId"]
        .as_str()
        .zip(artifact["originalBasename"].as_str())
        .zip(artifact["direction"].as_str())
        .zip(artifact["producerRole"].as_str())
        .is_some_and(|(((source_id, basename), direction), role)| {
            exact_source_tuple(source_id, basename, direction, role)
        })
}

fn artifact_has_exact_public_provenance(artifact: &Value) -> bool {
    artifact["producerHostHandle"]
        .as_str()
        .is_some_and(safe_server_handle)
        && artifact["sanitizedSourcePath"]
            .as_str()
            .is_some_and(|value| safe_segmented_path(value, "SYNTHETIC://"))
        && artifact["pathFingerprint"].as_str().is_some_and(|value| {
            value
                .strip_prefix("synthetic:")
                .is_some_and(|suffix| !suffix.is_empty())
        })
        && artifact["sourceVersion"].as_str() == Some(EXACT_SOURCE_VERSION)
}

fn target_host_for_site<'a>(manifest: &'a Value, site: &str) -> Option<&'a str> {
    let hosts = std::iter::once((
        manifest["topology"]["targetSiteCode"].as_str(),
        manifest["topology"]["targetHostHandle"].as_str(),
    ))
    .chain(
        manifest["topology"]["additionalTargets"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|target| (target["siteCode"].as_str(), target["hostHandle"].as_str())),
    )
    .filter_map(|(candidate_site, host)| (candidate_site == Some(site)).then_some(host).flatten())
    .collect::<BTreeSet<_>>();
    (hosts.len() == 1)
        .then(|| hosts.into_iter().next())
        .flatten()
}

fn artifact_matches_topology(manifest: &Value, artifact: &Value) -> bool {
    match (
        artifact["direction"].as_str(),
        artifact["producerHostHandle"].as_str(),
    ) {
        (Some("origin"), Some(host)) => {
            manifest["topology"]["originHostHandle"].as_str() == Some(host)
        }
        (Some("target"), Some(host)) => {
            std::iter::once(manifest["topology"]["targetHostHandle"].as_str())
                .chain(
                    manifest["topology"]["additionalTargets"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|target| target["hostHandle"].as_str()),
                )
                .flatten()
                .any(|target_host| target_host == host)
        }
        _ => false,
    }
}

fn record_matches_topology(
    manifest: &Value,
    artifact: &Value,
    fields: &BTreeMap<String, String>,
) -> bool {
    let Some(origin_site) = fields.get("OriginSite").map(String::as_str) else {
        return false;
    };
    let Some(target_site) = fields.get("TargetSite").map(String::as_str) else {
        return false;
    };
    if manifest["topology"]["originSiteCode"].as_str() != Some(origin_site) {
        return false;
    }
    match artifact["direction"].as_str() {
        Some("origin") => {
            artifact_matches_topology(manifest, artifact)
                && target_host_for_site(manifest, target_site).is_some()
        }
        Some("target") => artifact["producerHostHandle"]
            .as_str()
            .zip(target_host_for_site(manifest, target_site))
            .is_some_and(|(producer_host, target_host)| producer_host == target_host),
        _ => false,
    }
}

fn artifact_is_exact_candidate(manifest: &Value, artifact: &Value) -> bool {
    artifact["captureState"] == "captured"
        && artifact["sourceVersion"] == EXACT_SOURCE_VERSION
        && artifact["collectedUtc"]
            .as_str()
            .is_some_and(|value| DateTime::parse_from_rfc3339(value).is_ok())
        && artifact["encoding"] == "utf-8"
        && artifact["bytesCopied"].as_u64().is_some()
        && artifact["collectionLimit"]["byteLimit"].as_u64().is_some()
        && artifact["collectionLimit"]["limitApplied"]
            .as_bool()
            .is_some()
        && artifact["relativePath"]
            .as_str()
            .is_some_and(|value| safe_segmented_path(value, "evidence/"))
        && artifact["pathFingerprint"].as_str().is_some_and(|value| {
            value
                .strip_prefix("synthetic:")
                .is_some_and(|suffix| !suffix.is_empty())
        })
        && rotation(&artifact["rotation"]).is_some()
        && artifact["rotation"]["lineageId"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
        && artifact["rotation"]["fragmentComplete"] == true
        && artifact_has_exact_source_tuple(artifact)
        && artifact_matches_topology(manifest, artifact)
}

fn normalized_records(
    scenario: &str,
    manifest: &Value,
) -> BTreeMap<(String, u32, u32), SccmEvidence> {
    try_normalized_records(scenario, manifest).expect("fixture records normalize")
}

fn try_normalized_records(
    scenario: &str,
    manifest: &Value,
) -> Result<BTreeMap<(String, u32, u32), SccmEvidence>, String> {
    let mut records = BTreeMap::new();
    let artifacts = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| format!("{scenario}: manifest artifacts are an array"))?;
    for artifact in artifacts {
        let state = required_string(artifact, "captureState", scenario)?;
        if !matches!(state, "captured" | "capped") {
            continue;
        }
        let artifact_id = required_string(artifact, "artifactId", scenario)?;
        let relative_path = required_string(artifact, "relativePath", scenario)?;
        if !safe_segmented_path(relative_path, "evidence/") {
            return Err(format!(
                "{scenario}/{artifact_id}: physical evidence path is safe"
            ));
        }
        let content = std::fs::read_to_string(corpus_root().join(scenario).join(relative_path))
            .map_err(|error| {
                format!("{scenario}/{artifact_id}: fixture evidence is readable UTF-8: {error}")
            })?;
        let model = SccmArtifact {
            artifact_id: artifact_id.to_owned(),
            display_name: artifact["originalBasename"]
                .as_str()
                .ok_or_else(|| format!("{scenario}/{artifact_id}: artifact basename is a string"))?
                .to_owned(),
            original_path: None,
            host: artifact["producerHostHandle"].as_str().map(str::to_owned),
            role: SccmRole::SiteServer,
            configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
            collected_at_utc: artifact["collectedUtc"].as_str().map(str::to_owned),
            rotation: rotation(&artifact["rotation"])
                .ok_or_else(|| format!("{scenario}/{artifact_id}: rotation is valid"))?,
            coverage: coverage_state(state)
                .ok_or_else(|| format!("{scenario}/{artifact_id}: coverage is valid"))?,
            encoding: artifact["encoding"].as_str().map(str::to_owned),
        };
        for record in normalize_ccm_artifact(model, &content) {
            let line_start = record.reference.line_start.ok_or_else(|| {
                format!("{scenario}/{artifact_id}: normalized evidence has a start line")
            })?;
            let line_end = record.reference.line_end.ok_or_else(|| {
                format!("{scenario}/{artifact_id}: normalized evidence has an end line")
            })?;
            if records
                .insert((artifact_id.to_owned(), line_start, line_end), record)
                .is_some()
            {
                return Err(format!(
                    "{scenario}/{artifact_id}: duplicate physical logical evidence"
                ));
            }
        }
    }
    Ok(records)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HierarchyCandidateKey {
    message_id: String,
    link_id: String,
    origin_site_code: String,
    target_site_code: String,
    extraction_profile_id: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HierarchyCandidateFact {
    phase: String,
    disposition: String,
    terminal: bool,
    artifact_id: String,
    producer_host_handle: String,
    direction: String,
    relative_path: String,
    path_fingerprint: String,
    rotation_kind: String,
    rotation_value: Option<String>,
    rotation_lineage_id: String,
    line_start: u32,
    line_end: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
struct HierarchyCandidateGroup {
    key: HierarchyCandidateKey,
    facts: Vec<HierarchyCandidateFact>,
}

fn hierarchy_candidate_groups(
    scenario: &str,
    manifest: &Value,
) -> Result<Vec<HierarchyCandidateGroup>, String> {
    let mut grouped_facts =
        BTreeMap::<HierarchyCandidateKey, BTreeSet<HierarchyCandidateFact>>::new();
    let artifacts = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| format!("{scenario}: artifacts are an array"))?;
    for artifact in artifacts {
        if !artifact_is_exact_candidate(manifest, artifact) {
            continue;
        }
        let state = required_string(artifact, "captureState", scenario)?;
        let artifact_id = required_string(artifact, "artifactId", scenario)?;
        let basename = required_string(artifact, "originalBasename", scenario)?;
        let relative_path = required_string(artifact, "relativePath", scenario)?;
        let producer_host_handle = required_string(artifact, "producerHostHandle", scenario)?;
        let direction = required_string(artifact, "direction", scenario)?;
        let path_fingerprint = required_string(artifact, "pathFingerprint", scenario)?;
        let rotation_kind = required_string(&artifact["rotation"], "kind", scenario)?;
        let rotation_lineage_id = required_string(&artifact["rotation"], "lineageId", scenario)?;
        let rotation_value = artifact["rotation"]["value"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| {
                artifact["rotation"]["value"]
                    .as_u64()
                    .map(|value| value.to_string())
            });
        let content = std::fs::read_to_string(corpus_root().join(scenario).join(relative_path))
            .map_err(|error| {
                format!("{scenario}/{artifact_id}: physical evidence is readable: {error}")
            })?;
        let model = SccmArtifact {
            artifact_id: artifact_id.to_owned(),
            display_name: basename.to_owned(),
            original_path: None,
            host: Some(producer_host_handle.to_owned()),
            role: SccmRole::SiteServer,
            configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
            collected_at_utc: artifact["collectedUtc"].as_str().map(str::to_owned),
            rotation: rotation(&artifact["rotation"])
                .ok_or_else(|| format!("{scenario}/{artifact_id}: rotation is valid"))?,
            coverage: coverage_state(state)
                .ok_or_else(|| format!("{scenario}/{artifact_id}: coverage is valid"))?,
            encoding: Some("utf-8".to_owned()),
        };
        for record in normalize_ccm_artifact(model, &content) {
            if record.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc {
                continue;
            }
            let Ok(fields) = parse_fixture_fields(&record.message) else {
                continue;
            };
            let Some(message_id) = fields.get("MessageId") else {
                continue;
            };
            let Some(link_id) = fields.get("LinkId") else {
                continue;
            };
            let Some(origin_site_code) = fields.get("OriginSite") else {
                continue;
            };
            let Some(target_site_code) = fields.get("TargetSite") else {
                continue;
            };
            let Some(extraction_profile_id) = fields.get("ProfileId") else {
                continue;
            };
            let Some(phase) = fields.get("Phase") else {
                continue;
            };
            let Some(disposition) = fields.get("Disposition") else {
                continue;
            };
            let Some(terminal) = fields.get("Terminal") else {
                continue;
            };
            if extraction_profile_id != EXACT_PROFILE
                || !phase_is_owned_by(basename, phase)
                || !record_matches_topology(manifest, artifact, &fields)
            {
                continue;
            }
            let terminal = match terminal.as_str() {
                "true" => true,
                "false" => false,
                _ => continue,
            };
            let Some(line_start) = record.reference.line_start else {
                continue;
            };
            let Some(line_end) = record.reference.line_end else {
                continue;
            };
            let key = HierarchyCandidateKey {
                message_id: message_id.to_owned(),
                link_id: link_id.to_owned(),
                origin_site_code: origin_site_code.to_owned(),
                target_site_code: target_site_code.to_owned(),
                extraction_profile_id: extraction_profile_id.to_owned(),
            };
            let fact = HierarchyCandidateFact {
                phase: phase.to_owned(),
                disposition: disposition.to_owned(),
                terminal,
                artifact_id: artifact_id.to_owned(),
                producer_host_handle: producer_host_handle.to_owned(),
                direction: direction.to_owned(),
                relative_path: relative_path.to_owned(),
                path_fingerprint: path_fingerprint.to_owned(),
                rotation_kind: rotation_kind.to_owned(),
                rotation_value: rotation_value.clone(),
                rotation_lineage_id: rotation_lineage_id.to_owned(),
                line_start,
                line_end,
            };
            grouped_facts.entry(key).or_default().insert(fact);
        }
    }
    Ok(grouped_facts
        .into_iter()
        .map(|(key, facts)| HierarchyCandidateGroup {
            key,
            facts: facts.into_iter().collect(),
        })
        .collect())
}

fn hierarchy_candidate_bytes(scenario: &str, manifest: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&hierarchy_candidate_groups(scenario, manifest)?)
        .map_err(|error| format!("{scenario}: candidate output serializes: {error}"))
}

fn phase_is_owned_by(basename: &str, phase: &str) -> bool {
    matches!(
        (basename, phase),
        ("replmgr.log", "initiate" | "queueOrSerialize")
            | ("sender.log", "send")
            | ("despool.log", "receive" | "process" | "healthyOrTerminal")
            | ("rcmctrl.log", "acknowledge" | "healthyOrTerminal")
    )
}

fn evidence_reference_key(reference: &Value) -> Option<(String, u32, u32)> {
    let artifact_id = reference["artifactId"]
        .as_str()
        .filter(|value| !value.is_empty())?
        .to_owned();
    let line_start = reference["startLine"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())?;
    let line_end = reference["endLine"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())?;
    (line_start <= line_end).then_some((artifact_id, line_start, line_end))
}

fn observation_matches_record(
    manifest: &Value,
    artifact: &Value,
    transaction: &Value,
    observation: &Value,
    record: &SccmEvidence,
) -> bool {
    let Ok(fields) = parse_fixture_fields(&record.message) else {
        return false;
    };
    let key = &transaction["key"];
    fields.get("MessageId").map(String::as_str) == key["messageId"].as_str()
        && fields.get("LinkId").map(String::as_str) == key["linkId"].as_str()
        && fields.get("OriginSite").map(String::as_str) == key["originSiteCode"].as_str()
        && fields.get("TargetSite").map(String::as_str) == key["targetSiteCode"].as_str()
        && fields.get("ProfileId").map(String::as_str) == Some(EXACT_PROFILE)
        && fields.get("Phase").map(String::as_str) == observation["phase"].as_str()
        && fields.get("Disposition").map(String::as_str) == observation["disposition"].as_str()
        && fields.get("Terminal").map(String::as_str)
            == observation["terminal"]
                .as_bool()
                .map(|terminal| if terminal { "true" } else { "false" })
        && artifact["originalBasename"]
            .as_str()
            .zip(observation["phase"].as_str())
            .is_some_and(|(basename, phase)| phase_is_owned_by(basename, phase))
        && artifact_has_exact_source_tuple(artifact)
        && record_matches_topology(manifest, artifact, &fields)
}

fn transaction_semantics_are_coherent(transaction: &Value) -> bool {
    let Some(observations) = transaction["observations"].as_array() else {
        return false;
    };
    let mut retrying = false;
    let mut terminal_success = false;
    let mut terminal_failure = false;
    for observation in observations {
        let Some(disposition) = observation["disposition"].as_str() else {
            return false;
        };
        let Some(terminal) = observation["terminal"].as_bool() else {
            return false;
        };
        if !observation_disposition_is_coherent(disposition, terminal) {
            return false;
        }
        retrying |= disposition == "retrying";
        terminal_success |= terminal && disposition == "succeeded";
        terminal_failure |= terminal && disposition == "failed";
    }
    let terminal_evidence = terminal_success || terminal_failure;
    if transaction["terminalEvidence"].as_bool() != Some(terminal_evidence) {
        return false;
    }

    let (state, classification) = if transaction["timestampOrdering"] != "usable" {
        ("incomplete", "insufficientEvidence")
    } else if terminal_failure {
        ("failed", "confirmedFailure")
    } else if terminal_success && retrying {
        ("recovered", "success")
    } else if terminal_success {
        ("succeeded", "success")
    } else if retrying {
        ("deferred", "blockedOrDeferred")
    } else {
        ("incomplete", "insufficientEvidence")
    };
    transaction["state"] == state && transaction["classification"] == classification
}

fn observation_disposition_is_coherent(disposition: &str, terminal: bool) -> bool {
    matches!(
        (disposition, terminal),
        ("succeeded", false | true) | ("failed", true) | ("retrying", false)
    )
}

fn expected_transaction_ids(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "absent-remote-source" => &["hierarchy:msg-absent-01:LAB:CHD:link-lab-chd"],
        "backlog-retry" => &["hierarchy:msg-backlog-01:LAB:CHD:link-lab-chd"],
        "clock-offset-unknown" => &["hierarchy:msg-clock-01:LAB:CHD:link-lab-chd"],
        "healthy-link" => &["hierarchy:msg-healthy-01:LAB:CHD:link-lab-chd"],
        "receiver-processing-failure" => &["hierarchy:msg-receiver-01:LAB:CHD:link-lab-chd"],
        "recovery" => &["hierarchy:msg-recovery-01:LAB:CHD:link-lab-chd"],
        "sender-failure" => &[
            "hierarchy:msg-send-chd:LAB:CHD:link-lab-chd",
            "hierarchy:msg-send-sec:LAB:SEC:link-lab-sec",
        ],
        "incomplete" | "rotation-boundary" | "topology-mismatch" => &[],
        _ => &[],
    }
}

fn expected_observation_ids(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "absent-remote-source" => &["absent-01-send"],
        "backlog-retry" => &["backlog-01-queue"],
        "clock-offset-unknown" => &["clock-01-send", "clock-02-process"],
        "healthy-link" => &[
            "healthy-01-initiate",
            "healthy-02-queue",
            "healthy-03-send",
            "healthy-04-receive",
            "healthy-05-process",
            "healthy-06-acknowledge",
            "healthy-07-terminal",
        ],
        "receiver-processing-failure" => &[
            "receiver-01-send",
            "receiver-02-receive",
            "receiver-03-process",
        ],
        "recovery" => &[
            "recovery-01-retry",
            "recovery-02-send",
            "recovery-03-receive",
            "recovery-04-process",
            "recovery-05-terminal",
        ],
        "sender-failure" => &["sender-01-chd-failure", "sender-02-sec-failure"],
        "incomplete" | "rotation-boundary" | "topology-mismatch" => &[],
        _ => &[],
    }
}

fn expected_source_local_ids(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "incomplete" => &["incomplete-01-fragment"],
        "rotation-boundary" => &["rotation-01-split"],
        "topology-mismatch" => &["mismatch-01-origin", "mismatch-02-target"],
        _ => &[],
    }
}

fn object_has_only(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.keys().all(|field| fields.contains(&field.as_str())))
}

fn declared_target_site_codes(manifest: &Value) -> BTreeSet<&str> {
    std::iter::once(manifest["topology"]["targetSiteCode"].as_str())
        .chain(
            manifest["topology"]["additionalTargets"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|target| target["siteCode"].as_str()),
        )
        .flatten()
        .collect()
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ArtifactRequestBasis {
    source_id: String,
    direction: String,
    target_site_code: String,
    basenames: Vec<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ArtifactRequestContract {
    basis: ArtifactRequestBasis,
    reason_code: String,
}

fn exact_request_direction(directions: &BTreeSet<&str>) -> Option<String> {
    match directions.iter().copied().collect::<Vec<_>>().as_slice() {
        ["origin"] => Some("origin".to_owned()),
        ["target"] => Some("target".to_owned()),
        ["origin", "target"] => Some("both".to_owned()),
        _ => None,
    }
}

fn exact_target_site_for_artifact(manifest: &Value, artifact: &Value) -> Option<String> {
    let producer_host = artifact["producerHostHandle"].as_str()?;
    match artifact["direction"].as_str()? {
        "origin" => {
            if manifest["topology"]["originHostHandle"].as_str() != Some(producer_host) {
                return None;
            }
            let target_sites = declared_target_site_codes(manifest);
            (target_sites.len() == 1)
                .then(|| target_sites.into_iter().next().map(str::to_owned))
                .flatten()
        }
        "target" => {
            let matching_sites = std::iter::once((
                manifest["topology"]["targetSiteCode"].as_str(),
                manifest["topology"]["targetHostHandle"].as_str(),
            ))
            .chain(
                manifest["topology"]["additionalTargets"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|target| (target["siteCode"].as_str(), target["hostHandle"].as_str())),
            )
            .filter_map(|(site, host)| (host == Some(producer_host)).then_some(site).flatten())
            .collect::<BTreeSet<_>>();
            (matching_sites.len() == 1)
                .then(|| matching_sites.into_iter().next().map(str::to_owned))
                .flatten()
        }
        _ => None,
    }
}

fn coverage_request_basis(
    manifest: &Value,
    source_id: &str,
    reason: &str,
) -> Option<ArtifactRequestBasis> {
    let matching = manifest["artifacts"]
        .as_array()?
        .iter()
        .filter(|artifact| {
            artifact["sourceId"].as_str() == Some(source_id)
                && match reason {
                    "coverageAbsent" => artifact["captureState"] == "absent",
                    "coverageCapped" => artifact["captureState"] == "capped",
                    "coverageRotationSplit" => {
                        matches!(
                            artifact["captureState"].as_str(),
                            Some("captured" | "capped")
                        ) && artifact["rotation"]["fragmentComplete"] == false
                    }
                    _ => false,
                }
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return None;
    }

    let directions = matching
        .iter()
        .map(|artifact| artifact["direction"].as_str())
        .collect::<Option<BTreeSet<_>>>()?;
    let target_sites = matching
        .iter()
        .map(|artifact| exact_target_site_for_artifact(manifest, artifact))
        .collect::<Option<BTreeSet<_>>>()?;
    let basenames = matching
        .iter()
        .map(|artifact| artifact["originalBasename"].as_str().map(str::to_owned))
        .collect::<Option<BTreeSet<_>>>()?;

    if target_sites.len() != 1 {
        return None;
    }
    if reason == "coverageRotationSplit" {
        let lineages = matching
            .iter()
            .map(|artifact| artifact["rotation"]["lineageId"].as_str())
            .collect::<Option<BTreeSet<_>>>()?;
        let canonical_rotation = matching.iter().all(|artifact| {
            matches!(
                (
                    artifact["originalBasename"].as_str(),
                    artifact["rotation"]["kind"].as_str(),
                    artifact["rotation"].get("value"),
                ),
                (Some("sender.log"), Some("current"), None)
                    | (Some("sender.lo_"), Some("loUnderscore"), None)
            )
        });
        let canonical_basenames =
            BTreeSet::from(["sender.lo_".to_owned(), "sender.log".to_owned()]);
        if matching.len() != 2
            || lineages.len() != 1
            || !canonical_rotation
            || basenames != canonical_basenames
        {
            return None;
        }
    }

    Some(ArtifactRequestBasis {
        source_id: source_id.to_owned(),
        direction: exact_request_direction(&directions)?,
        target_site_code: target_sites.into_iter().next()?,
        basenames: basenames.into_iter().collect(),
    })
}

fn invalid_offset_request_basis(scenario: &str, manifest: &Value) -> Option<ArtifactRequestBasis> {
    let mut source_ids = BTreeSet::new();
    let mut directions = BTreeSet::new();
    let mut target_sites = BTreeSet::new();
    let mut basenames = BTreeSet::new();

    for artifact in manifest["artifacts"].as_array()? {
        let state = artifact["captureState"].as_str()?;
        if !matches!(state, "captured" | "capped") {
            continue;
        }
        let artifact_id = artifact["artifactId"].as_str()?;
        let source_id = artifact["sourceId"].as_str()?;
        let direction = artifact["direction"].as_str()?;
        let basename = artifact["originalBasename"].as_str()?;
        let relative_path = artifact["relativePath"].as_str()?;
        if !safe_segmented_path(relative_path, "evidence/") {
            return None;
        }
        let content =
            std::fs::read_to_string(corpus_root().join(scenario).join(relative_path)).ok()?;
        let model = SccmArtifact {
            artifact_id: artifact_id.to_owned(),
            display_name: basename.to_owned(),
            original_path: None,
            host: artifact["producerHostHandle"].as_str().map(str::to_owned),
            role: SccmRole::SiteServer,
            configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
            collected_at_utc: artifact["collectedUtc"].as_str().map(str::to_owned),
            rotation: rotation(&artifact["rotation"])?,
            coverage: coverage_state(state)?,
            encoding: artifact["encoding"].as_str().map(str::to_owned),
        };
        for record in normalize_ccm_artifact(model, &content) {
            if record.timestamp.ordering_state != SccmTimeOrderingState::OffsetInvalid {
                continue;
            }
            let Ok(fields) = parse_fixture_fields(&record.message) else {
                continue;
            };
            let target_site = fields.get("TargetSite")?;
            source_ids.insert(source_id.to_owned());
            directions.insert(direction.to_owned());
            target_sites.insert(target_site.to_owned());
            basenames.insert(basename.to_owned());
        }
    }

    let direction_values = directions.iter().map(String::as_str).collect::<Vec<_>>();
    let direction = match direction_values.as_slice() {
        ["origin"] => "origin",
        ["target"] => "target",
        ["origin", "target"] => "both",
        _ => return None,
    };
    if source_ids.len() != 1 || target_sites.len() != 1 {
        return None;
    }
    Some(ArtifactRequestBasis {
        source_id: source_ids.into_iter().next()?,
        direction: direction.to_owned(),
        target_site_code: target_sites.into_iter().next()?,
        basenames: basenames.into_iter().collect(),
    })
}

fn derived_artifact_requests(
    scenario: &str,
    manifest: &Value,
) -> BTreeSet<ArtifactRequestContract> {
    let mut requests = BTreeSet::new();
    for source_id in ["server-hierarchy-control", "server-hierarchy-transfer"] {
        for reason_code in ["coverageAbsent", "coverageCapped", "coverageRotationSplit"] {
            if let Some(basis) = coverage_request_basis(manifest, source_id, reason_code) {
                requests.insert(ArtifactRequestContract {
                    basis,
                    reason_code: reason_code.to_owned(),
                });
            }
        }
    }
    if let Some(basis) = invalid_offset_request_basis(scenario, manifest) {
        requests.insert(ArtifactRequestContract {
            basis,
            reason_code: "invalidOffset".to_owned(),
        });
    }
    requests
}

fn declared_artifact_request(request: &Value) -> Option<ArtifactRequestContract> {
    Some(ArtifactRequestContract {
        basis: ArtifactRequestBasis {
            source_id: request["sourceId"].as_str()?.to_owned(),
            direction: request["direction"].as_str()?.to_owned(),
            target_site_code: request["targetSiteCode"].as_str()?.to_owned(),
            basenames: request["basenames"]
                .as_array()?
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()?,
        },
        reason_code: request["reasonCode"].as_str()?.to_owned(),
    })
}

fn artifact_request_failures(scenario: &str, manifest: &Value, expected: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    let Some(requests) = expected["artifactRequests"].as_array() else {
        failures.push(format!("{scenario}: artifact requests are not an array"));
        return failures;
    };
    let target_sites = declared_target_site_codes(manifest);
    let request_keys = requests
        .iter()
        .map(|request| {
            (
                request["sourceId"].as_str(),
                request["direction"].as_str(),
                request["targetSiteCode"].as_str(),
                request["reasonCode"].as_str(),
            )
        })
        .collect::<Vec<_>>();
    let mut sorted_request_keys = request_keys.clone();
    sorted_request_keys.sort_unstable();
    sorted_request_keys.dedup();
    if request_keys != sorted_request_keys {
        failures.push(format!("{scenario}: requests are not sorted and unique"));
    }

    for request in requests {
        if !object_has_only(
            request,
            &[
                "sourceId",
                "producerRole",
                "direction",
                "targetSiteCode",
                "basenames",
                "reasonCode",
            ],
        ) {
            failures.push(format!(
                "{scenario}: request has an unsupported field or shape"
            ));
        }
        let source_id = request["sourceId"].as_str();
        let direction = request["direction"].as_str();
        let target_site = request["targetSiteCode"].as_str();
        let reason = request["reasonCode"].as_str();
        let basename_values = request["basenames"].as_array();
        let basenames = basename_values
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut sorted_basenames = basenames.clone();
        sorted_basenames.sort_unstable();
        sorted_basenames.dedup();
        let source_owns_basenames = source_id.is_some_and(|source_id| {
            basenames.iter().all(|basename| {
                ["origin", "target"].iter().any(|direction| {
                    exact_source_tuple(source_id, basename, direction, "siteServer")
                })
            })
        });
        if request["producerRole"] != "siteServer"
            || !matches!(direction, Some("origin" | "target" | "both"))
            || target_site.is_none_or(|site| !target_sites.contains(site))
            || basename_values.is_none_or(|values| values.len() != basenames.len())
            || basenames.is_empty()
            || basenames != sorted_basenames
            || !source_owns_basenames
        {
            failures.push(format!("{scenario}: request is broad or malformed"));
            continue;
        }

        let actual_basis = ArtifactRequestBasis {
            source_id: source_id.unwrap_or_default().to_owned(),
            direction: direction.unwrap_or_default().to_owned(),
            target_site_code: target_site.unwrap_or_default().to_owned(),
            basenames: basenames.iter().map(|value| (*value).to_owned()).collect(),
        };
        let backed = match reason {
            Some("invalidOffset") => {
                invalid_offset_request_basis(scenario, manifest).as_ref() == Some(&actual_basis)
            }
            Some(reason @ ("coverageAbsent" | "coverageCapped" | "coverageRotationSplit")) => {
                coverage_request_basis(manifest, source_id.unwrap_or_default(), reason).as_ref()
                    == Some(&actual_basis)
            }
            _ => false,
        };
        if !backed {
            failures.push(format!(
                "{scenario}: request is not backed by exact coverage/time evidence"
            ));
        }
    }

    let declared_requests = requests
        .iter()
        .filter_map(declared_artifact_request)
        .collect::<BTreeSet<_>>();
    if declared_requests.len() != requests.len()
        || declared_requests != derived_artifact_requests(scenario, manifest)
    {
        failures.push(format!(
            "{scenario}: artifact requests are not the complete derived bounded set"
        ));
    }

    failures
}

fn identity_and_schema_failures(scenario: &str, manifest: &Value, expected: &Value) -> Vec<String> {
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
    ) || !object_has_only(
        &manifest["bundle"],
        &["bundleRole", "workflow", "capturedUtc"],
    ) || !object_has_only(
        &manifest["topology"],
        &[
            "originSiteCode",
            "targetSiteCode",
            "originHostHandle",
            "targetHostHandle",
            "additionalTargets",
            "rolesObserved",
        ],
    ) {
        failures.push("manifest contains an unsupported field or shape".to_owned());
    }
    if manifest["sccmManifestVersion"] != 1
        || manifest["proposalOnly"] != true
        || manifest["syntheticFixture"] != true
        || manifest["scenario"] != scenario
        || manifest["bundle"]["bundleRole"] != "server"
        || manifest["bundle"]["workflow"] != "hierarchyAndReplication"
        || manifest["bundle"]["capturedUtc"]
            .as_str()
            .is_none_or(|value| DateTime::parse_from_rfc3339(value).is_err())
    {
        failures.push("manifest loses the versioned synthetic preparation boundary".to_owned());
    }
    let topology = &manifest["topology"];
    let origin_host = topology["originHostHandle"].as_str();
    let primary_target_site = topology["targetSiteCode"].as_str();
    let primary_target_host = topology["targetHostHandle"].as_str();
    if topology["originSiteCode"]
        .as_str()
        .is_none_or(str::is_empty)
        || primary_target_site.is_none_or(str::is_empty)
        || origin_host.is_none_or(|value| !safe_server_handle(value))
        || primary_target_host.is_none_or(|value| !safe_server_handle(value))
        || origin_host == primary_target_host
    {
        failures.push("topology lacks exact safe origin/target identity".to_owned());
    }
    let mut topology_target_sites = BTreeSet::new();
    let mut topology_target_hosts = BTreeSet::new();
    let mut topology_target_host_by_site = BTreeMap::new();
    if let (Some(site), Some(host)) = (primary_target_site, primary_target_host) {
        topology_target_sites.insert(site);
        topology_target_hosts.insert(host);
        topology_target_host_by_site.insert(site, host);
    }
    if let Some(additional_targets) = topology.get("additionalTargets") {
        let Some(additional_targets) = additional_targets.as_array() else {
            failures.push("additional topology targets are not an array".to_owned());
            return failures;
        };
        for target in additional_targets {
            if !object_has_only(target, &["siteCode", "hostHandle"]) {
                failures.push("additional topology target has unsupported fields".to_owned());
                continue;
            }
            let site = target["siteCode"].as_str();
            let host = target["hostHandle"].as_str();
            if site.is_none_or(str::is_empty)
                || host.is_none_or(|value| !safe_server_handle(value))
                || host == origin_host
                || !topology_target_sites.insert(site.unwrap_or_default())
                || !topology_target_hosts.insert(host.unwrap_or_default())
            {
                failures.push("additional topology target is invalid or duplicated".to_owned());
            } else if let (Some(site), Some(host)) = (site, host) {
                topology_target_host_by_site.insert(site, host);
            }
        }
    }
    let role_values = manifest["topology"]["rolesObserved"].as_array();
    if role_values.is_none_or(|roles| {
        roles.len() != 1 || roles.iter().any(|role| role.as_str() != Some("siteServer"))
    }) {
        failures.push("topology roles are not exact strings".to_owned());
    }

    let artifacts = manifest["artifacts"].as_array();
    if artifacts.is_none() {
        failures.push("artifacts is not an array".to_owned());
    }
    let mut artifact_ids = Vec::new();
    let mut destinations = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    for artifact in artifacts.into_iter().flatten() {
        if !object_has_only(
            artifact,
            &[
                "artifactId",
                "sourceId",
                "producerRole",
                "producerHostHandle",
                "direction",
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
            failures.push("artifact contains an unsupported field or shape".to_owned());
        }
        let Some(artifact_id) = artifact["artifactId"]
            .as_str()
            .filter(|artifact_id| !artifact_id.is_empty())
        else {
            failures.push("artifactId is not a non-empty string".to_owned());
            continue;
        };
        artifact_ids.push(artifact_id);
        let state = artifact["captureState"].as_str();
        if state.and_then(coverage_state).is_none() {
            failures.push(format!("{artifact_id}: invalid coverage type/state"));
        }
        if artifact["producerRole"] != "siteServer"
            || !matches!(artifact["direction"].as_str(), Some("origin" | "target"))
            || !artifact_has_exact_source_tuple(artifact)
            || !artifact_has_exact_public_provenance(artifact)
            || artifact["collectedUtc"]
                .as_str()
                .is_none_or(|value| DateTime::parse_from_rfc3339(value).is_err())
        {
            failures.push(format!("{artifact_id}: invalid typed provenance"));
        }
        let direction = artifact["direction"].as_str();
        let producer_host = artifact["producerHostHandle"].as_str();
        match direction {
            Some("origin") if producer_host != topology["originHostHandle"].as_str() => {
                failures.push(format!(
                    "{artifact_id}: origin evidence host diverges from topology"
                ));
            }
            Some("target")
                if producer_host.is_none_or(|host| !topology_target_hosts.contains(host)) =>
            {
                failures.push(format!(
                    "{artifact_id}: target evidence host is outside topology"
                ));
            }
            _ => {}
        }
        if artifact["pathFingerprint"]
            .as_str()
            .map(str::to_ascii_lowercase)
            .is_none_or(|value| !fingerprints.insert(value))
        {
            failures.push(format!("{artifact_id}: duplicate or invalid fingerprint"));
        }
        if rotation(&artifact["rotation"]).is_none()
            || artifact["rotation"]["lineageId"]
                .as_str()
                .is_none_or(str::is_empty)
        {
            failures.push(format!("{artifact_id}: invalid rotation provenance"));
        }
        match state {
            Some("captured" | "capped" | "parseFailed") => {
                let relative_path = artifact["relativePath"].as_str();
                if relative_path.is_none_or(|value| !safe_segmented_path(value, "evidence/"))
                    || relative_path
                        .map(str::to_ascii_lowercase)
                        .is_none_or(|value| !destinations.insert(value))
                    || artifact["bytesCopied"].as_u64().is_none()
                    || artifact["encoding"] != "utf-8"
                    || artifact["collectionLimit"]["byteLimit"].as_u64().is_none()
                    || artifact["collectionLimit"]["limitApplied"]
                        .as_bool()
                        .is_none()
                    || artifact["rotation"]["fragmentComplete"].as_bool().is_none()
                {
                    failures.push(format!("{artifact_id}: invalid physical provenance"));
                }
                if direction == Some("target")
                    && relative_path.is_some_and(|path| safe_segmented_path(path, "evidence/"))
                    && producer_host.is_some()
                {
                    let path = corpus_root()
                        .join(scenario)
                        .join(relative_path.unwrap_or_default());
                    let Ok(content) = std::fs::read_to_string(path) else {
                        failures.push(format!(
                            "{artifact_id}: target evidence is unavailable for topology validation"
                        ));
                        continue;
                    };
                    let model = SccmArtifact {
                        artifact_id: artifact_id.to_owned(),
                        display_name: artifact["originalBasename"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                        original_path: None,
                        host: producer_host.map(str::to_owned),
                        role: SccmRole::SiteServer,
                        configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
                        collected_at_utc: artifact["collectedUtc"].as_str().map(str::to_owned),
                        rotation: rotation(&artifact["rotation"]).unwrap_or(SccmRotation::Current),
                        coverage: state
                            .and_then(coverage_state)
                            .unwrap_or(SccmCoverageState::ParseFailed),
                        encoding: Some("utf-8".to_owned()),
                    };
                    for record in normalize_ccm_artifact(model, &content) {
                        let Ok(fields) = parse_fixture_fields(&record.message) else {
                            continue;
                        };
                        let target_site = fields.get("TargetSite").map(String::as_str);
                        if target_site
                            .and_then(|site| topology_target_host_by_site.get(site).copied())
                            != producer_host
                        {
                            failures.push(format!(
                                "{artifact_id}: target evidence host does not match record topology"
                            ));
                        }
                    }
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
                        "{artifact_id}: nonphysical state invents physical provenance"
                    ));
                }
            }
            _ => {}
        }
    }
    let mut sorted_artifact_ids = artifact_ids.clone();
    sorted_artifact_ids.sort_unstable();
    sorted_artifact_ids.dedup();
    if artifact_ids != sorted_artifact_ids {
        failures.push("artifact IDs are not sorted and unique".to_owned());
    }

    let manifest_coverage = artifacts
        .into_iter()
        .flatten()
        .map(|artifact| {
            artifact["artifactId"]
                .as_str()
                .zip(artifact["captureState"].as_str())
        })
        .collect::<Option<Vec<_>>>();
    let coverage_values = expected["coverage"].as_array();
    let declared_coverage = coverage_values.and_then(|rows| {
        rows.iter()
            .map(|row| {
                if !object_has_only(row, &["artifactId", "state"]) {
                    return None;
                }
                row["artifactId"]
                    .as_str()
                    .filter(|artifact_id| !artifact_id.is_empty())
                    .zip(row["state"].as_str())
            })
            .collect::<Option<Vec<_>>>()
    });
    if manifest_coverage.as_ref() != declared_coverage.as_ref()
        || declared_coverage.as_ref().is_some_and(|rows| {
            rows.iter()
                .any(|(_, state)| coverage_state(state).is_none())
        })
    {
        failures.push("coverage rows are not the exact typed manifest projection".to_owned());
    }

    if !object_has_only(
        expected,
        &[
            "contractState",
            "workflow",
            "scenario",
            "stateChain",
            "analysisContract",
            "extractionProfile",
            "coverage",
            "transactions",
            "sourceLocalObservations",
            "artifactRequests",
            "crossSideCausalClaims",
            "correlationHandoff",
        ],
    ) || expected["contractState"] != "proposedPendingReviewed318And335"
        || expected["workflow"] != "hierarchyAndReplication"
        || expected["scenario"] != scenario
    {
        failures.push("expected output loses the preparation boundary".to_owned());
    }
    let state_values = expected["stateChain"].as_array();
    let state_chain = state_values
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if state_values.is_none_or(|values| values.len() != state_chain.len())
        || state_chain != STATE_CHAIN
    {
        failures.push("state chain is not exact typed #331 grammar".to_owned());
    }
    if expected["analysisContract"]["independentReducer"] != true
        || expected["analysisContract"]["crossSideCorrelationPerformed"] != false
        || expected["analysisContract"]["nativeCollectionPerformed"] != false
        || expected["extractionProfile"]["selectionState"] != "selectedSynthetic"
        || expected["extractionProfile"]["profileId"] != EXACT_PROFILE
        || expected["extractionProfile"]["validatedRole"] != "siteServer"
        || expected["crossSideCausalClaims"] != Value::Array(Vec::new())
        || expected["correlationHandoff"]["issue"] != "#333"
        || expected["correlationHandoff"]["performed"] != false
        || expected["correlationHandoff"]["timeOnlyEligible"] != false
    {
        failures
            .push("expected output enables unsupported production/correlation state".to_owned());
    }

    let normalized = match try_normalized_records(scenario, manifest) {
        Ok(records) => records,
        Err(error) => {
            failures.push(error);
            BTreeMap::new()
        }
    };
    let artifact_by_id = artifacts
        .into_iter()
        .flatten()
        .filter_map(|artifact| {
            artifact["artifactId"]
                .as_str()
                .map(|artifact_id| (artifact_id, artifact))
        })
        .collect::<BTreeMap<_, _>>();

    let transactions = expected["transactions"].as_array();
    let transaction_ids = transactions
        .into_iter()
        .flatten()
        .filter_map(|transaction| transaction["transactionId"].as_str())
        .collect::<Vec<_>>();
    if transaction_ids != expected_transaction_ids(scenario) {
        failures.push("transaction identity/cardinality matrix changed".to_owned());
    }
    for transaction in transactions.into_iter().flatten() {
        if !object_has_only(
            transaction,
            &[
                "transactionId",
                "key",
                "topologyCompatibility",
                "timestampOrdering",
                "terminalEvidence",
                "state",
                "classification",
                "confidence",
                "confidenceCeiling",
                "coverageGapArtifactIds",
                "observations",
            ],
        ) || !object_has_only(
            &transaction["key"],
            &[
                "messageId",
                "linkId",
                "originSiteCode",
                "targetSiteCode",
                "confidence",
                "extractionProfileId",
            ],
        ) {
            failures.push("transaction contains an unsupported field or shape".to_owned());
        }
        let transaction_id = transaction["transactionId"].as_str().unwrap_or_default();
        let key = &transaction["key"];
        let derived_id = [
            key["messageId"].as_str(),
            key["originSiteCode"].as_str(),
            key["targetSiteCode"].as_str(),
            key["linkId"].as_str(),
        ];
        if derived_id
            .iter()
            .any(|value| value.is_none_or(str::is_empty))
            || key["confidence"] != "exact"
            || key["extractionProfileId"] != EXACT_PROFILE
            || transaction_id
                != format!(
                    "hierarchy:{}:{}:{}:{}",
                    derived_id[0].unwrap_or_default(),
                    derived_id[1].unwrap_or_default(),
                    derived_id[2].unwrap_or_default(),
                    derived_id[3].unwrap_or_default()
                )
        {
            failures.push("transaction is not derived from one exact immutable key".to_owned());
        }
        if key["originSiteCode"].as_str() != topology["originSiteCode"].as_str()
            || key["targetSiteCode"]
                .as_str()
                .is_none_or(|site| !topology_target_sites.contains(site))
        {
            failures.push("transaction key is outside declared topology".to_owned());
        }
        if !transaction_semantics_are_coherent(transaction) {
            failures
                .push("transaction state/classification is not derived from its facts".to_owned());
        }
        let gap_values = transaction["coverageGapArtifactIds"].as_array();
        let gap_ids = gap_values
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|artifact_id| !artifact_id.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut sorted_gap_ids = gap_ids.clone();
        sorted_gap_ids.sort_unstable();
        sorted_gap_ids.dedup();
        if gap_values.is_none_or(|values| values.len() != gap_ids.len())
            || gap_ids != sorted_gap_ids
        {
            failures.push("coverage gap IDs are not exact sorted strings".to_owned());
        }
        for gap_id in &gap_ids {
            let manifest_matches = artifacts
                .into_iter()
                .flatten()
                .filter(|artifact| artifact["artifactId"].as_str() == Some(*gap_id))
                .collect::<Vec<_>>();
            let coverage_matches = coverage_values
                .into_iter()
                .flatten()
                .filter(|row| row["artifactId"].as_str() == Some(*gap_id))
                .collect::<Vec<_>>();
            if manifest_matches.len() != 1
                || coverage_matches.len() != 1
                || manifest_matches[0]["captureState"]
                    .as_str()
                    .and_then(coverage_state)
                    .is_none()
                || manifest_matches[0]["captureState"] == "captured"
                || coverage_matches[0]["state"] != manifest_matches[0]["captureState"]
            {
                failures
                    .push("coverage gap does not close against one non-captured row".to_owned());
            }
        }
        if transaction["confidence"] == "high"
            && (transaction["confidenceCeiling"] != "high"
                || transaction["topologyCompatibility"] != "exact"
                || transaction["timestampOrdering"] != "usable"
                || transaction["terminalEvidence"] != true
                || !gap_ids.is_empty())
        {
            failures
                .push("high confidence bypasses topology/time/terminal/coverage gates".to_owned());
        }
        let mut cited_gap_ids = BTreeSet::new();
        let observations = transaction["observations"].as_array();
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
                failures.push("observation contains an unsupported field or shape".to_owned());
            }
            if observation["observationId"]
                .as_str()
                .is_none_or(str::is_empty)
            {
                failures.push("transaction observation has an empty identity".to_owned());
            }
            let references = observation["evidence"].as_array();
            if references.is_none_or(Vec::is_empty) {
                failures.push("transaction observation lacks cited evidence".to_owned());
            }
            for reference in references.into_iter().flatten() {
                if !object_has_only(reference, &["artifactId", "startLine", "endLine"])
                    || evidence_reference_key(reference).is_none()
                {
                    failures.push("evidence reference is not exact and typed".to_owned());
                    continue;
                }
                let reference_key =
                    evidence_reference_key(reference).expect("typed reference was checked");
                let Some(artifact) = artifact_by_id.get(reference_key.0.as_str()).copied() else {
                    failures.push(
                        "transaction evidence does not name one manifest artifact".to_owned(),
                    );
                    continue;
                };
                if artifact["captureState"] != "captured"
                    || artifact["rotation"]["fragmentComplete"] != true
                {
                    cited_gap_ids.insert(reference_key.0.clone());
                }
                let Some(record) = normalized.get(&reference_key) else {
                    failures.push(
                        "transaction evidence does not close against one logical record".to_owned(),
                    );
                    continue;
                };
                if !observation_matches_record(manifest, artifact, transaction, observation, record)
                {
                    failures.push(
                        "transaction observation semantics diverge from cited evidence".to_owned(),
                    );
                }
                if transaction["confidence"] == "high"
                    && record.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
                {
                    failures.push(
                        "high transaction cites evidence without usable timestamp provenance"
                            .to_owned(),
                    );
                }
            }
        }
        let declared_gap_ids = gap_ids.iter().copied().collect::<BTreeSet<_>>();
        if cited_gap_ids
            .iter()
            .any(|artifact_id| !declared_gap_ids.contains(artifact_id.as_str()))
        {
            failures.push(
                "cited incomplete coverage is missing from the derived transaction gaps".to_owned(),
            );
        }
        if transaction["confidence"] == "high" && !cited_gap_ids.is_empty() {
            failures.push("high transaction cites incomplete coverage".to_owned());
        }
    }
    let observation_ids = transactions
        .into_iter()
        .flatten()
        .flat_map(|transaction| transaction["observations"].as_array().into_iter().flatten())
        .filter_map(|observation| observation["observationId"].as_str())
        .collect::<Vec<_>>();
    if observation_ids != expected_observation_ids(scenario) {
        failures.push("observation identity/cardinality matrix changed".to_owned());
    }
    let source_local_observations = expected["sourceLocalObservations"].as_array();
    for observation in source_local_observations.into_iter().flatten() {
        if !object_has_only(
            observation,
            &[
                "observationId",
                "classification",
                "confidence",
                "correlationEligible",
                "artifactIds",
                "evidence",
            ],
        ) || observation["observationId"]
            .as_str()
            .is_none_or(str::is_empty)
        {
            failures.push("source-local observation has an invalid shape or identity".to_owned());
        }
        let artifact_id_values = observation["artifactIds"].as_array();
        let source_local_artifact_ids = artifact_id_values
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|artifact_id| !artifact_id.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut sorted_source_local_artifact_ids = source_local_artifact_ids.clone();
        sorted_source_local_artifact_ids.sort_unstable();
        sorted_source_local_artifact_ids.dedup();
        if artifact_id_values.is_none_or(|values| {
            values.len() != source_local_artifact_ids.len() || source_local_artifact_ids.is_empty()
        }) || source_local_artifact_ids != sorted_source_local_artifact_ids
            || source_local_artifact_ids
                .iter()
                .any(|artifact_id| !artifact_ids.contains(artifact_id))
        {
            failures.push("source-local artifact IDs are not exact closed identities".to_owned());
        }
        let source_local_artifacts = source_local_artifact_ids
            .iter()
            .map(|artifact_id| artifact_by_id.get(artifact_id).copied())
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        let classification = observation["classification"].as_str();
        let exact_backing = match classification {
            Some("coverageOnly") => {
                !source_local_artifacts.is_empty()
                    && source_local_artifacts.iter().all(|artifact| {
                        artifact["captureState"] == "capped"
                            && artifact["rotation"]["fragmentComplete"] == false
                    })
            }
            Some("rotationSplit") => {
                let lineages = source_local_artifacts
                    .iter()
                    .filter_map(|artifact| artifact["rotation"]["lineageId"].as_str())
                    .collect::<BTreeSet<_>>();
                let basenames = source_local_artifacts
                    .iter()
                    .filter_map(|artifact| artifact["originalBasename"].as_str())
                    .collect::<BTreeSet<_>>();
                source_local_artifacts.len() == 2
                    && lineages.len() == 1
                    && basenames == BTreeSet::from(["sender.lo_", "sender.log"])
                    && source_local_artifacts.iter().all(|artifact| {
                        artifact["captureState"] == "captured"
                            && artifact["rotation"]["fragmentComplete"] == false
                    })
            }
            Some("topologyMismatch") => {
                !source_local_artifacts.is_empty()
                    && source_local_artifacts.iter().all(|artifact| {
                        artifact["captureState"] == "captured"
                            && artifact["rotation"]["fragmentComplete"] == true
                    })
            }
            _ => false,
        };
        if observation["confidence"] != "low"
            || observation["correlationEligible"] != false
            || !exact_backing
        {
            failures.push(
                "source-local observation exceeds its exact low-confidence backing".to_owned(),
            );
        }
        let references = observation["evidence"].as_array();
        if references.is_none()
            || matches!(classification, Some("coverageOnly" | "rotationSplit"))
                && references.is_some_and(|values| !values.is_empty())
            || classification == Some("topologyMismatch") && references.is_none_or(Vec::is_empty)
        {
            failures.push("source-local evidence does not match its classification".to_owned());
        }
        for reference in references.into_iter().flatten() {
            if !object_has_only(reference, &["artifactId", "startLine", "endLine"])
                || evidence_reference_key(reference).is_none()
            {
                failures.push("source-local evidence reference is not exact and typed".to_owned());
                continue;
            }
            let reference_key =
                evidence_reference_key(reference).expect("typed reference was checked");
            if !source_local_artifact_ids.contains(&reference_key.0.as_str())
                || !normalized.contains_key(&reference_key)
            {
                failures.push(
                    "source-local evidence does not close against its declared artifacts"
                        .to_owned(),
                );
            }
        }
    }
    let source_local_ids = source_local_observations
        .into_iter()
        .flatten()
        .filter_map(|observation| observation["observationId"].as_str())
        .collect::<Vec<_>>();
    if source_local_ids != expected_source_local_ids(scenario) {
        failures.push("source-local identity/cardinality matrix changed".to_owned());
    }

    failures.extend(artifact_request_failures(scenario, manifest, expected));

    failures
}

#[test]
fn hierarchy_and_replication_scenario_matrix_is_exact() {
    assert_eq!(
        actual_scenarios().expect("hierarchy corpus root exists"),
        SCENARIOS,
        "the #331 scenario matrix changed"
    );

    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        assert_eq!(manifest["scenario"], *scenario);
        assert_eq!(expected["scenario"], *scenario);
        assert_eq!(manifest["proposalOnly"], true);
        assert_eq!(manifest["syntheticFixture"], true);
        assert_eq!(expected["extractionProfile"]["profileId"], EXACT_PROFILE);
        assert_eq!(
            expected["stateChain"]
                .as_array()
                .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .as_deref(),
            Some(STATE_CHAIN)
        );
    }
}

#[test]
fn hierarchy_candidates_are_deterministic_and_collision_resistant() {
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let artifacts = manifest["artifacts"]
            .as_array()
            .unwrap_or_else(|| panic!("{scenario}: artifacts are an array"));
        let ids = artifacts
            .iter()
            .filter_map(|artifact| artifact["artifactId"].as_str())
            .collect::<Vec<_>>();
        let mut sorted_ids = ids.clone();
        sorted_ids.sort_unstable();
        assert_eq!(ids, sorted_ids, "{scenario}: artifacts are stably sorted");
        assert_eq!(
            ids.iter().copied().collect::<BTreeSet<_>>().len(),
            ids.len(),
            "{scenario}: artifact IDs are unique"
        );

        let canonical = hierarchy_candidate_bytes(scenario, &manifest)
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let mut reversed_manifest = manifest.clone();
        reversed_manifest["artifacts"]
            .as_array_mut()
            .expect("artifacts are mutable")
            .reverse();
        let reversed = hierarchy_candidate_bytes(scenario, &reversed_manifest)
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        assert_eq!(
            canonical, reversed,
            "{scenario}: input order changed byte-identical candidate output"
        );
    }

    let manifest = read_json("healthy-link", "manifest.json").expect("healthy manifest loads");
    let mut artifacts = manifest["artifacts"]
        .as_array()
        .expect("healthy artifacts are an array")
        .clone();
    let mut collision = artifacts[1].clone();
    collision["artifactId"] = Value::String("healthy-05-sender-numbered".to_owned());
    collision["pathFingerprint"] = Value::String("synthetic:healthy-sender-numbered".to_owned());
    collision["rotation"] = serde_json::json!({
        "kind": "numbered",
        "value": 1,
        "lineageId": "healthy-sender-numbered",
        "fragmentComplete": true
    });
    artifacts.push(collision);
    let mut collision_manifest = manifest.clone();
    collision_manifest["artifacts"] = Value::Array(artifacts.clone());
    let groups = hierarchy_candidate_groups("healthy-link", &collision_manifest)
        .expect("candidates project");
    let exact_groups = groups
        .iter()
        .filter(|group| {
            group.key.message_id == "msg-healthy-01"
                && group.key.link_id == "link-lab-chd"
                && group.key.origin_site_code == "LAB"
                && group.key.target_site_code == "CHD"
        })
        .collect::<Vec<_>>();
    assert_eq!(
        exact_groups.len(),
        1,
        "same-key evidence must form one candidate group"
    );
    let colliding_sender_facts = exact_groups[0]
        .facts
        .iter()
        .filter(|fact| fact.phase == "send")
        .collect::<Vec<_>>();
    assert_eq!(
        colliding_sender_facts.len(),
        2,
        "same-key sender facts with distinct rotation provenance must both survive"
    );
    assert_ne!(
        colliding_sender_facts[0].artifact_id,
        colliding_sender_facts[1].artifact_id
    );
    assert_ne!(
        colliding_sender_facts[0].rotation_kind,
        colliding_sender_facts[1].rotation_kind
    );
    let canonical = hierarchy_candidate_bytes("healthy-link", &collision_manifest)
        .expect("candidates serialize");
    collision_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are mutable")
        .reverse();
    let reversed = hierarchy_candidate_bytes("healthy-link", &collision_manifest)
        .expect("candidates serialize");
    assert_eq!(
        canonical, reversed,
        "provenance collision changed canonical candidate bytes"
    );
}

#[test]
fn generic_ccm_site_code_token_cannot_create_a_hierarchy_candidate() {
    let scenario = "generic-site-token";
    let manifest =
        read_json(scenario, "manifest.json").unwrap_or_else(|error| panic!("{scenario}: {error}"));
    let expected =
        read_json(scenario, "expected.json").unwrap_or_else(|error| panic!("{scenario}: {error}"));
    let records = normalized_records(scenario, &manifest);
    assert_eq!(records.len(), 1, "generic CCM evidence remains observable");
    let record = records.values().next().expect("generic evidence exists");
    assert!(
        record.message.contains("CHD"),
        "negative contains a site-code-looking token"
    );
    assert!(
        parse_fixture_fields(&record.message).is_err(),
        "generic CCM text must not satisfy the exact hierarchy grammar"
    );
    let candidates =
        hierarchy_candidate_groups(scenario, &manifest).expect("generic artifacts project safely");
    assert!(
        candidates.is_empty(),
        "a site-code-looking token alone created a hierarchy candidate"
    );
    assert_eq!(expected["transactions"], Value::Array(Vec::new()));
}

#[test]
fn hierarchy_outputs_never_promote_coverage_or_time_to_cause() {
    for scenario in SCENARIOS {
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        assert_eq!(expected["crossSideCausalClaims"], Value::Array(Vec::new()));
        assert_eq!(expected["correlationHandoff"]["performed"], false);
        assert_eq!(expected["correlationHandoff"]["timeOnlyEligible"], false);

        let coverage = expected["coverage"]
            .as_array()
            .unwrap_or_else(|| panic!("{scenario}: coverage is an array"));
        for transaction in expected["transactions"]
            .as_array()
            .unwrap_or_else(|| panic!("{scenario}: transactions are an array"))
        {
            let confidence = transaction["confidence"].as_str().unwrap_or_default();
            let gaps = transaction["coverageGapArtifactIds"]
                .as_array()
                .unwrap_or_else(|| panic!("{scenario}: coverage gaps are an array"));
            if confidence == "high" {
                assert!(
                    gaps.is_empty(),
                    "{scenario}: high confidence retained a coverage gap"
                );
                assert_eq!(transaction["topologyCompatibility"], "exact");
                assert_eq!(transaction["timestampOrdering"], "usable");
                assert_eq!(transaction["terminalEvidence"], true);
            }
            for gap in gaps {
                let artifact_id = gap
                    .as_str()
                    .unwrap_or_else(|| panic!("{scenario}: gap ID is a string"));
                let matches = coverage
                    .iter()
                    .filter(|row| row["artifactId"].as_str() == Some(artifact_id))
                    .collect::<Vec<_>>();
                assert_eq!(
                    matches.len(),
                    1,
                    "{scenario}: gap must close against exactly one coverage row"
                );
                assert!(
                    matches[0]["state"]
                        .as_str()
                        .and_then(coverage_state)
                        .is_some()
                        && matches[0]["state"] != "captured",
                    "{scenario}: gap row must have a typed non-captured state"
                );
            }
        }
    }
}

#[test]
fn hierarchy_manifest_sources_and_physical_evidence_are_bounded() {
    let mut failures = Vec::new();
    for scenario in SCENARIOS {
        let scenario_root = corpus_root().join(scenario);
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        if manifest["sccmManifestVersion"] != 1
            || manifest["bundle"]["bundleRole"] != "server"
            || manifest["bundle"]["workflow"] != "hierarchyAndReplication"
        {
            failures.push(format!(
                "{scenario}: manifest loses the additive server boundary"
            ));
        }
        if DateTime::parse_from_rfc3339(
            manifest["bundle"]["capturedUtc"]
                .as_str()
                .unwrap_or_default(),
        )
        .is_err()
        {
            failures.push(format!("{scenario}: capture time is not RFC3339"));
        }
        let roles = manifest["topology"]["rolesObserved"].as_array();
        if roles.is_none_or(|values| {
            values.len() != 1 || values.first().and_then(Value::as_str) != Some("siteServer")
        }) {
            failures.push(format!("{scenario}: topology roles are not exact strings"));
        }

        let mut destinations = BTreeSet::new();
        let mut fingerprints = BTreeSet::new();
        let artifacts = manifest["artifacts"]
            .as_array()
            .unwrap_or_else(|| panic!("{scenario}: artifacts are an array"));
        for artifact in artifacts {
            let artifact_id =
                required_string(artifact, "artifactId", scenario).unwrap_or("<invalid>");
            let context = format!("{scenario}/{artifact_id}");
            let role = required_string(artifact, "producerRole", &context).unwrap_or("invalid");
            let basename =
                required_string(artifact, "originalBasename", &context).unwrap_or("invalid");
            let direction = required_string(artifact, "direction", &context).unwrap_or("invalid");
            let state = required_string(artifact, "captureState", &context).unwrap_or("invalid");
            let source_id = required_string(artifact, "sourceId", &context).unwrap_or("invalid");
            if role != "siteServer"
                || !matches!(direction, "origin" | "target")
                || !matches!(
                    (source_id, basename),
                    ("server-hierarchy-control", "replmgr.log" | "rcmctrl.log")
                        | (
                            "server-hierarchy-transfer",
                            "sender.log" | "sender.lo_" | "despool.log"
                        )
                )
            {
                failures.push(format!("{context}: uncatalogued source tuple"));
            }
            let catalog = classify_artifact_name(basename, SccmRole::SiteServer);
            if catalog.family != SccmArtifactFamily::Hierarchy || !catalog.uses_ccm_records {
                failures.push(format!(
                    "{context}: source escapes the raw CCM hierarchy catalog"
                ));
            }
            if !artifact_has_exact_public_provenance(artifact) {
                failures.push(format!("{context}: unsafe or empty provenance"));
            }
            if artifact["pathFingerprint"]
                .as_str()
                .map(str::to_ascii_lowercase)
                .is_some_and(|value| !fingerprints.insert(value))
            {
                failures.push(format!("{context}: duplicate physical fingerprint"));
            }
            let Some(coverage) = coverage_state(state) else {
                failures.push(format!("{context}: unknown coverage state"));
                continue;
            };
            let Some(rotation) = rotation(&artifact["rotation"]) else {
                failures.push(format!("{context}: invalid rotation shape"));
                continue;
            };
            let physical = matches!(state, "captured" | "capped" | "parseFailed");
            if physical {
                let relative_path = artifact["relativePath"].as_str().unwrap_or_default();
                if !safe_segmented_path(relative_path, "evidence/")
                    || !destinations.insert(relative_path.to_ascii_lowercase())
                    || artifact["encoding"] != "utf-8"
                    || artifact["bytesCopied"].as_u64().is_none()
                    || artifact["collectionLimit"]["byteLimit"].as_u64().is_none()
                    || artifact["collectionLimit"]["limitApplied"]
                        .as_bool()
                        .is_none()
                {
                    failures.push(format!("{context}: invalid physical storage provenance"));
                    continue;
                }
                let path = scenario_root.join(relative_path);
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        failures.push(format!("{} is readable: {error}", path.display()));
                        continue;
                    }
                };
                if artifact["bytesCopied"].as_u64() != Some(bytes.len() as u64)
                    || !String::from_utf8_lossy(&bytes).contains("SYNTHETIC FIXTURE")
                {
                    failures.push(format!("{context}: physical bytes are not exact/synthetic"));
                }
                let model = SccmArtifact {
                    artifact_id: artifact_id.to_owned(),
                    display_name: basename.to_owned(),
                    original_path: None,
                    host: artifact["producerHostHandle"].as_str().map(str::to_owned),
                    role: SccmRole::SiteServer,
                    configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
                    collected_at_utc: artifact["collectedUtc"].as_str().map(str::to_owned),
                    rotation,
                    coverage,
                    encoding: Some("utf-8".to_owned()),
                };
                let normalized = normalize_ccm_artifact(model, &String::from_utf8_lossy(&bytes));
                if artifact["rotation"]["fragmentComplete"] == false && !normalized.is_empty() {
                    failures.push(format!(
                        "{context}: incomplete rotation fragment emitted a logical record"
                    ));
                }
                if artifact["rotation"]["fragmentComplete"] == true
                    && normalized.iter().any(|record| {
                        !record.message.contains("SYNTHETIC FIXTURE")
                            || record.reference.line_start.is_none()
                            || record.reference.line_end.is_none()
                    })
                {
                    failures.push(format!("{context}: logical evidence is not line-cited"));
                }
            } else if artifact.get("relativePath").is_some()
                || artifact.get("bytesCopied").is_some()
                || artifact.get("encoding").is_some()
                || artifact.get("collectionLimit").is_some()
                || artifact["rotation"].get("fragmentComplete").is_some()
            {
                failures.push(format!(
                    "{context}: nonphysical coverage invents file provenance"
                ));
            }
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn hierarchy_transactions_require_exact_keys_topology_time_and_citations() {
    let mut failures = Vec::new();
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let records = normalized_records(scenario, &manifest);
        let artifacts = manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
            .iter()
            .filter_map(|artifact| {
                Some((
                    artifact["artifactId"].as_str()?.to_owned(),
                    artifact.clone(),
                ))
            })
            .collect::<BTreeMap<_, _>>();

        let manifest_coverage = artifacts
            .iter()
            .filter_map(|(artifact_id, artifact)| {
                Some((
                    artifact_id.clone(),
                    artifact["captureState"].as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        let declared_coverage = expected["coverage"]
            .as_array()
            .expect("expected coverage is an array")
            .iter()
            .filter_map(|row| {
                Some((
                    row["artifactId"].as_str()?.to_owned(),
                    row["state"].as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        if manifest_coverage != declared_coverage {
            failures.push(format!(
                "{scenario}: coverage is not the exact manifest projection"
            ));
        }

        let transactions = expected["transactions"]
            .as_array()
            .expect("transactions are an array");
        let declared_target_sites = declared_target_site_codes(&manifest);
        let transaction_ids = transactions
            .iter()
            .filter_map(|transaction| transaction["transactionId"].as_str())
            .collect::<Vec<_>>();
        let mut sorted_transaction_ids = transaction_ids.clone();
        sorted_transaction_ids.sort_unstable();
        sorted_transaction_ids.dedup();
        if transaction_ids != sorted_transaction_ids {
            failures.push(format!(
                "{scenario}: transactions are not sorted and unique"
            ));
        }

        for transaction in transactions {
            let transaction_id = transaction["transactionId"].as_str().unwrap_or("<invalid>");
            let key = &transaction["key"];
            let key_fields = [
                ("MessageId", key["messageId"].as_str()),
                ("LinkId", key["linkId"].as_str()),
                ("OriginSite", key["originSiteCode"].as_str()),
                ("TargetSite", key["targetSiteCode"].as_str()),
                ("ProfileId", key["extractionProfileId"].as_str()),
            ];
            if key_fields
                .iter()
                .any(|(_, value)| value.is_none_or(str::is_empty))
                || key["confidence"] != "exact"
                || key["extractionProfileId"] != EXACT_PROFILE
            {
                failures.push(format!("{scenario}/{transaction_id}: key is not exact"));
                continue;
            }
            if key["originSiteCode"].as_str() != manifest["topology"]["originSiteCode"].as_str()
                || key["targetSiteCode"]
                    .as_str()
                    .is_none_or(|site| !declared_target_sites.contains(site))
            {
                failures.push(format!(
                    "{scenario}/{transaction_id}: key is outside declared topology"
                ));
            }
            let derived_id = format!(
                "hierarchy:{}:{}:{}:{}",
                key["messageId"].as_str().unwrap_or_default(),
                key["originSiteCode"].as_str().unwrap_or_default(),
                key["targetSiteCode"].as_str().unwrap_or_default(),
                key["linkId"].as_str().unwrap_or_default()
            );
            if transaction_id != derived_id {
                failures.push(format!(
                    "{scenario}/{transaction_id}: ID is not key-derived"
                ));
            }

            let observations = transaction["observations"]
                .as_array()
                .expect("transaction observations are an array");
            let observation_ids = observations
                .iter()
                .filter_map(|observation| observation["observationId"].as_str())
                .collect::<Vec<_>>();
            let mut sorted_observation_ids = observation_ids.clone();
            sorted_observation_ids.sort_unstable();
            sorted_observation_ids.dedup();
            if observation_ids != sorted_observation_ids || observation_ids.is_empty() {
                failures.push(format!(
                    "{scenario}/{transaction_id}: observations are not exact sorted identities"
                ));
            }

            let mut prior_phase = 0usize;
            let mut prior_utc = i64::MIN;
            let mut cited_terminal = false;
            let mut cited_records = BTreeSet::new();
            for observation in observations {
                let observation_id = observation["observationId"].as_str().unwrap_or("<invalid>");
                let phase = observation["phase"].as_str().unwrap_or("invalid");
                let disposition = observation["disposition"].as_str().unwrap_or("invalid");
                let terminal = observation["terminal"].as_bool().unwrap_or(false);
                let Some(phase_index) =
                    STATE_CHAIN.iter().position(|candidate| *candidate == phase)
                else {
                    failures.push(format!("{scenario}/{observation_id}: unsupported phase"));
                    continue;
                };
                if phase_index < prior_phase {
                    failures.push(format!(
                        "{scenario}/{transaction_id}: backward phase ordering"
                    ));
                }
                prior_phase = phase_index;
                if !observation_disposition_is_coherent(disposition, terminal) {
                    failures.push(format!(
                        "{scenario}/{observation_id}: incoherent disposition/terminality"
                    ));
                }
                cited_terminal |= terminal;

                let references = observation["evidence"]
                    .as_array()
                    .expect("observation evidence is an array");
                if references.is_empty() {
                    failures.push(format!("{scenario}/{observation_id}: no evidence"));
                }
                for reference in references {
                    let artifact_id = reference["artifactId"].as_str().unwrap_or_default();
                    let line_start = reference["startLine"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok());
                    let line_end = reference["endLine"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok());
                    let Some(record) = line_start.zip(line_end).and_then(|(start, end)| {
                        records.get(&(artifact_id.to_owned(), start, end))
                    }) else {
                        failures.push(format!(
                            "{scenario}/{observation_id}: evidence is not a physical logical record"
                        ));
                        continue;
                    };
                    if !cited_records.insert((
                        artifact_id.to_owned(),
                        line_start.unwrap_or_default(),
                        line_end.unwrap_or_default(),
                    )) {
                        failures.push(format!(
                            "{scenario}/{transaction_id}: physical evidence reused"
                        ));
                    }
                    let Some(artifact) = artifacts.get(artifact_id) else {
                        failures.push(format!("{scenario}/{observation_id}: unknown artifact"));
                        continue;
                    };
                    if !phase_is_owned_by(
                        artifact["originalBasename"].as_str().unwrap_or_default(),
                        phase,
                    ) {
                        failures.push(format!(
                            "{scenario}/{observation_id}: source cannot own phase {phase}"
                        ));
                    }
                    let fields = match parse_fixture_fields(&record.message) {
                        Ok(fields) => fields,
                        Err(error) => {
                            failures.push(format!("{scenario}/{observation_id}: {error}"));
                            continue;
                        }
                    };
                    for (field, value) in &key_fields {
                        if fields.get(*field).map(String::as_str) != *value {
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
                                    "{scenario}/{transaction_id}: unusable or reversed time"
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
                                    "{scenario}/{transaction_id}: invalid offset was treated as usable"
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

        let outcome = transactions
            .iter()
            .map(|transaction| {
                (
                    transaction["state"].as_str(),
                    transaction["classification"].as_str(),
                    transaction["confidence"].as_str(),
                )
            })
            .collect::<Vec<_>>();
        let expected_outcome: &[(Option<&str>, Option<&str>, Option<&str>)] = match *scenario {
            "absent-remote-source" | "clock-offset-unknown" => &[(
                Some("incomplete"),
                Some("insufficientEvidence"),
                Some("low"),
            )],
            "backlog-retry" => &[(Some("deferred"), Some("blockedOrDeferred"), Some("medium"))],
            "healthy-link" => &[(Some("succeeded"), Some("success"), Some("high"))],
            "incomplete" | "rotation-boundary" | "topology-mismatch" => &[],
            "receiver-processing-failure" => {
                &[(Some("failed"), Some("confirmedFailure"), Some("high"))]
            }
            "recovery" => &[(Some("recovered"), Some("success"), Some("high"))],
            "sender-failure" => &[
                (Some("failed"), Some("confirmedFailure"), Some("high")),
                (Some("failed"), Some("confirmedFailure"), Some("high")),
            ],
            _ => &[],
        };
        if outcome != expected_outcome {
            failures.push(format!("{scenario}: outcome matrix changed"));
        }

        if *scenario == "topology-mismatch" {
            let fields = records
                .values()
                .map(|record| parse_fixture_fields(&record.message).expect("fields parse"))
                .collect::<Vec<_>>();
            if fields.len() != 2
                || fields[0].get("MessageId") != fields[1].get("MessageId")
                || fields[0].get("LinkId") == fields[1].get("LinkId")
                || fields[0].get("TargetSite") == fields[1].get("TargetSite")
            {
                failures.push(
                    "topology-mismatch: adversarial facts are not exact-key mismatches".to_owned(),
                );
            }
        }
        if *scenario == "rotation-boundary" && !records.is_empty() {
            failures.push("rotation-boundary: split fragments formed evidence".to_owned());
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn hierarchy_gaps_requests_and_source_local_controls_are_bounded() {
    let mut failures = Vec::new();
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let records = normalized_records(scenario, &manifest);
        failures.extend(artifact_request_failures(scenario, &manifest, &expected));
        let requests = expected["artifactRequests"]
            .as_array()
            .expect("artifact requests are an array");

        let request_reason_codes = requests
            .iter()
            .filter_map(|request| request["reasonCode"].as_str())
            .collect::<Vec<_>>();
        let expected_reasons: &[&str] = match *scenario {
            "absent-remote-source" => &["coverageAbsent"],
            "clock-offset-unknown" => &["invalidOffset"],
            "incomplete" => &["coverageCapped"],
            "rotation-boundary" => &["coverageRotationSplit"],
            _ => &[],
        };
        if request_reason_codes != expected_reasons {
            failures.push(format!("{scenario}: bounded request matrix changed"));
        }

        let source_local = expected["sourceLocalObservations"]
            .as_array()
            .expect("source-local observations are an array");
        let source_local_classes = source_local
            .iter()
            .filter_map(|observation| observation["classification"].as_str())
            .collect::<Vec<_>>();
        let expected_classes: &[&str] = match *scenario {
            "incomplete" => &["coverageOnly"],
            "rotation-boundary" => &["rotationSplit"],
            "topology-mismatch" => &["topologyMismatch", "topologyMismatch"],
            _ => &[],
        };
        if source_local_classes != expected_classes {
            failures.push(format!("{scenario}: source-local control matrix changed"));
        }
        for observation in source_local {
            if observation["confidence"] != "low" || observation["correlationEligible"] != false {
                failures.push(format!(
                    "{scenario}: source-local evidence became correlatable"
                ));
            }
            for reference in observation["evidence"]
                .as_array()
                .expect("source-local evidence is an array")
            {
                let key = (
                    reference["artifactId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    reference["startLine"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .unwrap_or_default(),
                    reference["endLine"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .unwrap_or_default(),
                );
                if !records.contains_key(&key) {
                    failures.push(format!(
                        "{scenario}: source-local evidence is not physically cited"
                    ));
                }
            }
        }
    }

    let contract =
        include_str!("../../../docs/sccm/preparation/issue-331-hierarchy-replication-corpus.md")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
    for required in [
        "Raw CCM remains the transport grammar",
        "timestamp proximity alone cannot create a transaction",
        "A missing remote artifact is a coverage state, not evidence that the remote role is absent or broken",
        "time alone is never eligible",
        "not an acceptance source",
    ] {
        let required = required.split_whitespace().collect::<Vec<_>>().join(" ");
        if !contract.contains(&required) {
            failures.push(format!("preparation document lost boundary: {required}"));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn hierarchy_schema_and_identity_mutations_fail_closed() {
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        assert!(
            identity_and_schema_failures(scenario, &manifest, &expected).is_empty(),
            "{scenario}: committed schema is invalid"
        );
    }

    let healthy_manifest = read_json("healthy-link", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-link", "expected.json").expect("expected loads");
    let absent_manifest =
        read_json("absent-remote-source", "manifest.json").expect("manifest loads");
    let absent_expected =
        read_json("absent-remote-source", "expected.json").expect("expected loads");
    let clock_manifest =
        read_json("clock-offset-unknown", "manifest.json").expect("manifest loads");
    let clock_expected =
        read_json("clock-offset-unknown", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut unknown_manifest_field = healthy_manifest.clone();
    unknown_manifest_field["serverRootCause"] = Value::String("network".to_owned());
    if identity_and_schema_failures("healthy-link", &unknown_manifest_field, &healthy_expected)
        .is_empty()
    {
        accepted.push("unknown manifest cause field");
    }

    let mut non_string_role = healthy_manifest.clone();
    non_string_role["topology"]["rolesObserved"]
        .as_array_mut()
        .expect("roles are mutable")
        .push(Value::from(7));
    if identity_and_schema_failures("healthy-link", &non_string_role, &healthy_expected).is_empty()
    {
        accepted.push("non-string topology role");
    }

    let mut aliased_destination = healthy_manifest.clone();
    aliased_destination["artifacts"][1]["relativePath"] =
        Value::String("evidence/server-hierarchy-control/origin/current/./replmgr.log".to_owned());
    if identity_and_schema_failures("healthy-link", &aliased_destination, &healthy_expected)
        .is_empty()
    {
        accepted.push("dot-segment evidence alias");
    }

    let mut unsafe_source = healthy_manifest.clone();
    unsafe_source["artifacts"][0]["sanitizedSourcePath"] =
        Value::String("SYNTHETIC://../../Users/Real/replmgr.log".to_owned());
    if identity_and_schema_failures("healthy-link", &unsafe_source, &healthy_expected).is_empty() {
        accepted.push("unsafe sanitized source path");
    }

    let mut empty_fingerprint = healthy_manifest.clone();
    empty_fingerprint["artifacts"][0]["pathFingerprint"] = Value::String("synthetic:".to_owned());
    if identity_and_schema_failures("healthy-link", &empty_fingerprint, &healthy_expected)
        .is_empty()
    {
        accepted.push("empty path fingerprint");
    }

    let mut unknown_version = healthy_manifest.clone();
    unknown_version["artifacts"][0]["sourceVersion"] = Value::String("9.99.UNKNOWN".to_owned());
    if identity_and_schema_failures("healthy-link", &unknown_version, &healthy_expected).is_empty()
    {
        accepted.push("unknown source version retained selected profile");
    }

    let mut nonphysical_file = absent_manifest.clone();
    nonphysical_file["artifacts"][1]["relativePath"] = Value::Bool(false);
    if identity_and_schema_failures("absent-remote-source", &nonphysical_file, &absent_expected)
        .is_empty()
    {
        accepted.push("nonphysical coverage invented a malformed path");
    }

    let mut non_string_state = healthy_expected.clone();
    non_string_state["stateChain"]
        .as_array_mut()
        .expect("state chain is mutable")
        .push(Value::from(7));
    if identity_and_schema_failures("healthy-link", &healthy_manifest, &non_string_state).is_empty()
    {
        accepted.push("non-string state-chain entry");
    }

    let mut missing_observation = healthy_expected.clone();
    missing_observation["transactions"][0]["observations"]
        .as_array_mut()
        .expect("observations are mutable")
        .remove(1);
    if identity_and_schema_failures("healthy-link", &healthy_manifest, &missing_observation)
        .is_empty()
    {
        accepted.push("required observation deleted");
    }

    let mut mismatched_key = healthy_expected.clone();
    mismatched_key["transactions"][0]["key"]["targetSiteCode"] = Value::String("SEC".to_owned());
    if identity_and_schema_failures("healthy-link", &healthy_manifest, &mismatched_key).is_empty() {
        accepted.push("transaction ID diverged from immutable topology key");
    }

    let mut undeclared_topology_key = healthy_expected.clone();
    undeclared_topology_key["transactions"][0]["key"]["targetSiteCode"] =
        Value::String("SEC".to_owned());
    undeclared_topology_key["transactions"][0]["transactionId"] =
        Value::String("hierarchy:MSG-HEALTHY-001:LAB:SEC:LINK-LAB-CHD".to_owned());
    if identity_and_schema_failures("healthy-link", &healthy_manifest, &undeclared_topology_key)
        .is_empty()
    {
        accepted.push("transaction key target is outside manifest topology");
    }

    let mut time_only_high = clock_expected.clone();
    time_only_high["transactions"][0]["confidence"] = Value::String("high".to_owned());
    time_only_high["transactions"][0]["confidenceCeiling"] = Value::String("high".to_owned());
    if identity_and_schema_failures("clock-offset-unknown", &clock_manifest, &time_only_high)
        .is_empty()
    {
        accepted.push("invalid-offset transaction became high confidence");
    }

    let mut origin_evidence_on_target_host = healthy_manifest.clone();
    origin_evidence_on_target_host["artifacts"][1]["producerHostHandle"] =
        healthy_manifest["topology"]["targetHostHandle"].clone();
    if identity_and_schema_failures(
        "healthy-link",
        &origin_evidence_on_target_host,
        &healthy_expected,
    )
    .is_empty()
    {
        accepted.push("origin evidence retained a target host");
    }

    let mut target_evidence_on_origin_host = healthy_manifest.clone();
    target_evidence_on_origin_host["artifacts"][2]["producerHostHandle"] =
        healthy_manifest["topology"]["originHostHandle"].clone();
    if identity_and_schema_failures(
        "healthy-link",
        &target_evidence_on_origin_host,
        &healthy_expected,
    )
    .is_empty()
    {
        accepted.push("target evidence retained an origin host");
    }

    let mismatch_manifest =
        read_json("topology-mismatch", "manifest.json").expect("manifest loads");
    let mismatch_expected =
        read_json("topology-mismatch", "expected.json").expect("expected loads");
    let mut additional_target_on_primary_host = mismatch_manifest.clone();
    additional_target_on_primary_host["artifacts"][1]["producerHostHandle"] =
        mismatch_manifest["topology"]["targetHostHandle"].clone();
    if identity_and_schema_failures(
        "topology-mismatch",
        &additional_target_on_primary_host,
        &mismatch_expected,
    )
    .is_empty()
    {
        accepted.push("additional-target evidence retained the primary target host");
    }

    let mut fabricated_gap = absent_expected.clone();
    fabricated_gap["transactions"][0]["coverageGapArtifactIds"][0] =
        Value::String("unknown-artifact".to_owned());
    if identity_and_schema_failures("absent-remote-source", &absent_manifest, &fabricated_gap)
        .is_empty()
    {
        accepted.push("fabricated coverage-gap artifact ID");
    }

    let mut missing_coverage_row = absent_expected.clone();
    missing_coverage_row["coverage"]
        .as_array_mut()
        .expect("coverage is mutable")
        .remove(1);
    if identity_and_schema_failures(
        "absent-remote-source",
        &absent_manifest,
        &missing_coverage_row,
    )
    .is_empty()
    {
        accepted.push("missing manifest coverage row");
    }

    let mut duplicate_coverage_row = absent_expected.clone();
    let repeated_row = duplicate_coverage_row["coverage"][1].clone();
    duplicate_coverage_row["coverage"]
        .as_array_mut()
        .expect("coverage is mutable")
        .push(repeated_row);
    if identity_and_schema_failures(
        "absent-remote-source",
        &absent_manifest,
        &duplicate_coverage_row,
    )
    .is_empty()
    {
        accepted.push("duplicate manifest coverage row");
    }

    let mut unknown_coverage_row = absent_expected.clone();
    unknown_coverage_row["coverage"]
        .as_array_mut()
        .expect("coverage is mutable")
        .push(serde_json::json!({
            "artifactId": "unknown-artifact",
            "state": "absent"
        }));
    if identity_and_schema_failures(
        "absent-remote-source",
        &absent_manifest,
        &unknown_coverage_row,
    )
    .is_empty()
    {
        accepted.push("unknown manifest coverage row");
    }

    let mut malformed_coverage_row = absent_expected.clone();
    malformed_coverage_row["coverage"][1]["unexpected"] = Value::Bool(true);
    if identity_and_schema_failures(
        "absent-remote-source",
        &absent_manifest,
        &malformed_coverage_row,
    )
    .is_empty()
    {
        accepted.push("malformed manifest coverage row");
    }

    let mut causal_claim = healthy_expected.clone();
    causal_claim["crossSideCausalClaims"] =
        Value::Array(vec![Value::String("same-time client impact".to_owned())]);
    if identity_and_schema_failures("healthy-link", &healthy_manifest, &causal_claim).is_empty() {
        accepted.push("cross-side causal claim");
    }

    assert!(
        accepted.is_empty(),
        "hierarchy contract accepted adversarial mutations: {accepted:?}"
    );
}

#[test]
fn hierarchy_artifact_request_mutations_fail_closed() {
    let manifest =
        read_json("clock-offset-unknown", "manifest.json").expect("clock manifest loads");
    let expected =
        read_json("clock-offset-unknown", "expected.json").expect("clock expected loads");
    assert!(
        identity_and_schema_failures("clock-offset-unknown", &manifest, &expected).is_empty(),
        "the committed invalid-offset request is the bounded control"
    );
    assert!(
        artifact_request_failures("clock-offset-unknown", &manifest, &expected).is_empty(),
        "the shared request loader accepts the bounded both-direction control"
    );

    let mutations = [
        (
            "wrong source ID",
            "sourceId",
            serde_json::json!("server-hierarchy-control"),
        ),
        ("wrong direction", "direction", serde_json::json!("origin")),
        (
            "undeclared target site",
            "targetSiteCode",
            serde_json::json!("XYZ"),
        ),
        (
            "wrong source basename",
            "basenames",
            serde_json::json!(["replmgr.log"]),
        ),
        (
            "missing origin companion",
            "basenames",
            serde_json::json!(["despool.log"]),
        ),
        (
            "missing target companion",
            "basenames",
            serde_json::json!(["sender.log"]),
        ),
    ];

    let mut accepted = Vec::new();
    for (label, field, value) in mutations {
        let mut mutated = expected.clone();
        mutated["artifactRequests"][0][field] = value;
        if artifact_request_failures("clock-offset-unknown", &manifest, &mutated).is_empty()
            || identity_and_schema_failures("clock-offset-unknown", &manifest, &mutated).is_empty()
        {
            accepted.push(label);
        }
    }

    assert!(
        accepted.is_empty(),
        "artifact request provenance mutations were accepted: {accepted:?}"
    );
}

#[test]
fn hierarchy_review_4826191775_mutations_fail_closed() {
    let absent_manifest =
        read_json("absent-remote-source", "manifest.json").expect("absent manifest loads");
    let absent_expected =
        read_json("absent-remote-source", "expected.json").expect("absent expected loads");
    let incomplete_manifest =
        read_json("incomplete", "manifest.json").expect("incomplete manifest loads");
    let incomplete_expected =
        read_json("incomplete", "expected.json").expect("incomplete expected loads");
    let rotation_manifest =
        read_json("rotation-boundary", "manifest.json").expect("rotation manifest loads");
    let rotation_expected =
        read_json("rotation-boundary", "expected.json").expect("rotation expected loads");
    let healthy_manifest =
        read_json("healthy-link", "manifest.json").expect("healthy manifest loads");
    let healthy_expected =
        read_json("healthy-link", "expected.json").expect("healthy expected loads");

    let mut accepted = Vec::new();
    let mut audit = |label: &'static str, scenario: &str, manifest: &Value, expected: &Value| {
        if identity_and_schema_failures(scenario, manifest, expected).is_empty() {
            accepted.push(label);
        }
    };

    let mut absent_both = absent_expected.clone();
    absent_both["artifactRequests"][0]["direction"] = serde_json::json!("both");
    audit(
        "target-only absent request broadened to both",
        "absent-remote-source",
        &absent_manifest,
        &absent_both,
    );

    let mut capped_both = incomplete_expected.clone();
    capped_both["artifactRequests"][0]["direction"] = serde_json::json!("both");
    audit(
        "origin-only capped request broadened to both",
        "incomplete",
        &incomplete_manifest,
        &capped_both,
    );

    let mut rotation_both = rotation_expected.clone();
    rotation_both["artifactRequests"][0]["direction"] = serde_json::json!("both");
    audit(
        "origin-only rotation request broadened to both",
        "rotation-boundary",
        &rotation_manifest,
        &rotation_both,
    );

    let mut wrong_declared_site_manifest = absent_manifest.clone();
    wrong_declared_site_manifest["topology"]["additionalTargets"] = serde_json::json!([{
        "siteCode": "SEC",
        "hostHandle": "safe:server:lab-sec-01"
    }]);
    let mut wrong_declared_site_expected = absent_expected.clone();
    wrong_declared_site_expected["artifactRequests"][0]["targetSiteCode"] =
        serde_json::json!("SEC");
    audit(
        "coverage request targeted a different declared site",
        "absent-remote-source",
        &wrong_declared_site_manifest,
        &wrong_declared_site_expected,
    );

    let mut wrong_coverage_host_manifest = absent_manifest.clone();
    wrong_coverage_host_manifest["topology"]["additionalTargets"] = serde_json::json!([{
        "siteCode": "SEC",
        "hostHandle": "safe:server:lab-sec-01"
    }]);
    wrong_coverage_host_manifest["artifacts"][1]["producerHostHandle"] =
        serde_json::json!("safe:server:lab-sec-01");
    audit(
        "coverage artifact moved to a different target host",
        "absent-remote-source",
        &wrong_coverage_host_manifest,
        &absent_expected,
    );

    let mut split_lineage = rotation_manifest.clone();
    split_lineage["artifacts"][1]["rotation"]["lineageId"] = serde_json::json!("unrelated-lineage");
    audit(
        "rotation request joined unrelated lineages",
        "rotation-boundary",
        &split_lineage,
        &rotation_expected,
    );

    let mut wrong_rotation_identity = rotation_manifest.clone();
    wrong_rotation_identity["artifacts"][1]["rotation"] = serde_json::json!({
        "kind": "numbered",
        "value": 1,
        "lineageId": "rotation-sender",
        "fragmentComplete": false
    });
    audit(
        "sender.lo_ declared as a numbered rotation",
        "rotation-boundary",
        &wrong_rotation_identity,
        &rotation_expected,
    );

    let mut out_of_profile_version = healthy_manifest.clone();
    out_of_profile_version["artifacts"][2]["sourceVersion"] = serde_json::json!("5.00.TEST.9999");
    audit(
        "unadmitted source version retained selected profile",
        "healthy-link",
        &out_of_profile_version,
        &healthy_expected,
    );

    let mut noncanonical_version = healthy_manifest.clone();
    noncanonical_version["artifacts"][2]["sourceVersion"] =
        serde_json::json!("5.00.TEST.not-canonical");
    audit(
        "noncanonical source version retained selected profile",
        "healthy-link",
        &noncanonical_version,
        &healthy_expected,
    );

    let mut invalid_collection_time = healthy_manifest.clone();
    invalid_collection_time["artifacts"][2]["collectedUtc"] = serde_json::json!("not-a-timestamp");
    audit(
        "invalid collection timestamp retained exact output",
        "healthy-link",
        &invalid_collection_time,
        &healthy_expected,
    );

    let mut empty_target_handle = healthy_manifest.clone();
    empty_target_handle["topology"]["targetHostHandle"] = serde_json::json!("safe:server:");
    empty_target_handle["artifacts"][2]["producerHostHandle"] = serde_json::json!("safe:server:");
    empty_target_handle["artifacts"][3]["producerHostHandle"] = serde_json::json!("safe:server:");
    audit(
        "empty safe target-handle payload retained exact topology",
        "healthy-link",
        &empty_target_handle,
        &healthy_expected,
    );

    let mut colliding_hosts = healthy_manifest.clone();
    let origin_host = colliding_hosts["topology"]["originHostHandle"].clone();
    colliding_hosts["topology"]["targetHostHandle"] = origin_host.clone();
    colliding_hosts["artifacts"][2]["producerHostHandle"] = origin_host.clone();
    colliding_hosts["artifacts"][3]["producerHostHandle"] = origin_host;
    audit(
        "origin and target sites shared one host handle",
        "healthy-link",
        &colliding_hosts,
        &healthy_expected,
    );

    let mut empty_identity_manifest = absent_manifest.clone();
    empty_identity_manifest["artifacts"][1]["artifactId"] = serde_json::json!("");
    empty_identity_manifest["artifacts"]
        .as_array_mut()
        .expect("artifact array is mutable")
        .swap(0, 1);
    let mut empty_identity_expected = absent_expected.clone();
    empty_identity_expected["coverage"][1]["artifactId"] = serde_json::json!("");
    empty_identity_expected["coverage"]
        .as_array_mut()
        .expect("coverage array is mutable")
        .swap(0, 1);
    empty_identity_expected["transactions"][0]["coverageGapArtifactIds"][0] = serde_json::json!("");
    audit(
        "empty artifact and gap identity retained exact coverage",
        "absent-remote-source",
        &empty_identity_manifest,
        &empty_identity_expected,
    );

    assert!(
        accepted.is_empty(),
        "review 4826191775 mutations were accepted: {accepted:?}"
    );
}

#[test]
fn hierarchy_review_4826454819_mutations_fail_closed() {
    let healthy_manifest =
        read_json("healthy-link", "manifest.json").expect("healthy manifest loads");
    let healthy_expected =
        read_json("healthy-link", "expected.json").expect("healthy expected loads");
    let incomplete_manifest =
        read_json("incomplete", "manifest.json").expect("incomplete manifest loads");
    let incomplete_expected =
        read_json("incomplete", "expected.json").expect("incomplete expected loads");
    let absent_manifest =
        read_json("absent-remote-source", "manifest.json").expect("absent manifest loads");
    let absent_expected =
        read_json("absent-remote-source", "expected.json").expect("absent expected loads");

    let mut accepted = Vec::new();
    let mut candidate_acceptances = Vec::new();
    {
        let mut audit =
            |label: &'static str, scenario: &str, manifest: &Value, expected: &Value| {
                if identity_and_schema_failures(scenario, manifest, expected).is_empty() {
                    accepted.push(label);
                }
            };

        let mut capped_terminal_manifest = healthy_manifest.clone();
        capped_terminal_manifest["artifacts"][3]["captureState"] = serde_json::json!("capped");
        let mut capped_terminal_expected = healthy_expected.clone();
        capped_terminal_expected["coverage"][3]["state"] = serde_json::json!("capped");
        audit(
            "high transaction cited capped terminal evidence without a gap",
            "healthy-link",
            &capped_terminal_manifest,
            &capped_terminal_expected,
        );

        let mut denied_terminal_manifest = healthy_manifest.clone();
        denied_terminal_manifest["artifacts"][3]["captureState"] =
            serde_json::json!("accessDenied");
        let denied_terminal_artifact = denied_terminal_manifest["artifacts"][3]
            .as_object_mut()
            .expect("terminal artifact is mutable");
        for physical_field in ["relativePath", "bytesCopied", "encoding", "collectionLimit"] {
            denied_terminal_artifact.remove(physical_field);
        }
        denied_terminal_artifact["rotation"]
            .as_object_mut()
            .expect("terminal rotation is mutable")
            .remove("fragmentComplete");
        let mut denied_terminal_expected = healthy_expected.clone();
        denied_terminal_expected["coverage"][3]["state"] = serde_json::json!("accessDenied");
        audit(
            "high transaction cited access-denied terminal evidence without a gap",
            "healthy-link",
            &denied_terminal_manifest,
            &denied_terminal_expected,
        );

        let mut partial_terminal_manifest = healthy_manifest.clone();
        partial_terminal_manifest["artifacts"][3]["rotation"]["fragmentComplete"] =
            serde_json::json!(false);
        audit(
            "high transaction cited an incomplete terminal fragment without a gap",
            "healthy-link",
            &partial_terminal_manifest,
            &healthy_expected,
        );

        let mut relabeled_failure = healthy_expected.clone();
        let terminal_observation = &mut relabeled_failure["transactions"][0]["observations"][6];
        terminal_observation["disposition"] = serde_json::json!("failed");
        terminal_observation["evidence"] = serde_json::json!([{
            "artifactId": "healthy-02-sender",
            "startLine": 1,
            "endLine": 1
        }]);
        relabeled_failure["transactions"][0]["state"] = serde_json::json!("failed");
        relabeled_failure["transactions"][0]["classification"] =
            serde_json::json!("confirmedFailure");
        audit(
            "successful evidence was relabeled and recited as a confirmed failure",
            "healthy-link",
            &healthy_manifest,
            &relabeled_failure,
        );

        let mut sender_moved_to_target = healthy_manifest.clone();
        sender_moved_to_target["artifacts"][1]["direction"] = serde_json::json!("target");
        sender_moved_to_target["artifacts"][1]["producerHostHandle"] =
            healthy_manifest["topology"]["targetHostHandle"].clone();
        audit(
            "origin sender evidence moved to the target direction",
            "healthy-link",
            &sender_moved_to_target,
            &healthy_expected,
        );

        let mut sender_wrong_source = healthy_manifest.clone();
        sender_wrong_source["artifacts"][1]["sourceId"] =
            serde_json::json!("server-hierarchy-control");
        audit(
            "sender evidence was relabeled as a control source",
            "healthy-link",
            &sender_wrong_source,
            &healthy_expected,
        );

        let mut sender_wrong_basename = healthy_manifest.clone();
        sender_wrong_basename["artifacts"][1]["originalBasename"] =
            serde_json::json!("despool.log");
        audit(
            "origin sender evidence was relabeled with a target-only basename",
            "healthy-link",
            &sender_wrong_basename,
            &healthy_expected,
        );

        let mut out_of_profile_sender = healthy_manifest.clone();
        out_of_profile_sender["artifacts"][1]["sourceVersion"] =
            serde_json::json!("5.00.TEST.9999");
        if hierarchy_candidate_groups("healthy-link", &out_of_profile_sender)
            .expect("candidate projection remains deterministic")
            .iter()
            .flat_map(|group| &group.facts)
            .any(|fact| fact.artifact_id == "healthy-02-sender")
        {
            candidate_acceptances.push("out-of-profile sender entered an exact candidate");
        }

        let mut partial_sender = healthy_manifest.clone();
        partial_sender["artifacts"][1]["rotation"]["fragmentComplete"] = serde_json::json!(false);
        if hierarchy_candidate_groups("healthy-link", &partial_sender)
            .expect("candidate projection remains deterministic")
            .iter()
            .flat_map(|group| &group.facts)
            .any(|fact| fact.artifact_id == "healthy-02-sender")
        {
            candidate_acceptances.push("incomplete sender fragment entered an exact candidate");
        }

        let mut escalated_source_local = incomplete_expected.clone();
        escalated_source_local["sourceLocalObservations"][0]["confidence"] =
            serde_json::json!("high");
        escalated_source_local["sourceLocalObservations"][0]["correlationEligible"] =
            serde_json::json!(true);
        audit(
            "capped source-local evidence became high and correlation eligible",
            "incomplete",
            &incomplete_manifest,
            &escalated_source_local,
        );

        let mut missing_required_request = absent_expected.clone();
        missing_required_request["artifactRequests"] = serde_json::json!([]);
        audit(
            "required absent-coverage request was deleted",
            "absent-remote-source",
            &absent_manifest,
            &missing_required_request,
        );

        let mut production_labeled_fixture = healthy_manifest.clone();
        production_labeled_fixture["proposalOnly"] = serde_json::json!(false);
        production_labeled_fixture["syntheticFixture"] = serde_json::json!(false);
        audit(
            "synthetic proposal fixture was relabeled as production evidence",
            "healthy-link",
            &production_labeled_fixture,
            &healthy_expected,
        );
    }
    accepted.extend(candidate_acceptances);

    assert!(
        accepted.is_empty(),
        "review 4826454819 mutations were accepted: {accepted:?}"
    );
}

#[test]
fn hierarchy_coderabbit_5ead896_target_topology_requires_present_handles() {
    let mut manifest = read_json("healthy-link", "manifest.json").expect("healthy manifest loads");
    let mut target_artifact = manifest["artifacts"][2].clone();
    manifest["topology"]
        .as_object_mut()
        .expect("topology is mutable")
        .remove("targetHostHandle");
    target_artifact
        .as_object_mut()
        .expect("target artifact is mutable")
        .remove("producerHostHandle");
    let fields = BTreeMap::from([
        ("OriginSite".to_owned(), "LAB".to_owned()),
        ("TargetSite".to_owned(), "CHD".to_owned()),
    ]);

    assert!(
        !record_matches_topology(&manifest, &target_artifact, &fields),
        "two absent target handles cannot satisfy exact topology"
    );
}

#[test]
fn hierarchy_coderabbit_878a051_control_requests_include_target_rcmctrl() {
    let mut manifest =
        read_json("absent-remote-source", "manifest.json").expect("absent manifest loads");
    let mut expected =
        read_json("absent-remote-source", "expected.json").expect("absent expected loads");
    manifest["artifacts"][1]["sourceId"] = serde_json::json!("server-hierarchy-control");
    manifest["artifacts"][1]["originalBasename"] = serde_json::json!("rcmctrl.log");
    expected["artifactRequests"][0]["sourceId"] = serde_json::json!("server-hierarchy-control");
    expected["artifactRequests"][0]["basenames"] = serde_json::json!(["rcmctrl.log"]);

    let failures = artifact_request_failures("absent-remote-source", &manifest, &expected);
    assert!(
        failures.is_empty(),
        "target-side rcmctrl coverage request is exact: {failures:?}"
    );
}

#[test]
fn hierarchy_coderabbit_878a051_shared_predicates_stay_narrow() {
    let manifest = read_json("healthy-link", "manifest.json").expect("healthy manifest loads");
    let artifact = manifest["artifacts"][1].clone();
    assert!(artifact_has_exact_public_provenance(&artifact));

    let mut unsafe_host = artifact.clone();
    unsafe_host["producerHostHandle"] = serde_json::json!("safe:server:bad/path");
    assert!(!artifact_has_exact_public_provenance(&unsafe_host));

    let mut unadmitted_version = artifact;
    unadmitted_version["sourceVersion"] = serde_json::json!("5.00.TEST.9999");
    assert!(!artifact_has_exact_public_provenance(&unadmitted_version));

    for (disposition, terminal) in [
        ("succeeded", false),
        ("succeeded", true),
        ("failed", true),
        ("retrying", false),
    ] {
        assert!(observation_disposition_is_coherent(disposition, terminal));
    }
    assert!(
        !observation_disposition_is_coherent("deferred", false),
        "deferred is a transaction state, not a source observation disposition"
    );
}

#[test]
fn hierarchy_coderabbit_0a6ba32_rotation_uses_shared_wire_kind() {
    let manifest =
        read_json("rotation-boundary", "manifest.json").expect("rotation manifest loads");
    let archived = &manifest["artifacts"][1];

    assert_eq!(
        archived["rotation"]["kind"], "loUnderscore",
        "the .lo_ filename uses the shared SccmRotation wire tag"
    );
    assert_eq!(
        rotation(&archived["rotation"]),
        Some(SccmRotation::LoUnderscore)
    );

    let mut legacy_kind = archived["rotation"].clone();
    legacy_kind["kind"] = serde_json::json!("lo_");
    assert!(
        rotation(&legacy_kind).is_none(),
        "the #331 fixture contract must not preserve a private rotation alias"
    );
}

#[test]
fn hierarchy_coderabbit_0a6ba32_identity_matrices_reject_unknown_scenarios() {
    let unknown = "future-unregistered-scenario";

    assert_ne!(
        expected_transaction_ids(unknown),
        expected_transaction_ids("generic-site-token")
    );
    assert_ne!(
        expected_observation_ids(unknown),
        expected_observation_ids("generic-site-token")
    );
    assert_ne!(
        expected_source_local_ids(unknown),
        expected_source_local_ids("healthy-link")
    );
}
