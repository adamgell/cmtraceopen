//! Bounded process observations for ESP and allowlisted installer activity.

use std::collections::BTreeSet;
use std::time::Duration;

use chrono::{DateTime, FixedOffset, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use cmtraceopen_parser::esp::{
    EspEvidenceProvenance, EspEvidenceRef, EspObservationContext, EspParseState,
    EspProcessObservation, EspSensitivity, EspSourceAccessState, EspSourceKind, EspTimestamp,
    EspTimestampKind,
};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
#[path = "process_win32.rs"]
mod process_win32;
#[cfg(target_os = "windows")]
pub use process_win32::LiveProcessProvider;

pub const PROCESS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_PROCESS_RECORDS: usize = 512;
pub const MAX_PARENT_CHAIN_DEPTH: usize = 16;
pub const MAX_LOCAL_INSTALLER_NAMES: usize = 32;

pub const FIXED_PROCESS_ALLOWLIST: &[&str] = &[
    "IntuneManagementExtension.exe",
    "AgentExecutor.exe",
    "msiexec.exe",
    "winget.exe",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessReadError {
    Missing,
    PermissionDenied,
    TimedOut,
    Failed(String),
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RawProcessSnapshot {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image_name: String,
    pub start_time_utc: String,
    pub command_line: Option<String>,
}

impl RawProcessSnapshot {
    pub fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            start_time_utc: self.start_time_utc.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshotBatch {
    pub snapshots: Vec<RawProcessSnapshot>,
    pub completion: Result<(), ProcessReadError>,
}

impl ProcessSnapshotBatch {
    pub fn complete(snapshots: Vec<RawProcessSnapshot>) -> Self {
        Self {
            snapshots,
            completion: Ok(()),
        }
    }
}

pub trait ProcessProvider {
    fn snapshot(
        &self,
        allowed_image_names: &[String],
        timeout: Duration,
        max_records: usize,
    ) -> ProcessSnapshotBatch;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessEvidence {
    pub access_state: EspSourceAccessState,
    pub detail: Option<String>,
    pub observations: Vec<EspProcessObservation>,
}

pub fn collect_process_evidence(
    provider: &impl ProcessProvider,
    local_installer_names: &[String],
    observed_at_utc: &str,
) -> ProcessEvidence {
    let allowlist = process_allowlist(local_installer_names);
    let allowed_image_names = allowlist.iter().cloned().collect::<Vec<_>>();
    let mut batch = provider.snapshot(
        &allowed_image_names,
        PROCESS_QUERY_TIMEOUT,
        MAX_PROCESS_RECORDS,
    );
    batch.snapshots.truncate(MAX_PROCESS_RECORDS);
    let partial = !batch.snapshots.is_empty();
    let (access_state, detail) = process_coverage(&batch.completion, partial);

    let observations = batch
        .snapshots
        .into_iter()
        .filter(|snapshot| {
            allowlist
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&snapshot.image_name))
        })
        .enumerate()
        .map(|(index, snapshot)| process_observation(snapshot, index, observed_at_utc))
        .collect();

    ProcessEvidence {
        access_state,
        detail,
        observations,
    }
}

pub fn parent_chain(
    child: &ProcessIdentity,
    snapshots: &[RawProcessSnapshot],
    max_depth: usize,
) -> Vec<ProcessIdentity> {
    let mut chain = Vec::new();
    let mut visited = BTreeSet::from([child.clone()]);
    let mut current = child.clone();

    for _ in 0..max_depth.min(MAX_PARENT_CHAIN_DEPTH) {
        let Some(current_snapshot) = snapshots
            .iter()
            .find(|snapshot| snapshot.identity() == current)
        else {
            break;
        };
        let Some(parent_pid) = current_snapshot.parent_pid else {
            break;
        };
        let Some(parent) = snapshots
            .iter()
            .filter(|candidate| {
                candidate.pid == parent_pid
                    && candidate.start_time_utc <= current_snapshot.start_time_utc
            })
            .max_by(|left, right| left.start_time_utc.cmp(&right.start_time_utc))
        else {
            break;
        };
        let identity = parent.identity();
        if !visited.insert(identity.clone()) {
            break;
        }
        chain.push(identity.clone());
        current = identity;
    }

    chain
}

pub fn sanitize_command_line(command_line: &str) -> String {
    let digest_authorization =
        Regex::new(r#"(?i)(^|\s)((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)digest\s+.*"#)
            .expect("constant digest-authorization regex");
    let authorization_credential = Regex::new(
        r#"(?i)(^|\s)((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)(?:bearer|basic|api[-_]?key)\s+(?:"[^"]*"|'[^']*'|[^\s&"]+)"#,
    )
    .expect("constant authorization-credential regex");
    let bearer = Regex::new(r#"(?i)(bearer\s+)(?:"[^"]*"|'[^']*'|[^\s&"]+)"#)
        .expect("constant bearer regex");
    let named_secret = Regex::new(
        r#"(?i)(^|\s)((?:--|/)?(?:access[-_]?token|client[-_]?secret|token|password|secret|authorization))(\s*(?:=|:)\s*|\s+)(?:"[^"]*"|'[^']*'|[^\s&"]+)"#,
    )
    .expect("constant named-secret regex");
    let query_secret = Regex::new(
        r#"(?i)([?&](?:sig|access[-_]?token|client[-_]?secret|token|password|secret|authorization)=)(?:"[^"]*"|'[^']*'|[^&\s"]+)"#,
    )
    .expect("constant query-secret regex");

    // Digest credentials can contain a comma-separated parameter list, so conservatively
    // redact the rest of the command line once an unquoted Digest authorization value starts.
    let command_line = digest_authorization.replace_all(command_line, "$1$2$3[REDACTED]");
    // Authorization schemes are redacted with their credential before the generic named-secret
    // pass can consume only the scheme and leave the credential behind.
    let command_line = authorization_credential.replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = bearer.replace_all(&command_line, "$1[REDACTED]");
    let command_line = named_secret.replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = query_secret.replace_all(&command_line, "$1[REDACTED]");
    command_line.into_owned()
}

fn process_allowlist(local_installer_names: &[String]) -> BTreeSet<String> {
    let mut allowlist = FIXED_PROCESS_ALLOWLIST
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    allowlist.extend(
        local_installer_names
            .iter()
            .filter_map(|name| normalize_local_installer_name(name))
            .take(MAX_LOCAL_INSTALLER_NAMES)
            .map(|name| name.to_ascii_lowercase()),
    );
    allowlist
}

fn normalize_local_installer_name(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.contains('*') || raw.contains('?') {
        return None;
    }
    let components = raw.split(['/', '\\']).collect::<Vec<_>>();
    if components.contains(&"..") {
        return None;
    }
    let name = components.last()?.trim();
    if name.len() > 255
        || !name.to_ascii_lowercase().ends_with(".exe")
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || " ._-()".contains(character))
    {
        return None;
    }
    Some(name.to_string())
}

fn process_observation(
    snapshot: RawProcessSnapshot,
    index: usize,
    observed_at_utc: &str,
) -> EspProcessObservation {
    let command_line = snapshot
        .command_line
        .as_deref()
        .filter(|command_line| !command_line.trim().is_empty());
    EspProcessObservation {
        context: process_context(index, observed_at_utc),
        pid: snapshot.pid,
        process_start_time: process_timestamp(&snapshot.start_time_utc),
        parent_pid: snapshot.parent_pid,
        executable_name: snapshot.image_name,
        sanitized_command_line: command_line.map(sanitize_command_line),
        referenced_log_path: command_line.and_then(extract_log_path),
        app_id: command_line.and_then(extract_app_id),
        product_code: command_line.and_then(extract_product_code),
    }
}

fn extract_product_code(command_line: &str) -> Option<String> {
    let regex = Regex::new(
        r#"(?i)(?:^|\s)/(?:i|package)\s+"?(\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})"#,
    )
    .expect("constant MSI product-code regex");
    regex
        .captures(command_line)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn extract_app_id(command_line: &str) -> Option<String> {
    let regex = Regex::new(
        r"(?i)(?:^|\s)--app-id(?:=|\s+)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\s|$)",
    )
    .expect("constant app-id regex");
    regex
        .captures(command_line)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn extract_log_path(command_line: &str) -> Option<String> {
    let regex = Regex::new(r#"(?i)(?:^|\s)/l[*+!voicewarmupx]*\s+(?:"([^"]+)"|(\S+))"#)
        .expect("constant MSI log-path regex");
    regex.captures(command_line).and_then(|captures| {
        captures
            .get(1)
            .or_else(|| captures.get(2))
            .map(|value| value.as_str().to_string())
    })
}

fn process_timestamp(raw: &str) -> EspTimestamp {
    if let Ok(timestamp) = DateTime::parse_from_rfc3339(raw) {
        return EspTimestamp {
            raw_text: raw.to_string(),
            original_offset: Some(timestamp.offset().to_string()),
            normalized_utc: Some(
                timestamp
                    .with_timezone(&Utc)
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
            ),
            kind: if timestamp.offset().local_minus_utc() == 0 {
                EspTimestampKind::Utc
            } else {
                EspTimestampKind::Offset
            },
        };
    }
    if let Some(timestamp) = parse_wmi_datetime(raw) {
        return EspTimestamp {
            raw_text: raw.to_string(),
            original_offset: Some(timestamp.offset().to_string()),
            normalized_utc: Some(
                timestamp
                    .with_timezone(&Utc)
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
            ),
            kind: EspTimestampKind::Offset,
        };
    }
    EspTimestamp {
        raw_text: raw.to_string(),
        original_offset: None,
        normalized_utc: None,
        kind: EspTimestampKind::Invalid,
    }
}

fn parse_wmi_datetime(raw: &str) -> Option<DateTime<FixedOffset>> {
    if raw.len() < 25 {
        return None;
    }
    let naive = NaiveDateTime::parse_from_str(&raw[..14], "%Y%m%d%H%M%S").ok()?;
    let sign = match raw.as_bytes().get(21)? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let offset_minutes = raw.get(22..25)?.parse::<i32>().ok()? * sign;
    let offset = FixedOffset::east_opt(offset_minutes * 60)?;
    offset.from_local_datetime(&naive).single()
}

fn process_context(index: usize, observed_at_utc: &str) -> EspObservationContext {
    let source_artifact_id = "system.process-snapshot".to_string();
    EspObservationContext {
        evidence_ref: EspEvidenceRef {
            evidence_id: format!("esp-process-{index}"),
            source_artifact_id: source_artifact_id.clone(),
        },
        provenance: EspEvidenceProvenance {
            source_kind: EspSourceKind::Process,
            source_artifact_id,
            file_path: None,
            line_number: None,
            record_number: Some(index as u64),
            registry: None,
            event: None,
        },
        source_timestamp: None,
        observed_at_utc: observed_at_utc.to_string(),
        sensitivity: EspSensitivity::Sensitive,
        parse_state: EspParseState::Parsed,
        access_state: EspSourceAccessState::Available,
    }
}

fn process_coverage(
    completion: &Result<(), ProcessReadError>,
    partial: bool,
) -> (EspSourceAccessState, Option<String>) {
    match completion {
        Ok(()) => (EspSourceAccessState::Available, None),
        Err(ProcessReadError::Missing) => (EspSourceAccessState::Missing, None),
        Err(ProcessReadError::PermissionDenied) => (EspSourceAccessState::PermissionDenied, None),
        Err(ProcessReadError::TimedOut) => (
            EspSourceAccessState::Failed,
            Some(
                if partial {
                    "process query timed out after partial results"
                } else {
                    "process query timed out"
                }
                .to_string(),
            ),
        ),
        Err(ProcessReadError::Failed(detail)) => {
            (EspSourceAccessState::Failed, Some(detail.clone()))
        }
        Err(ProcessReadError::Unsupported) => (EspSourceAccessState::Unsupported, None),
    }
}

#[cfg(not(target_os = "windows"))]
pub struct LiveProcessProvider;

#[cfg(not(target_os = "windows"))]
impl ProcessProvider for LiveProcessProvider {
    fn snapshot(
        &self,
        _allowed_image_names: &[String],
        _timeout: Duration,
        _max_records: usize,
    ) -> ProcessSnapshotBatch {
        ProcessSnapshotBatch {
            snapshots: Vec::new(),
            completion: Err(ProcessReadError::Unsupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::time::Duration;

    use cmtraceopen_parser::esp::EspSourceAccessState;

    use super::*;

    #[derive(Clone)]
    struct FakeProcessProvider {
        batch: ProcessSnapshotBatch,
    }

    impl ProcessProvider for FakeProcessProvider {
        fn snapshot(
            &self,
            _allowed_image_names: &[String],
            timeout: Duration,
            max_records: usize,
        ) -> ProcessSnapshotBatch {
            assert_eq!(timeout, PROCESS_QUERY_TIMEOUT);
            assert_eq!(max_records, MAX_PROCESS_RECORDS);
            self.batch.clone()
        }
    }

    struct RecordingProcessProvider {
        requested_names: RefCell<Vec<String>>,
    }

    impl ProcessProvider for RecordingProcessProvider {
        fn snapshot(
            &self,
            allowed_image_names: &[String],
            _timeout: Duration,
            _max_records: usize,
        ) -> ProcessSnapshotBatch {
            *self.requested_names.borrow_mut() = allowed_image_names.to_vec();
            ProcessSnapshotBatch::complete(Vec::new())
        }
    }

    fn process(
        pid: u32,
        parent_pid: Option<u32>,
        image_name: &str,
        start_time_utc: &str,
        command_line: Option<&str>,
    ) -> RawProcessSnapshot {
        RawProcessSnapshot {
            pid,
            parent_pid,
            image_name: image_name.into(),
            start_time_utc: start_time_utc.into(),
            command_line: command_line.map(str::to_string),
        }
    }

    fn collect(snapshots: Vec<RawProcessSnapshot>, local_installers: &[String]) -> ProcessEvidence {
        collect_process_evidence(
            &FakeProcessProvider {
                batch: ProcessSnapshotBatch::complete(snapshots),
            },
            local_installers,
            "2026-07-15T14:00:00Z",
        )
    }

    #[test]
    fn process_sampling_uses_fixed_and_local_evidence_allowlists_only() {
        let snapshots = vec![
            process(
                1,
                None,
                "IntuneManagementExtension.exe",
                "2026-07-15T13:59:00Z",
                None,
            ),
            process(
                2,
                Some(1),
                "AgentExecutor.EXE",
                "2026-07-15T13:59:10Z",
                None,
            ),
            process(3, Some(2), "msiexec.exe", "2026-07-15T13:59:20Z", None),
            process(4, Some(2), "winget.exe", "2026-07-15T13:59:30Z", None),
            process(5, Some(2), "ContosoSetup.exe", "2026-07-15T13:59:40Z", None),
            process(6, Some(2), "notepad.exe", "2026-07-15T13:59:50Z", None),
            process(7, Some(2), "evil.exe", "2026-07-15T13:59:55Z", None),
        ];
        let local_installers = vec![
            r"C:\ProgramData\Microsoft\IntuneManagementExtension\Content\ContosoSetup.exe"
                .to_string(),
            "*.exe".to_string(),
            r"..\evil.exe".to_string(),
        ];

        let evidence = collect(snapshots, &local_installers);
        let names = evidence
            .observations
            .iter()
            .map(|observation| observation.executable_name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "IntuneManagementExtension.exe",
                "AgentExecutor.EXE",
                "msiexec.exe",
                "winget.exe",
                "ContosoSetup.exe",
            ]
        );
        assert!(!names.contains(&"notepad.exe"));
        assert!(!names.contains(&"evil.exe"));
    }

    #[test]
    fn provider_receives_only_validated_allowlisted_names_before_querying_command_lines() {
        let provider = RecordingProcessProvider {
            requested_names: RefCell::new(Vec::new()),
        };
        collect_process_evidence(
            &provider,
            &[
                r"C:\IME\ContosoSetup.exe".to_string(),
                r"..\evil.exe".to_string(),
                "*.exe".to_string(),
            ],
            "2026-07-15T14:00:00Z",
        );

        assert_eq!(
            provider.requested_names.into_inner(),
            vec![
                "agentexecutor.exe",
                "contososetup.exe",
                "intunemanagementextension.exe",
                "msiexec.exe",
                "winget.exe",
            ]
        );
    }

    #[test]
    fn process_identity_includes_pid_and_start_time_to_survive_pid_reuse() {
        let before = process(42, None, "msiexec.exe", "2026-07-15T13:00:00Z", None);
        let after = process(42, None, "msiexec.exe", "2026-07-15T14:00:00Z", None);
        assert_ne!(before.identity(), after.identity());
        assert_eq!(before.identity().pid, after.identity().pid);
    }

    #[test]
    fn parent_chain_selects_parent_instance_that_existed_when_child_started() {
        let snapshots = vec![
            process(
                10,
                None,
                "IntuneManagementExtension.exe",
                "2026-07-15T13:00:00Z",
                None,
            ),
            process(
                20,
                Some(10),
                "AgentExecutor.exe",
                "2026-07-15T13:10:00Z",
                None,
            ),
            process(10, None, "unrelated.exe", "2026-07-15T13:30:00Z", None),
            process(30, Some(20), "msiexec.exe", "2026-07-15T13:20:00Z", None),
        ];
        let child = snapshots[3].identity();

        let chain = parent_chain(&child, &snapshots, MAX_PARENT_CHAIN_DEPTH);
        assert_eq!(
            chain,
            vec![snapshots[1].identity(), snapshots[0].identity()]
        );
    }

    #[test]
    fn command_line_is_sanitized_before_storage_but_installer_refs_are_extracted() {
        let raw = r#"msiexec.exe /i {12345678-1234-1234-1234-1234567890AB} /L*V "C:\Windows\Temp\contoso.log" --app-id 87654321-4321-4321-4321-BA0987654321 --token "top secret" https://cache/?sig=sas-secret&content=ok"#;
        let snapshots = vec![process(
            50,
            Some(20),
            "msiexec.exe",
            "2026-07-15T13:20:00Z",
            Some(raw),
        )];

        let evidence = collect(snapshots, &[]);
        let observation = &evidence.observations[0];
        let sanitized = observation
            .sanitized_command_line
            .as_deref()
            .expect("sanitized command line");
        assert!(!sanitized.contains("top secret"));
        assert!(!sanitized.contains("sas-secret"));
        assert!(sanitized.matches("[REDACTED]").count() >= 2);
        assert_eq!(
            observation.product_code.as_deref(),
            Some("{12345678-1234-1234-1234-1234567890AB}")
        );
        assert_eq!(
            observation.app_id.as_deref(),
            Some("87654321-4321-4321-4321-BA0987654321")
        );
        assert_eq!(
            observation.referenced_log_path.as_deref(),
            Some(r"C:\Windows\Temp\contoso.log")
        );
    }

    #[test]
    fn command_line_sanitizer_redacts_named_secret_and_bearer_variants() {
        let cases = [
            "--access-token s3cr3t",
            "--access_token=s3cr3t",
            "--client_secret:s3cr3t",
            "TOKEN=s3cr3t",
            "Access_Token = s3cr3t",
            "/CLIENT-SECRET \"s3cr3t\"",
            "--authorization:Bearer s3cr3t",
            "Authorization=Bearer s3cr3t",
            "https://cache.invalid/content?access_token=s3cr3t&safe=true",
        ];

        for secret_argument in cases {
            let raw = format!(
                "msiexec.exe /i {{12345678-1234-1234-1234-1234567890AB}} /L*V C:\\Windows\\Temp\\contoso.log {secret_argument}"
            );
            let sanitized = sanitize_command_line(&raw);

            assert!(
                !sanitized.contains("s3cr3t"),
                "secret leaked for variant {secret_argument}: {sanitized}"
            );
            assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
            assert!(sanitized.contains("/L*V C:\\Windows\\Temp\\contoso.log"));
            assert!(sanitized.contains("[REDACTED]"));
        }
    }

    #[test]
    fn command_line_sanitizer_redacts_authorization_credentials_and_quoted_query_secrets() {
        let cases: &[(&str, &str, &[&str])] = &[
            (
                "basic authorization",
                "--authorization Basic basic-credential-sentinel",
                &["basic-credential-sentinel"],
            ),
            (
                "api key authorization",
                "Authorization: ApiKey api-key-credential-sentinel",
                &["api-key-credential-sentinel"],
            ),
            (
                "digest authorization",
                "Authorization=Digest username=\"digest-user-sentinel\", realm=\"digest-realm-sentinel\", response=\"digest-response-sentinel\"",
                &[
                    "digest-user-sentinel",
                    "digest-realm-sentinel",
                    "digest-response-sentinel",
                ],
            ),
            (
                "double-quoted query secret",
                "https://cache.invalid/content?token=\"quoted-query-secret-sentinel\"&safe=true",
                &["quoted-query-secret-sentinel"],
            ),
            (
                "single-quoted query secret",
                "https://cache.invalid/content?access_token='single-quoted-query-secret-sentinel'&safe=true",
                &["single-quoted-query-secret-sentinel"],
            ),
        ];

        for (case, secret_argument, sentinels) in cases {
            let raw = format!(
                "msiexec.exe /i {{12345678-1234-1234-1234-1234567890AB}} /L*V C:\\Windows\\Temp\\contoso.log {secret_argument}"
            );
            let sanitized = sanitize_command_line(&raw);

            for sentinel in *sentinels {
                assert!(
                    !sanitized.contains(sentinel),
                    "{case} leaked {sentinel}: {sanitized}"
                );
            }
            assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
            assert!(sanitized.contains("/L*V C:\\Windows\\Temp\\contoso.log"));
            assert!(sanitized.contains("[REDACTED]"));
        }
    }

    #[test]
    fn timed_out_batch_keeps_bounded_partial_observations() {
        let snapshots = (0..(MAX_PROCESS_RECORDS + 3))
            .map(|offset| {
                process(
                    100 + offset as u32,
                    None,
                    "msiexec.exe",
                    "2026-07-15T13:20:00Z",
                    None,
                )
            })
            .collect();
        let provider = FakeProcessProvider {
            batch: ProcessSnapshotBatch {
                snapshots,
                completion: Err(ProcessReadError::TimedOut),
            },
        };

        let evidence = collect_process_evidence(&provider, &[], "2026-07-15T14:00:00Z");
        assert_eq!(evidence.observations.len(), MAX_PROCESS_RECORDS);
        assert_eq!(evidence.access_state, EspSourceAccessState::Failed);
        assert_eq!(
            evidence.detail.as_deref(),
            Some("process query timed out after partial results")
        );
    }

    #[test]
    fn zero_one_and_multiple_msi_snapshots_are_preserved_exactly() {
        let zero = collect(Vec::new(), &[]);
        assert_eq!(zero.observations.len(), 0);

        let one = collect(
            vec![process(
                1,
                None,
                "msiexec.exe",
                "2026-07-15T13:00:00Z",
                None,
            )],
            &[],
        );
        assert_eq!(one.observations.len(), 1);

        let multiple = collect(
            vec![
                process(1, None, "msiexec.exe", "2026-07-15T13:00:00Z", None),
                process(2, None, "msiexec.exe", "2026-07-15T13:00:01Z", None),
                process(3, None, "msiexec.exe", "2026-07-15T13:00:02Z", None),
            ],
            &[],
        );
        assert_eq!(multiple.observations.len(), 3);
        assert_eq!(
            multiple
                .observations
                .iter()
                .map(|observation| observation.pid)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn live_process_provider_is_explicitly_unsupported_off_windows() {
        let batch = LiveProcessProvider.snapshot(
            &FIXED_PROCESS_ALLOWLIST
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
            PROCESS_QUERY_TIMEOUT,
            MAX_PROCESS_RECORDS,
        );
        assert!(batch.snapshots.is_empty());
        assert_eq!(batch.completion, Err(ProcessReadError::Unsupported));
    }
}
