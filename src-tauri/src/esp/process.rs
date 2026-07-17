//! Bounded process observations for ESP and allowlisted installer activity.

use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, FixedOffset, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use cmtraceopen_parser::esp::{
    process_start_instant, EspEvidenceProvenance, EspEvidenceRef, EspObservationContext,
    EspParseState, EspProcessObservation, EspSensitivity, EspSourceAccessState, EspSourceKind,
    EspTimestamp, EspTimestampKind,
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

const TRUSTED_DYNAMIC_PROCESS_ANCESTORS: &[&str] =
    &["IntuneManagementExtension.exe", "AgentExecutor.exe"];

// Registry-derived hints are matched by image basename. Never widen that query to a shared
// interpreter or host, because an unrelated process with the same basename could expose its
// command line. Intentionally fixed names above (for example msiexec.exe) remain unaffected.
const GENERIC_PROCESS_HOSTS: &[&str] = &[
    "bash.exe",
    "cmd.exe",
    "conhost.exe",
    "cscript.exe",
    "dotnet.exe",
    "installutil.exe",
    "java.exe",
    "javaw.exe",
    "msbuild.exe",
    "mshta.exe",
    "node.exe",
    "powershell.exe",
    "pwsh.exe",
    "py.exe",
    "python.exe",
    "pythonw.exe",
    "regasm.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "sh.exe",
    "wmic.exe",
    "wscript.exe",
    "wsl.exe",
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
    pub sampled_at_utc: String,
    pub access_state: EspSourceAccessState,
    pub detail: Option<String>,
    pub observations: Vec<EspProcessObservation>,
}

/// Collects the bounded allowlisted process sample, then invokes
/// `completion_time` exactly once after the provider returns. The shared sample
/// timestamp is raised to the latest trustworthy retained process start when a
/// wall-clock rollback would otherwise predate an observation.
pub fn collect_process_evidence<F>(
    provider: &impl ProcessProvider,
    local_installer_names: &[String],
    completion_time: F,
) -> ProcessEvidence
where
    F: FnOnce() -> String,
{
    let fixed_allowlist = fixed_process_allowlist();
    let local_allowlist = local_process_allowlist(local_installer_names);
    let allowlist = fixed_allowlist
        .union(&local_allowlist)
        .cloned()
        .collect::<BTreeSet<_>>();
    let allowed_image_names = allowlist.iter().cloned().collect::<Vec<_>>();
    let mut batch = provider.snapshot(
        &allowed_image_names,
        PROCESS_QUERY_TIMEOUT,
        MAX_PROCESS_RECORDS,
    );
    batch.snapshots.truncate(MAX_PROCESS_RECORDS);
    let retained_snapshots = batch
        .snapshots
        .iter()
        .filter(|snapshot| {
            let image_name = snapshot.image_name.to_ascii_lowercase();
            fixed_allowlist.contains(&image_name)
                || (local_allowlist.contains(&image_name)
                    && has_trusted_dynamic_process_ancestor(snapshot, &batch.snapshots))
        })
        .cloned()
        .collect::<Vec<_>>();
    let partial = !retained_snapshots.is_empty();
    let (access_state, detail) = process_coverage(&batch.completion, partial);
    let sampled_at_utc = coherent_process_sample_time(&retained_snapshots, completion_time());
    let observations = retained_snapshots
        .into_iter()
        .enumerate()
        .map(|(index, snapshot)| process_observation(snapshot, index, &sampled_at_utc))
        .collect();

    ProcessEvidence {
        sampled_at_utc,
        access_state,
        detail,
        observations,
    }
}

fn has_trusted_dynamic_process_ancestor(
    snapshot: &RawProcessSnapshot,
    snapshots: &[RawProcessSnapshot],
) -> bool {
    parent_chain(&snapshot.identity(), snapshots, MAX_PARENT_CHAIN_DEPTH)
        .into_iter()
        .any(|ancestor| {
            snapshots.iter().any(|candidate| {
                candidate.identity() == ancestor
                    && TRUSTED_DYNAMIC_PROCESS_ANCESTORS
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(&candidate.image_name))
            })
        })
}

fn coherent_process_sample_time(
    snapshots: &[RawProcessSnapshot],
    completed_at_utc: String,
) -> String {
    let completed_at = DateTime::parse_from_rfc3339(&completed_at_utc)
        .ok()
        .map(|value| value.with_timezone(&Utc));
    let latest_process_start = snapshots
        .iter()
        .filter_map(|snapshot| process_start_instant(&process_timestamp(&snapshot.start_time_utc)))
        .max();
    completed_at
        .into_iter()
        .chain(latest_process_start)
        .max()
        .map(|value| value.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        .unwrap_or(completed_at_utc)
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

struct CommandLineSanitizers {
    unterminated_hardware_identity: Regex,
    unterminated_double_quoted_authorization_header: Regex,
    unterminated_single_quoted_authorization_header: Regex,
    unterminated_authorization_credential: Regex,
    unterminated_standalone_credential: Regex,
    double_quoted_authorization: Regex,
    single_quoted_authorization: Regex,
    quoted_authorization_redaction_end: Regex,
    parameterized_authorization: Regex,
    standalone_digest_challenge: Regex,
    digest_secret_parameter: Regex,
    digest_authorization: Regex,
    authorization_credential: Regex,
    standalone_basic_credential: Regex,
    bearer: Regex,
    named_secret: Regex,
    named_secret_argument_prefix: Regex,
    query_secret: Regex,
    query_secret_argument_prefix: Regex,
    json_secret: Regex,
    json_secret_key_prefix: Regex,
}

fn command_line_sanitizers() -> &'static CommandLineSanitizers {
    static SANITIZERS: OnceLock<CommandLineSanitizers> = OnceLock::new();
    SANITIZERS.get_or_init(|| CommandLineSanitizers {
        unterminated_hardware_identity: Regex::new(
            r#"(?i)(^|\s)((?:--?|/)?(?:hardware[-_]?hash|device[-_]?hardware[-_]?data))(\s*(?:=|:)\s*|\s+)(?:\"(?:\\.|[^\"])*$|'(?:\\.|[^'])*$)"#,
        )
        .expect("constant unterminated-hardware-identity regex"),
        unterminated_double_quoted_authorization_header: Regex::new(
            r#"(?i)(\")((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)(?:\\.|[^\"])*$"#,
        )
        .expect("constant unterminated-double-quoted-authorization-header regex"),
        unterminated_single_quoted_authorization_header: Regex::new(
            r#"(?i)(')((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)(?:\\.|[^'])*$"#,
        )
        .expect("constant unterminated-single-quoted-authorization-header regex"),
        unterminated_authorization_credential: Regex::new(
            r#"(?i)(^|\s|["'])((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)(?:[!#$%&'*+\-.^_\x60|~a-z0-9]+\s+)?(?:\"(?:\\.|[^\"])*$|'(?:\\.|[^'])*$)"#,
        )
        .expect("constant unterminated-authorization-credential regex"),
        unterminated_standalone_credential: Regex::new(
            r#"(?i)(^|\s)(bearer|basic)(\s+)(?:\"(?:\\.|[^\"])*$|'(?:\\.|[^'])*$)"#,
        )
        .expect("constant unterminated-standalone-credential regex"),
        double_quoted_authorization: Regex::new(
            r#"(?i)(\")((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)[!#$%&'*+\-.^_`|~a-z0-9]+\s+(?:\\.|[^\"])*\""#,
        )
        .expect("constant double-quoted-authorization regex"),
        single_quoted_authorization: Regex::new(
            r#"(?i)(')((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)[!#$%&'*+\-.^_`|~a-z0-9]+\s+(?:\\.|[^'])*'"#,
        )
        .expect("constant single-quoted-authorization regex"),
        quoted_authorization_redaction_end: Regex::new(
            r#"(?i)(?:"(?:--|/)?authorization(?:\s*(?:=|:)\s*|\s+)\[REDACTED\]"|'(?:--|/)?authorization(?:\s*(?:=|:)\s*|\s+)\[REDACTED\]')"#,
        )
        .expect("constant quoted-authorization-redaction-end regex"),
        parameterized_authorization: Regex::new(
            r#"(?i)(^|\s)((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)[!#$%&'*+\-.^_`|~a-z0-9]+\s+[!#$%&'*+\-.^_`|~a-z0-9]+\s*=\s*(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,]+)(?:(?:\s*,\s*[!#$%&'*+\-.^_`|~a-z0-9]+|\s+[!#$%&'*+.^_`|~a-z0-9][!#$%&'*+\-.^_`|~a-z0-9]*)\s*=\s*(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,]+))*(?:\s+[!#$%&'*+.^_`|~a-z0-9][^\s]*)*"#,
        )
        .expect("constant parameterized-authorization regex"),
        standalone_digest_challenge: Regex::new(
            r#"(?i)(^|\s)(digest)(\s+)[!#$%&'*+\-.^_`|~a-z0-9]+\s*=\s*(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,]+)(?:(?:\s*,\s*[!#$%&'*+\-.^_`|~a-z0-9]+|\s+[!#$%&'*+.^_`|~a-z0-9][!#$%&'*+\-.^_`|~a-z0-9]*)\s*=\s*(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,]+))*"#,
        )
        .expect("constant standalone-Digest-challenge regex"),
        digest_secret_parameter: Regex::new(
            r#"(?i)(?:^|[\s,])(?:username|response|nonce|cnonce|opaque|uri)\s*="#,
        )
        .expect("constant Digest-secret-parameter regex"),
        digest_authorization: Regex::new(
            r#"(?i)(^|\s)((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)digest\s+.*"#,
        )
        .expect("constant digest-authorization regex"),
        authorization_credential: Regex::new(
            r#"(?i)(^|\s)((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)[!#$%&'*+\-.^_`|~a-z0-9]+\s+(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s&"]+)"#,
        )
        .expect("constant authorization-credential regex"),
        standalone_basic_credential: Regex::new(
            r#"(?i)(^|\s)(basic)(\s+)((?:"[a-z0-9+/]+={0,2}"|'[a-z0-9+/]+={0,2}'|[a-z0-9+/]+={0,2})+)(\s|[.,;:!?)\]}]|$)"#,
        )
        .expect("constant standalone-Basic-credential regex"),
        bearer: Regex::new(
            r#"(?i)(bearer\s+)("(?:\\.|[^"])*"(?:[^\s&"]+|"(?:\\.|[^"])*")*|'(?:\\.|[^'])*'(?:[^\s&']+|'(?:\\.|[^'])*')*|[^\s&"]+)"#,
        )
        .expect("constant bearer regex"),
        named_secret: Regex::new(
            r#"(?i)(^|\s)((?:--?|/)?(?:access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|bearer[-_]?token|client[-_]?secret|app[-_]?secret|api[-_]?key|hardware[-_]?hash|device[-_]?hardware[-_]?data|token|password|secret|authorization))(\s*(?:=|:)\s*|\s+)(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s&"]+)"#,
        )
        .expect("constant named-secret regex"),
        named_secret_argument_prefix: Regex::new(
            r#"(?i)(^|\s)((?:--?|/)?(?:access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|bearer[-_]?token|client[-_]?secret|app[-_]?secret|api[-_]?key|hardware[-_]?hash|device[-_]?hardware[-_]?data|token|password|secret|authorization))(\s*(?:=|:)\s*|\s+)"#,
        )
        .expect("constant named-secret-argument-prefix regex"),
        query_secret: Regex::new(
            r#"(?i)([?&](?:sig|access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|bearer[-_]?token|client[-_]?secret|app[-_]?secret|api[-_]?key|hardware[-_]?hash|device[-_]?hardware[-_]?data|token|password|secret|authorization)=)(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^&\s"]+)"#,
        )
        .expect("constant query-secret regex"),
        query_secret_argument_prefix: Regex::new(
            r#"(?i)[?&](?:sig|access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|bearer[-_]?token|client[-_]?secret|app[-_]?secret|api[-_]?key|hardware[-_]?hash|device[-_]?hardware[-_]?data|token|password|secret|authorization)="#,
        )
        .expect("constant query-secret-argument-prefix regex"),
        json_secret: Regex::new(
            r#"(?i)("(?:access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|bearer[-_]?token|client[-_]?secret|app[-_]?secret|api[-_]?key|hardware[-_]?hash|device[-_]?hardware[-_]?data|token|password|secret|authorization)"\s*:\s*")(?:\\.|[^"])*(\")"#,
        )
        .expect("constant JSON-secret regex"),
        json_secret_key_prefix: Regex::new(
            r#"(?i)(?:(?:\\+)?\"(?:access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|bearer[-_]?token|client[-_]?secret|app[-_]?secret|api[-_]?key|hardware[-_]?hash|device[-_]?hardware[-_]?data|token|password|secret|authorization)(?:\\+)?\"\s*:\s*)"#,
        )
        .expect("constant JSON-secret-key-prefix regex"),
    })
}

pub fn sanitize_command_line(command_line: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(command_line) {
        if sanitize_json_command_value(&mut value) {
            return serde_json::to_string(&value)
                .expect("serializing a sanitized JSON value cannot fail");
        }
        return command_line.to_string();
    }

    sanitize_raw_command_line(command_line)
}

fn sanitize_json_command_value(value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(members) => {
            let mut changed = false;
            for (key, value) in members {
                if is_json_secret_key(key) {
                    let redacted = serde_json::Value::String("[REDACTED]".to_string());
                    if *value != redacted {
                        *value = redacted;
                        changed = true;
                    }
                } else {
                    changed |= sanitize_json_command_value(value);
                }
            }
            changed
        }
        serde_json::Value::Array(values) => values.iter_mut().fold(false, |changed, value| {
            sanitize_json_command_value(value) || changed
        }),
        serde_json::Value::String(text) => {
            let sanitized = sanitize_raw_command_line(text);
            if sanitized == *text {
                false
            } else {
                *text = sanitized;
                true
            }
        }
        _ => false,
    }
}

fn sanitize_raw_command_line(command_line: &str) -> String {
    let command_line = redact_fully_quoted_arguments(command_line);
    sanitize_raw_command_line_core(&command_line)
}

fn sanitize_raw_command_line_core(command_line: &str) -> String {
    let sanitizers = command_line_sanitizers();
    // Redact escaped JSON members before raw quote handling so their structural terminators
    // cannot be mistaken for unterminated Windows arguments.
    let command_line = redact_escaped_json_secrets(command_line);
    let command_line = redact_embedded_json_secrets(&command_line);
    let command_line = fail_closed_unstructured_json_secrets(&command_line);

    // Hardware identity payloads can be very long and may contain argument-like text. If a
    // quoted value is truncated before its closing quote, fail closed by redacting the rest.
    let command_line = sanitizers
        .unterminated_hardware_identity
        .replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = sanitizers
        .unterminated_double_quoted_authorization_header
        .replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = sanitizers
        .unterminated_single_quoted_authorization_header
        .replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = sanitizers
        .unterminated_authorization_credential
        .replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = sanitizers
        .unterminated_standalone_credential
        .replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = sanitizers
        .double_quoted_authorization
        .replace_all(&command_line, "$1$2$3[REDACTED]\"");
    let command_line = sanitizers
        .single_quoted_authorization
        .replace_all(&command_line, "$1$2$3[REDACTED]'");
    let command_line = consume_adjacent_redacted_fragments(
        &command_line,
        &sanitizers.quoted_authorization_redaction_end,
    );
    let command_line = sanitizers
        .parameterized_authorization
        .replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = sanitizers.standalone_digest_challenge.replace_all(
        &command_line,
        |captures: &regex::Captures<'_>| {
            if sanitizers.digest_secret_parameter.is_match(&captures[0]) {
                format!("{}{}{}[REDACTED]", &captures[1], &captures[2], &captures[3])
            } else {
                captures[0].to_string()
            }
        },
    );
    // Digest credentials can contain a comma-separated parameter list, so conservatively
    // redact the rest of the command line once an unquoted Digest authorization value starts.
    let command_line = sanitizers
        .digest_authorization
        .replace_all(&command_line, "$1$2$3[REDACTED]");
    // Authorization schemes are redacted with their credential before the generic named-secret
    // pass can consume only the scheme and leave the credential behind.
    let command_line = sanitizers
        .authorization_credential
        .replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = sanitizers.standalone_basic_credential.replace_all(
        &command_line,
        |captures: &regex::Captures<'_>| {
            let credential = captures[4]
                .chars()
                .filter(|character| *character != '"' && *character != '\'')
                .collect::<String>();
            let is_basic_credential = base64::engine::general_purpose::STANDARD
                .decode(credential.as_bytes())
                .or_else(|_| {
                    base64::engine::general_purpose::STANDARD_NO_PAD.decode(credential.as_bytes())
                })
                .is_ok_and(|decoded| decoded.contains(&b':'));
            if is_basic_credential {
                format!(
                    "{}{}{}[REDACTED]{}",
                    &captures[1], &captures[2], &captures[3], &captures[5]
                )
            } else {
                captures[0].to_string()
            }
        },
    );
    let command_line =
        sanitizers
            .bearer
            .replace_all(&command_line, |captures: &regex::Captures<'_>| {
                let credential =
                    captures[2].trim_matches(|character| character == '"' || character == '\'');
                let narrative_word = credential.trim_end_matches(|character| {
                    matches!(character, ',' | '.' | ';' | ':' | '!' | '?')
                });
                let narrative_word = narrative_word
                    .strip_prefix('(')
                    .and_then(|value| value.strip_suffix(')'))
                    .unwrap_or(narrative_word);
                let narrative_word = narrative_word.strip_suffix(')').unwrap_or(narrative_word);
                if narrative_word.eq_ignore_ascii_case("authentication") {
                    captures[0].to_string()
                } else {
                    format!("{}[REDACTED]", &captures[1])
                }
            });
    let command_line = redact_secret_argument_fragments(
        &command_line,
        &sanitizers.named_secret_argument_prefix,
        false,
        false,
    );
    let command_line = sanitizers
        .named_secret
        .replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = redact_secret_argument_fragments(
        &command_line,
        &sanitizers.query_secret_argument_prefix,
        true,
        false,
    );
    let command_line = sanitizers
        .query_secret
        .replace_all(&command_line, "$1[REDACTED]");
    let command_line = sanitizers
        .json_secret
        .replace_all(&command_line, "$1[REDACTED]$2");
    command_line.into_owned()
}

fn redact_fully_quoted_arguments(command_line: &str) -> String {
    let bytes = command_line.as_bytes();
    let mut output = String::with_capacity(command_line.len());
    let mut copied_through = 0usize;
    let mut cursor = 0usize;
    let mut changed = false;

    while cursor < bytes.len() {
        let quote = bytes[cursor];
        let is_argument_start = cursor == 0 || bytes[cursor - 1].is_ascii_whitespace();
        if !is_argument_start || !matches!(quote, b'"' | b'\'') {
            cursor += 1;
            continue;
        }

        let inner_start = cursor + 1;
        let closing_quote = find_matching_argument_quote(bytes, inner_start, quote);
        let inner_end = closing_quote.unwrap_or(bytes.len());
        let inner = &command_line[inner_start..inner_end];
        let sanitized_inner = sanitize_complete_quoted_argument(inner);
        if sanitized_inner != inner {
            output.push_str(&command_line[copied_through..inner_start]);
            output.push_str(&sanitized_inner);
            copied_through = inner_end;
            changed = true;
        }

        cursor = closing_quote.map_or(bytes.len(), |closing_quote| closing_quote + 1);
    }

    if !changed {
        command_line.to_string()
    } else {
        output.push_str(&command_line[copied_through..]);
        output
    }
}

fn find_matching_argument_quote(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut cursor = start;
    while cursor < bytes.len() {
        if bytes[cursor] == quote {
            let mut slash_start = cursor;
            while slash_start > start && bytes[slash_start - 1] == b'\\' {
                slash_start -= 1;
            }
            if (cursor - slash_start) % 2 == 0 {
                return Some(cursor);
            }
        }
        cursor += 1;
    }
    None
}

fn sanitize_complete_quoted_argument(argument: &str) -> String {
    let prefix = &command_line_sanitizers().named_secret_argument_prefix;
    if let Some(prefix_match) = prefix.find(argument) {
        if prefix_match.start() == 0 && prefix_match.end() < argument.len() {
            return format!("{}[REDACTED]", &argument[..prefix_match.end()]);
        }
    }
    sanitize_raw_command_line_core(argument)
}

const MAX_EMBEDDED_JSON_ESCAPE_LAYERS: usize = 3;
const MAX_EMBEDDED_JSON_NESTING: usize = 128;

fn redact_embedded_json_secrets(command_line: &str) -> String {
    let mut output = String::with_capacity(command_line.len());
    let mut copied_through = 0usize;
    let mut search_from = 0usize;
    let mut changed = false;

    while search_from < command_line.len() {
        let Some(relative_start) = command_line[search_from..].find(['{', '[']) else {
            break;
        };
        let start = search_from + relative_start;
        let Some(end) = embedded_json_container_end(command_line.as_bytes(), start) else {
            search_from = start + 1;
            continue;
        };
        let Some((mut value, escape_layers)) =
            decode_embedded_json_container(&command_line[start..end])
        else {
            search_from = start + 1;
            continue;
        };

        if sanitize_json_command_value(&mut value) {
            output.push_str(&command_line[copied_through..start]);
            output.push_str(&encode_embedded_json_container(&value, escape_layers));
            copied_through = end;
            changed = true;
        }
        search_from = end;
    }

    if !changed {
        command_line.to_string()
    } else {
        output.push_str(&command_line[copied_through..]);
        output
    }
}

fn embedded_json_container_end(bytes: &[u8], start: usize) -> Option<usize> {
    let first_closer = match bytes.get(start) {
        Some(b'{') => b'}',
        Some(b'[') => b']',
        _ => return None,
    };
    let mut stack = vec![first_closer];
    let mut cursor = start + 1;
    let mut in_string = false;
    let mut quote_width: Option<usize> = None;

    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            let mut slash_start = cursor;
            while slash_start > start && bytes[slash_start - 1] == b'\\' {
                slash_start -= 1;
            }
            let width = cursor - slash_start;
            match quote_width {
                None => {
                    quote_width = Some(width);
                    in_string = true;
                }
                Some(expected_width) if width == expected_width => {
                    in_string = !in_string;
                }
                _ => {}
            }
            cursor += 1;
            continue;
        }

        if !in_string {
            match bytes[cursor] {
                b'{' | b'[' => {
                    if stack.len() == MAX_EMBEDDED_JSON_NESTING {
                        return None;
                    }
                    stack.push(if bytes[cursor] == b'{' { b'}' } else { b']' });
                }
                b'}' | b']' => {
                    if stack.pop() != Some(bytes[cursor]) {
                        return None;
                    }
                    if stack.is_empty() {
                        return Some(cursor + 1);
                    }
                }
                _ => {}
            }
        }
        cursor += 1;
    }
    None
}

fn decode_embedded_json_container(container: &str) -> Option<(serde_json::Value, usize)> {
    let mut decoded = container.to_string();
    for escape_layers in 0..=MAX_EMBEDDED_JSON_ESCAPE_LAYERS {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&decoded) {
            return Some((value, escape_layers));
        }
        if escape_layers == MAX_EMBEDDED_JSON_ESCAPE_LAYERS {
            break;
        }
        decoded = serde_json::from_str::<String>(&format!("\"{decoded}\"")).ok()?;
    }
    None
}

fn encode_embedded_json_container(value: &serde_json::Value, escape_layers: usize) -> String {
    let mut encoded =
        serde_json::to_string(value).expect("serializing a sanitized JSON value cannot fail");
    for _ in 0..escape_layers {
        let wrapped =
            serde_json::to_string(&encoded).expect("serializing a JSON string cannot fail");
        encoded = wrapped[1..wrapped.len() - 1].to_string();
    }
    encoded
}

fn fail_closed_unstructured_json_secrets(command_line: &str) -> String {
    let prefix = &command_line_sanitizers().json_secret_key_prefix;
    let mut search_from = 0usize;

    while let Some(prefix_match) = prefix.find_at(command_line, search_from) {
        let value_start = prefix_match.end();
        if let Some(redacted_end) = encoded_redacted_json_string_end(command_line, value_start) {
            search_from = redacted_end;
            continue;
        }
        return format!("{}[REDACTED]", &command_line[..value_start]);
    }
    command_line.to_string()
}

fn encoded_redacted_json_string_end(command_line: &str, start: usize) -> Option<usize> {
    let bytes = command_line.as_bytes();
    let mut quote = start;
    while bytes.get(quote) == Some(&b'\\') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }

    let delimiter = &command_line[start..=quote];
    let value_start = quote + 1;
    let value_end = value_start + "[REDACTED]".len();
    (command_line.get(value_start..value_end) == Some("[REDACTED]")
        && command_line
            .get(value_end..)
            .is_some_and(|suffix| suffix.starts_with(delimiter)))
    .then_some(value_end + delimiter.len())
}

fn redact_secret_argument_fragments(
    command_line: &str,
    prefix: &Regex,
    stop_at_ampersand: bool,
    stop_at_json_string_end: bool,
) -> String {
    let mut sanitized = String::with_capacity(command_line.len());
    let mut copied_through = 0;
    let mut search_from = 0;

    while search_from < command_line.len() {
        let Some(prefix_match) = prefix.find_at(command_line, search_from) else {
            break;
        };
        let value_start = prefix_match.end();
        let value_end = secret_argument_end(
            command_line,
            value_start,
            stop_at_ampersand,
            stop_at_json_string_end,
        );
        if value_end == value_start {
            search_from = value_start;
            if search_from == command_line.len() {
                break;
            }
            continue;
        }

        sanitized.push_str(&command_line[copied_through..value_start]);
        sanitized.push_str("[REDACTED]");
        copied_through = value_end;
        search_from = value_end;
    }

    sanitized.push_str(&command_line[copied_through..]);
    sanitized
}

fn consume_adjacent_redacted_fragments(command_line: &str, redaction_end: &Regex) -> String {
    let mut sanitized = String::with_capacity(command_line.len());
    let mut copied_through = 0;
    let mut search_from = 0;

    while search_from < command_line.len() {
        let Some(redacted_match) = redaction_end.find_at(command_line, search_from) else {
            break;
        };
        let suffix_start = redacted_match.end();
        let suffix_end = secret_argument_end(command_line, suffix_start, false, false);
        if suffix_end == suffix_start {
            search_from = suffix_start;
            if search_from == command_line.len() {
                break;
            }
            continue;
        }

        sanitized.push_str(&command_line[copied_through..suffix_start]);
        copied_through = suffix_end;
        search_from = suffix_end;
    }

    sanitized.push_str(&command_line[copied_through..]);
    sanitized
}

// Windows joins adjacent quoted and unquoted fragments into one argument. Track quote state
// (including double-quote backslash parity) so a sensitive value is consumed to its real
// argument boundary; an unmatched quote deliberately consumes the remaining command line.
fn secret_argument_end(
    command_line: &str,
    value_start: usize,
    stop_at_ampersand: bool,
    stop_at_json_string_end: bool,
) -> usize {
    let bytes = command_line.as_bytes();
    let mut index = value_start;
    let mut in_double_quotes = false;
    let mut in_single_quotes = false;

    while index < bytes.len() {
        let byte = bytes[index];
        if !in_double_quotes
            && !in_single_quotes
            && (matches!(byte, b' ' | b'\t' | b'\r' | b'\n') || (stop_at_ampersand && byte == b'&'))
        {
            break;
        }

        if !in_double_quotes
            && !in_single_quotes
            && byte == b'"'
            && stop_at_json_string_end
            && is_json_string_end(bytes, index)
        {
            break;
        }

        if byte == b'\\' {
            let slash_start = index;
            while index < bytes.len() && bytes[index] == b'\\' {
                index += 1;
            }
            if index < bytes.len() && bytes[index] == b'"' {
                if !in_single_quotes && (index - slash_start) % 2 == 0 {
                    in_double_quotes = !in_double_quotes;
                }
                index += 1;
            }
            continue;
        }

        if byte == b'"' && !in_single_quotes {
            in_double_quotes = !in_double_quotes;
        } else if byte == b'\'' && !in_double_quotes && (in_single_quotes || index == value_start) {
            in_single_quotes = !in_single_quotes;
        }
        index += 1;
    }

    index
}

fn is_json_string_end(bytes: &[u8], quote_index: usize) -> bool {
    let mut index = quote_index + 1;
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'\r' | b'\n') {
        index += 1;
    }
    index == bytes.len() || matches!(bytes[index], b',' | b'}' | b']')
}

fn redact_escaped_json_secrets(command_line: &str) -> String {
    let mut output = String::with_capacity(command_line.len());
    let mut copied_through = 0usize;
    let mut search_from = 0usize;

    while let Some((value_start, closing_start, closing_end)) =
        find_escaped_json_secret(command_line, search_from)
    {
        output.push_str(&command_line[copied_through..value_start]);
        output.push_str("[REDACTED]");
        copied_through = closing_start;
        search_from = closing_end;
    }

    if copied_through == 0 {
        command_line.to_string()
    } else {
        output.push_str(&command_line[copied_through..]);
        output
    }
}

fn find_escaped_json_secret(
    command_line: &str,
    search_from: usize,
) -> Option<(usize, usize, usize)> {
    let bytes = command_line.as_bytes();
    let mut cursor = search_from;

    while cursor < bytes.len() {
        let Some((quote_width, opening_quote)) = escaped_quote_run(bytes, cursor) else {
            cursor += 1;
            continue;
        };
        if !is_escaped_json_key_boundary(bytes, cursor) {
            cursor = opening_quote + 1;
            continue;
        }
        let key_start = opening_quote + 1;
        let Some((key_closing_start, key_closing_quote)) =
            find_escaped_json_key_end(bytes, key_start, quote_width)
        else {
            cursor = opening_quote + 1;
            continue;
        };
        let key = &command_line[key_start..key_closing_start];
        if !is_json_secret_key(key) {
            cursor = key_closing_quote + 1;
            continue;
        }

        let mut value_opening_start = key_closing_quote + 1;
        skip_ascii_whitespace(bytes, &mut value_opening_start);
        if bytes.get(value_opening_start) != Some(&b':') {
            cursor = key_closing_quote + 1;
            continue;
        }
        value_opening_start += 1;
        skip_ascii_whitespace(bytes, &mut value_opening_start);
        let Some((value_quote_width, value_opening_quote)) =
            escaped_quote_run(bytes, value_opening_start)
        else {
            cursor = key_closing_quote + 1;
            continue;
        };

        let value_start = value_opening_quote + 1;
        return Some(
            match find_escaped_json_value_end(
                bytes,
                value_start,
                value_quote_width,
                (value_quote_width == quote_width).then_some(quote_width),
            ) {
                EscapedJsonValueEnd::Complete {
                    closing_start,
                    closing_quote,
                } => (value_start, closing_start, closing_quote + 1),
                EscapedJsonValueEnd::Malformed { boundary } => {
                    // The candidate key is sensitive, so an unterminated value must fail closed.
                    // Stop at a defensible outer boundary when one exists; scanning resumes there
                    // so a later well-formed secret is redacted independently.
                    (value_start, boundary, boundary)
                }
            },
        );
    }

    None
}

fn escaped_quote_run(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    if bytes.get(start) != Some(&b'\\') {
        return None;
    }
    let mut quote = start;
    while bytes.get(quote) == Some(&b'\\') {
        quote += 1;
    }
    (bytes.get(quote) == Some(&b'"')).then_some((quote - start, quote))
}

fn is_escaped_json_key_boundary(bytes: &[u8], start: usize) -> bool {
    let mut cursor = start;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    cursor == 0 || matches!(bytes[cursor - 1], b'{' | b'[' | b',' | b'=')
}

fn find_escaped_json_key_end(
    bytes: &[u8],
    start: usize,
    quote_width: usize,
) -> Option<(usize, usize)> {
    let mut cursor = start;
    while bytes.get(cursor).is_some_and(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b' ')
    }) && cursor - start < MAX_ESCAPED_JSON_KEY_BYTES
    {
        cursor += 1;
    }
    if cursor == start || cursor - start > MAX_ESCAPED_JSON_KEY_BYTES {
        return None;
    }
    let (width, quote) = escaped_quote_run(bytes, cursor)?;
    (width == quote_width).then_some((cursor, quote))
}

const MAX_ESCAPED_JSON_KEY_BYTES: usize = 64;

enum EscapedJsonValueEnd {
    Complete {
        closing_start: usize,
        closing_quote: usize,
    },
    Malformed {
        boundary: usize,
    },
}

fn find_escaped_json_value_end(
    bytes: &[u8],
    start: usize,
    quote_width: usize,
    member_quote_width: Option<usize>,
) -> EscapedJsonValueEnd {
    let mut cursor = start;
    let mut terminal_fallback: Option<(usize, usize)> = None;
    while cursor < bytes.len() {
        if let Some((width, quote)) = escaped_quote_run(bytes, cursor) {
            if let Some(fallback) = terminal_fallback {
                if is_escaped_json_member_opener_with_width(bytes, cursor, None) {
                    return EscapedJsonValueEnd::Complete {
                        closing_start: fallback.0,
                        closing_quote: fallback.1,
                    };
                }
            }
            if width == quote_width {
                if is_escaped_json_value_close(bytes, quote + 1, member_quote_width) {
                    return EscapedJsonValueEnd::Complete {
                        closing_start: cursor,
                        closing_quote: quote,
                    };
                }
                cursor = quote + 1;
                continue;
            }
            if width > quote_width {
                let closing = (cursor + width - quote_width, quote);
                match escaped_json_value_boundary(bytes, quote + 1, member_quote_width) {
                    EscapedJsonValueBoundary::NextMember => {
                        return EscapedJsonValueEnd::Complete {
                            closing_start: closing.0,
                            closing_quote: closing.1,
                        };
                    }
                    EscapedJsonValueBoundary::Terminal => {
                        // Retain the first structurally plausible terminator. A later object with
                        // a wider escape layer must not move the boundary across real arguments.
                        terminal_fallback.get_or_insert(closing);
                    }
                    EscapedJsonValueBoundary::None => {}
                }
            }
            cursor = quote + 1;
        } else if terminal_fallback.is_none() && matches!(bytes[cursor], b'}' | b']') {
            if let Some(boundary) = malformed_raw_closer_boundary(bytes, cursor) {
                return EscapedJsonValueEnd::Malformed { boundary };
            }
            cursor += 1;
        } else {
            cursor += 1;
        }
    }
    let Some((closing_start, closing_quote)) = terminal_fallback else {
        return EscapedJsonValueEnd::Malformed {
            boundary: bytes.len(),
        };
    };
    if let Some(boundary) = ambiguous_terminal_suffix_boundary(bytes, closing_quote + 1) {
        EscapedJsonValueEnd::Malformed { boundary }
    } else {
        EscapedJsonValueEnd::Complete {
            closing_start,
            closing_quote,
        }
    }
}

fn malformed_raw_closer_boundary(bytes: &[u8], closer: usize) -> Option<usize> {
    let suffix_start = closer + 1;
    if bytes[suffix_start..]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        // Without a closing quote, neither an option-shaped token nor a new container can prove
        // where the sensitive value ended. The value may contain either. Privacy therefore wins
        // over retaining the ambiguous command-line suffix.
        Some(bytes.len())
    } else {
        Some(closer)
    }
}

fn ambiguous_terminal_suffix_boundary(bytes: &[u8], after_quote: usize) -> Option<usize> {
    let mut container = after_quote;
    skip_ascii_whitespace(bytes, &mut container);
    if !matches!(bytes.get(container), Some(b'}' | b']')) {
        return None;
    }

    let suffix_start = container + 1;
    bytes[suffix_start..]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
        .then_some(bytes.len())
}

fn is_escaped_json_member_opener_with_width(
    bytes: &[u8],
    start: usize,
    quote_width: Option<usize>,
) -> bool {
    if !is_escaped_json_key_boundary(bytes, start) {
        return false;
    }
    let Some((width, opening_quote)) = escaped_quote_run(bytes, start) else {
        return false;
    };
    if quote_width.is_some_and(|quote_width| width != quote_width) {
        return false;
    }
    let Some((_, key_closing_quote)) =
        find_escaped_json_member_key_end(bytes, opening_quote + 1, width)
    else {
        return false;
    };
    let mut cursor = key_closing_quote + 1;
    skip_ascii_whitespace(bytes, &mut cursor);
    bytes.get(cursor) == Some(&b':')
}

fn find_escaped_json_member_key_end(
    bytes: &[u8],
    start: usize,
    quote_width: usize,
) -> Option<(usize, usize)> {
    let mut cursor = start;
    while bytes.get(cursor).is_some_and(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b' ')
    }) && cursor - start < MAX_ESCAPED_JSON_KEY_BYTES
    {
        cursor += 1;
    }
    if cursor == start || cursor - start > MAX_ESCAPED_JSON_KEY_BYTES {
        return None;
    }
    let (width, quote) = escaped_quote_run(bytes, cursor)?;
    (width == quote_width).then_some((cursor, quote))
}

fn is_escaped_json_value_close(
    bytes: &[u8],
    after_quote: usize,
    member_quote_width: Option<usize>,
) -> bool {
    let mut cursor = after_quote;
    skip_ascii_whitespace(bytes, &mut cursor);
    match bytes.get(cursor) {
        None | Some(b'}' | b']') => true,
        Some(b',') => {
            cursor += 1;
            skip_ascii_whitespace(bytes, &mut cursor);
            is_escaped_json_member_opener_with_width(bytes, cursor, member_quote_width)
        }
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EscapedJsonValueBoundary {
    None,
    NextMember,
    Terminal,
}

fn escaped_json_value_boundary(
    bytes: &[u8],
    after_quote: usize,
    member_quote_width: Option<usize>,
) -> EscapedJsonValueBoundary {
    let mut cursor = after_quote;
    skip_ascii_whitespace(bytes, &mut cursor);
    match bytes.get(cursor) {
        None | Some(b'}' | b']') => EscapedJsonValueBoundary::Terminal,
        Some(b',') => {
            cursor += 1;
            skip_ascii_whitespace(bytes, &mut cursor);
            if is_escaped_json_member_opener_with_width(bytes, cursor, member_quote_width) {
                EscapedJsonValueBoundary::NextMember
            } else {
                EscapedJsonValueBoundary::None
            }
        }
        _ => EscapedJsonValueBoundary::None,
    }
}

fn skip_ascii_whitespace(bytes: &[u8], cursor: &mut usize) {
    while bytes.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
        *cursor += 1;
    }
}

fn is_json_secret_key(key: &str) -> bool {
    let normalized = key
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    matches!(
        normalized.as_slice(),
        b"accesstoken"
            | b"refreshtoken"
            | b"idtoken"
            | b"authtoken"
            | b"bearertoken"
            | b"clientsecret"
            | b"appsecret"
            | b"apikey"
            | b"hardwarehash"
            | b"devicehardwaredata"
            | b"token"
            | b"password"
            | b"secret"
            | b"authorization"
    )
}

fn fixed_process_allowlist() -> BTreeSet<String> {
    FIXED_PROCESS_ALLOWLIST
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect()
}

fn local_process_allowlist(local_installer_names: &[String]) -> BTreeSet<String> {
    let mut allowlist = BTreeSet::new();
    for name in local_installer_names
        .iter()
        .filter_map(|name| normalize_local_installer_name(name))
        .map(|name| name.to_ascii_lowercase())
    {
        allowlist.insert(name);
        if allowlist.len() == MAX_LOCAL_INSTALLER_NAMES {
            break;
        }
    }
    allowlist
}

pub(super) fn normalize_local_installer_name(raw: &str) -> Option<String> {
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
        || GENERIC_PROCESS_HOSTS
            .iter()
            .any(|host| host.eq_ignore_ascii_case(name))
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
    let sanitized_command_line = command_line.map(sanitize_command_line);
    let safe_command_line = sanitized_command_line.as_deref();
    EspProcessObservation {
        context: process_context(index, observed_at_utc),
        pid: snapshot.pid,
        process_start_time: process_timestamp(&snapshot.start_time_utc),
        parent_pid: snapshot.parent_pid,
        executable_name: snapshot.image_name,
        referenced_log_path: safe_command_line.and_then(extract_log_path),
        app_id: safe_command_line.and_then(extract_app_id),
        product_code: safe_command_line.and_then(extract_product_code),
        sanitized_command_line,
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
    let regex = Regex::new(r#"(?i)(?:^|\s)/(?:log|l[*+!voicewarmupx]*)\s+(?:"([^"]+)"|(\S+))"#)
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use cmtraceopen_parser::esp::{
        correlate_installer_processes, EspSourceAccessState, EspTimestampKind,
    };

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

    struct DelayedBirthProcessProvider {
        query_completed: Arc<AtomicBool>,
    }

    impl ProcessProvider for DelayedBirthProcessProvider {
        fn snapshot(
            &self,
            _allowed_image_names: &[String],
            timeout: Duration,
            max_records: usize,
        ) -> ProcessSnapshotBatch {
            assert_eq!(timeout, PROCESS_QUERY_TIMEOUT);
            assert_eq!(max_records, MAX_PROCESS_RECORDS);
            self.query_completed.store(true, Ordering::SeqCst);
            ProcessSnapshotBatch::complete(vec![RawProcessSnapshot {
                pid: 45,
                parent_pid: None,
                image_name: "msiexec.exe".to_string(),
                start_time_utc: "2026-07-15T14:00:01.123456789Z".to_string(),
                command_line: None,
            }])
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
            || "2026-07-15T14:00:00Z".to_string(),
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
    fn local_installer_name_cap_applies_after_deduplication() {
        let mut local_installers = (0..MAX_LOCAL_INSTALLER_NAMES)
            .map(|index| {
                if index % 2 == 0 {
                    r"C:\IME\RepeatedSetup.EXE".to_string()
                } else {
                    "repeatedsetup.exe".to_string()
                }
            })
            .collect::<Vec<_>>();
        local_installers.push("LateUniqueSetup.exe".to_string());

        let allowlist = local_process_allowlist(&local_installers);

        assert_eq!(allowlist.len(), 2);
        assert!(allowlist.contains("repeatedsetup.exe"));
        assert!(allowlist.contains("lateuniquesetup.exe"));
    }

    #[test]
    fn dynamic_installer_snapshot_requires_trusted_intune_ancestry() {
        let snapshots = vec![
            process(20, None, "AgentExecutor.exe", "2026-07-15T13:00:00Z", None),
            process(
                30,
                Some(20),
                "ContosoSetup.exe",
                "2026-07-15T13:01:00Z",
                Some("ContosoSetup.exe /quiet"),
            ),
            process(
                31,
                None,
                "ContosoSetup.exe",
                "2026-07-15T13:02:00Z",
                Some("ContosoSetup.exe --note unrelated-command-line-sentinel"),
            ),
        ];

        let evidence = collect(snapshots, &["ContosoSetup.exe".to_string()]);
        let identities = evidence
            .observations
            .iter()
            .map(|observation| (observation.pid, observation.executable_name.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            identities,
            vec![(20, "AgentExecutor.exe"), (30, "ContosoSetup.exe")]
        );
        let serialized = serde_json::to_string(&evidence).expect("serialize process evidence");
        assert!(!serialized.contains("unrelated-command-line-sentinel"));
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
            || "2026-07-15T14:00:00Z".to_string(),
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
    fn generic_interpreters_are_never_promoted_by_local_installer_hints() {
        let provider = RecordingProcessProvider {
            requested_names: RefCell::new(Vec::new()),
        };
        collect_process_evidence(
            &provider,
            &[
                "powershell.exe".to_string(),
                "pwsh.exe".to_string(),
                "cmd.exe".to_string(),
                "wscript.exe".to_string(),
                "ContosoSetup.exe".to_string(),
            ],
            || "2026-07-15T14:00:00Z".to_string(),
        );

        let requested_names = provider.requested_names.into_inner();
        assert!(requested_names.contains(&"contososetup.exe".to_string()));
        for generic_host in ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe"] {
            assert!(!requested_names.contains(&generic_host.to_string()));
        }
    }

    #[test]
    fn process_identity_includes_pid_and_start_time_to_survive_pid_reuse() {
        let before = process(42, None, "msiexec.exe", "2026-07-15T13:00:00Z", None);
        let after = process(42, None, "msiexec.exe", "2026-07-15T14:00:00Z", None);
        assert_ne!(before.identity(), after.identity());
        assert_eq!(before.identity().pid, after.identity().pid);
    }

    #[test]
    fn native_known_zero_offset_process_start_survives_parser_correlation() {
        let evidence = collect(
            vec![process(
                43,
                None,
                "msiexec.exe",
                "2026-07-15T13:00:00+00:00",
                None,
            )],
            &[],
        );
        let observation = &evidence.observations[0];

        assert_eq!(observation.process_start_time.kind, EspTimestampKind::Utc);
        let correlations =
            correlate_installer_processes(&[], std::slice::from_ref(observation), &[], &[]);
        assert_eq!(correlations.len(), 1);
        assert_eq!(
            correlations[0].correlation_id,
            "installer|43|2026-07-15T13:00:00Z"
        );
    }

    #[test]
    fn native_unknown_negative_zero_offset_process_start_stays_uncorrelated() {
        let evidence = collect(
            vec![process(
                44,
                None,
                "msiexec.exe",
                "2026-07-15T13:00:00-00:00",
                None,
            )],
            &[],
        );
        let observation = &evidence.observations[0];

        assert_eq!(observation.process_start_time.kind, EspTimestampKind::Utc);
        assert!(
            correlate_installer_processes(&[], std::slice::from_ref(observation), &[], &[],)
                .is_empty()
        );
    }

    #[test]
    fn process_born_during_snapshot_query_keeps_a_correlatable_sample_time() {
        let query_completed = Arc::new(AtomicBool::new(false));
        let provider = DelayedBirthProcessProvider {
            query_completed: Arc::clone(&query_completed),
        };

        let evidence = collect_process_evidence(&provider, &[], || {
            assert!(query_completed.load(Ordering::SeqCst));
            "2026-07-15T14:00:02Z".to_string()
        });
        let observation = &evidence.observations[0];
        let started = DateTime::parse_from_rfc3339(&observation.process_start_time.raw_text)
            .expect("process start time");
        let sampled = DateTime::parse_from_rfc3339(&observation.context.observed_at_utc)
            .expect("process sample time");

        assert!(
            sampled >= started,
            "sampled {sampled} before start {started}"
        );
        assert_eq!(
            correlate_installer_processes(&[], std::slice::from_ref(observation), &[], &[],).len(),
            1
        );
    }

    #[test]
    fn injected_completion_clock_is_repeatable_and_preserves_valid_start_precision() {
        let snapshots = vec![
            process(
                46,
                None,
                "msiexec.exe",
                "2026-07-15T14:00:01.123456789Z",
                None,
            ),
            process(
                47,
                None,
                "msiexec.exe",
                "2026-07-15T14:00:01.9999999991Z",
                None,
            ),
            process(48, None, "msiexec.exe", "not-a-process-start", None),
        ];
        let collect_once = || {
            collect_process_evidence(
                &FakeProcessProvider {
                    batch: ProcessSnapshotBatch::complete(snapshots.clone()),
                },
                &[],
                || "2026-07-15T14:00:00Z".to_string(),
            )
        };

        let first = collect_once();
        let second = collect_once();

        assert_eq!(first, second);
        assert_eq!(first.sampled_at_utc, "2026-07-15T14:00:01.123456789Z");
        assert!(first
            .observations
            .iter()
            .all(|observation| observation.context.observed_at_utc == first.sampled_at_utc));
    }

    #[test]
    fn disallowed_future_snapshot_does_not_move_the_retained_sample_time() {
        let evidence = collect_process_evidence(
            &FakeProcessProvider {
                batch: ProcessSnapshotBatch::complete(vec![
                    process(49, None, "msiexec.exe", "2026-07-15T14:00:01Z", None),
                    process(50, None, "untrusted.exe", "2099-01-01T00:00:00Z", None),
                ]),
            },
            &[],
            || "2026-07-15T14:00:02Z".to_string(),
        );

        assert_eq!(evidence.observations.len(), 1);
        assert_eq!(evidence.sampled_at_utc, "2026-07-15T14:00:02Z");
        assert_eq!(
            evidence.observations[0].context.observed_at_utc,
            evidence.sampled_at_utc
        );
    }

    #[test]
    fn future_snapshot_beyond_record_cap_does_not_move_the_retained_sample_time() {
        let mut snapshots = (0..MAX_PROCESS_RECORDS)
            .map(|index| {
                process(
                    1_000 + index as u32,
                    None,
                    "msiexec.exe",
                    "2026-07-15T14:00:01Z",
                    None,
                )
            })
            .collect::<Vec<_>>();
        snapshots.push(process(
            9_999,
            None,
            "msiexec.exe",
            "2099-01-01T00:00:00Z",
            None,
        ));

        let evidence = collect_process_evidence(
            &FakeProcessProvider {
                batch: ProcessSnapshotBatch::complete(snapshots),
            },
            &[],
            || "2026-07-15T14:00:02Z".to_string(),
        );

        assert_eq!(evidence.observations.len(), MAX_PROCESS_RECORDS);
        assert_eq!(evidence.sampled_at_utc, "2026-07-15T14:00:02Z");
        assert!(evidence
            .observations
            .iter()
            .all(|observation| observation.context.observed_at_utc == evidence.sampled_at_utc));
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
    fn hardware_identity_values_are_redacted_before_process_evidence_serialization() {
        let raw = concat!(
            "msiexec.exe /i {12345678-1234-1234-1234-1234567890AB} ",
            "--HardwareHash hardware-hash-raw-secret ",
            "--DeviceHardwareData=device-hardware-data-raw-secret ",
            "/L*V C:\\Windows\\Temp\\contoso.log"
        );
        let evidence = collect(
            vec![process(
                52,
                Some(20),
                "msiexec.exe",
                "2026-07-15T13:20:00Z",
                Some(raw),
            )],
            &[],
        );

        let serialized = serde_json::to_string(&evidence).expect("serialize process evidence");
        assert!(!serialized.contains("hardware-hash-raw-secret"));
        assert!(!serialized.contains("device-hardware-data-raw-secret"));
        assert!(serialized.matches("[REDACTED]").count() >= 2);
        assert!(serialized.contains("contoso.log"));
    }

    #[test]
    fn hardware_identity_payload_cannot_seed_derived_installer_references() {
        let raw = concat!(
            "msiexec.exe --DeviceHardwareData \"opaque-hardware-payload ",
            "/L*V C:\\Windows\\Temp\\hardware-payload-secret.log ",
            "/i {11111111-1111-1111-1111-111111111111} ",
            "--app-id 22222222-2222-2222-2222-222222222222\""
        );
        let evidence = collect(
            vec![process(
                53,
                Some(20),
                "msiexec.exe",
                "2026-07-15T13:20:00Z",
                Some(raw),
            )],
            &[],
        );
        let observation = &evidence.observations[0];

        assert_eq!(observation.referenced_log_path, None);
        assert_eq!(observation.product_code, None);
        assert_eq!(observation.app_id, None);
        let serialized = serde_json::to_string(&evidence).expect("serialize process evidence");
        assert!(!serialized.contains("hardware-payload-secret"));
        assert!(!serialized.contains("11111111-1111-1111-1111-111111111111"));
        assert!(!serialized.contains("22222222-2222-2222-2222-222222222222"));
    }

    #[test]
    fn command_line_sanitizer_redacts_hardware_identity_field_variants() {
        let cases = [
            (
                "-HardwareHash single-dash-hash-secret",
                "single-dash-hash-secret",
            ),
            ("--HardwareHash direct-hash-secret", "direct-hash-secret"),
            (
                "/device_hardware_data=direct-device-data-secret",
                "direct-device-data-secret",
            ),
            (
                "https://enrollment.invalid/?hardware-hash=query-hash-secret&safe=true",
                "query-hash-secret",
            ),
            (
                r#"--payload {"DeviceHardwareData":"json-device-data-secret","safe":"keep-json-control"}"#,
                "json-device-data-secret",
            ),
            (
                r#"--payload {\"HardwareHash\":\"escaped-hash-secret\",\"safe\":\"keep-escaped-control\"}"#,
                "escaped-hash-secret",
            ),
        ];

        for (argument, sentinel) in cases {
            let raw = format!("msiexec.exe {argument} --mode keep-this-control");
            let sanitized = sanitize_command_line(&raw);

            assert!(
                !sanitized.contains(sentinel),
                "hardware identity leaked for {argument}: {sanitized}"
            );
            assert!(sanitized.contains("[REDACTED]"));
            assert!(sanitized.contains("--mode keep-this-control"));
        }

        let safe_neighbors =
            "installer.exe --hardware-hash-mode SHA256 --device-hardware-data-format base64";
        assert_eq!(sanitize_command_line(safe_neighbors), safe_neighbors);
    }

    #[test]
    fn unterminated_hardware_identity_quotes_fail_closed_before_serialization() {
        for option in ["--HardwareHash", "--DeviceHardwareData"] {
            let raw = format!(
                "msiexec.exe {option} \"unterminated-hardware-secret \
                 /L*V C:\\Windows\\Temp\\hardware-secret.log \
                 /i {{33333333-3333-3333-3333-333333333333}} \
                 --app-id 44444444-4444-4444-4444-444444444444"
            );
            let evidence = collect(
                vec![process(
                    54,
                    Some(20),
                    "msiexec.exe",
                    "2026-07-15T13:20:00Z",
                    Some(&raw),
                )],
                &[],
            );
            let observation = &evidence.observations[0];
            let serialized = serde_json::to_string(&evidence).expect("serialize process evidence");

            assert!(serialized.contains("[REDACTED]"));
            assert!(!serialized.contains("unterminated-hardware-secret"));
            assert!(!serialized.contains("hardware-secret.log"));
            assert!(!serialized.contains("33333333-3333-3333-3333-333333333333"));
            assert!(!serialized.contains("44444444-4444-4444-4444-444444444444"));
            assert_eq!(observation.referenced_log_path, None);
            assert_eq!(observation.product_code, None);
            assert_eq!(observation.app_id, None);
        }
    }

    #[test]
    fn adjacent_windows_hardware_identity_fragments_are_fully_redacted_before_serialization() {
        for option in ["--HardwareHash", "--DeviceHardwareData"] {
            let raw = format!(
                r#"msiexec.exe {option}="prefix-hardware-secret"suffix-hardware-secret /L*V C:\Windows\Temp\safe-installer.log"#
            );
            let evidence = collect(
                vec![process(
                    55,
                    Some(20),
                    "msiexec.exe",
                    "2026-07-15T13:20:00Z",
                    Some(&raw),
                )],
                &[],
            );
            let observation = &evidence.observations[0];
            let serialized = serde_json::to_string(&evidence).expect("serialize process evidence");

            assert!(serialized.contains("[REDACTED]"));
            assert!(!serialized.contains("prefix-hardware-secret"));
            assert!(!serialized.contains("suffix-hardware-secret"));
            assert_eq!(
                observation.referenced_log_path.as_deref(),
                Some(r"C:\Windows\Temp\safe-installer.log")
            );
        }
    }

    #[test]
    fn adjacent_windows_named_and_query_secret_fragments_are_fully_redacted() {
        let cases = [
            (
                r#"--token="prefix-token-secret"suffix-token-secret --mode keep-option"#,
                ["prefix-token-secret", "suffix-token-secret"],
                "keep-option",
            ),
            (
                r#"https://cache.invalid/content?token="prefix-query-secret"suffix-query-secret&safe=keep-query"#,
                ["prefix-query-secret", "suffix-query-secret"],
                "keep-query",
            ),
        ];

        for (secret_argument, sentinels, safe_sentinel) in cases {
            let raw = format!("msiexec.exe {secret_argument}");
            let evidence = collect(
                vec![process(
                    56,
                    Some(20),
                    "msiexec.exe",
                    "2026-07-15T13:20:00Z",
                    Some(&raw),
                )],
                &[],
            );
            let serialized = serde_json::to_string(&evidence).expect("serialize process evidence");

            assert!(serialized.contains("[REDACTED]"));
            for sentinel in sentinels {
                assert!(
                    !serialized.contains(sentinel),
                    "adjacent fragment leaked {sentinel}: {serialized}"
                );
            }
            assert!(serialized.contains(safe_sentinel));
        }
    }

    #[test]
    fn adjacent_authorization_credential_fragments_are_fully_redacted() {
        let cases = [
            (
                r#"Bearer "prefix-bearer-secret"suffix-bearer-secret --mode keep-bearer"#,
                ["prefix-bearer-secret", "suffix-bearer-secret"],
                "keep-bearer",
            ),
            (
                r#"Basic "dXNlcjpwYXNz"d29yZA== --mode keep-basic"#,
                ["dXNlcjpwYXNz", "d29yZA=="],
                "keep-basic",
            ),
            (
                r#""Authorization: Bearer prefix-header-secret"suffix-header-secret --mode keep-header"#,
                ["prefix-header-secret", "suffix-header-secret"],
                "keep-header",
            ),
        ];

        for (secret_argument, sentinels, safe_sentinel) in cases {
            let sanitized = sanitize_command_line(secret_argument);

            assert!(sanitized.contains("[REDACTED]"));
            for sentinel in sentinels {
                assert!(
                    !sanitized.contains(sentinel),
                    "adjacent authorization fragment leaked {sentinel}: {sanitized}"
                );
            }
            assert!(sanitized.contains(safe_sentinel));
        }
    }

    #[test]
    fn named_secret_arguments_inside_valid_json_preserve_safe_siblings() {
        let cases: &[(&str, &[&str], &str)] = &[
            (
                r#"{"command":"installer --token=embedded-token-secret","safe":"keep-json-sibling"}"#,
                &["embedded-token-secret"],
                "keep-json-sibling",
            ),
            (
                r#"{"command":"installer --token=\"prefix-json-token-secret\"suffix-json-token-secret","safe":"keep-escaped-json-sibling"}"#,
                &["prefix-json-token-secret", "suffix-json-token-secret"],
                "keep-escaped-json-sibling",
            ),
            (
                r#"{"command":"--token=start-token-secret","safe":"keep-start-sibling"}"#,
                &["start-token-secret"],
                "keep-start-sibling",
            ),
            (
                r#"{"command":"--token=\"quoted named secret\" --mode keep-named","safe":"keep-named-sibling"}"#,
                &["quoted named secret"],
                "keep-named-sibling",
            ),
            (
                r#"{"nested":{"command":"--DeviceHardwareData=\"quoted hardware secret\" --mode keep-hardware"},"safe":"keep-hardware-sibling"}"#,
                &["quoted hardware secret"],
                "keep-hardware-sibling",
            ),
            (
                r#"{"commands":["https://cache.invalid/content?token=\"quoted query secret\"&safe=keep-query"],"safe":"keep-query-sibling"}"#,
                &["quoted query secret"],
                "keep-query-sibling",
            ),
            (
                r#"{"command":"Bearer \"quoted bearer secret\" --mode keep-bearer","safe":"keep-bearer-sibling"}"#,
                &["quoted bearer secret"],
                "keep-bearer-sibling",
            ),
            (
                r#"{"command":"Basic \"dXNlcjpwYXNzd29yZA==\" --mode keep-basic","safe":"keep-basic-sibling"}"#,
                &["dXNlcjpwYXNzd29yZA=="],
                "keep-basic-sibling",
            ),
            (
                r#"{"command":"-H \"Authorization: Bearer json-header-secret\" --mode keep-header","safe":"keep-authorization-sibling"}"#,
                &["json-header-secret"],
                "keep-authorization-sibling",
            ),
            (
                r#"{"command":"\"--token=whole-arg-secret\"","safe":"keep-whole-named-sibling"}"#,
                &["whole-arg-secret"],
                "keep-whole-named-sibling",
            ),
            (
                r#"{"command":"\"--token=whole argument secret\"","safe":"keep-spaced-whole-named-sibling"}"#,
                &["whole argument secret"],
                "keep-spaced-whole-named-sibling",
            ),
            (
                r#"{"command":"\"Basic dXNlcjpwYXNzd29yZA==\"","safe":"keep-whole-basic-sibling"}"#,
                &["dXNlcjpwYXNzd29yZA=="],
                "keep-whole-basic-sibling",
            ),
            (
                r#"{"command":"--header=\"Authorization: Bearer json-attached-primary json-attached-tail","safe":"keep-json-attached-sibling"}"#,
                &["json-attached-primary", "json-attached-tail"],
                "keep-json-attached-sibling",
            ),
            (
                r#"{"command":"--header='Authorization: Custom json-single-primary json-single-tail","safe":"keep-json-single-sibling"}"#,
                &["json-single-primary", "json-single-tail"],
                "keep-json-single-sibling",
            ),
        ];

        for (raw, sentinels, safe_sentinel) in cases {
            serde_json::from_str::<serde_json::Value>(raw).expect("valid source JSON");
            let sanitized = sanitize_command_line(raw);

            for sentinel in *sentinels {
                assert!(
                    !sanitized.contains(sentinel),
                    "JSON command secret leaked {sentinel}: {sanitized}"
                );
            }
            assert!(
                sanitized.contains(safe_sentinel),
                "safe JSON sibling was consumed: {sanitized}"
            );
            serde_json::from_str::<serde_json::Value>(&sanitized)
                .expect("sanitized command container remains valid JSON");
        }
    }

    #[test]
    fn valid_json_whole_argument_secret_wrappers_preserve_safe_siblings() {
        let raw = r#"{"argv":["\"--client-secret=whole-named-secret\"","\"Basic dXNlcjpwYXNz\"","'--password=whole-single-secret'","'Basic dXNlcjpwYXNz'","--safe"],"safe":"keep-sibling"}"#;
        let sanitized = sanitize_command_line(raw);

        for secret in ["whole-named-secret", "whole-single-secret", "dXNlcjpwYXNz"] {
            assert!(
                !sanitized.contains(secret),
                "whole argument secret leaked {secret}: {sanitized}"
            );
        }
        assert!(sanitized.contains("--safe"));
        assert!(sanitized.contains("keep-sibling"));
        serde_json::from_str::<serde_json::Value>(&sanitized)
            .expect("sanitized argv container remains valid JSON");
    }

    #[test]
    fn unterminated_quoted_sensitive_schemes_fail_closed() {
        let cases: &[(&str, &[&str])] = &[
            (
                r#"Authorization: Bearer "unterminated-authorization-secret tail-secret"#,
                &["unterminated-authorization-secret", "tail-secret"],
            ),
            (
                "Authorization: Custom 'unterminated-custom-secret tail-secret",
                &["unterminated-custom-secret", "tail-secret"],
            ),
            (
                r#"-H "Authorization: Bearer unterminated-header-secret tail-secret"#,
                &["unterminated-header-secret", "tail-secret"],
            ),
            (
                r#"--header="Authorization: Bearer attached-double-primary attached-double-tail"#,
                &["attached-double-primary", "attached-double-tail"],
            ),
            (
                "--header='Authorization: Custom attached-single-primary attached-single-tail",
                &["attached-single-primary", "attached-single-tail"],
            ),
            (
                r#"-H"Authorization: Bearer short-double-primary short-double-tail"#,
                &["short-double-primary", "short-double-tail"],
            ),
            (
                "-H'Authorization: Custom short-single-primary short-single-tail",
                &["short-single-primary", "short-single-tail"],
            ),
            (
                r#"Bearer "unterminated-bearer-secret tail-secret"#,
                &["unterminated-bearer-secret", "tail-secret"],
            ),
            (
                "Bearer 'unterminated-single-bearer-secret tail-secret",
                &["unterminated-single-bearer-secret", "tail-secret"],
            ),
            (r#"Basic "dXNlcjpwYXNzd29yZA=="#, &["dXNlcjpwYXNzd29yZA=="]),
            ("Basic 'dXNlcjpwYXNzd29yZA==", &["dXNlcjpwYXNzd29yZA=="]),
        ];

        for (raw, sentinels) in cases {
            let sanitized = sanitize_command_line(raw);

            assert!(
                sanitized.contains("[REDACTED]"),
                "unterminated credential was not redacted: {sanitized}"
            );
            for sentinel in *sentinels {
                assert!(
                    !sanitized.contains(sentinel),
                    "unterminated credential leaked {sentinel}: {sanitized}"
                );
            }
        }
    }

    #[test]
    fn embedded_json_non_string_secret_values_are_structurally_redacted() {
        let cases: &[(&str, &[&str], &[&str])] = &[
            (
                r#"installer.exe --payload {"HardwareHash":123456789,"safe":"keep-number-sibling"} --mode keep-number-tail"#,
                &["123456789"],
                &["keep-number-sibling", "keep-number-tail"],
            ),
            (
                r#"installer.exe --payload {"DeviceHardwareData":{"opaque":"structured-secret"},"safe":"keep-object-sibling"} --mode keep-object-tail"#,
                &["structured-secret", r#""opaque""#],
                &["keep-object-sibling", "keep-object-tail"],
            ),
            (
                r#"installer.exe --payload {"DeviceHardwareData":[1,true,null,{"blob":"array-secret"}],"safe":"keep-array-sibling"} --mode keep-array-tail"#,
                &["array-secret", r#""blob""#],
                &["keep-array-sibling", "keep-array-tail"],
            ),
            (
                r#"installer.exe --payload {\"HardwareHash\":[1,{\"blob\":\"escaped-structured-secret\"}],\"safe\":true} --mode keep-escaped-tail"#,
                &["escaped-structured-secret", r#"{\"blob\""#],
                &[r#"\"safe\":true"#, "keep-escaped-tail"],
            ),
        ];

        for (raw, secret_sentinels, safe_sentinels) in cases {
            let sanitized = sanitize_command_line(raw);

            assert!(sanitized.contains("[REDACTED]"));
            for sentinel in *secret_sentinels {
                assert!(
                    !sanitized.contains(sentinel),
                    "embedded JSON secret leaked {sentinel}: {sanitized}"
                );
            }
            for sentinel in *safe_sentinels {
                assert!(
                    sanitized.contains(sentinel),
                    "embedded JSON redaction consumed {sentinel}: {sanitized}"
                );
            }
        }
    }

    #[test]
    fn malformed_embedded_json_secret_values_fail_closed() {
        let cases: &[(&str, &[&str])] = &[
            (
                r#"installer.exe --payload {"DeviceHardwareData":{"opaque":"malformed-secret" --mode ambiguous-tail"#,
                &["malformed-secret", "ambiguous-tail"],
            ),
            (
                r#"installer.exe --payload {\"HardwareHash\":[1,{\"blob\":\"escaped-malformed-secret\"} --mode escaped-ambiguous-tail"#,
                &["escaped-malformed-secret", "escaped-ambiguous-tail"],
            ),
        ];

        for (raw, sentinels) in cases {
            let sanitized = sanitize_command_line(raw);

            assert!(sanitized.contains("[REDACTED]"));
            for sentinel in *sentinels {
                assert!(
                    !sanitized.contains(sentinel),
                    "malformed embedded JSON leaked {sentinel}: {sanitized}"
                );
            }
        }
    }

    #[test]
    fn attached_closed_authorization_headers_preserve_following_arguments() {
        let cases = [
            (
                r#"curl.exe --header="Authorization: Bearer attached-closed-secret" --url keep-double-url"#,
                "attached-closed-secret",
                "keep-double-url",
            ),
            (
                r#"curl.exe -H"Authorization: Basic dXNlcjpwYXNz" --url keep-short-url"#,
                "dXNlcjpwYXNz",
                "keep-short-url",
            ),
            (
                "curl.exe --header='Authorization: Negotiate attached-single-secret' --url keep-single-url",
                "attached-single-secret",
                "keep-single-url",
            ),
        ];

        for (raw, secret, safe) in cases {
            let sanitized = sanitize_command_line(raw);

            assert!(
                !sanitized.contains(secret),
                "closed attached header leaked {secret}: {sanitized}"
            );
            assert!(
                sanitized.contains(safe),
                "closed attached header consumed {safe}: {sanitized}"
            );
        }
    }

    #[test]
    fn command_line_log_switch_variants_preserve_canonical_path_and_sanitization() {
        let cases = [
            (
                r#"/log "C:\Windows\Temp\quoted installer.log""#,
                r"C:\Windows\Temp\quoted installer.log",
            ),
            (
                r"/log C:\Windows\Temp\unquoted.log",
                r"C:\Windows\Temp\unquoted.log",
            ),
            (
                r#"/LoG "C:\Windows\Temp\Mixed Case.log""#,
                r"C:\Windows\Temp\Mixed Case.log",
            ),
        ];

        for (log_argument, expected_path) in cases {
            let raw = format!(
                "msiexec.exe /i {{12345678-1234-1234-1234-1234567890AB}} {log_argument} --token log-secret-sentinel"
            );
            let evidence = collect(
                vec![process(
                    51,
                    Some(20),
                    "msiexec.exe",
                    "2026-07-15T13:20:00Z",
                    Some(&raw),
                )],
                &[],
            );
            let observation = &evidence.observations[0];

            assert_eq!(
                observation.referenced_log_path.as_deref(),
                Some(expected_path),
                "failed to extract {log_argument}"
            );
            let sanitized = observation
                .sanitized_command_line
                .as_deref()
                .expect("sanitized command line");
            assert!(!sanitized.contains("log-secret-sentinel"));
            assert!(sanitized.contains("[REDACTED]"));
            assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
            assert!(sanitized.contains(expected_path));
        }
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
    fn command_line_sanitizer_redacts_escaped_quotes_inside_named_secrets() {
        let cases = [
            (
                r#"--client-secret "prefix\"client-secret-sentinel""#,
                "client-secret-sentinel",
            ),
            (
                r#"--app_secret="prefix\"app-secret-sentinel""#,
                "app-secret-sentinel",
            ),
            (
                r#"Bearer "prefix\"bearer-secret-sentinel""#,
                "bearer-secret-sentinel",
            ),
            (
                r#"https://cache.invalid/content?access_token="prefix\"query-secret-sentinel"&safe=true"#,
                "query-secret-sentinel",
            ),
        ];

        for (secret_argument, sentinel) in cases {
            let raw = format!(
                "msiexec.exe /i {{12345678-1234-1234-1234-1234567890AB}} {secret_argument} /L*V C:\\Windows\\Temp\\contoso.log"
            );
            let sanitized = sanitize_command_line(&raw);

            assert!(
                !sanitized.contains(sentinel),
                "escaped quoted secret leaked for {secret_argument}: {sanitized}"
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
    fn command_line_sanitizer_redacts_quoted_authorization_headers() {
        let cases: &[(&str, &str, &[&str], &str)] = &[
            (
                "basic header",
                "-H \"Authorization: Basic basic-header-sentinel\"",
                &["basic-header-sentinel"],
                "-H \"Authorization: [REDACTED]\"",
            ),
            (
                "api key header",
                "-H \"Authorization: ApiKey api-key-header-sentinel\"",
                &["api-key-header-sentinel"],
                "-H \"Authorization: [REDACTED]\"",
            ),
            (
                "digest header",
                "-H \"Authorization: Digest username=digest-user-header-sentinel, realm=digest-realm-header-sentinel, response=digest-response-header-sentinel\"",
                &[
                    "digest-user-header-sentinel",
                    "digest-realm-header-sentinel",
                    "digest-response-header-sentinel",
                ],
                "-H \"Authorization: [REDACTED]\"",
            ),
            (
                "bearer header",
                "-H \"Authorization: Bearer bearer-header-sentinel\"",
                &["bearer-header-sentinel"],
                "-H \"Authorization: [REDACTED]\"",
            ),
        ];

        for (case, secret_argument, sentinels, expected_header) in cases {
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
            assert!(sanitized.contains(expected_header));
            assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
            assert!(sanitized.contains("/L*V C:\\Windows\\Temp\\contoso.log"));
            assert!(sanitized.contains("[REDACTED]"));
        }
    }

    #[test]
    fn command_line_sanitizer_redacts_unknown_authorization_schemes_as_one_value() {
        let cases = [
            (
                "unquoted RFC token scheme",
                "--authorization Custom._~+-V1 unknown-auth-secret",
                "unknown-auth-secret",
            ),
            (
                "double-quoted header",
                "-H \"Authorization: Custom+V1 quoted-auth-secret\"",
                "quoted-auth-secret",
            ),
            (
                "single-quoted header",
                "-H 'Authorization: Negotiate negotiate-auth-secret'",
                "negotiate-auth-secret",
            ),
        ];

        for (case, secret_argument, sentinel) in cases {
            let raw = format!(
                "msiexec.exe /i {{12345678-1234-1234-1234-1234567890AB}} /L*V C:\\Windows\\Temp\\contoso.log {secret_argument}"
            );
            let sanitized = sanitize_command_line(&raw);

            assert!(
                !sanitized.contains(sentinel),
                "{case} leaked {sentinel}: {sanitized}"
            );
            assert!(sanitized.contains("[REDACTED]"));
            assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
            assert!(sanitized.contains("/L*V C:\\Windows\\Temp\\contoso.log"));
        }
    }

    #[test]
    fn command_line_sanitizer_redacts_every_unknown_authorization_parameter() {
        let raw = concat!(
            "installer.exe Authorization: Custom-V1 realm=public, ",
            "response=multi-param-auth-secret-sentinel ",
            "/i {12345678-1234-1234-1234-1234567890AB} ",
            "/L*V C:\\Windows\\Temp\\contoso.log --response keep-this-positive-control"
        );

        let sanitized = sanitize_command_line(raw);

        assert!(!sanitized.contains("multi-param-auth-secret-sentinel"));
        assert!(!sanitized.contains("realm=public"));
        assert!(sanitized.contains("Authorization: [REDACTED]"));
        assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
        assert!(sanitized.contains("/L*V C:\\Windows\\Temp\\contoso.log"));
        assert!(sanitized.contains("--response keep-this-positive-control"));

        let safe_neighbor =
            "installer.exe --authorization-mode Custom-V1 response=keep-this-safe-neighbor";
        assert_eq!(sanitize_command_line(safe_neighbor), safe_neighbor);
    }

    #[test]
    fn command_line_sanitizer_redacts_json_authorization_values() {
        let raw = concat!(
            r#"installer.exe --payload {"Authorization":"Custom-V1 json-auth-secret-sentinel","safe":"keep-this-json-control"} "#,
            "/i {12345678-1234-1234-1234-1234567890AB}"
        );

        let sanitized = sanitize_command_line(raw);

        assert!(!sanitized.contains("json-auth-secret-sentinel"));
        assert!(sanitized.contains(r#""Authorization":"[REDACTED]""#));
        assert!(sanitized.contains(r#""safe":"keep-this-json-control""#));
        assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
    }

    #[test]
    fn command_line_sanitizer_redacts_uncommaed_unknown_authorization_parameter_tails() {
        let raw = concat!(
            "installer.exe Authorization: Custom-V1 realm=public ",
            "response=uncommaed-authorization-secret-sentinel ",
            "/i {12345678-1234-1234-1234-1234567890AB} ",
            "/L*V C:\\Windows\\Temp\\contoso.log --response keep-this-positive-control"
        );

        let sanitized = sanitize_command_line(raw);

        assert!(!sanitized.contains("uncommaed-authorization-secret-sentinel"));
        assert!(!sanitized.contains("realm=public"));
        assert!(sanitized.contains("Authorization: [REDACTED]"));
        assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
        assert!(sanitized.contains("/L*V C:\\Windows\\Temp\\contoso.log"));
        assert!(sanitized.contains("--response keep-this-positive-control"));
    }

    #[test]
    fn command_line_sanitizer_redacts_opaque_unknown_authorization_tails() {
        let raw = concat!(
            "installer.exe Authorization: Custom-V1 realm=public ",
            "response=known-authorization-secret opaque-tail-secret ",
            "/i {12345678-1234-1234-1234-1234567890AB}"
        );

        let sanitized = sanitize_command_line(raw);

        for secret in [
            "realm=public",
            "known-authorization-secret",
            "opaque-tail-secret",
        ] {
            assert!(!sanitized.contains(secret), "Authorization leaked {secret}");
        }
        assert!(sanitized.contains("Authorization: [REDACTED]"));
        assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
    }

    #[test]
    fn command_line_sanitizer_redacts_one_layer_escaped_json_authorization_and_token_aliases() {
        let raw = concat!(
            r#"installer.exe --payload {\"Authorization\":\"Custom-V1 escaped-authorization-secret-sentinel\","#,
            r#"\"refresh_token\":\"escaped-refresh-token-secret-sentinel\","#,
            r#"\"id_token\":\"escaped-id-token-secret-sentinel\",\"safe\":\"keep-this-escaped-json-control\"} "#,
            "/i {12345678-1234-1234-1234-1234567890AB}"
        );

        let sanitized = sanitize_command_line(raw);

        for secret in [
            "escaped-authorization-secret-sentinel",
            "escaped-refresh-token-secret-sentinel",
            "escaped-id-token-secret-sentinel",
        ] {
            assert!(!sanitized.contains(secret), "escaped JSON leaked {secret}");
        }
        assert!(sanitized.contains(r#"\"Authorization\":\"[REDACTED]\""#));
        assert!(sanitized.contains(r#"\"refresh_token\":\"[REDACTED]\""#));
        assert!(sanitized.contains(r#"\"id_token\":\"[REDACTED]\""#));
        assert!(sanitized.contains(r#"\"safe\":\"keep-this-escaped-json-control\""#));
        assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
    }

    #[test]
    fn command_line_sanitizer_redacts_backslashes_inside_one_layer_escaped_json_secrets() {
        let raw = concat!(
            r#"installer.exe --payload {\"refresh_token\":\"prefix\\escaped-token-secret\","#,
            r#"\"safe\":\"keep-this-escaped-json-control\"} "#,
            "/i {12345678-1234-1234-1234-1234567890AB}"
        );

        let sanitized = sanitize_command_line(raw);

        assert!(!sanitized.contains("escaped-token-secret"));
        assert!(sanitized.contains(r#"\"refresh_token\":\"[REDACTED]\""#));
        assert!(sanitized.contains(r#"\"safe\":\"keep-this-escaped-json-control\""#));
        assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
    }

    #[test]
    fn command_line_sanitizer_redacts_complete_standalone_digest_challenges() {
        let raw = concat!(
            r#"installer.exe Digest username=\"digest-user-sentinel\", realm=\"digest-realm-sentinel\", response=\"digest-response-secret-sentinel\" "#,
            "/i {12345678-1234-1234-1234-1234567890AB} ",
            "/L*V C:\\Windows\\Temp\\contoso.log"
        );

        let sanitized = sanitize_command_line(raw);

        for secret in [
            "digest-user-sentinel",
            "digest-realm-sentinel",
            "digest-response-secret-sentinel",
        ] {
            assert!(
                !sanitized.contains(secret),
                "Digest challenge leaked {secret}"
            );
        }
        assert!(sanitized.contains("Digest [REDACTED]"));
        assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
        assert!(sanitized.contains("/L*V C:\\Windows\\Temp\\contoso.log"));
    }

    #[test]
    fn command_line_sanitizer_preserves_safe_digest_algorithm_narratives() {
        let narrative = "Digest algorithm=SHA-256 is supported";

        assert_eq!(sanitize_command_line(narrative), narrative);
    }

    #[test]
    fn command_line_sanitizer_preserves_safe_bearer_authentication_narratives() {
        let narrative = "The Bearer authentication mode is supported";

        assert_eq!(sanitize_command_line(narrative), narrative);
    }

    #[test]
    fn command_line_sanitizer_redacts_standalone_basic_credentials() {
        for credential in ["Zm9vOmJhcg==", "Og=="] {
            let raw = format!(
                "installer.exe Basic {credential} /i {{12345678-1234-1234-1234-1234567890AB}}"
            );

            let sanitized = sanitize_command_line(&raw);

            assert!(
                !sanitized.contains(credential),
                "Basic credential leaked: {sanitized}"
            );
            assert!(sanitized.contains("Basic [REDACTED]"));
            assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
        }
    }

    #[test]
    fn command_line_sanitizer_redacts_api_key_option_and_query_variants() {
        let cases = [
            ("--api-key hyphen-option-api-key-sentinel", "hyphen-option-api-key-sentinel"),
            ("--api_key=underscore-option-api-key-sentinel", "underscore-option-api-key-sentinel"),
            (
                "https://cache.invalid/content?api-key=hyphen-query-api-key-sentinel&safe=true",
                "hyphen-query-api-key-sentinel",
            ),
            (
                "https://cache.invalid/content?api_key=\"underscore-query-api-key-sentinel\"&safe=true",
                "underscore-query-api-key-sentinel",
            ),
        ];

        for (secret_argument, sentinel) in cases {
            let raw = format!(
                "msiexec.exe /i {{12345678-1234-1234-1234-1234567890AB}} /L*V C:\\Windows\\Temp\\contoso.log {secret_argument}"
            );
            let sanitized = sanitize_command_line(&raw);

            assert!(
                !sanitized.contains(sentinel),
                "secret leaked for variant {secret_argument}: {sanitized}"
            );
            assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
            assert!(sanitized.contains("/L*V C:\\Windows\\Temp\\contoso.log"));
            assert!(sanitized.contains("[REDACTED]"));
        }
    }

    #[test]
    fn command_line_sanitizer_redacts_app_secret_and_bearer_token_names_only() {
        let secret_cases = [
            (
                "--app-secret direct-app-secret-sentinel",
                "direct-app-secret-sentinel",
            ),
            (
                "--APP_SECRET=underscore-app-secret-sentinel",
                "underscore-app-secret-sentinel",
            ),
            (
                "/Bearer-Token bearer-token-option-sentinel",
                "bearer-token-option-sentinel",
            ),
            (
                "BEARER_TOKEN=bearer-token-assignment-sentinel",
                "bearer-token-assignment-sentinel",
            ),
            (
                "https://cache.invalid/content?app_secret=query-app-secret-sentinel&safe=true",
                "query-app-secret-sentinel",
            ),
            (
                "https://cache.invalid/content?safe=true&bearer-token=query-bearer-token-sentinel",
                "query-bearer-token-sentinel",
            ),
        ];

        for (secret_argument, sentinel) in secret_cases {
            let raw = format!(
                "msiexec.exe /i {{12345678-1234-1234-1234-1234567890AB}} /L*V C:\\Windows\\Temp\\contoso.log {secret_argument}"
            );
            let sanitized = sanitize_command_line(&raw);

            assert!(
                !sanitized.contains(sentinel),
                "secret leaked for variant {secret_argument}: {sanitized}"
            );
            assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
            assert!(sanitized.contains("/L*V C:\\Windows\\Temp\\contoso.log"));
            assert!(sanitized.contains("[REDACTED]"));
        }

        let safe_neighbors =
            "msiexec.exe --app-secret-mode keep-app-secret-mode --bearer-token-cache keep-bearer-token-cache";
        assert_eq!(sanitize_command_line(safe_neighbors), safe_neighbors);
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

        let evidence =
            collect_process_evidence(&provider, &[], || "2026-07-15T14:00:00Z".to_string());
        assert_eq!(evidence.observations.len(), MAX_PROCESS_RECORDS);
        assert_eq!(evidence.access_state, EspSourceAccessState::Failed);
        assert_eq!(
            evidence.detail.as_deref(),
            Some("process query timed out after partial results")
        );
    }

    #[test]
    fn timed_out_batch_is_not_partial_when_only_untrusted_dynamic_snapshots_were_returned() {
        let provider = FakeProcessProvider {
            batch: ProcessSnapshotBatch {
                snapshots: vec![process(
                    404,
                    None,
                    "UntrustedSetup.exe",
                    "2026-07-15T13:20:00Z",
                    Some("UntrustedSetup.exe --secret must-not-be-observed"),
                )],
                completion: Err(ProcessReadError::TimedOut),
            },
        };

        let evidence =
            collect_process_evidence(&provider, &["UntrustedSetup.exe".to_string()], || {
                "2026-07-15T14:00:00Z".to_string()
            });

        assert!(evidence.observations.is_empty());
        assert_eq!(evidence.access_state, EspSourceAccessState::Failed);
        assert_eq!(evidence.detail.as_deref(), Some("process query timed out"));
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
