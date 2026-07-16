//! Bounded process observations for ESP and allowlisted installer activity.

use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine as _;
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

struct CommandLineSanitizers {
    double_quoted_authorization: Regex,
    single_quoted_authorization: Regex,
    parameterized_authorization: Regex,
    standalone_digest_challenge: Regex,
    digest_secret_parameter: Regex,
    digest_authorization: Regex,
    authorization_credential: Regex,
    standalone_basic_credential: Regex,
    bearer: Regex,
    named_secret: Regex,
    query_secret: Regex,
    json_secret: Regex,
}

fn command_line_sanitizers() -> &'static CommandLineSanitizers {
    static SANITIZERS: OnceLock<CommandLineSanitizers> = OnceLock::new();
    SANITIZERS.get_or_init(|| CommandLineSanitizers {
        double_quoted_authorization: Regex::new(
            r#"(?i)(\")((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)[!#$%&'*+\-.^_`|~a-z0-9]+\s+(?:\\.|[^\"])*\""#,
        )
        .expect("constant double-quoted-authorization regex"),
        single_quoted_authorization: Regex::new(
            r#"(?i)(')((?:--|/)?authorization)(\s*(?:=|:)\s*|\s+)[!#$%&'*+\-.^_`|~a-z0-9]+\s+(?:\\.|[^'])*'"#,
        )
        .expect("constant single-quoted-authorization regex"),
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
            r#"(?i)(^|\s)(basic)(\s+)("[a-z0-9+/]+={0,2}"|'[a-z0-9+/]+={0,2}'|[a-z0-9+/]+={0,2})(\s|[.,;:!?)\]}]|$)"#,
        )
        .expect("constant standalone-Basic-credential regex"),
        bearer: Regex::new(
            r#"(?i)(bearer\s+)("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s&"]+)"#,
        )
        .expect("constant bearer regex"),
        named_secret: Regex::new(
            r#"(?i)(^|\s)((?:--|/)?(?:access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|bearer[-_]?token|client[-_]?secret|app[-_]?secret|api[-_]?key|token|password|secret|authorization))(\s*(?:=|:)\s*|\s+)(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s&"]+)"#,
        )
        .expect("constant named-secret regex"),
        query_secret: Regex::new(
            r#"(?i)([?&](?:sig|access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|bearer[-_]?token|client[-_]?secret|app[-_]?secret|api[-_]?key|token|password|secret|authorization)=)(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^&\s"]+)"#,
        )
        .expect("constant query-secret regex"),
        json_secret: Regex::new(
            r#"(?i)("(?:access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|bearer[-_]?token|client[-_]?secret|app[-_]?secret|api[-_]?key|token|password|secret|authorization)"\s*:\s*")(?:\\.|[^"])*(\")"#,
        )
        .expect("constant JSON-secret regex"),
    })
}

pub fn sanitize_command_line(command_line: &str) -> String {
    let sanitizers = command_line_sanitizers();

    let command_line = sanitizers
        .double_quoted_authorization
        .replace_all(command_line, "$1$2$3[REDACTED]\"");
    let command_line = sanitizers
        .single_quoted_authorization
        .replace_all(&command_line, "$1$2$3[REDACTED]'");
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
            let credential =
                captures[4].trim_matches(|character| character == '"' || character == '\'');
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
    let command_line = sanitizers
        .named_secret
        .replace_all(&command_line, "$1$2$3[REDACTED]");
    let command_line = sanitizers
        .query_secret
        .replace_all(&command_line, "$1[REDACTED]");
    let command_line = sanitizers
        .json_secret
        .replace_all(&command_line, "$1[REDACTED]$2");
    redact_escaped_json_secrets(&command_line)
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
    let mut first_non_whitespace = suffix_start;
    skip_ascii_whitespace(bytes, &mut first_non_whitespace);
    if matches!(bytes.get(first_non_whitespace), None | Some(b'{' | b'[')) {
        return Some(closer);
    }

    let argument_boundary =
        find_non_sensitive_command_argument_boundary(bytes, suffix_start).unwrap_or(bytes.len());
    if bytes[suffix_start..argument_boundary]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        Some(argument_boundary)
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
    let argument_boundary =
        find_non_sensitive_command_argument_boundary(bytes, suffix_start).unwrap_or(bytes.len());
    bytes[suffix_start..argument_boundary]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
        .then_some(argument_boundary)
}

fn find_non_sensitive_command_argument_boundary(bytes: &[u8], start: usize) -> Option<usize> {
    // An option-shaped token is not automatically outside a malformed secret: the value can
    // itself contain `-`, `--`, or `/` prefixes. Treat every secret-named option as part of the
    // value, then preserve only the first non-sensitive option that follows the final one. If a
    // sensitive option is last, callers fail closed through EOF. Reordering therefore consumes
    // earlier safe-looking arguments instead of exposing the later credential-shaped suffix.
    let mut cursor = start;
    let mut last_sensitive_option = None;
    while cursor < bytes.len() {
        if (cursor == start || bytes[cursor - 1].is_ascii_whitespace())
            && is_command_option_start(bytes, cursor)
            && is_sensitive_command_option(bytes, cursor)
        {
            last_sensitive_option = Some(cursor);
        }
        cursor += 1;
    }

    let mut cursor = last_sensitive_option.map_or(start, |option| option + 1);
    while cursor < bytes.len() {
        if (cursor == start || bytes[cursor - 1].is_ascii_whitespace())
            && is_command_option_start(bytes, cursor)
            && !is_sensitive_command_option(bytes, cursor)
        {
            return Some(command_argument_separator_start(bytes, start, cursor));
        }
        cursor += 1;
    }
    None
}

fn command_argument_separator_start(bytes: &[u8], start: usize, option: usize) -> usize {
    let mut boundary = option;
    while boundary > start && bytes[boundary - 1].is_ascii_whitespace() {
        boundary -= 1;
    }
    boundary
}

fn is_command_option_start(bytes: &[u8], start: usize) -> bool {
    match bytes.get(start) {
        Some(b'-') => bytes
            .get(start + 1)
            .is_some_and(|byte| *byte == b'-' || byte.is_ascii_alphabetic()),
        Some(b'/') => bytes.get(start + 1).is_some_and(u8::is_ascii_alphabetic),
        _ => false,
    }
}

fn is_sensitive_command_option(bytes: &[u8], start: usize) -> bool {
    let mut cursor = start;
    match bytes.get(cursor) {
        Some(b'-') => {
            cursor += 1;
            if bytes.get(cursor) == Some(&b'-') {
                cursor += 1;
            }
        }
        Some(b'/') => cursor += 1,
        _ => return false,
    }

    let name_start = cursor;
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        cursor += 1;
    }
    if cursor == name_start {
        return false;
    }

    let normalized = bytes[name_start..cursor]
        .iter()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    [
        b"token".as_slice(),
        b"password".as_slice(),
        b"secret".as_slice(),
        b"authorization".as_slice(),
        b"apikey".as_slice(),
        b"credential".as_slice(),
        b"signature".as_slice(),
    ]
    .iter()
    .any(|marker| {
        normalized
            .windows(marker.len())
            .any(|candidate| candidate == *marker)
    }) || matches!(normalized.as_slice(), b"sig" | b"sas")
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
            | b"token"
            | b"password"
            | b"secret"
            | b"authorization"
    )
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
