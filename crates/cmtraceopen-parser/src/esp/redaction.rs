use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;

use super::models::*;

const REDACTED: &str = "[redacted]";
const REMOVED_OVERSIZE: &str = "[redacted: oversized text omitted]";
const MAX_REDACTION_INPUT_BYTES: usize = 256 * 1024;
const SECRET_LABEL_PATTERN: &str = r#"(?:authorization|password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|bearer[_-]?token|token|tenant(?:[_-]?id)?|(?:aad|azure[_-]?ad)[_-]?tenant[_-]?id|entdm(?:[_-]?id)?|serial(?:[_-]?number)?|device[_-]?serial(?:[_-]?number)?|hardware[_-]?hash|device[_-]?hardware[_-]?data)"#;
const JSON_CONTAINER_SECRET_LABEL_PATTERN: &str = r#"(?:authorization|tenant[_-]?id|(?:aad|azure[_-]?ad)[_-]?tenant[_-]?id|entdm[_-]?id|serial[_-]?number|device[_-]?serial(?:[_-]?number)?|hardware[_-]?hash|device[_-]?hardware[_-]?data)"#;
const QUOTED_OR_BARE_VALUE_PATTERN: &str =
    r#"(?:\\+"[^"\r\n]*"|\\+'[^'\r\n]*'|"[^"\r\n]*"|'[^'\r\n]*'|[^\s]+)"#;
const DIGEST_VALUE_PATTERN: &str =
    r#"(?:\\+"[^"\r\n]*"|\\+'[^'\r\n]*'|"[^"\r\n]*"|'[^'\r\n]*'|[^,;\s\r\n]+)"#;

fn email_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")
            .expect("email redaction pattern must compile")
    })
}

fn sid_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\bS-1-(?:0x[0-9A-F]{1,12}|\d{1,10})(?:-\d{1,10}){1,15}\b")
            .expect("SID redaction pattern must compile")
    })
}

fn user_profile_path_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<prefix>(?:^|[\\/])(?:users|documents and settings)[\\/])(?P<user>[^\\/\r\n]+)",
        )
        .expect("user-profile path redaction pattern must compile")
    })
}

fn authorization_digest_challenge_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        let parameter = format!(
            r#"[A-Z0-9!#$%&'*+.^_`|~-]+[ \t]*=[ \t]*{DIGEST_VALUE_PATTERN}"#
        );
        Regex::new(&format!(
            r#"(?i)(?P<prefix>(?:(?:--?|/)authorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*|\s+)|\bauthorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*|\s+)))digest(?:[ \t]+|\r?\n[ \t]+){parameter}(?:(?:[ \t]*[,;][ \t]*(?:\r?\n[ \t]+)?|\r?\n[ \t]+|[ \t]+){parameter})*(?:[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*)"#,
        ))
        .expect("Authorization Digest challenge redaction pattern must compile")
    })
}

fn escaped_json_secret_member_key_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)\\["]{SECRET_LABEL_PATTERN}\\["][ \t\r\n]*:[ \t\r\n]*"#,
        ))
        .expect("escaped JSON secret-member key pattern must compile")
    })
}

fn plain_json_secret_member_key_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)["]{JSON_CONTAINER_SECRET_LABEL_PATTERN}["][ \t\r\n]*:[ \t\r\n]*"#,
        ))
        .expect("plain JSON secret-member key pattern must compile")
    })
}

fn authorization_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?P<prefix>(?:(?:--?|/)authorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*|\s+)|\bauthorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*)))(?:basic\s+|bearer\s+|digest\s+|apikey\s+)?(?P<value>{QUOTED_OR_BARE_VALUE_PATTERN}(?:\r?\n[ \t]+[^\r\n]+)*)"#,
        ))
        .expect("authorization redaction pattern must compile")
    })
}

fn authorization_scheme_and_credential_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?P<prefix>(?:(?:--?|/)authorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*|\s+)|\bauthorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*|\s+)))(?:\\+"(?:basic|bearer|digest|apikey)\s+[^"\r\n]+"|\\+'(?:basic|bearer|digest|apikey)\s+[^'\r\n]+'|"(?:basic|bearer|digest|apikey)\s+[^"\r\n]+"|'(?:basic|bearer|digest|apikey)\s+[^'\r\n]+'|(?:"(?:basic|bearer|digest|apikey)"|'(?:basic|bearer|digest|apikey)'|(?:basic|bearer|digest|apikey))[ \t]+{QUOTED_OR_BARE_VALUE_PATTERN})(?:\r?\n[ \t]+[^\r\n]+)*"#,
        ))
        .expect("authorization scheme-and-credential redaction pattern must compile")
    })
}

fn standalone_digest_challenge_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        let parameter = format!(
            r#"[A-Z0-9!#$%&'*+.^_`|~-]+[ \t]*=[ \t]*{DIGEST_VALUE_PATTERN}"#
        );
        Regex::new(&format!(
            r#"(?i)(?P<prefix>\bdigest)(?:[ \t]+|\r?\n[ \t]+)(?P<parameters>{parameter}(?:(?:[ \t]*[,;][ \t]*(?:\r?\n[ \t]+)?|\r?\n[ \t]+|[ \t]+){parameter})*)(?P<tail>[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*)"#,
        ))
        .expect("standalone Digest challenge redaction pattern must compile")
    })
}

fn safe_digest_narrative_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)^digest[ \t]+(?:algorithm[ \t]*=[ \t]*(?:md5(?:-sess)?|sha-256(?:-sess)?|sha-512-256(?:-sess)?)[ \t]+(?:is|was|remains)[ \t]+(?:supported|configured)|retry-count[ \t]*=[ \t]*[0-9]+[ \t]+(?:is|was|remains)[ \t]+within[ \t]+policy)(?:[.!?])?$"#,
        )
        .expect("safe Digest narrative pattern must compile")
    })
}

fn safe_authorization_narrative_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)^(?:(?:basic|bearer|digest|apikey|negotiate|ntlm)[ \t]+(?:authentication[ \t]+(?:is[ \t]+configured|remains[ \t]+available)|authorization[ \t]+is[ \t]+required|scheme[ \t]+negotiation[ \t]+was[ \t]+retried|token[ \t]+support[ \t]+is[ \t]+enabled)|authorization[ \t]+(?:is[ \t]+required|remains[ \t]+required|policy[ \t]+is[ \t]+enforced|status[ \t]+remains[ \t]+available))(?:[.!?])?$"#,
        )
        .expect("safe authorization narrative pattern must compile")
    })
}

fn generic_authorization_scheme_and_credential_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(?P<prefix>(?:(?:--?|/)authorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*|\s+)|\bauthorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*|\s+)))(?P<scheme>[A-Z0-9!#$%&'*+.^_`|~-]+)(?:[ \t]+|\r?\n[ \t]+)(?P<credential>[^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)"#,
        )
        .expect("generic authorization scheme-and-credential pattern must compile")
    })
}

fn secret_argument_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?P<prefix>(?:(?:--?|/){SECRET_LABEL_PATTERN}["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*|\s+)|\b{SECRET_LABEL_PATTERN}["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*)))(?P<value>{QUOTED_OR_BARE_VALUE_PATTERN})"#,
        ))
        .expect("secret argument redaction pattern must compile")
    })
}

fn bare_authorization_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?P<prefix>\bauthorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s+))(?:(?P<scheme>basic|bearer|digest|apikey)\s+)?(?P<value>{QUOTED_OR_BARE_VALUE_PATTERN})"#,
        ))
        .expect("bare authorization redaction pattern must compile")
    })
}

fn bare_secret_argument_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?P<prefix>\b(?P<name>{SECRET_LABEL_PATTERN})["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s+))(?P<value>{QUOTED_OR_BARE_VALUE_PATTERN})"#,
        ))
        .expect("bare secret-argument redaction pattern must compile")
    })
}

fn standalone_authorization_scheme_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(?P<prefix>\b(?P<scheme>basic|bearer|digest|apikey|negotiate|ntlm)[ \t]+)(?:\\+"[^"\r\n]*"|\\+'[^'\r\n]*'|"(?P<double_quoted>[^"\r\n]+)"|'(?P<single_quoted>[^'\r\n]+)'|(?P<bare>[A-Z0-9._~+/=-]+))(?P<tail>[^\r\n]*)(?:\r?\n[ \t]+[^\r\n]+)*"#,
        )
        .expect("standalone authorization-scheme redaction pattern must compile")
    })
}

fn quoted_authorization_credential_start_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(?P<prefix>(?:\b(?:basic|bearer|digest|apikey|negotiate|ntlm)[ \t]+|(?:(?:--?|/)authorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*|\s+)|\bauthorization["']?(?:[ \t]*(?:\r?\n[ \t]+)?(?:->|=>)[ \t]*(?:\r?\n[ \t]+)?|\s*[=:]\s*|\s+))(?:(?:basic|bearer|digest|apikey|negotiate|ntlm)[ \t]+)?))(?P<opening>\\*["'])"#,
        )
        .expect("quoted authorization-credential start pattern must compile")
    })
}

fn redact_quoted_authorization_credentials(value: &str) -> String {
    let pattern = quoted_authorization_credential_start_pattern();
    let mut redacted = String::with_capacity(value.len());
    let mut cursor = 0;

    while let Some(captures) = pattern.captures_at(value, cursor) {
        let prefix = captures
            .name("prefix")
            .expect("quoted authorization pattern must capture the prefix");
        let opening = captures
            .name("opening")
            .expect("quoted authorization pattern must capture the opening delimiter");
        let first_credential_end =
            serialized_quoted_credential_end(value, opening.start(), opening.end());
        let mut credential_end = first_credential_end;
        let mut has_adjacent_quoted_segment = false;

        loop {
            let next_non_space = value.as_bytes()[credential_end..]
                .iter()
                .position(|byte| !matches!(byte, b' ' | b'\t'))
                .map_or(value.len(), |offset| credential_end + offset);
            let Some((next_opening_start, next_opening_end)) =
                serialized_quote_opening_at(value, next_non_space)
            else {
                break;
            };
            has_adjacent_quoted_segment = true;
            credential_end =
                serialized_quoted_credential_end(value, next_opening_start, next_opening_end);
        }
        credential_end = folded_authorization_credential_end(value, credential_end);

        if !has_adjacent_quoted_segment
            && serialized_quoted_credential_is_redacted(
                value,
                opening.start(),
                opening.end(),
                first_credential_end,
            )
        {
            redacted.push_str(&value[cursor..first_credential_end]);
        } else {
            redacted.push_str(&value[cursor..prefix.end()]);
            redacted.push_str(REDACTED);
        }
        cursor = credential_end;
    }

    redacted.push_str(&value[cursor..]);
    redacted
}

fn serialized_quote_opening_at(value: &str, start: usize) -> Option<(usize, usize)> {
    let bytes = value.as_bytes();
    if start >= bytes.len() || matches!(bytes[start], b'\r' | b'\n') {
        return None;
    }
    let mut quote_index = start;
    while quote_index < bytes.len() && bytes[quote_index] == b'\\' {
        quote_index += 1;
    }
    (quote_index < bytes.len() && matches!(bytes[quote_index], b'"' | b'\''))
        .then_some((start, quote_index + 1))
}

fn serialized_quoted_credential_is_redacted(
    value: &str,
    opening_start: usize,
    opening_end: usize,
    credential_end: usize,
) -> bool {
    let delimiter_bytes = opening_end - opening_start;
    if credential_end < opening_end + delimiter_bytes {
        return false;
    }
    let closing_start = credential_end - delimiter_bytes;
    value[opening_start..opening_end] == value[closing_start..credential_end]
        && value[opening_end..closing_start] == *REDACTED
}

fn serialized_quoted_credential_end(
    value: &str,
    opening_start: usize,
    opening_end: usize,
) -> usize {
    let bytes = value.as_bytes();
    let quote = bytes[opening_end - 1];
    let delimiter_backslashes = opening_end - opening_start - 1;
    let line_end = bytes[opening_end..]
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .map_or(bytes.len(), |offset| opening_end + offset);

    for index in opening_end..line_end {
        if bytes[index] == quote && preceding_backslash_count(bytes, index) == delimiter_backslashes
        {
            return index + 1;
        }
    }

    line_end
}

fn folded_authorization_credential_end(value: &str, mut credential_end: usize) -> usize {
    let bytes = value.as_bytes();

    loop {
        let mut line_break_start = credential_end;
        while bytes
            .get(line_break_start)
            .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
        {
            line_break_start += 1;
        }
        let continuation_start = if bytes.get(line_break_start) == Some(&b'\r')
            && bytes.get(line_break_start + 1) == Some(&b'\n')
        {
            line_break_start + 2
        } else if bytes.get(line_break_start) == Some(&b'\n') {
            line_break_start + 1
        } else {
            break;
        };
        if !bytes
            .get(continuation_start)
            .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
        {
            break;
        }
        credential_end = bytes[continuation_start..]
            .iter()
            .position(|byte| matches!(byte, b'\r' | b'\n'))
            .map_or(bytes.len(), |offset| continuation_start + offset);
    }

    credential_end
}

fn redact_escaped_json_secret_members(value: &str) -> String {
    let pattern = escaped_json_secret_member_key_pattern();
    let mut redacted = String::with_capacity(value.len());
    let mut cursor = 0;

    while let Some(secret_key) = pattern.find_at(value, cursor) {
        redacted.push_str(&value[cursor..secret_key.end()]);
        redacted.push_str(r#"\"[redacted]\""#);
        cursor = escaped_json_value_end(value, secret_key.end());
        if cursor >= value.len() {
            break;
        }
    }
    redacted.push_str(&value[cursor..]);
    redacted
}

fn redact_plain_json_secret_members(value: &str) -> String {
    let pattern = plain_json_secret_member_key_pattern();
    let mut redacted = String::with_capacity(value.len());
    let mut cursor = 0;

    while let Some(secret_key) = pattern.find_at(value, cursor) {
        redacted.push_str(&value[cursor..secret_key.end()]);
        redacted.push_str(r#""[redacted]""#);
        cursor = plain_json_value_end(value, secret_key.end());
        if cursor >= value.len() {
            break;
        }
    }
    redacted.push_str(&value[cursor..]);
    redacted
}

fn plain_json_value_end(value: &str, start: usize) -> usize {
    let bytes = value.as_bytes();
    if start >= bytes.len() {
        return bytes.len();
    }

    if bytes[start] == b'"' {
        return json_string_end(bytes, start + 1);
    }
    if matches!(bytes[start], b'{' | b'[') {
        return plain_json_container_end(bytes, start);
    }

    bytes[start..]
        .iter()
        .position(|byte| matches!(byte, b',' | b'}' | b']' | b'\r' | b'\n'))
        .map_or(bytes.len(), |offset| start + offset)
}

fn plain_json_container_end(bytes: &[u8], start: usize) -> usize {
    let mut delimiters = Vec::with_capacity(4);
    let mut in_string = false;

    for index in start..bytes.len() {
        if bytes[index] == b'"' && preceding_backslash_count(bytes, index) % 2 == 0 {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match bytes[index] {
            b'{' => delimiters.push(b'}'),
            b'[' => delimiters.push(b']'),
            b'}' | b']' if delimiters.last() == Some(&bytes[index]) => {
                delimiters.pop();
                if delimiters.is_empty() {
                    return index + 1;
                }
            }
            b'}' | b']' => return bytes.len(),
            _ => {}
        }
    }
    bytes.len()
}

fn escaped_json_value_end(value: &str, start: usize) -> usize {
    let bytes = value.as_bytes();
    if start >= bytes.len() {
        return bytes.len();
    }

    if bytes[start] == b'\\' && bytes.get(start + 1) == Some(&b'"') {
        return escaped_json_string_end(bytes, start + 2);
    }
    if bytes[start] == b'"' {
        return json_string_end(bytes, start + 1);
    }
    if matches!(bytes[start], b'{' | b'[') {
        return escaped_json_container_end(bytes, start);
    }

    bytes[start..]
        .iter()
        .position(|byte| matches!(byte, b',' | b'}' | b']' | b'\r' | b'\n'))
        .map_or(bytes.len(), |offset| start + offset)
}

fn escaped_json_string_end(bytes: &[u8], start: usize) -> usize {
    for index in start..bytes.len() {
        if bytes[index] == b'"' && escaped_json_quote_is_delimiter(bytes, index) {
            return index + 1;
        }
    }
    bytes.len()
}

fn json_string_end(bytes: &[u8], start: usize) -> usize {
    for index in start..bytes.len() {
        if bytes[index] != b'"' {
            continue;
        }
        let slash_count = preceding_backslash_count(bytes, index);
        if slash_count % 2 == 0 {
            return index + 1;
        }
    }
    bytes.len()
}

fn escaped_json_container_end(bytes: &[u8], start: usize) -> usize {
    let mut delimiters = Vec::with_capacity(4);
    let mut in_string = false;

    for index in start..bytes.len() {
        if bytes[index] == b'"' && escaped_json_quote_is_delimiter(bytes, index) {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match bytes[index] {
            b'{' => delimiters.push(b'}'),
            b'[' => delimiters.push(b']'),
            b'}' | b']' if delimiters.last() == Some(&bytes[index]) => {
                delimiters.pop();
                if delimiters.is_empty() {
                    return index + 1;
                }
            }
            b'}' | b']' => return bytes.len(),
            _ => {}
        }
    }
    bytes.len()
}

fn escaped_json_quote_is_delimiter(bytes: &[u8], quote_index: usize) -> bool {
    preceding_backslash_count(bytes, quote_index) % 4 != 3
}

fn preceding_backslash_count(bytes: &[u8], index: usize) -> usize {
    let mut cursor = index;
    while cursor > 0 && bytes[cursor - 1] == b'\\' {
        cursor -= 1;
    }
    index - cursor
}

fn forbidden_raw_content_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(authorization["']?\s*[:=]|(?:access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|bearer[_-]?token|hardware[_-]?hash|device[_-]?hardware[_-]?data)["']?\s*(?:[:=]|\s)|token["']?\s*[:=])"#,
        )
            .expect("forbidden raw-content pattern must compile")
    })
}

/// Return a safe copy/export projection without changing the local snapshot.
///
/// Typed sensitive fields are masked, secret-like command arguments are
/// redacted, reference-bearing identifiers are consistently pseudonymized,
/// and source records that could contain credentials, raw Graph responses,
/// or hardware hashes are omitted completely.
pub fn redacted_export_projection(snapshot: &EspDiagnosticsSnapshot) -> EspDiagnosticsSnapshot {
    let mut safe = snapshot.clone();
    let reference_pseudonyms = collect_reference_pseudonyms(&safe);
    pseudonymize_sid_references(&mut safe, &reference_pseudonyms.sids);
    redact_all_evidence_refs(&mut safe, &reference_pseudonyms);

    for source in &mut safe.elevation.restricted_sources {
        redact_reference(source, &reference_pseudonyms);
    }

    redact_identity(&mut safe.identity);
    if let Some(profile) = &mut safe.profile {
        redact_profile(profile);
    }
    for enrollment in &mut safe.enrollments {
        mask_classified(&mut enrollment.tenant_id);
        mask_classified(&mut enrollment.user_principal_name);
        mask_classified(&mut enrollment.entdm_id);
    }
    for session in &mut safe.sessions {
        pseudonymize_classified_sid(&mut session.user_sid, &reference_pseudonyms.sids);
    }
    for workload in &mut safe.workloads {
        redact_optional_text(&mut workload.display_name);
        redact_status(&mut workload.status);
    }
    for correlation in &mut safe.installer_correlations {
        correlation.reason = redact_narrative_text(&correlation.reason);
        for process in &mut correlation.process_observations {
            redact_optional_text(&mut process.sanitized_command_line);
            redact_optional_text(&mut process.referenced_log_path);
            redact_provenance(&mut process.context.provenance, &reference_pseudonyms);
        }
    }
    for node in &mut safe.node_cache {
        if node.expected_value.is_some() {
            node.expected_value = Some(REDACTED.to_string());
        }
    }
    for registration in &mut safe.registration_events {
        registration.message = redact_narrative_text(&registration.message);
        redact_status(&mut registration.status);
        for named in &mut registration.named_data {
            redact_named_value(named);
        }
    }
    if let Some(hardware) = &mut safe.hardware {
        mask_classified(&mut hardware.serial_number);
    }
    for activity in &mut safe.activity {
        activity.title = redact_narrative_text(&activity.title);
        redact_optional_narrative_text(&mut activity.detail);
        if let Some(status) = &mut activity.status {
            redact_status(status);
        }
    }
    for finding in &mut safe.findings {
        for coverage_gap_id in &mut finding.coverage_gap_ids {
            redact_reference(coverage_gap_id, &reference_pseudonyms);
        }
    }
    for coverage in &mut safe.coverage {
        redact_reference(&mut coverage.artifact_id, &reference_pseudonyms);
        redact_reference(&mut coverage.family, &reference_pseudonyms);
        redact_optional_narrative_text(&mut coverage.detail);
    }
    safe.raw_evidence
        .retain(|record| !raw_record_must_be_removed(record));
    for record in &mut safe.raw_evidence {
        if raw_record_must_be_masked(record) {
            mask_observation_value(&mut record.raw_value);
        } else {
            redact_observation_value(&mut record.raw_value);
        }
        redact_reference(&mut record.record_id, &reference_pseudonyms);
        redact_provenance(&mut record.provenance, &reference_pseudonyms);
    }
    if let Some(graph) = &mut safe.graph {
        redact_graph_overlay(graph);
    }

    safe
}

fn redact_identity(identity: &mut EspIdentityEvidence) {
    mask_classified(&mut identity.entdm_id);
    mask_classified(&mut identity.tenant_id);
    mask_classified(&mut identity.tenant_domain);
    mask_classified(&mut identity.user_principal_name);
    mask_classified(&mut identity.serial_number);
}

fn redact_profile(profile: &mut EspProfileEvidence) {
    redact_optional_text(&mut profile.profile_name);
    mask_classified(&mut profile.tenant_domain);
    mask_classified(&mut profile.tenant_id);
}

fn mask_classified(value: &mut Option<EspClassifiedString>) {
    if let Some(value) = value {
        value.value = REDACTED.to_string();
    }
}

fn redact_status(status: &mut EspStatus) {
    redact_raw_status(&mut status.raw);
    status.display = redact_narrative_text(&status.display);
    if let Some(detail) = &mut status.detail {
        redact_raw_status(&mut detail.raw);
        detail.display = redact_narrative_text(&detail.display);
    }
}

fn redact_raw_status(status: &mut EspRawStatus) {
    if let EspRawStatus::Text(value) = status {
        *value = redact_text(value);
    }
}

fn redact_observation_value(value: &mut EspObservationValue) {
    match value {
        EspObservationValue::Text(value) => *value = redact_text(value),
        EspObservationValue::StringList(values) => {
            for value in values {
                *value = redact_text(value);
            }
        }
        EspObservationValue::Integer(_)
        | EspObservationValue::Unsigned(_)
        | EspObservationValue::Boolean(_) => {}
    }
}

fn mask_observation_value(value: &mut EspObservationValue) {
    *value = EspObservationValue::Text(REDACTED.to_string());
}

#[derive(Default)]
struct ReferencePseudonyms {
    sids: BTreeMap<String, String>,
    emails: BTreeMap<String, String>,
    profile_users: BTreeMap<String, String>,
}

fn collect_reference_pseudonyms(snapshot: &EspDiagnosticsSnapshot) -> ReferencePseudonyms {
    let mut sids = BTreeSet::new();
    let mut emails = BTreeSet::new();
    let mut profile_users = BTreeSet::new();
    for source in &snapshot.elevation.restricted_sources {
        collect_reference_tokens(source, &mut sids, &mut emails, &mut profile_users);
    }
    for session in &snapshot.sessions {
        collect_sids(&session.session_id, &mut sids);
        if let Some(user_sid) = &session.user_sid {
            collect_sids(&user_sid.value, &mut sids);
        }
        for workload_id in &session.workload_ids {
            collect_sids(workload_id, &mut sids);
        }
    }
    for workload in &snapshot.workloads {
        collect_sids(&workload.workload_id, &mut sids);
        collect_sids(&workload.session_id, &mut sids);
    }
    for correlation in &snapshot.installer_correlations {
        if let Some(workload_id) = &correlation.workload_id {
            collect_sids(workload_id, &mut sids);
        }
        for workload_id in &correlation.candidate_workload_ids {
            collect_sids(workload_id, &mut sids);
        }
    }
    for finding in &snapshot.findings {
        for coverage_gap_id in &finding.coverage_gap_ids {
            collect_reference_tokens(coverage_gap_id, &mut sids, &mut emails, &mut profile_users);
        }
    }
    for coverage in &snapshot.coverage {
        collect_reference_tokens(
            &coverage.artifact_id,
            &mut sids,
            &mut emails,
            &mut profile_users,
        );
        collect_reference_tokens(&coverage.family, &mut sids, &mut emails, &mut profile_users);
    }
    for record in &snapshot.raw_evidence {
        collect_reference_tokens(
            &record.record_id,
            &mut sids,
            &mut emails,
            &mut profile_users,
        );
        collect_reference_tokens(
            &record.provenance.source_artifact_id,
            &mut sids,
            &mut emails,
            &mut profile_users,
        );
        if let Some(value_name) = record
            .provenance
            .registry
            .as_ref()
            .and_then(|registry| registry.value_name.as_deref())
        {
            collect_reference_tokens(value_name, &mut sids, &mut emails, &mut profile_users);
        }
    }
    for_each_evidence_ref(snapshot, |evidence| {
        collect_reference_tokens(
            &evidence.evidence_id,
            &mut sids,
            &mut emails,
            &mut profile_users,
        );
        collect_reference_tokens(
            &evidence.source_artifact_id,
            &mut sids,
            &mut emails,
            &mut profile_users,
        );
    });

    ReferencePseudonyms {
        sids: build_pseudonyms(sids, "sid"),
        emails: build_pseudonyms(emails, "email"),
        profile_users: build_pseudonyms(profile_users, "user"),
    }
}

fn collect_reference_tokens(
    value: &str,
    sids: &mut BTreeSet<String>,
    emails: &mut BTreeSet<String>,
    profile_users: &mut BTreeSet<String>,
) {
    collect_sids(value, sids);
    emails.extend(
        email_pattern()
            .find_iter(value)
            .map(|matched| matched.as_str().to_ascii_lowercase()),
    );
    profile_users.extend(
        user_profile_path_pattern()
            .captures_iter(value)
            .map(|captures| {
                captures
                    .name("user")
                    .expect("user-profile pattern must capture the user component")
                    .as_str()
                    .to_ascii_lowercase()
            }),
    );
}

fn build_pseudonyms(values: BTreeSet<String>, kind: &str) -> BTreeMap<String, String> {
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| (value, format!("[redacted-{kind}-{}]", index + 1)))
        .collect()
}

fn collect_sids(value: &str, sids: &mut BTreeSet<String>) {
    sids.extend(
        sid_pattern()
            .find_iter(value)
            .map(|matched| matched.as_str().to_ascii_uppercase()),
    );
}

fn pseudonymize_sid_references(
    snapshot: &mut EspDiagnosticsSnapshot,
    pseudonyms: &BTreeMap<String, String>,
) {
    for session in &mut snapshot.sessions {
        pseudonymize_sids(&mut session.session_id, pseudonyms);
        for workload_id in &mut session.workload_ids {
            pseudonymize_sids(workload_id, pseudonyms);
        }
    }
    for workload in &mut snapshot.workloads {
        pseudonymize_sids(&mut workload.workload_id, pseudonyms);
        pseudonymize_sids(&mut workload.session_id, pseudonyms);
    }
    for correlation in &mut snapshot.installer_correlations {
        if let Some(workload_id) = &mut correlation.workload_id {
            pseudonymize_sids(workload_id, pseudonyms);
        }
        for workload_id in &mut correlation.candidate_workload_ids {
            pseudonymize_sids(workload_id, pseudonyms);
        }
    }
}

fn pseudonymize_classified_sid(
    value: &mut Option<EspClassifiedString>,
    pseudonyms: &BTreeMap<String, String>,
) {
    if let Some(value) = value {
        value.value = pseudonyms
            .get(&value.value.to_ascii_uppercase())
            .cloned()
            .unwrap_or_else(|| REDACTED.to_string());
    }
}

fn pseudonymize_sids(value: &mut String, pseudonyms: &BTreeMap<String, String>) {
    *value = sid_pattern()
        .replace_all(value, |captures: &regex::Captures<'_>| {
            pseudonyms
                .get(&captures[0].to_ascii_uppercase())
                .cloned()
                .unwrap_or_else(|| REDACTED.to_string())
        })
        .into_owned();
}

fn redact_reference(value: &mut String, pseudonyms: &ReferencePseudonyms) {
    let bounded = bounded_text(value);
    let redacted = redact_plain_json_secret_members(bounded);
    let redacted = redact_escaped_json_secret_members(&redacted);
    let redacted = redact_quoted_authorization_credentials(&redacted);
    let redacted =
        authorization_digest_challenge_pattern().replace_all(&redacted, "${prefix}[redacted]");
    let redacted = redact_standalone_digest_challenges(&redacted, TextRedactionContext::Arbitrary);
    let redacted =
        authorization_scheme_and_credential_pattern().replace_all(&redacted, "${prefix}[redacted]");
    let redacted =
        redact_standalone_authorization_credentials(&redacted, TextRedactionContext::Arbitrary);
    let redacted =
        redact_generic_authorization_credentials(&redacted, TextRedactionContext::Arbitrary);
    let redacted = redact_assigned_authorization(&redacted);
    let redacted = redact_assigned_secret_argument(&redacted);
    let redacted = redact_bare_secret_arguments(&redacted, TextRedactionContext::Arbitrary);
    let redacted =
        user_profile_path_pattern().replace_all(&redacted, |captures: &regex::Captures<'_>| {
            let user = captures
                .name("user")
                .expect("user-profile pattern must capture the user component")
                .as_str()
                .to_ascii_lowercase();
            let pseudonym = pseudonyms
                .profile_users
                .get(&user)
                .map_or(REDACTED, String::as_str);
            format!("{}{pseudonym}", &captures["prefix"])
        });
    let redacted = email_pattern().replace_all(&redacted, |captures: &regex::Captures<'_>| {
        pseudonyms
            .emails
            .get(&captures[0].to_ascii_lowercase())
            .map_or(REDACTED, String::as_str)
            .to_string()
    });
    let redacted = sid_pattern().replace_all(&redacted, |captures: &regex::Captures<'_>| {
        pseudonyms
            .sids
            .get(&captures[0].to_ascii_uppercase())
            .map_or(REDACTED, String::as_str)
            .to_string()
    });
    *value = if bounded.len() == value.len() {
        redacted.into_owned()
    } else {
        format!("{redacted}\n{REMOVED_OVERSIZE}")
    };
}

fn redact_all_evidence_refs(
    snapshot: &mut EspDiagnosticsSnapshot,
    pseudonyms: &ReferencePseudonyms,
) {
    for_each_evidence_ref_mut(snapshot, |evidence| {
        redact_reference(&mut evidence.evidence_id, pseudonyms);
        redact_reference(&mut evidence.source_artifact_id, pseudonyms);
    });
}

fn for_each_evidence_ref(
    snapshot: &EspDiagnosticsSnapshot,
    mut visit: impl FnMut(&EspEvidenceRef),
) {
    for evidence in &snapshot.identity.evidence {
        visit(evidence);
    }
    if let Some(profile) = &snapshot.profile {
        for evidence in &profile.evidence {
            visit(evidence);
        }
        if let Some(device_preparation) = &profile.device_preparation {
            for evidence in &device_preparation.evidence {
                visit(evidence);
            }
        }
    }
    for enrollment in &snapshot.enrollments {
        for evidence in &enrollment.evidence {
            visit(evidence);
        }
    }
    for session in &snapshot.sessions {
        for evidence in &session.evidence {
            visit(evidence);
        }
    }
    for workload in &snapshot.workloads {
        for evidence in &workload.evidence {
            visit(evidence);
        }
    }
    for correlation in &snapshot.installer_correlations {
        for evidence in &correlation.evidence {
            visit(evidence);
        }
        for process in &correlation.process_observations {
            visit(&process.context.evidence_ref);
        }
    }
    for node in &snapshot.node_cache {
        for evidence in &node.evidence {
            visit(evidence);
        }
    }
    for registration in &snapshot.registration_events {
        for evidence in &registration.evidence {
            visit(evidence);
        }
    }
    if let Some(delivery) = &snapshot.delivery_optimization {
        for evidence in &delivery.evidence {
            visit(evidence);
        }
        for transfer in &delivery.transfers {
            for evidence in &transfer.evidence {
                visit(evidence);
            }
        }
    }
    if let Some(hardware) = &snapshot.hardware {
        for evidence in &hardware.evidence {
            visit(evidence);
        }
    }
    for activity in &snapshot.activity {
        for evidence in &activity.evidence {
            visit(evidence);
        }
    }
    for finding in &snapshot.findings {
        for evidence in &finding.evidence {
            visit(evidence);
        }
    }
    for coverage in &snapshot.coverage {
        for evidence in &coverage.evidence {
            visit(evidence);
        }
    }
    for record in &snapshot.raw_evidence {
        for evidence in &record.evidence {
            visit(evidence);
        }
    }
    if let Some(graph) = &snapshot.graph {
        if let Some(device_match) = &graph.device_match.data {
            for evidence in &device_match.evidence {
                visit(evidence);
            }
            if let Some(selected) = &device_match.selected {
                for evidence in &selected.evidence {
                    visit(evidence);
                }
            }
            for candidate in &device_match.candidates {
                for evidence in &candidate.evidence {
                    visit(evidence);
                }
            }
        }
        if let Some(identity) = &graph.autopilot_identity.data {
            for evidence in &identity.evidence {
                visit(evidence);
            }
        }
        for section in [
            &graph.deployment_profile,
            &graph.intended_deployment_profile,
        ] {
            if let Some(profile) = &section.data {
                for evidence in &profile.evidence {
                    visit(evidence);
                }
            }
        }
        if let Some(assignments) = &graph.profile_assignments.data {
            for assignment in assignments {
                for evidence in &assignment.evidence {
                    visit(evidence);
                }
            }
        }
        if let Some(events) = &graph.autopilot_events.data {
            for event in events {
                for evidence in &event.evidence {
                    visit(evidence);
                }
                for detail in &event.policy_status_details {
                    for evidence in &detail.evidence {
                        visit(evidence);
                    }
                }
            }
        }
        if let Some(configuration) = &graph.enrollment_configuration.data {
            for evidence in &configuration.evidence {
                visit(evidence);
            }
            for assignment in &configuration.assignments {
                for evidence in &assignment.evidence {
                    visit(evidence);
                }
            }
        }
        if let Some(apps) = &graph.apps.data {
            for app in apps {
                for evidence in &app.evidence {
                    visit(evidence);
                }
                for assignment in &app.assignments {
                    for evidence in &assignment.evidence {
                        visit(evidence);
                    }
                }
            }
        }
        if let Some(policies) = &graph.policies.data {
            for policy in policies {
                for evidence in &policy.evidence {
                    visit(evidence);
                }
                for assignment in &policy.assignments {
                    for evidence in &assignment.evidence {
                        visit(evidence);
                    }
                }
            }
        }
        if let Some(scripts) = &graph.scripts.data {
            for script in scripts {
                for evidence in &script.evidence {
                    visit(evidence);
                }
                for assignment in &script.assignments {
                    for evidence in &assignment.evidence {
                        visit(evidence);
                    }
                }
            }
        }
    }
}

fn for_each_evidence_ref_mut(
    snapshot: &mut EspDiagnosticsSnapshot,
    mut visit: impl FnMut(&mut EspEvidenceRef),
) {
    for evidence in &mut snapshot.identity.evidence {
        visit(evidence);
    }
    if let Some(profile) = &mut snapshot.profile {
        for evidence in &mut profile.evidence {
            visit(evidence);
        }
        if let Some(device_preparation) = &mut profile.device_preparation {
            for evidence in &mut device_preparation.evidence {
                visit(evidence);
            }
        }
    }
    for enrollment in &mut snapshot.enrollments {
        for evidence in &mut enrollment.evidence {
            visit(evidence);
        }
    }
    for session in &mut snapshot.sessions {
        for evidence in &mut session.evidence {
            visit(evidence);
        }
    }
    for workload in &mut snapshot.workloads {
        for evidence in &mut workload.evidence {
            visit(evidence);
        }
    }
    for correlation in &mut snapshot.installer_correlations {
        for evidence in &mut correlation.evidence {
            visit(evidence);
        }
        for process in &mut correlation.process_observations {
            visit(&mut process.context.evidence_ref);
        }
    }
    for node in &mut snapshot.node_cache {
        for evidence in &mut node.evidence {
            visit(evidence);
        }
    }
    for registration in &mut snapshot.registration_events {
        for evidence in &mut registration.evidence {
            visit(evidence);
        }
    }
    if let Some(delivery) = &mut snapshot.delivery_optimization {
        for evidence in &mut delivery.evidence {
            visit(evidence);
        }
        for transfer in &mut delivery.transfers {
            for evidence in &mut transfer.evidence {
                visit(evidence);
            }
        }
    }
    if let Some(hardware) = &mut snapshot.hardware {
        for evidence in &mut hardware.evidence {
            visit(evidence);
        }
    }
    for activity in &mut snapshot.activity {
        for evidence in &mut activity.evidence {
            visit(evidence);
        }
    }
    for finding in &mut snapshot.findings {
        for evidence in &mut finding.evidence {
            visit(evidence);
        }
    }
    for coverage in &mut snapshot.coverage {
        for evidence in &mut coverage.evidence {
            visit(evidence);
        }
    }
    for record in &mut snapshot.raw_evidence {
        for evidence in &mut record.evidence {
            visit(evidence);
        }
    }
    if let Some(graph) = &mut snapshot.graph {
        if let Some(device_match) = &mut graph.device_match.data {
            for evidence in &mut device_match.evidence {
                visit(evidence);
            }
            if let Some(selected) = &mut device_match.selected {
                for evidence in &mut selected.evidence {
                    visit(evidence);
                }
            }
            for candidate in &mut device_match.candidates {
                for evidence in &mut candidate.evidence {
                    visit(evidence);
                }
            }
        }
        if let Some(identity) = &mut graph.autopilot_identity.data {
            for evidence in &mut identity.evidence {
                visit(evidence);
            }
        }
        for section in [
            &mut graph.deployment_profile,
            &mut graph.intended_deployment_profile,
        ] {
            if let Some(profile) = &mut section.data {
                for evidence in &mut profile.evidence {
                    visit(evidence);
                }
            }
        }
        if let Some(assignments) = &mut graph.profile_assignments.data {
            for assignment in assignments {
                for evidence in &mut assignment.evidence {
                    visit(evidence);
                }
            }
        }
        if let Some(events) = &mut graph.autopilot_events.data {
            for event in events {
                for evidence in &mut event.evidence {
                    visit(evidence);
                }
                for detail in &mut event.policy_status_details {
                    for evidence in &mut detail.evidence {
                        visit(evidence);
                    }
                }
            }
        }
        if let Some(configuration) = &mut graph.enrollment_configuration.data {
            for evidence in &mut configuration.evidence {
                visit(evidence);
            }
            for assignment in &mut configuration.assignments {
                for evidence in &mut assignment.evidence {
                    visit(evidence);
                }
            }
        }
        if let Some(apps) = &mut graph.apps.data {
            for app in apps {
                for evidence in &mut app.evidence {
                    visit(evidence);
                }
                for assignment in &mut app.assignments {
                    for evidence in &mut assignment.evidence {
                        visit(evidence);
                    }
                }
            }
        }
        if let Some(policies) = &mut graph.policies.data {
            for policy in policies {
                for evidence in &mut policy.evidence {
                    visit(evidence);
                }
                for assignment in &mut policy.assignments {
                    for evidence in &mut assignment.evidence {
                        visit(evidence);
                    }
                }
            }
        }
        if let Some(scripts) = &mut graph.scripts.data {
            for script in scripts {
                for evidence in &mut script.evidence {
                    visit(evidence);
                }
                for assignment in &mut script.assignments {
                    for evidence in &mut assignment.evidence {
                        visit(evidence);
                    }
                }
            }
        }
    }
}

fn redact_optional_text(value: &mut Option<String>) {
    if let Some(value) = value {
        *value = redact_text(value);
    }
}

fn redact_optional_narrative_text(value: &mut Option<String>) {
    if let Some(value) = value {
        *value = redact_narrative_text(value);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TextRedactionContext {
    Arbitrary,
    Narrative,
}

fn redact_standalone_digest_challenges(value: &str, context: TextRedactionContext) -> String {
    standalone_digest_challenge_pattern()
        .replace_all(value, |captures: &regex::Captures<'_>| {
            if context == TextRedactionContext::Narrative
                && standalone_digest_match_is_safe_narrative(value, captures)
            {
                captures[0].to_string()
            } else {
                format!("{} [redacted]", &captures["prefix"])
            }
        })
        .into_owned()
}

fn standalone_digest_match_is_safe_narrative(value: &str, captures: &regex::Captures<'_>) -> bool {
    let Some(matched) = captures.get(0) else {
        return false;
    };
    safe_digest_narrative_pattern().is_match(matched.as_str().trim())
        && value[matched.end()..].is_empty()
}

fn redact_text(value: &str) -> String {
    redact_text_for_context(value, TextRedactionContext::Arbitrary)
}

fn redact_narrative_text(value: &str) -> String {
    redact_text_for_context(value, TextRedactionContext::Narrative)
}

fn redact_text_for_context(value: &str, context: TextRedactionContext) -> String {
    let bounded = bounded_text(value);
    let redacted = redact_plain_json_secret_members(bounded);
    let redacted = redact_escaped_json_secret_members(&redacted);
    let redacted = redact_quoted_authorization_credentials(&redacted);
    let redacted =
        authorization_digest_challenge_pattern().replace_all(&redacted, "${prefix}[redacted]");
    let redacted = redact_standalone_digest_challenges(&redacted, context);
    let redacted =
        authorization_scheme_and_credential_pattern().replace_all(&redacted, "${prefix}[redacted]");
    let redacted = redact_standalone_authorization_credentials(&redacted, context);
    let redacted = redact_generic_authorization_credentials(&redacted, context);
    let redacted = redact_assigned_authorization(&redacted);
    let redacted = redact_assigned_secret_argument(&redacted);
    let redacted = redact_bare_secret_arguments(&redacted, context);
    let redacted = user_profile_path_pattern().replace_all(&redacted, "${prefix}[redacted]");
    let redacted = email_pattern().replace_all(&redacted, REDACTED);
    let redacted = sid_pattern().replace_all(&redacted, REDACTED);
    if bounded.len() == value.len() {
        redacted.into_owned()
    } else {
        format!("{redacted}\n{REMOVED_OVERSIZE}")
    }
}

fn bounded_text(value: &str) -> &str {
    if value.len() <= MAX_REDACTION_INPUT_BYTES {
        return value;
    }
    let mut end = MAX_REDACTION_INPUT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn raw_record_must_be_removed(record: &EspRawEvidenceRecord) -> bool {
    if record.provenance.source_kind == EspSourceKind::Graph {
        return true;
    }
    let mut labels = vec![
        record.record_id.as_str(),
        record.provenance.source_artifact_id.as_str(),
    ];
    if let Some(path) = record.provenance.file_path.as_deref() {
        labels.push(path);
    }
    if let Some(registry) = &record.provenance.registry {
        labels.push(registry.key.as_str());
        if let Some(value_name) = registry.value_name.as_deref() {
            labels.push(value_name);
        }
    }
    if let Some(event) = &record.provenance.event {
        labels.extend(event.named_data.iter().map(|value| value.name.as_str()));
    }
    if labels.iter().any(|label| forbidden_raw_label(label)) {
        return true;
    }
    match &record.raw_value {
        EspObservationValue::Text(value) => forbidden_raw_content(value),
        EspObservationValue::StringList(values) => {
            values.iter().any(|value| forbidden_raw_content(value))
        }
        EspObservationValue::Integer(_)
        | EspObservationValue::Unsigned(_)
        | EspObservationValue::Boolean(_) => false,
    }
}

fn raw_record_must_be_masked(record: &EspRawEvidenceRecord) -> bool {
    if matches!(
        record.sensitivity,
        EspSensitivity::Sensitive | EspSensitivity::Restricted
    ) {
        return true;
    }
    let Some(registry) = &record.provenance.registry else {
        return false;
    };
    if normalize_label(&registry.key).contains("nodecache") {
        return true;
    }
    registry
        .value_name
        .as_deref()
        .is_some_and(sensitive_value_label)
}

fn sensitive_value_label(value: &str) -> bool {
    let normalized = normalize_label(value);
    matches!(
        normalized.as_str(),
        "upn"
            | "userprincipalname"
            | "usersid"
            | "sid"
            | "aadtenantid"
            | "azureadtenantid"
            | "tenantid"
            | "tenantdomain"
            | "cloudassignedtenantid"
            | "cloudassignedtenantdomain"
            | "entdmid"
            | "serial"
            | "serialnumber"
            | "deviceserialnumber"
    )
}

fn forbidden_raw_label(value: &str) -> bool {
    let normalized = normalize_label(value);
    if matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "clientsecret"
            | "apikey"
            | "token"
            | "authtoken"
            | "bearertoken"
    ) {
        return true;
    }
    [
        "authorization",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "hardwarehash",
        "devicehardwaredata",
        "rawgraphbody",
        "graphresponsebody",
    ]
    .iter()
    .any(|forbidden| normalized.contains(forbidden))
}

fn normalize_label(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn forbidden_raw_content(value: &str) -> bool {
    let bounded = bounded_text(value);
    plain_json_secret_member_key_pattern().is_match(bounded)
        || escaped_json_secret_member_key_pattern().is_match(bounded)
        || forbidden_raw_content_pattern().is_match(bounded)
        || authorization_pattern().is_match(bounded)
        || standalone_digest_challenge_pattern().is_match(bounded)
        || authorization_scheme_and_credential_pattern().is_match(bounded)
        || generic_authorization_scheme_and_credential_pattern().is_match(bounded)
        || standalone_authorization_scheme_pattern().is_match(bounded)
        || quoted_authorization_credential_start_pattern().is_match(bounded)
        || bare_authorization_pattern().is_match(bounded)
}

fn redact_assigned_authorization(value: &str) -> String {
    authorization_pattern()
        .replace_all(value, |captures: &regex::Captures<'_>| {
            redact_assigned_value(captures)
        })
        .into_owned()
}

fn redact_assigned_secret_argument(value: &str) -> String {
    secret_argument_pattern()
        .replace_all(value, |captures: &regex::Captures<'_>| {
            redact_assigned_value(captures)
        })
        .into_owned()
}

fn redact_assigned_value(captures: &regex::Captures<'_>) -> String {
    if captures["value"].trim_matches(['"', '\'']) == REDACTED {
        captures[0].to_string()
    } else {
        format!("{}[redacted]", &captures["prefix"])
    }
}

fn redact_generic_authorization_credentials(value: &str, context: TextRedactionContext) -> String {
    generic_authorization_scheme_and_credential_pattern()
        .replace_all(value, |captures: &regex::Captures<'_>| {
            if context == TextRedactionContext::Narrative
                && captures.get(0).is_some_and(|matched| {
                    safe_authorization_narrative_pattern().is_match(matched.as_str().trim())
                })
            {
                captures[0].to_string()
            } else {
                format!("{}[redacted]", &captures["prefix"])
            }
        })
        .into_owned()
}

fn redact_standalone_authorization_credentials(
    value: &str,
    context: TextRedactionContext,
) -> String {
    standalone_authorization_scheme_pattern()
        .replace_all(value, |captures: &regex::Captures<'_>| {
            if context == TextRedactionContext::Narrative
                && authorization_scheme_match_is_safe_narrative(captures)
            {
                captures[0].to_string()
            } else if context == TextRedactionContext::Narrative
                && authorization_scheme_match_starts_narrative_clause(captures)
            {
                format!("{}[redacted]", &captures["prefix"])
            } else {
                format!("{}[redacted]{}", &captures["prefix"], &captures["tail"])
            }
        })
        .into_owned()
}

fn redact_bare_secret_arguments(value: &str, context: TextRedactionContext) -> String {
    let redacted =
        bare_authorization_pattern().replace_all(value, |captures: &regex::Captures<'_>| {
            if bare_argument_is_safe_narrative(context, "authorization", &captures["value"]) {
                captures[0].to_string()
            } else {
                format!("{}[redacted]", &captures["prefix"])
            }
        });
    bare_secret_argument_pattern()
        .replace_all(&redacted, |captures: &regex::Captures<'_>| {
            if bare_argument_is_safe_narrative(context, &captures["name"], &captures["value"]) {
                captures[0].to_string()
            } else {
                format!("{}[redacted]", &captures["prefix"])
            }
        })
        .into_owned()
}

fn bare_argument_is_safe_narrative(context: TextRedactionContext, name: &str, value: &str) -> bool {
    if context != TextRedactionContext::Narrative || value.starts_with(['"', '\'']) {
        return false;
    }

    let name = normalize_label(name);
    let value = value
        .trim_end_matches(['.', ',', ':', ';', '!', '?'])
        .to_ascii_lowercase();
    if matches!(value.as_str(), "is" | "was" | "remains") {
        return true;
    }

    match name.as_str() {
        "authorization" => matches!(value.as_str(), "header" | "policy" | "status"),
        "password" | "passwd" | "pwd" => matches!(
            value.as_str(),
            "policy"
                | "policies"
                | "requirement"
                | "requirements"
                | "reset"
                | "expiration"
                | "expiry"
        ),
        "secret" | "clientsecret" => matches!(
            value.as_str(),
            "management" | "retrieval" | "rotation" | "storage"
        ),
        "token" | "accesstoken" | "refreshtoken" | "idtoken" | "authtoken" | "bearertoken" => {
            matches!(
                value.as_str(),
                "acquisition"
                    | "cache"
                    | "expiration"
                    | "expiry"
                    | "refresh"
                    | "request"
                    | "status"
                    | "support"
                    | "validation"
            )
        }
        "tenant" => matches!(value.as_str(), "configuration" | "discovery" | "id"),
        "tenantid" | "entdmid" => value == "missing",
        "serial" => value == "number",
        "serialnumber" => value == "missing",
        _ => false,
    }
}

fn authorization_scheme_match_is_safe_narrative(captures: &regex::Captures<'_>) -> bool {
    // Arbitrary evidence never reaches this exception. Parser-owned narrative
    // fields preserve only complete known prose clauses; quoted, extended, and
    // unrecognized values remain credentials and are redacted with their tails.
    let Some(matched) = captures.get(0) else {
        return false;
    };
    let clause = matched.as_str().trim();
    safe_authorization_narrative_pattern().is_match(clause)
        || safe_digest_narrative_pattern().is_match(clause)
}

fn authorization_scheme_match_starts_narrative_clause(captures: &regex::Captures<'_>) -> bool {
    let Some(candidate) = captures.name("bare") else {
        return false;
    };
    let next_word = captures["tail"]
        .trim_start_matches([' ', '\t'])
        .split(|character: char| !character.is_ascii_alphabetic())
        .next()
        .unwrap_or_default();
    (candidate.as_str().eq_ignore_ascii_case("authentication")
        && (next_word.eq_ignore_ascii_case("is") || next_word.eq_ignore_ascii_case("remains")))
        || (candidate.as_str().eq_ignore_ascii_case("authorization")
            && (next_word.eq_ignore_ascii_case("is") || next_word.eq_ignore_ascii_case("remains")))
        || (candidate.as_str().eq_ignore_ascii_case("scheme")
            && next_word.eq_ignore_ascii_case("negotiation"))
        || (candidate.as_str().eq_ignore_ascii_case("token")
            && next_word.eq_ignore_ascii_case("support"))
}

fn redact_provenance(provenance: &mut EspEvidenceProvenance, pseudonyms: &ReferencePseudonyms) {
    redact_reference(&mut provenance.source_artifact_id, pseudonyms);
    if let Some(path) = &mut provenance.file_path {
        *path = redact_text(path);
    }
    if let Some(registry) = &mut provenance.registry {
        registry.key = redact_text(&registry.key);
        if let Some(value_name) = &mut registry.value_name {
            redact_reference(value_name, pseudonyms);
        }
    }
    if let Some(event) = &mut provenance.event {
        for named in &mut event.named_data {
            redact_named_value(named);
        }
    }
}

fn redact_named_value(named: &mut EspNamedValue) {
    named.value = if sensitive_value_label(&named.name) || forbidden_raw_label(&named.name) {
        REDACTED.to_string()
    } else {
        redact_text(&named.value)
    };
}

fn redact_graph_overlay(graph: &mut EspGraphOverlay) {
    if let Some(device_match) = &mut graph.device_match.data {
        if let Some(selected) = &mut device_match.selected {
            redact_graph_managed_device(selected);
        }
        for candidate in &mut device_match.candidates {
            redact_graph_managed_device(candidate);
        }
    }
    redact_graph_error(&mut graph.device_match.error);

    if let Some(identity) = &mut graph.autopilot_identity.data {
        mask_classified(&mut identity.serial_number);
        redact_optional_text(&mut identity.group_tag);
    }
    redact_graph_error(&mut graph.autopilot_identity.error);

    redact_graph_profile_section(&mut graph.deployment_profile);
    redact_graph_profile_section(&mut graph.intended_deployment_profile);
    redact_graph_error(&mut graph.profile_assignments.error);

    if let Some(events) = &mut graph.autopilot_events.data {
        for event in events {
            redact_status(&mut event.deployment_state);
            for detail in &mut event.policy_status_details {
                redact_optional_text(&mut detail.display_name);
                redact_status(&mut detail.status);
            }
        }
    }
    redact_graph_error(&mut graph.autopilot_events.error);

    if let Some(configuration) = &mut graph.enrollment_configuration.data {
        redact_optional_text(&mut configuration.display_name);
    }
    redact_graph_error(&mut graph.enrollment_configuration.error);

    if let Some(apps) = &mut graph.apps.data {
        for app in apps {
            redact_optional_text(&mut app.display_name);
            if let Some(status) = &mut app.status {
                redact_status(status);
            }
        }
    }
    redact_graph_error(&mut graph.apps.error);

    if let Some(policies) = &mut graph.policies.data {
        for policy in policies {
            redact_optional_text(&mut policy.display_name);
            if let Some(status) = &mut policy.status {
                redact_status(status);
            }
        }
    }
    redact_graph_error(&mut graph.policies.error);

    if let Some(scripts) = &mut graph.scripts.data {
        for script in scripts {
            redact_optional_text(&mut script.display_name);
            if let Some(status) = &mut script.status {
                redact_status(status);
            }
        }
    }
    redact_graph_error(&mut graph.scripts.error);
}

fn redact_graph_managed_device(device: &mut EspGraphManagedDevice) {
    mask_classified(&mut device.serial_number);
    mask_classified(&mut device.user_principal_name);
    mask_classified(&mut device.tenant_id);
}

fn redact_graph_profile_section(section: &mut GraphSection<EspGraphDeploymentProfile>) {
    if let Some(profile) = &mut section.data {
        redact_optional_text(&mut profile.display_name);
    }
    redact_graph_error(&mut section.error);
}

fn redact_graph_error(error: &mut Option<GraphSectionError>) {
    if let Some(error) = error {
        error.message = redact_narrative_text(&error.message);
    }
}
