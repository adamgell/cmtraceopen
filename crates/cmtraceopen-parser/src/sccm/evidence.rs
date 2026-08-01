use crate::parser::ccm::{CcmLogicalRecord, CcmTimestampParse, CcmTimestampParseState};
use regex::Regex;
use std::sync::OnceLock;

use super::models::{
    SccmArtifact, SccmEvidence, SccmEvidenceRef, SccmRecordCompleteness, SccmRole,
    SccmTimeOrderingState, SccmTimestamp,
};

const PUBLIC_MESSAGE_PROFILE: &str = "sccm-public-message-v1";
const PUBLIC_MESSAGE_REDACTION: &str = "[redacted:sccm-public-message-v1]";

fn sensitive_message_label_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            (?:
                ["']?\b authorization(?:[\x20_-]?(?:header|token))?\b ["']?
                    (?:[\x20\t]*[:=][\x20\t]*|[\x20\t]+)
                    (?:[a-z][a-z0-9._-]*[\x20\t]+)?
                |
                ["']?\b bearer\b ["']?
                    (?:[\x20\t]*[:=][\x20\t]*|[\x20\t]+)
                |
                ["']?\b(?:
                    shared[\x20_-]?access[\x20_-]?signature
                    | client[\x20_-]?secret
                    | (?:client|access|refresh|id|device|session)[\x20_-]?token
                    | api[\x20_-]?key
                    | account[\x20_-]?key
                    | samaccountname
                    | accountname
                    | callerhandle
                    | localuser
                    | identity
                    | queryhandle
                    | user[\x20_-]?principal[\x20_-]?name
                    | credential
                    | password
                    | passwd
                    | secret
                    | token
                    | username
                    | user
                    | upn
                    | sig
                )\b["']?(?:[\x20\t]*[:=][\x20\t]*|[\x20\t]+)
            )"#,
        )
        .expect("SCCM sensitive message label regex must compile")
    })
}

fn windows_identity_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\b(?:NT AUTHORITY|[A-Z0-9][A-Z0-9._-]*)|\.)(?:\\)+[A-Z0-9][A-Z0-9._$-]*\b",
        )
        .expect("SCCM Windows identity regex must compile")
    })
}

fn windows_user_path_identity_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?ix)
            (?:^|[\\/]+)
            (?:users|profiles|home|documents[\x20_-]+and[\x20_-]+settings)
            [\\/]+
            (?P<identity>
                (?:(?:NT[\x20]+AUTHORITY|[A-Z0-9][A-Z0-9._-]*|\.)[\\/]+)?
                [A-Z0-9][A-Z0-9._$-]*\b
            )",
        )
        .expect("SCCM Windows user-path identity regex must compile")
    })
}

fn email_identity_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
            .expect("SCCM email identity regex must compile")
    })
}

/// Profile v1 is a deterministic, parser-only public projection. It removes
/// recognized identity and secret-bearing values while leaving diagnostic
/// codes and approved structured keys outside those values unchanged. It does
/// not imply native collector validation.
fn project_public_message_v1(raw: &str) -> String {
    format!("[{PUBLIC_MESSAGE_PROFILE}] {}", project_public_text_v1(raw))
}

fn project_public_text_v1(raw: &str) -> String {
    let redacted = redact_sensitive_segments(raw);
    let identities_redacted = redact_windows_identities(&redacted);
    redact_email_identities(&identities_redacted)
}

fn redact_sensitive_segments(value: &str) -> String {
    let mut projected = String::with_capacity(value.len());
    let mut copied_through = 0;
    let mut search_from = 0;

    while let Some(label) = sensitive_message_label_re().find_at(value, search_from) {
        projected.push_str(&value[copied_through..label.start()]);
        projected.push_str(PUBLIC_MESSAGE_REDACTION);

        let value_end = if is_provider_private_label(label.as_str()) {
            provider_private_value_end(value, label.end())
        } else {
            sensitive_value_end(value, label.end())
        };
        copied_through = value_end;
        search_from = value_end;
    }

    projected.push_str(&value[copied_through..]);
    projected
}

fn is_provider_private_label(label: &str) -> bool {
    let label = label.to_ascii_lowercase();
    label.contains("authorization")
        || label.contains("callerhandle")
        || label.contains("queryhandle")
}

fn provider_private_value_end(value: &str, value_start: usize) -> usize {
    let remaining = &value[value_start..];
    if remaining
        .chars()
        .next()
        .is_some_and(|first| matches!(first, '"' | '\''))
    {
        return sensitive_value_end(value, value_start);
    }

    let line_end = remaining
        .char_indices()
        .find_map(|(offset, character)| {
            matches!(character, '\r' | '\n').then_some(value_start + offset)
        })
        .unwrap_or(value.len());
    let private_value = &value[value_start..line_end];

    private_value
        .match_indices(';')
        .find_map(|(offset, delimiter)| {
            let tail_start = offset + delimiter.len();
            provider_tail_has_independent_boundary(&private_value[tail_start..])
                .then_some(value_start + offset)
        })
        .unwrap_or(line_end)
}

fn provider_tail_has_independent_boundary(value: &str) -> bool {
    let trimmed = value.trim_start();
    provider_public_tail_is_safe(trimmed)
        || sensitive_message_label_re()
            .find(trimmed)
            .is_some_and(|label| label.start() == 0)
}

fn provider_public_tail_is_safe(value: &str) -> bool {
    let mut segments = value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty());
    let Some(first) = segments.next() else {
        return false;
    };

    std::iter::once(first).chain(segments).all(|segment| {
        let Some((label, value)) = segment.split_once('=') else {
            return false;
        };
        let label = label.trim();
        let value = value.trim();
        matches!(
            label.to_ascii_lowercase().as_str(),
            "phase"
                | "disposition"
                | "terminal"
                | "requestid"
                | "operationhandle"
                | "endpointid"
                | "layer"
                | "profileid"
                | "status"
                | "result"
                | "errorcode"
                | "hresult"
        ) && !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'-' | b'{' | b'}' | b':' | b'+')
            })
    })
}

fn sensitive_value_end(value: &str, value_start: usize) -> usize {
    let remaining = &value[value_start..];
    let Some(first) = remaining.chars().next() else {
        return value.len();
    };

    if matches!(first, '"' | '\'') {
        let quote_width = first.len_utf8();
        let mut escaped = false;
        for (offset, character) in remaining[quote_width..].char_indices() {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == first {
                return value_start + quote_width + offset + character.len_utf8();
            }
        }

        return value.len();
    }

    remaining
        .char_indices()
        .find_map(|(offset, character)| {
            (character.is_whitespace() || matches!(character, ',' | ';' | '&'))
                .then_some(value_start + offset)
        })
        .unwrap_or(value.len())
}

fn redact_windows_identities(value: &str) -> String {
    let mut projected = String::with_capacity(value.len());
    let mut copied_through = 0;
    let mut identity_ranges = windows_identity_re()
        .find_iter(value)
        .filter_map(|matched| {
            let preceding = value[..matched.start()].chars().next_back();
            let following = value[matched.end()..].chars().next();
            let begins_relative_path =
                matched.as_str().starts_with(r".\") && matches!(following, Some('\\' | '/'));
            (!matches!(preceding, Some('\\' | '/')) && !begins_relative_path)
                .then_some((matched.start(), matched.end()))
        })
        .collect::<Vec<_>>();
    identity_ranges.extend(
        windows_user_path_identity_re()
            .captures_iter(value)
            .filter_map(|captures| {
                captures
                    .name("identity")
                    .map(|matched| (matched.start(), matched.end()))
            }),
    );
    identity_ranges.sort_unstable();
    identity_ranges.dedup();

    let mut merged_ranges: Vec<(usize, usize)> = Vec::with_capacity(identity_ranges.len());
    for (start, end) in identity_ranges {
        if let Some((_, merged_end)) = merged_ranges.last_mut() {
            if start <= *merged_end {
                *merged_end = (*merged_end).max(end);
                continue;
            }
        }
        merged_ranges.push((start, end));
    }

    for (start, end) in merged_ranges {
        projected.push_str(&value[copied_through..start]);
        projected.push_str(PUBLIC_MESSAGE_REDACTION);
        copied_through = end;
    }

    projected.push_str(&value[copied_through..]);
    projected
}

fn redact_email_identities(value: &str) -> String {
    email_identity_re()
        .replace_all(value, PUBLIC_MESSAGE_REDACTION)
        .into_owned()
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SccmRawEvidenceSnapshot {
    evidence_id: String,
    completeness: SccmRecordCompleteness,
    reference: SccmEvidenceRef,
    role: SccmRole,
    component: Option<String>,
    ccm_source_file: Option<String>,
    message: String,
    timestamp: SccmTimestamp,
    raw_execution_context: Option<String>,
}

impl SccmRawEvidenceSnapshot {
    pub(crate) fn from_record(artifact: &SccmArtifact, record: CcmLogicalRecord) -> Self {
        let CcmLogicalRecord {
            entry,
            context,
            line_start,
            line_end,
            timestamp,
        } = record;
        let entry_id = format!("{}:{line_start}-{line_end}", artifact.artifact_id);

        Self {
            evidence_id: entry_id.clone(),
            completeness: SccmRecordCompleteness::LogicalRecord,
            reference: SccmEvidenceRef {
                artifact_id: artifact.artifact_id.clone(),
                entry_id,
                line_start: Some(line_start),
                line_end: Some(line_end),
            },
            role: artifact.role.clone(),
            component: entry.component,
            ccm_source_file: entry.source_file,
            message: entry.message,
            timestamp: timestamp.into(),
            raw_execution_context: context,
        }
    }

    /// One physical line that never became a logical record.
    ///
    /// The snapshot carries no timestamp: a fragment has no provable instant,
    /// so it can never be ordered against, or attached to, a real record.
    pub(crate) fn from_physical_line(
        artifact: &SccmArtifact,
        line_number: u32,
        text: &str,
    ) -> Self {
        let entry_id = format!("{}:{line_number}-{line_number}", artifact.artifact_id);

        Self {
            evidence_id: entry_id.clone(),
            completeness: SccmRecordCompleteness::PhysicalFragment,
            reference: SccmEvidenceRef {
                artifact_id: artifact.artifact_id.clone(),
                entry_id,
                line_start: Some(line_number),
                line_end: Some(line_number),
            },
            role: artifact.role.clone(),
            component: None,
            ccm_source_file: None,
            message: text.to_owned(),
            timestamp: SccmTimestamp {
                original_display: None,
                offset_minutes: None,
                utc_millis: None,
                ordering_state: SccmTimeOrderingState::TimestampMissing,
            },
            raw_execution_context: None,
        }
    }

    pub(crate) fn export(&self) -> SccmEvidence {
        SccmEvidence {
            evidence_id: self.evidence_id.clone(),
            completeness: self.completeness,
            reference: self.reference.clone(),
            role: self.role.clone(),
            component: self.component.as_deref().map(project_public_text_v1),
            ccm_source_file: self.ccm_source_file.as_deref().map(project_public_text_v1),
            message: project_public_message_v1(&self.message),
            timestamp: self.timestamp.clone(),
            // Raw execution context remains available only to this
            // crate-private snapshot. A public handle requires a separately
            // reviewed keyed scheme and explicit caller-provided key.
            execution_context: None,
        }
    }
}

impl From<CcmTimestampParse> for SccmTimestamp {
    fn from(timestamp: CcmTimestampParse) -> Self {
        Self {
            original_display: timestamp.original_display,
            offset_minutes: timestamp.offset_minutes,
            utc_millis: timestamp.utc_millis,
            ordering_state: timestamp.ordering_state.into(),
        }
    }
}

impl From<CcmTimestampParseState> for SccmTimeOrderingState {
    fn from(state: CcmTimestampParseState) -> Self {
        match state {
            CcmTimestampParseState::NormalizedUtc => Self::NormalizedUtc,
            CcmTimestampParseState::OffsetMissing => Self::OffsetMissing,
            CcmTimestampParseState::OffsetInvalid => Self::OffsetInvalid,
            CcmTimestampParseState::TimestampMissing => Self::TimestampMissing,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::ccm::scan_logical_records;

    use super::*;
    use crate::sccm::models::{SccmCoverageState, SccmRole, SccmRotation};

    #[test]
    fn export_redaction_does_not_mutate_raw_snapshot() {
        let raw_message = r#"Policy id={ABCDEFAB-0000-0000-0000-000000000001} failed hr=0x80070005 user=LAB\SyntheticUser token=synthetic-secret payload={"token":"synthetic-json-secret","user":"SyntheticJsonUser"} url=https://example.invalid/?token=synthetic-query-secret&status=71"#;
        let text = format!(
            r#"<![LOG[{raw_message}]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="NT AUTHORITY\SYSTEM" type="1" thread="42" file="policyagent.cpp">"#
        );
        let artifact = SccmArtifact {
            artifact_id: "client-policy-agent".into(),
            display_name: "PolicyAgent.log".into(),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: None,
            collected_at_utc: None,
            rotation: SccmRotation::Current,
            coverage: SccmCoverageState::Captured,
            encoding: Some("utf-8".into()),
        };
        let record = scan_logical_records(&text, &artifact.display_name)
            .into_iter()
            .next()
            .expect("fixture contains one CCM record");
        let snapshot = SccmRawEvidenceSnapshot::from_record(&artifact, record);
        let before = snapshot.clone();

        let exported = snapshot.export();

        assert_eq!(snapshot, before);
        assert_eq!(
            snapshot.raw_execution_context.as_deref(),
            Some(r"NT AUTHORITY\SYSTEM")
        );
        assert_eq!(snapshot.message, raw_message);
        let exported_json = serde_json::to_string(&exported).unwrap();
        assert!(!exported_json.contains(r"NT AUTHORITY\\SYSTEM"));
        assert!(!exported_json.contains(r"LAB\\SyntheticUser"));
        assert!(!exported_json.contains("synthetic-secret"));
        assert!(!exported_json.contains("synthetic-json-secret"));
        assert!(!exported_json.contains("SyntheticJsonUser"));
        assert!(!exported_json.contains("synthetic-query-secret"));
        assert!(exported.message.starts_with("[sccm-public-message-v1] "));
        assert!(exported.message.contains("hr=0x80070005"));
        assert!(exported.message.contains("&status=71"));
        assert!(exported
            .message
            .contains("{ABCDEFAB-0000-0000-0000-000000000001}"));
        assert_eq!(exported.execution_context, None);
    }

    #[test]
    fn export_merges_overlapping_identity_ranges_without_mutating_raw_snapshot() {
        let raw_identity = r"users\ADMIN\secret";
        let raw_message = format!("{raw_identity}; status=71");
        let text = format!(
            r#"<![LOG[{raw_message}]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="{raw_identity}" context="" type="1" thread="42" file="{raw_identity}">"#
        );
        let artifact = SccmArtifact {
            artifact_id: "client-policy-agent".into(),
            display_name: "PolicyAgent.log".into(),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: None,
            collected_at_utc: None,
            rotation: SccmRotation::Current,
            coverage: SccmCoverageState::Captured,
            encoding: Some("utf-8".into()),
        };
        let record = scan_logical_records(&text, &artifact.display_name)
            .into_iter()
            .next()
            .expect("fixture contains one CCM record");
        let snapshot = SccmRawEvidenceSnapshot::from_record(&artifact, record);
        let before = snapshot.clone();

        let exported = snapshot.export();
        let exported_json = serde_json::to_string(&exported).unwrap();

        assert_eq!(snapshot, before);
        assert!(snapshot.message.contains(raw_identity));
        assert_eq!(snapshot.component.as_deref(), Some(raw_identity));
        assert_eq!(snapshot.ccm_source_file.as_deref(), Some(raw_identity));
        for private_segment in ["ADMIN", "secret"] {
            assert!(
                !exported_json.contains(private_segment),
                "{private_segment} leaked after overlapping identity projection"
            );
        }
        assert!(exported.message.contains("status=71"));
        assert!(exported
            .component
            .as_deref()
            .is_some_and(|value| value.contains(PUBLIC_MESSAGE_REDACTION)));
        assert!(exported
            .ccm_source_file
            .as_deref()
            .is_some_and(|value| value.contains(PUBLIC_MESSAGE_REDACTION)));
    }
}
