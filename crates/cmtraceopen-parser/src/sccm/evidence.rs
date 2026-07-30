use crate::parser::ccm::{CcmLogicalRecord, CcmTimestampParse, CcmTimestampParseState};
use regex::Regex;
use std::sync::OnceLock;

use super::models::{
    SccmArtifact, SccmEvidence, SccmEvidenceRef, SccmRole, SccmTimeOrderingState, SccmTimestamp,
};

const PUBLIC_MESSAGE_PROFILE: &str = "sccm-public-message-v1";
const PUBLIC_MESSAGE_REDACTION: &str = "[redacted:sccm-public-message-v1]";

fn sensitive_message_label_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            (?:
                ["']?\b authorization\b ["']?
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
        Regex::new(r"(?i)(?:\b(?:NT AUTHORITY|[A-Z0-9][A-Z0-9._-]*)|\.)\\[A-Z0-9][A-Z0-9._$-]*\b")
            .expect("SCCM Windows identity regex must compile")
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
    let redacted = redact_sensitive_segments(raw);
    let identities_redacted = redact_windows_identities(&redacted);
    let projected = redact_email_identities(&identities_redacted);

    format!("[{PUBLIC_MESSAGE_PROFILE}] {projected}")
}

fn redact_sensitive_segments(value: &str) -> String {
    let mut projected = String::with_capacity(value.len());
    let mut copied_through = 0;
    let mut search_from = 0;

    while let Some(label) = sensitive_message_label_re().find_at(value, search_from) {
        projected.push_str(&value[copied_through..label.start()]);
        projected.push_str(PUBLIC_MESSAGE_REDACTION);

        let value_end = sensitive_value_end(value, label.end());
        copied_through = value_end;
        search_from = value_end;
    }

    projected.push_str(&value[copied_through..]);
    projected
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

    for matched in windows_identity_re().find_iter(value) {
        let preceding = value[..matched.start()].chars().next_back();
        let following = value[matched.end()..].chars().next();
        let path_adjacent =
            matches!(preceding, Some('\\' | '/' | ':')) || matches!(following, Some('\\' | '/'));
        if path_adjacent {
            continue;
        }

        projected.push_str(&value[copied_through..matched.start()]);
        projected.push_str(PUBLIC_MESSAGE_REDACTION);
        copied_through = matched.end();
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

    pub(crate) fn export(&self) -> SccmEvidence {
        SccmEvidence {
            evidence_id: self.evidence_id.clone(),
            reference: self.reference.clone(),
            role: self.role.clone(),
            component: self.component.clone(),
            ccm_source_file: self.ccm_source_file.clone(),
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
}
