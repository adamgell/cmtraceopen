//! Content-structure classification for report members.
//!
//! Issue #369's shared Company Portal constraints require that a path hint may
//! only *select a candidate*; content structure has to confirm it. Everything
//! decided here is therefore decided from the decoded text. The member path is
//! never consulted, which is what keeps a renamed or mislabelled member from
//! inheriting a role it does not have.
//!
//! Note what is deliberately absent: no rule maps a member onto an MSAL,
//! configuration, or system-fact role. Those roles need the report schema, and
//! no sanitized real report is fixture-backed. A declared role of that kind is
//! carried through as *declared and unconfirmed*, never promoted.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{MemberContentKind, ReportMemberRole, RoleConfirmation};

/// Lines sampled when deciding whether text is log-framed.
const LOG_SAMPLE_LINES: usize = 20;

/// Share of sampled lines that must start with a timestamp.
///
/// Well below 100% on purpose: real logs carry continuation lines, stack
/// traces, and blank separators, and a rule that demanded every line start with
/// a timestamp would classify a genuine log as unstructured text.
const LOG_TIMESTAMP_RATIO: f64 = 0.6;

/// Longest excerpt retained from a member that failed to parse.
const FAILURE_EXCERPT_CHARS: usize = 160;

/// Leading timestamp shapes that mark a line as log-framed.
///
/// Three families, all public formats rather than anything inferred from a
/// Company Portal report: ISO-8601, Apple's `os_log` wall-clock form with an
/// explicit offset, and BSD syslog.
fn log_timestamp_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?x)
              ^\s*(?:
                  \d{4}-\d{2}-\d{2}[T\ ]\d{2}:\d{2}:\d{2}
                | \[[A-Z][a-z]{2}\ +\d{1,2}\ \d{2}:\d{2}:\d{2}
                | [A-Z][a-z]{2}\ +\d{1,2}\ \d{2}:\d{2}:\d{2}
              )",
        )
        .expect("log timestamp detection pattern must compile")
    })
}

/// Classify decoded member text by structure alone.
///
/// `content` is `None` when the import boundary never produced text for the
/// member (absent, encrypted, unknown compression, and so on).
pub fn classify_content(content: Option<&str>) -> MemberContentKind {
    let Some(content) = content else {
        return MemberContentKind::Undecoded;
    };
    if content.trim().is_empty() {
        return MemberContentKind::Empty;
    }
    // A NUL that survived decoding means the importer handed over bytes that
    // were never text. Treating it as text would let a binary member masquerade
    // as an unstructured log.
    if content.contains('\0') {
        return MemberContentKind::Binary;
    }

    let trimmed = trimmed_body(content);

    if trimmed.starts_with('<') && looks_like_property_list(trimmed) {
        return MemberContentKind::PropertyList;
    }
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
    {
        return MemberContentKind::Json;
    }
    if is_log_framed(content) {
        return MemberContentKind::PlainTextLog;
    }
    MemberContentKind::PlainText
}

/// Whether text that *claimed* to be JSON actually is.
///
/// Used to separate "a member we never expected to be JSON" from "a member
/// declared as a structured fact whose bytes do not parse", which is the
/// malformed-manifest case rather than an unknown supplemental artifact.
pub fn looks_like_json_attempt(content: &str) -> bool {
    let trimmed = trimmed_body(content);
    trimmed.starts_with('{') || trimmed.starts_with('[')
}

/// Decide the confirmed role and how the declaration relates to the content.
///
/// Only [`ReportMemberRole::DirectLog`] is ever confirmed. Everything else
/// stays unclassified with the declaration preserved, because confirming it
/// would mean asserting the undocumented report schema.
pub fn confirm_role(
    declared: Option<&ReportMemberRole>,
    content_kind: &MemberContentKind,
) -> (ReportMemberRole, RoleConfirmation) {
    let is_log = *content_kind == MemberContentKind::PlainTextLog;

    match declared {
        Some(ReportMemberRole::DirectLog) if is_log => {
            (ReportMemberRole::DirectLog, RoleConfirmation::ContentConfirmed)
        }
        Some(ReportMemberRole::DirectLog) => (
            ReportMemberRole::Unclassified,
            RoleConfirmation::Contradicted,
        ),
        Some(ReportMemberRole::Unclassified) | None if is_log => {
            (ReportMemberRole::DirectLog, RoleConfirmation::ContentConfirmed)
        }
        Some(ReportMemberRole::Unclassified) | None => (
            ReportMemberRole::Unclassified,
            RoleConfirmation::NotDeclared,
        ),
        Some(_) => (
            ReportMemberRole::Unclassified,
            RoleConfirmation::DeclaredUnconfirmed,
        ),
    }
}

/// Whether a member is plausible evidence from *some* diagnostic report.
///
/// Used only to decide whether a declared container is contradicted by having
/// nothing readable in it. It is deliberately weak: it cannot and does not
/// claim the container is a Company Portal report.
pub fn is_plausible_evidence(content_kind: &MemberContentKind) -> bool {
    matches!(
        content_kind,
        MemberContentKind::PlainTextLog
            | MemberContentKind::Json
            | MemberContentKind::PropertyList
            | MemberContentKind::PlainText
    )
}

/// Number of lines in decoded text, counting a trailing fragment.
pub fn line_count(content: &str) -> u64 {
    if content.is_empty() {
        return 0;
    }
    content.lines().count() as u64
}

/// A short, character-boundary-safe excerpt of text that failed to parse.
pub fn failure_excerpt(content: &str) -> String {
    let excerpt: String = content
        .chars()
        .take(FAILURE_EXCERPT_CHARS)
        .map(|c| if c.is_control() && c != '\t' { ' ' } else { c })
        .collect();
    excerpt.trim().to_owned()
}

/// Strip whitespace and a UTF-8 BOM from the front of decoded text.
///
/// The importer hands over text, not bytes, so a byte-order mark arrives as
/// `U+FEFF`. Without stripping it, `{` is no longer the first character and
/// every BOM-prefixed JSON member classifies as unstructured text.
fn trimmed_body(content: &str) -> &str {
    content.trim_start_matches('\u{feff}').trim()
}

fn looks_like_property_list(trimmed: &str) -> bool {
    trimmed.contains("<plist") || trimmed.contains("<!DOCTYPE plist")
}

fn is_log_framed(content: &str) -> bool {
    let sample: Vec<&str> = content
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty())
        .take(LOG_SAMPLE_LINES)
        .collect();
    if sample.is_empty() {
        return false;
    }
    let stamped = sample
        .iter()
        .filter(|line| log_timestamp_pattern().is_match(line))
        .count();
    stamped as f64 / sample.len() as f64 >= LOG_TIMESTAMP_RATIO
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_property_list_and_log_shapes_are_distinguished() {
        assert_eq!(
            classify_content(Some("{\"a\": 1}")),
            MemberContentKind::Json
        );
        assert_eq!(
            classify_content(Some(
                "<?xml version=\"1.0\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"\">\n<plist version=\"1.0\"><dict/></plist>"
            )),
            MemberContentKind::PropertyList
        );
        assert_eq!(
            classify_content(Some(
                "2026-07-31T00:00:00Z start\n2026-07-31T00:00:01Z next\n  continuation\n"
            )),
            MemberContentKind::PlainTextLog
        );
        assert_eq!(
            classify_content(Some("just some prose\nand more prose\n")),
            MemberContentKind::PlainText
        );
    }

    #[test]
    fn a_bom_prefixed_json_member_still_classifies_as_json() {
        assert_eq!(
            classify_content(Some("\u{feff}{\"a\": 1}")),
            MemberContentKind::Json
        );
    }

    #[test]
    fn text_that_only_looks_like_json_is_not_json() {
        assert_eq!(
            classify_content(Some("{ not really json ")),
            MemberContentKind::PlainText
        );
        assert!(looks_like_json_attempt("{ not really json "));
    }

    #[test]
    fn undecoded_empty_and_binary_content_are_separated() {
        assert_eq!(classify_content(None), MemberContentKind::Undecoded);
        assert_eq!(classify_content(Some("   \n")), MemberContentKind::Empty);
        assert_eq!(
            classify_content(Some("abc\0def")),
            MemberContentKind::Binary
        );
    }

    #[test]
    fn a_declared_direct_log_that_is_not_log_framed_is_contradicted() {
        let (role, confirmation) = confirm_role(
            Some(&ReportMemberRole::DirectLog),
            &MemberContentKind::Json,
        );
        assert_eq!(role, ReportMemberRole::Unclassified);
        assert_eq!(confirmation, RoleConfirmation::Contradicted);
    }

    #[test]
    fn a_declared_auth_role_is_never_promoted_to_confirmed() {
        let (role, confirmation) = confirm_role(
            Some(&ReportMemberRole::AuthEvidence),
            &MemberContentKind::Json,
        );
        assert_eq!(role, ReportMemberRole::Unclassified);
        assert_eq!(confirmation, RoleConfirmation::DeclaredUnconfirmed);
    }

    #[test]
    fn an_undeclared_log_framed_member_is_confirmed_from_content_alone() {
        let (role, confirmation) = confirm_role(None, &MemberContentKind::PlainTextLog);
        assert_eq!(role, ReportMemberRole::DirectLog);
        assert_eq!(confirmation, RoleConfirmation::ContentConfirmed);
    }

    #[test]
    fn a_failure_excerpt_is_bounded_and_control_free() {
        let excerpt = failure_excerpt(&format!("bad\u{7}json {}", "x".repeat(500)));
        assert!(excerpt.chars().count() <= FAILURE_EXCERPT_CHARS);
        assert!(!excerpt.chars().any(|c| c.is_control() && c != '\t'));
    }
}
