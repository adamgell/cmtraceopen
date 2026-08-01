//! Deterministic redacted export projection.
//!
//! The projection is a parallel value, never a mutation: the caller keeps its
//! detailed snapshot and gets back something safe to attach to a support
//! ticket.
//!
//! Most of the privacy work was done by the snapshot's *shape* rather than
//! here. [`ClassifiedMember`] carries no member content, so there is no member
//! body to scrub. What is left is free text — member paths, the sanitized
//! source path, importer detail strings, finding summaries, and the bounded
//! excerpt kept from a member that failed to parse — and that is exactly where
//! identity, tenant, certificate, and network values end up.
//!
//! The projection is idempotent: `[redacted-*]` markers contain no character
//! any pattern here matches, so a second pass is a no-op.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::evidence::IntuneSensitivity;

use super::models::{ClassifiedMember, DiagnosticReportSnapshot};

const REDACTED_EMAIL: &str = "[redacted-upn]";
const REDACTED_GUID: &str = "[redacted-guid]";
const REDACTED_URL: &str = "[redacted-url]";
const REDACTED_PATH: &str = "[redacted-path]";
const REDACTED_ADDRESS: &str = "[redacted-address]";
const REDACTED_DIGEST: &str = "[redacted-digest]";
const REDACTED_SECRET: &str = "[redacted-secret]";
const REDACTED_EXCERPT: &str = "[redacted-excerpt]";

/// Longest input this scrubber will process.
///
/// A pathological member path or detail string should not turn the export into
/// a backtracking workload. Anything longer is replaced wholesale, which is the
/// conservative outcome.
const MAX_REDACTION_INPUT_BYTES: usize = 64 * 1024;

fn url_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s,;)\]}'\x22]+")
            .expect("URL redaction pattern must compile")
    })
}

fn email_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b")
            .expect("email redaction pattern must compile")
    })
}

fn guid_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("GUID redaction pattern must compile")
    })
}

/// Value shape a labelled secret may take.
///
/// Brackets and braces are excluded so an already-redacted `[redacted-secret]`
/// cannot match: the value would have to start at `[`, and with nothing left to
/// consume the whole pattern fails. That is what makes a second pass a no-op
/// rather than producing `[redacted-secret]]`.
const SECRET_VALUE_PATTERN: &str = r#"[^\s,;"'()\[\]{}]+"#;

/// Labelled secrets: `token=…`, `serialNumber: …`, `client_secret=…`.
///
/// Labelled rather than shape-based because a bare alphanumeric run is
/// indistinguishable from a version string or a member name, and redacting
/// every such run would empty the export of everything useful.
///
/// The separator must be `=` or `:`. Accepting bare whitespace as well turned
/// ordinary prose into a false positive — "member is password protected"
/// redacted the word "protected" — which is both useless and, because the
/// marker then sat mid-sentence, the source of a non-idempotent second pass.
/// Bearer tokens, which really are whitespace separated, have their own pattern.
fn labelled_secret_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?P<label>\b(?:authorization|password|passwd|pwd|client[_\-]?secret|secret|api[_\-]?key|access[_\-]?token|refresh[_\-]?token|id[_\-]?token|token|tenant[_\-]?id|device[_\-]?id|serial(?:[_\-]?number)?|udid|imei|hardware[_\-]?hash)\b["']?\s*[=:]\s*)(?P<value>{SECRET_VALUE_PATTERN})"#
        ))
        .expect("labelled secret redaction pattern must compile")
    })
}

/// `Authorization: Bearer …` and bare `Bearer …`, which are whitespace separated.
fn bearer_token_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?P<label>\bbearer\s+)(?P<value>{SECRET_VALUE_PATTERN})"#
        ))
        .expect("bearer token redaction pattern must compile")
    })
}

/// Long hex runs: certificate thumbprints, hashes, opaque token fragments.
fn digest_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{32,}\b").expect("digest redaction pattern must compile")
    })
}

fn ipv4_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("IPv4 redaction pattern must compile")
    })
}

/// POSIX absolute paths, which on macOS are the main filesystem-layout leak.
///
/// The leading boundary is captured and written back rather than matched with a
/// look-behind, which the `regex` crate does not support. Capturing it also
/// keeps two space-separated paths from merging into one match.
fn posix_path_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?P<pre>^|[\s,;:="'(\[])(?P<path>/[A-Za-z0-9._\-]+(?:/[^\s,;="')\]]*)+)"#,
        )
        .expect("POSIX path redaction pattern must compile")
    })
}

/// Scrub one free-text value.
///
/// Order matters. URLs are matched first because a URL contains a path and a
/// host that the later patterns would shred into fragments; labelled secrets
/// come before the shape-based patterns so `serialNumber=ABC123` is caught even
/// though `ABC123` matches nothing on its own.
pub fn redact_text(value: &str) -> String {
    if value.len() > MAX_REDACTION_INPUT_BYTES {
        return REDACTED_SECRET.to_owned();
    }
    let value = url_pattern().replace_all(value, REDACTED_URL);
    // Bearer first. In `Authorization: Bearer <token>` the labelled pattern
    // would otherwise consume the word `Bearer` as authorization's value and
    // leave the token itself in the clear.
    let value = bearer_token_pattern().replace_all(&value, mask_value);
    let value = labelled_secret_pattern().replace_all(&value, mask_value);
    let value = email_pattern().replace_all(&value, REDACTED_EMAIL);
    let value = guid_pattern().replace_all(&value, REDACTED_GUID);
    let value = digest_pattern().replace_all(&value, REDACTED_DIGEST);
    let value = ipv4_pattern().replace_all(&value, REDACTED_ADDRESS);
    posix_path_pattern()
        .replace_all(&value, format!("${{pre}}{REDACTED_PATH}").as_str())
        .into_owned()
}

/// Keep the label, replace the value.
fn mask_value(caps: &regex::Captures<'_>) -> String {
    format!("{}{REDACTED_SECRET}", &caps["label"])
}

/// Return a redacted copy of `snapshot`, leaving the input untouched.
///
/// Every free-text field is scrubbed, and the parse-failure excerpt is dropped
/// entirely rather than scrubbed: it is raw member bytes, so no pattern set is
/// a strong enough guarantee for it.
pub fn redacted_diagnostic_report_export(
    snapshot: &DiagnosticReportSnapshot,
) -> DiagnosticReportSnapshot {
    let mut safe = snapshot.clone();

    safe.report.sanitized_source_path = safe
        .report
        .sanitized_source_path
        .as_deref()
        .map(redact_text);
    safe.report.extraction_detail = safe.report.extraction_detail.as_deref().map(redact_text);
    safe.report.declared_app_version = safe
        .report
        .declared_app_version
        .as_deref()
        .map(redact_text);
    safe.report.declared_report_schema = safe
        .report
        .declared_report_schema
        .as_deref()
        .map(redact_text);

    for member in &mut safe.members {
        redact_member(member);
    }

    for fact in &mut safe.facts {
        if fact.context.sensitivity != IntuneSensitivity::Public {
            fact.fact.value = redact_text(&fact.fact.value);
        }
    }

    for coverage in std::iter::once(&mut safe.report_coverage).chain(safe.coverage.iter_mut()) {
        coverage.detail = coverage.detail.as_deref().map(redact_text);
    }

    for finding in &mut safe.findings {
        finding.title = redact_text(&finding.title);
        finding.summary = redact_text(&finding.summary);
        finding.recommended_checks = finding
            .recommended_checks
            .iter()
            .map(|check| redact_text(check))
            .collect();
    }

    safe
}

fn redact_member(member: &mut ClassifiedMember) {
    member.member_path = redact_text(&member.member_path);
    member.detail = member.detail.as_deref().map(redact_text);
    member.failure_excerpt = member
        .failure_excerpt
        .as_ref()
        .map(|_| REDACTED_EXCERPT.to_owned());
    member.context.provenance.file_path = member
        .context
        .provenance
        .file_path
        .as_deref()
        .map(redact_text);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_tenant_network_and_certificate_values_are_scrubbed() {
        let input = concat!(
            "user synthetic.user@example.invalid tenant ",
            "11111111-2222-3333-4444-555555555555 at https://login.example.invalid/x?y=1 ",
            "from 203.0.113.7 thumbprint ",
            "0123456789abcdef0123456789abcdef01234567 serialNumber=SYNTHSERIAL1 ",
            "path /Library/Application Support/Portal/state.json",
        );
        let redacted = redact_text(input);

        for leaked in [
            "synthetic.user@example.invalid",
            "11111111-2222-3333-4444-555555555555",
            "login.example.invalid",
            "203.0.113.7",
            "0123456789abcdef0123456789abcdef01234567",
            "SYNTHSERIAL1",
            "/Library/Application",
        ] {
            assert!(
                !redacted.contains(leaked),
                "{leaked:?} survived redaction in {redacted:?}"
            );
        }
    }

    #[test]
    fn bearer_tokens_are_scrubbed_even_though_they_are_whitespace_separated() {
        assert!(!redact_text("Authorization: Bearer abc.def.ghi").contains("abc.def.ghi"));
    }

    #[test]
    fn ordinary_prose_containing_a_secret_label_is_left_alone() {
        // "password protected" is a description, not a credential. Redacting
        // the following word was both useless and, because the marker then sat
        // mid-sentence, the cause of a non-idempotent second pass.
        assert_eq!(
            redact_text("member is password protected and was not decrypted"),
            "member is password protected and was not decrypted"
        );
    }

    #[test]
    fn redaction_is_idempotent() {
        for input in [
            "tenant 11111111-2222-3333-4444-555555555555 at /var/log/x.log",
            "member is password protected and was not decrypted",
            "serialNumber=SYNTHSERIAL1 thumbprint=0123456789abcdef0123456789abcdef01234567",
            "Authorization: Bearer abc.def.ghi",
            "user synthetic.user@example.invalid at https://host.example.invalid/a?b=1",
        ] {
            let once = redact_text(input);
            assert_eq!(redact_text(&once), once, "second pass changed {input:?}");
        }
    }

    #[test]
    fn oversized_input_is_replaced_wholesale() {
        let huge = "a".repeat(MAX_REDACTION_INPUT_BYTES + 1);
        assert_eq!(redact_text(&huge), REDACTED_SECRET);
    }
}
