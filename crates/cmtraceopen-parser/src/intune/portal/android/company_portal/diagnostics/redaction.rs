//! Deterministic redaction for Android Company Portal diagnostic exports.
//!
//! Microsoft states that the logs an Android user sends to a support team
//! include the user's email address, so identity is present by design. Every
//! rule here therefore runs by default rather than on request, and each one
//! replaces a match with a fixed marker so the same input always produces
//! byte-identical output.
//!
//! Rules are applied in a fixed order, most specific first, because an earlier
//! rule consuming a match changes what a later rule can see. URLs go first so
//! that a token in a query string is removed as part of its URL rather than
//! leaving a half-masked link behind.
//!
//! The dotted-identifier rule over-redacts on purpose. An Android package name
//! and a bare hostname are the same shape, and no cheap test separates them, so
//! both become [`PACKAGE_MARKER`]. Over-redacting a hostname is a cosmetic
//! loss; under-redacting a package name that identifies a line-of-business app
//! is a privacy failure, and only one of those is worth risking.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{
    AndroidDiagnosticMember, AndroidDiagnosticRecord, AndroidDiagnosticsSnapshot,
};
use crate::intune::evidence::IntuneNamedValue;

pub const URL_MARKER: &str = "[redacted:url]";
pub const EMAIL_MARKER: &str = "[redacted:email]";
pub const TOKEN_MARKER: &str = "[redacted:token]";
pub const GUID_MARKER: &str = "[redacted:guid]";
pub const DEVICE_ID_MARKER: &str = "[redacted:deviceId]";
pub const PACKAGE_MARKER: &str = "[redacted:package]";
pub const INCIDENT_MARKER: &str = "[redacted:incidentId]";

fn url_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>\\)\]}]+"#).expect("url pattern is valid")
    })
}

fn email_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
            .expect("email pattern is valid")
    })
}

/// A compact JSON web token: three base64url segments, the first starting `eyJ`.
fn jwt_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]+)?")
            .expect("jwt pattern is valid")
    })
}

/// `key=value` and `key: value` pairs whose key names a credential.
///
/// The value class excludes `[` so that a marker this module already inserted
/// cannot be re-consumed. Without that, a token masked by an earlier rule was
/// matched again here and came out with a stray bracket appended, which broke
/// idempotence in the one place it matters most.
fn credential_pair_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(access_token|refresh_token|id_token|session_token|auth|authorization|token|password|passwd|secret|apikey|api_key)(\s*[=:]\s*)[^\s,;&"'\[\]}]+"#,
        )
        .expect("credential pair pattern is valid")
    })
}

/// Identifier-shaped values: tenant, device, correlation, and incident GUIDs.
fn guid_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("guid pattern is valid")
    })
}

/// Hardware identifiers named outright, plus a bare 14-to-17 digit run, which
/// is the shape of an IMEI or MEID.
fn device_identifier_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(imei|meid|iccid|serial|serialnumber|serial_number|androidid|android_id)(\s*[=:]\s*)[A-Za-z0-9._-]+"#,
        )
        .expect("device identifier pattern is valid")
    })
}

fn bare_device_number_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\b\d{14,17}\b").expect("bare device number is valid"))
}

/// Reverse-DNS dotted identifiers: Android package names and the hostnames they
/// are indistinguishable from.
fn dotted_identifier_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\b[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,}\b")
            .expect("dotted identifier pattern is valid")
    })
}

/// Mask every sensitive shape in `text`.
///
/// Pure and total: the same input always yields the same output, and no rule
/// depends on locale, clock, or host state.
pub fn redact_text(text: &str) -> String {
    let masked = url_regex().replace_all(text, URL_MARKER);
    let masked = email_regex().replace_all(&masked, EMAIL_MARKER);
    // Named credentials before bare tokens. A `access_token = eyJ...` pair is
    // both, and letting the bare-token rule consume the value first left the
    // key/value rule to mask a marker a second time.
    let masked = credential_pair_regex().replace_all(&masked, format!("${{1}}${{2}}{TOKEN_MARKER}"));
    let masked = jwt_regex().replace_all(&masked, TOKEN_MARKER);
    let masked = guid_regex().replace_all(&masked, GUID_MARKER);
    let masked =
        device_identifier_regex().replace_all(&masked, format!("${{1}}${{2}}{DEVICE_ID_MARKER}"));
    let masked = bare_device_number_regex().replace_all(&masked, DEVICE_ID_MARKER);
    dotted_identifier_regex()
        .replace_all(&masked, PACKAGE_MARKER)
        .into_owned()
}

fn redact_option(value: &Option<String>) -> Option<String> {
    value.as_deref().map(redact_text)
}

fn redact_named_values(values: &[IntuneNamedValue]) -> Vec<IntuneNamedValue> {
    values
        .iter()
        .map(|entry| IntuneNamedValue {
            name: entry.name.clone(),
            value: redact_text(&entry.value),
        })
        .collect()
}

fn redact_member(member: &AndroidDiagnosticMember) -> AndroidDiagnosticMember {
    let mut redacted = member.clone();
    // Entry names are structure, but an Android bundle can name a member after
    // the package it came from, so they go through the same rules.
    redacted.entry_name = redact_text(&member.entry_name);
    redacted.sanitized_entry_path = redact_option(&member.sanitized_entry_path);
    redacted.context.provenance.file_path = redact_option(&member.context.provenance.file_path);
    redacted
}

fn redact_record(record: &AndroidDiagnosticRecord) -> AndroidDiagnosticRecord {
    let mut redacted = record.clone();
    redacted.message = redact_text(&record.message);
    redacted.fields = redact_named_values(&record.fields);
    redacted.context.provenance.file_path = redact_option(&record.context.provenance.file_path);
    redacted
}

/// A copy of `snapshot` safe to write to disk or attach to a ticket.
///
/// The unredacted snapshot stays in memory for an operator who is entitled to
/// see it; only this projection is meant to leave the process.
///
/// Findings are copied through untouched. They are built from counts and
/// vocabulary tokens only and never interpolate artifact content, an identity,
/// or a path, so there is nothing in them to mask. That is a property the
/// finding rules must preserve, and it is asserted in this leaf's tests.
pub fn redacted_export_projection(
    snapshot: &AndroidDiagnosticsSnapshot,
) -> AndroidDiagnosticsSnapshot {
    let mut projected = snapshot.clone();

    projected.metadata.incident_id = snapshot
        .metadata
        .incident_id
        .as_ref()
        .map(|_| INCIDENT_MARKER.to_owned());
    projected.metadata.app_version = redact_option(&snapshot.metadata.app_version);
    projected.metadata.declared_schema_token =
        redact_option(&snapshot.metadata.declared_schema_token);
    projected.metadata.supplied_extra = redact_named_values(&snapshot.metadata.supplied_extra);
    projected.metadata.supplied_context.provenance.file_path =
        redact_option(&snapshot.metadata.supplied_context.provenance.file_path);

    projected.members = snapshot.members.iter().map(redact_member).collect();
    projected.records = snapshot.records.iter().map(redact_record).collect();

    projected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_email_address_is_masked() {
        assert_eq!(
            redact_text("signed in as synthetic.user@fixture.example ok"),
            format!("signed in as {EMAIL_MARKER} ok")
        );
    }

    #[test]
    fn a_url_and_its_query_are_masked_as_one_unit() {
        assert_eq!(
            redact_text("GET https://synthetic.invalid/api?token=abc123 done"),
            format!("GET {URL_MARKER} done")
        );
    }

    #[test]
    fn a_guid_is_masked() {
        assert_eq!(
            redact_text("tenant 11111111-2222-4333-8444-555555555555 ready"),
            format!("tenant {GUID_MARKER} ready")
        );
    }

    #[test]
    fn a_compact_json_web_token_is_masked() {
        let masked = redact_text("value eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c2ln end");
        assert_eq!(masked, format!("value {TOKEN_MARKER} end"));
    }

    #[test]
    fn a_credential_pair_keeps_its_key_and_loses_its_value() {
        assert_eq!(
            redact_text("access_token=abc.def-ghi&next"),
            format!("access_token={TOKEN_MARKER}&next")
        );
        assert_eq!(
            redact_text("password: hunter2"),
            format!("password: {TOKEN_MARKER}")
        );
    }

    #[test]
    fn a_named_or_bare_hardware_identifier_is_masked() {
        assert_eq!(
            redact_text("imei=356938035643809"),
            format!("imei={DEVICE_ID_MARKER}")
        );
        assert_eq!(
            redact_text("device 356938035643809 seen"),
            format!("device {DEVICE_ID_MARKER} seen")
        );
    }

    #[test]
    fn a_package_name_is_masked() {
        assert_eq!(
            redact_text("launching com.synthetic.fixture.portal now"),
            format!("launching {PACKAGE_MARKER} now")
        );
    }

    #[test]
    fn a_two_segment_identifier_is_left_alone() {
        // `summary.txt` is structure, not identity. Masking it would make the
        // export unreadable without protecting anything.
        assert_eq!(redact_text("summary.txt"), "summary.txt");
    }

    #[test]
    fn a_named_credential_holding_a_token_is_masked_exactly_once() {
        // Regression: the bare-token rule masked the value, then the key/value
        // rule masked the marker again and appended a stray bracket.
        let masked =
            redact_text("access_token = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ln");
        assert_eq!(masked, format!("access_token = {TOKEN_MARKER}"));
        assert_eq!(redact_text(&masked), masked);
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = redact_text("user synthetic.user@fixture.example at https://synthetic.invalid/x");
        assert_eq!(redact_text(&once), once);
    }

    #[test]
    fn redaction_is_deterministic_across_repeated_calls() {
        let sample = "com.synthetic.fixture.portal 11111111-2222-4333-8444-555555555555";
        assert_eq!(redact_text(sample), redact_text(sample));
    }
}
