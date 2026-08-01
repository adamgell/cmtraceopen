//! Redaction of Console message text for export.
//!
//! The snapshot keeps messages as captured: an administrator reading their own
//! device's log is entitled to what it says, and pre-redacting the in-memory
//! model would make the viewer useless. Everything that *leaves* the process
//! goes through [`redacted_export_projection`] instead.
//!
//! Masked values are replaced by a stable per-analysis token rather than a
//! constant. `[redacted:guid#2]` appearing in four records still proves those
//! four records concern the same identifier, which is most of why the identifier
//! was worth reading, while carrying none of its bits.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use super::models::{
    ConsoleDiagnosticsSnapshot, ConsoleRedaction, ConsoleRedactionKind,
};
use crate::intune::evidence::IntuneSensitivity;

/// Text with its identity and secret material masked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedText {
    pub text: String,
    /// How many values of each class were masked, in a stable order.
    pub redactions: Vec<ConsoleRedaction>,
}

/// `-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----`, including the
/// inline single-line form a log message usually carries.
fn certificate_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----")
            .expect("certificate pattern is valid")
    })
}

/// Bearer tokens and named secret parameters.
fn secret_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:bearer\s+[A-Za-z0-9._~+/\-]{8,}={0,2}|(?:client_secret|access_token|refresh_token|id_token|password|pwd)\s*[=:]\s*[^\s,;)\]}]+)",
        )
        .expect("secret pattern is valid")
    })
}

/// Email addresses and user principal names.
fn upn_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("UPN pattern is valid")
    })
}

/// An http(s) URL, captured so the query and fragment can be dropped separately
/// from the endpoint.
///
/// The endpoint is diagnostic (which service was called); the query carries the
/// identifiers and tokens.
fn url_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?P<endpoint>https?://[^\s?#]*)(?P<tail>[?#][^\s]*)?")
            .expect("URL pattern is valid")
    })
}

/// Filesystem paths that identify a person or a device container.
fn file_path_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:/private)?/(?:var/mobile|var/containers|var/db|Users)/[^\s,;)\]}\x22]*")
            .expect("file path pattern is valid")
    })
}

fn guid_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
            .expect("GUID pattern is valid")
    })
}

/// Apple device identifiers: the 40-hex legacy UDID and the modern
/// `00008030-001C2D8A0EF8802E` form.
fn device_identifier_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:[0-9a-fA-F]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})\b")
            .expect("device identifier pattern is valid")
    })
}

/// Assigns each distinct masked value a stable ordinal for one analysis.
#[derive(Debug, Default)]
pub struct RedactionLedger {
    tokens: BTreeMap<(ConsoleRedactionKind, String), u32>,
    issued: BTreeMap<ConsoleRedactionKind, u32>,
}

impl RedactionLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// The token standing in for `original`, allocating one on first sight.
    fn token(&mut self, kind: ConsoleRedactionKind, original: &str) -> String {
        let Self { tokens, issued } = self;
        let ordinal = *tokens
            .entry((kind, original.to_owned()))
            .or_insert_with(|| {
                let next = issued.entry(kind).or_insert(0);
                *next += 1;
                *next
            });
        format!("[redacted:{}#{ordinal}]", label(kind))
    }
}

fn label(kind: ConsoleRedactionKind) -> &'static str {
    match kind {
        ConsoleRedactionKind::Upn => "upn",
        ConsoleRedactionKind::Secret => "secret",
        ConsoleRedactionKind::Guid => "guid",
        ConsoleRedactionKind::DeviceIdentifier => "deviceId",
        ConsoleRedactionKind::Url => "query",
        ConsoleRedactionKind::FilePath => "path",
        ConsoleRedactionKind::Certificate => "certificate",
    }
}

/// Mask identity and secret material in `text` using a fresh ledger.
///
/// Use [`redacted_export_projection`] for a whole snapshot: a shared ledger is
/// what makes the same identifier carry the same token across records.
pub fn redact_text(text: &str) -> RedactedText {
    let mut ledger = RedactionLedger::new();
    redact_with(text, &mut ledger)
}

/// Mask identity and secret material in `text`, sharing `ledger` across calls.
///
/// Ordering is deliberate: certificates and secrets first, so their contents are
/// never re-scanned as a UPN or a GUID; then endpoints, whose query strings are
/// dropped wholesale; then the identifiers that survive in free text.
pub fn redact_with(text: &str, ledger: &mut RedactionLedger) -> RedactedText {
    let mut counts: BTreeMap<ConsoleRedactionKind, u32> = BTreeMap::new();
    let mut current = text.to_owned();

    for (kind, pattern) in [
        (ConsoleRedactionKind::Certificate, certificate_pattern()),
        (ConsoleRedactionKind::Secret, secret_pattern()),
        (ConsoleRedactionKind::Upn, upn_pattern()),
    ] {
        current = pattern
            .replace_all(&current, |captures: &regex::Captures| {
                *counts.entry(kind).or_insert(0) += 1;
                ledger.token(kind, &captures[0])
            })
            .into_owned();
    }

    current = url_pattern()
        .replace_all(&current, |captures: &regex::Captures| {
            let endpoint = captures
                .name("endpoint")
                .map(|value| value.as_str())
                .unwrap_or_default()
                .to_owned();
            match captures.name("tail") {
                Some(tail) => {
                    *counts.entry(ConsoleRedactionKind::Url).or_insert(0) += 1;
                    let token = ledger.token(ConsoleRedactionKind::Url, tail.as_str());
                    format!("{endpoint}?{token}")
                }
                // A bare endpoint carries no identifiers, so it survives intact:
                // knowing which service was called is most of the diagnostic
                // value and none of the exposure.
                None => endpoint,
            }
        })
        .into_owned();

    for (kind, pattern) in [
        (ConsoleRedactionKind::FilePath, file_path_pattern()),
        (ConsoleRedactionKind::DeviceIdentifier, device_identifier_pattern()),
        (ConsoleRedactionKind::Guid, guid_pattern()),
    ] {
        current = pattern
            .replace_all(&current, |captures: &regex::Captures| {
                *counts.entry(kind).or_insert(0) += 1;
                ledger.token(kind, &captures[0])
            })
            .into_owned();
    }

    RedactedText {
        text: current,
        redactions: counts
            .into_iter()
            .map(|(kind, count)| ConsoleRedaction { kind, count })
            .collect(),
    }
}

/// The privacy class of a message, decided without modifying it.
///
/// Used to stamp each observation's `sensitivity` so a caller can filter before
/// ever rendering the text.
pub(super) fn classify_sensitivity(text: &str) -> IntuneSensitivity {
    if certificate_pattern().is_match(text) || secret_pattern().is_match(text) {
        return IntuneSensitivity::Restricted;
    }
    if upn_pattern().is_match(text)
        || file_path_pattern().is_match(text)
        || device_identifier_pattern().is_match(text)
        || guid_pattern().is_match(text)
        || url_pattern()
            .captures_iter(text)
            .any(|captures| captures.name("tail").is_some())
    {
        return IntuneSensitivity::Sensitive;
    }
    IntuneSensitivity::Public
}

/// A serialized snapshot with every message and path masked.
///
/// This is the only form that may be written to disk, attached to a ticket, or
/// sent anywhere. One ledger spans the whole snapshot, so a repeated identifier
/// keeps one token throughout and cross-record correlation survives redaction.
pub fn redacted_export_projection(snapshot: &ConsoleDiagnosticsSnapshot) -> Value {
    // Every type in the snapshot derives `Serialize` over plain data, so this
    // cannot fail. Falling back to an empty document would turn that impossible
    // case into an export that silently claims there was nothing to report.
    let mut document = serde_json::to_value(snapshot).expect("console snapshot serializes");
    let mut ledger = RedactionLedger::new();

    if let Some(artifacts) = document
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
    {
        for artifact in artifacts.iter_mut() {
            redact_string_field(artifact, "filePath", &mut ledger);
        }
    }

    if let Some(records) = document.get_mut("records").and_then(Value::as_array_mut) {
        for record in records.iter_mut() {
            let redactions = match record.get("message").and_then(Value::as_str) {
                Some(message) => {
                    let masked = redact_with(message, &mut ledger);
                    let redactions = serde_json::to_value(&masked.redactions)
                        .expect("redaction counts serialize");
                    if let Some(object) = record.as_object_mut() {
                        object.insert("message".to_owned(), Value::String(masked.text));
                    }
                    redactions
                }
                None => Value::Array(Vec::new()),
            };
            if let Some(object) = record.as_object_mut() {
                object.insert("redactions".to_owned(), redactions);
            }
            if let Some(provenance) = record
                .get_mut("context")
                .and_then(|context| context.get_mut("provenance"))
            {
                redact_string_field(provenance, "filePath", &mut ledger);
            }
            for unmodeled in record
                .get_mut("unmodeledColumns")
                .and_then(Value::as_array_mut)
                .into_iter()
                .flatten()
            {
                redact_string_field(unmodeled, "value", &mut ledger);
            }
        }
    }

    document
}

fn redact_string_field(target: &mut Value, field: &str, ledger: &mut RedactionLedger) {
    let Some(current) = target.get(field).and_then(Value::as_str) else {
        return;
    };
    let masked = redact_with(current, ledger).text;
    if let Some(object) = target.as_object_mut() {
        object.insert(field.to_owned(), Value::String(masked));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_upn_is_masked() {
        let masked = redact_text("signed in as synthetic.user@contoso.invalid");
        assert_eq!(masked.text, "signed in as [redacted:upn#1]");
        assert_eq!(
            masked.redactions,
            vec![ConsoleRedaction {
                kind: ConsoleRedactionKind::Upn,
                count: 1
            }]
        );
    }

    #[test]
    fn the_same_value_keeps_one_token_across_calls() {
        // Correlation is the whole reason for a ledger: two records naming the
        // same tenant must still be visibly about the same tenant.
        let mut ledger = RedactionLedger::new();
        let guid = "11111111-2222-4333-8444-555555555555";
        let first = redact_with(&format!("tenant {guid}"), &mut ledger);
        let second = redact_with(&format!("still tenant {guid}"), &mut ledger);
        assert!(first.text.ends_with("[redacted:guid#1]"));
        assert!(second.text.ends_with("[redacted:guid#1]"));
    }

    #[test]
    fn distinct_values_get_distinct_tokens() {
        let mut ledger = RedactionLedger::new();
        let text = redact_with(
            "a@one.invalid and b@two.invalid",
            &mut ledger,
        );
        assert_eq!(text.text, "[redacted:upn#1] and [redacted:upn#2]");
    }

    #[test]
    fn a_bearer_token_is_masked_before_anything_else_reads_it() {
        let masked = redact_text("Authorization header Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");
        assert!(masked.text.contains("[redacted:secret#1]"));
        assert!(!masked.text.contains("eyJhbGci"));
    }

    #[test]
    fn a_certificate_block_is_masked_whole() {
        let masked = redact_text(
            "cert -----BEGIN CERTIFICATE-----QUJDREVGRw==-----END CERTIFICATE----- done",
        );
        assert_eq!(masked.text, "cert [redacted:certificate#1] done");
    }

    #[test]
    fn an_endpoint_survives_while_its_query_does_not() {
        let masked = redact_text("GET https://example.invalid/api/devices?tenant=abc&user=d");
        assert_eq!(
            masked.text,
            "GET https://example.invalid/api/devices?[redacted:query#1]"
        );
    }

    #[test]
    fn a_bare_endpoint_is_left_alone() {
        let masked = redact_text("GET https://example.invalid/api/devices");
        assert_eq!(masked.text, "GET https://example.invalid/api/devices");
        assert!(masked.redactions.is_empty());
    }

    #[test]
    fn a_device_container_path_is_masked() {
        let masked = redact_text("wrote /var/mobile/Containers/Data/Application/log.txt");
        assert_eq!(masked.text, "wrote [redacted:path#1]");
    }

    #[test]
    fn a_device_identifier_is_masked_and_not_mistaken_for_a_guid() {
        let masked = redact_text("udid 00008030-001C2D8A0EF8802E");
        assert_eq!(masked.text, "udid [redacted:deviceId#1]");
    }

    #[test]
    fn sensitivity_separates_secrets_from_identifiers_from_plain_text() {
        assert_eq!(
            classify_sensitivity("Bearer abcdefghijkl"),
            IntuneSensitivity::Restricted
        );
        assert_eq!(
            classify_sensitivity("user synthetic@contoso.invalid"),
            IntuneSensitivity::Sensitive
        );
        assert_eq!(
            classify_sensitivity("warming caches"),
            IntuneSensitivity::Public
        );
    }
}
