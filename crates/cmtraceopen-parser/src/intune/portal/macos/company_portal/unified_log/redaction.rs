//! Deterministic privacy projection for Company Portal unified-log evidence.
//!
//! Unified-log messages quote UPNs, device serials, service URLs with tokens in
//! the query string, and home-directory paths. This projection masks those spans
//! while leaving the diagnostic grammar intact — levels, subsystems, categories,
//! activity and signpost identifiers, and the correlation keys the analyzer
//! already extracted into typed fields. Removing those would destroy the very
//! relationships an export exists to show.
//!
//! Masking is a pure function of the masked text, so the same input always
//! produces the same token and two records that mentioned the same user still
//! visibly mention the same user. The projection is idempotent: a replacement
//! token cannot itself match a rule.
//!
//! Note the ordering guarantee this relies on. Correlation keys are extracted by
//! the reducer *before* export, so masking a URL query string here cannot lose a
//! request identifier the analysis already keyed on.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::evidence::{IntuneNamedValue, IntuneSensitivity};

use super::models::{UnifiedLogAnalysis, UnifiedLogObservation};

/// FNV-1a. Stable across runs and platforms, which `DefaultHasher` is not.
fn stable_token(kind: &str, value: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("[{kind}:{hash:016x}]")
}

/// True when a value is already one of this module's replacement tokens.
fn is_masked(value: &str) -> bool {
    value.starts_with('[') && value.ends_with(']') && value.contains(':')
}

fn upn_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("UPN regex must compile")
    })
}

/// The profile segment of a POSIX home path.
///
/// The leading `[` exclusion is what makes the projection idempotent: an
/// already-masked `[user:...]` segment must not be masked again. The segment is
/// bounded by the path separator, a quote, or the end of the line rather than by
/// whitespace, because macOS permits spaces in a home-directory name.
fn home_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)(?P<prefix>/Users/)(?P<user>[^/\r\n\x22\[][^/\r\n\x22]*)")
            .expect("home path regex must compile")
    })
}

/// A credential supplied after a label, in a header or a query parameter.
///
/// The `authorization: <scheme>` alternative has to come first. Without it the
/// bare `authorization` alternative matched `Authorization: Bearer <token>` and
/// masked the *scheme* — leaving the token itself in the export.
fn secret_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<label>\b(?:authorization\s*[:=]\s*(?:bearer|basic|negotiate)|bearer|access[_-]?token|id[_-]?token|refresh[_-]?token|client[_-]?secret|password|authorization)\b\s*[:= ]\s*)(?P<value>[^\s&\r\n\x22]+)",
        )
        .expect("secret regex must compile")
    })
}

/// A hardware identifier supplied after a label.
fn hardware_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<label>\b(?:serial(?:[ _-]?number)?|udid|imei|hardware[ _-]?uuid)\b\s*[:=]\s*)(?P<value>[^\s,;\r\n\x22]+)",
        )
        .expect("hardware id regex must compile")
    })
}

/// A URL query string, masked whole.
///
/// Individual parameter names are not preserved: Company Portal service URLs
/// carry tenant and user identifiers under names that vary by endpoint, and an
/// allowlist of safe parameters would be wrong the first time a new one appears.
fn query_string_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?P<prefix>https?://[^\s\x22]*?)\?(?P<query>[^\s\x22]+)")
            .expect("query string regex must compile")
    })
}

/// Mask the sensitive spans inside a free-text value.
pub fn redact_text(value: &str) -> String {
    let masked = upn_re().replace_all(value, |caps: &regex::Captures<'_>| {
        stable_token("upn", &caps[0])
    });

    let masked = home_path_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        // Trailing whitespace is not part of the profile name; keeping it out of
        // the hashed value means the same user resolves to the same token
        // whether or not the path was padded.
        let user = caps["user"].trim_end();
        let trailing = &caps["user"][user.len()..];
        format!("{}{}{}", &caps["prefix"], stable_token("user", user), trailing)
    });

    let masked = query_string_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        let query = &caps["query"];
        if is_masked(query) {
            return format!("{}?{}", &caps["prefix"], query);
        }
        format!("{}?{}", &caps["prefix"], stable_token("query", query))
    });

    let masked = secret_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        let value = &caps["value"];
        if is_masked(value) {
            return format!("{}{}", &caps["label"], value);
        }
        format!("{}{}", &caps["label"], stable_token("secret", value))
    });

    hardware_id_re()
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            let value = &caps["value"];
            if is_masked(value) {
                return format!("{}{}", &caps["label"], value);
            }
            format!("{}{}", &caps["label"], stable_token("hardware", value))
        })
        .into_owned()
}

fn redact_named(named: &IntuneNamedValue) -> IntuneNamedValue {
    IntuneNamedValue {
        name: named.name.clone(),
        value: redact_text(&named.value),
    }
}

fn redact_observation(observation: &UnifiedLogObservation) -> UnifiedLogObservation {
    if observation.context.sensitivity == IntuneSensitivity::Public {
        return observation.clone();
    }
    UnifiedLogObservation {
        message: observation.message.as_deref().map(redact_text),
        sender_image_path: observation.sender_image_path.as_deref().map(redact_text),
        named_data: observation.named_data.iter().map(redact_named).collect(),
        ..observation.clone()
    }
}

/// Project an analysis into its default-safe export form.
///
/// Everything an activity or a correlation is keyed on survives. Only
/// classified-sensitive free text is masked. Findings are not rewritten: their
/// summaries are built from workflow labels and counts, never from message text.
pub fn redacted_export_projection(analysis: &UnifiedLogAnalysis) -> UnifiedLogAnalysis {
    UnifiedLogAnalysis {
        observations: analysis
            .observations
            .iter()
            .map(redact_observation)
            .collect(),
        ..analysis.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_upn_is_masked_deterministically() {
        let first = redact_text("signed in as adele.vance@contoso.example");
        let second = redact_text("token refreshed for adele.vance@contoso.example");
        assert!(!first.contains("adele.vance"));
        let token = first.split_whitespace().next_back().unwrap();
        assert!(second.contains(token), "the same UPN must yield one token");
    }

    #[test]
    fn different_users_get_different_tokens() {
        assert_ne!(
            redact_text("adele.vance@contoso.example"),
            redact_text("alex.wilber@contoso.example")
        );
    }

    #[test]
    fn a_home_directory_name_is_masked_but_the_path_shape_survives() {
        let redacted = redact_text("/Users/adele.vance/Library/Logs/Company Portal.log");
        assert!(!redacted.contains("adele.vance"), "got {redacted:?}");
        assert!(redacted.starts_with("/Users/"));
        assert!(redacted.ends_with("/Library/Logs/Company Portal.log"));
    }

    #[test]
    fn a_home_directory_name_containing_a_space_is_fully_masked() {
        let redacted = redact_text("/Users/John Doe/Library/Logs/a.log");
        assert!(!redacted.contains("John"), "got {redacted:?}");
        assert!(!redacted.contains("Doe"), "got {redacted:?}");
        assert!(redacted.ends_with("/Library/Logs/a.log"));
    }

    #[test]
    fn a_bearer_token_is_masked_not_its_scheme() {
        // Regression: the bare `authorization` alternative used to consume
        // "Bearer" as the value and leave the token in the export.
        let redacted = redact_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiJ9"), "got {redacted:?}");
        assert!(redacted.contains("Bearer"), "got {redacted:?}");
    }

    #[test]
    fn a_scheme_less_bearer_token_is_still_masked() {
        let redacted = redact_text("retrying with bearer abc.def.ghi");
        assert!(!redacted.contains("abc.def.ghi"), "got {redacted:?}");
    }

    #[test]
    fn a_device_serial_is_masked() {
        let redacted = redact_text("enrolling serialNumber=C02ABCDEFGHI");
        assert!(!redacted.contains("C02ABCDEFGHI"), "got {redacted:?}");
        assert!(redacted.contains("serialNumber="));
    }

    #[test]
    fn a_url_query_string_is_masked_but_the_endpoint_survives() {
        let redacted =
            redact_text("GET https://manage.microsoft.example/checkin?upn=a%40b.example&tid=9");
        assert!(!redacted.contains("upn="), "got {redacted:?}");
        assert!(redacted.contains("https://manage.microsoft.example/checkin?"));
    }

    #[test]
    fn activity_and_signpost_identifiers_survive_redaction() {
        let redacted = redact_text("activity 8402315 signpost 991122 completed");
        assert!(redacted.contains("8402315"));
        assert!(redacted.contains("991122"));
    }

    #[test]
    fn a_correlation_guid_survives_redaction() {
        let guid = "9f2c1c8a-0001-4f2b-9a11-aabbccddeeff";
        let redacted = redact_text(&format!("client-request-id: {guid}"));
        assert!(redacted.contains(guid), "correlation keys must not be lost");
    }

    #[test]
    fn the_projection_is_idempotent() {
        let source = "adele.vance@contoso.example opened /Users/adele.vance/Library/Logs/a.log \
                      via https://manage.microsoft.example/x?tid=9 with Bearer abc.def \
                      serialNumber=C02ABCDEFGHI";
        let once = redact_text(source);
        assert_eq!(once, redact_text(&once));
    }

    #[test]
    fn an_apple_masked_value_is_left_alone() {
        // Apple's own <private> marker is not something to re-mask.
        let redacted = redact_text("signed in as <private>");
        assert_eq!(redacted, "signed in as <private>");
    }
}
