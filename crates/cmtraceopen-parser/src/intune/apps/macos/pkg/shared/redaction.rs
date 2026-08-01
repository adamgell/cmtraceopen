//! Deterministic privacy projection shared by both macOS app leaves.
//!
//! macOS agent records quote UPNs, home-directory paths, content URLs, and
//! script output. The export projection masks those spans and leaves the
//! diagnostic grammar — phases, exit codes, and the policy/app/run identifiers a
//! transaction is keyed on — intact, because removing those would destroy the
//! correlation the export exists to show.
//!
//! Masking is a pure function of the masked text, so the same input always
//! produces the same token and two records naming the same user still visibly
//! name the same user. The projection is idempotent: a replacement token cannot
//! itself match a rule.

use std::sync::OnceLock;

use regex::Regex;

/// FNV-1a. Stable across runs and platforms, which `DefaultHasher` is not.
fn stable_token(kind: &str, value: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("[{kind}:{hash:016x}]")
}

fn upn_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("UPN regex must compile")
    })
}

/// The profile segment of a macOS home path.
///
/// The segment is bounded by the path separator, a quote, or end of line rather
/// than by whitespace, because macOS account names routinely contain spaces and
/// bounding on `\s` would mask only the first word. The leading `[` exclusion is
/// what makes the projection idempotent: an already-masked `[user:…]` segment
/// must not be masked again.
fn home_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)(?P<prefix>/Users/)(?P<user>[^/\r\n\x22\[][^/\r\n\x22]*)")
            .expect("home path regex must compile")
    })
}

/// A content-delivery URL. The host and path together identify a tenant's
/// storage account, so the whole URL is masked rather than just its query.
fn url_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\bhttps?://[^\s\x22]+").expect("url regex must compile")
    })
}

/// A credential supplied inline after a flag, in either `--flag value` or
/// `--flag=value` form. The value stops at a line break, not at end of string:
/// captured script output is multi-line and anchoring on `$` leaked all but the
/// last line.
fn secret_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<flag>--?(?:password|secret|client[-_]?secret|token|access[-_]?token|api[-_]?key|credential|authorization)(?:\s+|=))(?P<value>[^\r\n]+)",
        )
        .expect("secret regex must compile")
    })
}

/// Mask every sensitive span inside a free-text value.
pub fn redact_text(value: &str) -> String {
    let masked = upn_re().replace_all(value, |caps: &regex::Captures<'_>| {
        stable_token("upn", &caps[0])
    });

    let masked = home_path_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        // Trailing whitespace is not part of the account name, so keeping it out
        // of the hashed value means `/Users/Jo Smith ` and `/Users/Jo Smith`
        // still resolve to the same user.
        let user = caps["user"].trim_end();
        let trailing = &caps["user"][user.len()..];
        format!("{}{}{}", &caps["prefix"], stable_token("user", user), trailing)
    });

    let masked = url_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        stable_token("url", &caps[0])
    });

    secret_re()
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            format!("{}{}", &caps["flag"], stable_token("secret", &caps["value"]))
        })
        .into_owned()
}

/// Replace a free-text label with a stable, non-identifying token.
///
/// App and script display names are tenant catalog and configuration data. No
/// pattern rule can decide which part of an arbitrary product name is safe, so
/// the whole value is replaced. The token is stable, so two records naming the
/// same app still visibly name the same app.
pub fn redact_label(value: &str) -> String {
    // Idempotence: an already-masked label must not be masked again, or the
    // token changes on every export and correlation is lost.
    if value.starts_with("[label:") {
        return value.to_owned();
    }
    stable_token("label", value)
}

/// Mask a value that is script output or another arbitrary payload.
///
/// Output is never exported verbatim: it is arbitrary text under an
/// administrator's control and routinely contains credentials the redaction
/// rules above cannot recognize. Only its size and a stable identity survive.
pub fn redact_payload(value: &str) -> String {
    format!(
        "{} ({} bytes withheld)",
        stable_token("payload", value),
        value.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_upn_is_masked_but_stays_correlatable() {
        let once = redact_text("run as person@contoso.example");
        let twice = redact_text("also person@contoso.example");
        assert!(!once.contains("person@contoso.example"));
        let token = once.split_whitespace().last().expect("token present");
        assert!(twice.contains(token), "the same identity must mask alike");
    }

    #[test]
    fn a_home_path_masks_only_the_account_segment() {
        let masked = redact_text("/Users/Jo Smith/Library/Logs/x.log");
        assert!(masked.starts_with("/Users/[user:"));
        assert!(masked.ends_with("/Library/Logs/x.log"));
        assert!(!masked.contains("Jo Smith"));
    }

    #[test]
    fn masking_is_idempotent() {
        let once = redact_text("/Users/jo/Library https://cdn.example/pkg person@corp.example");
        assert_eq!(redact_text(&once), once);
    }

    #[test]
    fn a_content_url_is_masked_whole() {
        let masked = redact_text("Downloading from https://cdn.contoso.example/a/b?sig=abc");
        assert!(!masked.contains("cdn.contoso.example"));
        assert!(!masked.contains("sig=abc"));
    }

    #[test]
    fn an_inline_secret_is_masked_in_both_flag_forms() {
        for sample in ["--password hunter2", "--api-key=hunter2"] {
            let masked = redact_text(sample);
            assert!(!masked.contains("hunter2"), "{sample} leaked");
        }
    }

    #[test]
    fn a_label_is_replaced_wholesale_but_stays_correlatable() {
        let once = redact_label("Contoso Onboarding Helper");
        assert!(!once.contains("Contoso"));
        assert_eq!(once, redact_label("Contoso Onboarding Helper"));
        // Idempotent: masking a masked label must not change it.
        assert_eq!(redact_label(&once), once);
        assert_ne!(once, redact_label("Some Other App"));
    }

    #[test]
    fn payload_redaction_withholds_content_but_keeps_size() {
        let masked = redact_payload("secret output\nline two");
        assert!(!masked.contains("secret output"));
        assert!(masked.contains("22 bytes withheld"));
    }
}
