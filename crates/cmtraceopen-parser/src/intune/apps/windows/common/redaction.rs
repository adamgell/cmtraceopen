//! Deterministic text masking shared by the Intune Windows analyzers.
//!
//! Platform scripts and remediations quote the same kinds of sensitive value --
//! UPNs, user profile paths, inline command lines and credential switches -- so
//! they mask them with one implementation rather than two that can drift apart.
//! Each analyzer still owns its own *projection*: which fields are classified
//! sensitive is a property of that analyzer's contract, not of this module.
//!
//! Masking is a pure function of the masked text, so the same input always
//! produces the same token and two records that mentioned the same user still
//! visibly mention the same user. The projection is idempotent: replacement
//! tokens cannot themselves match a rule.

use std::sync::OnceLock;

use regex::Regex;

/// FNV-1a. Stable across runs and platforms, which `DefaultHasher` is not.
fn stable_token(kind: &str, value: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("[{kind}:{:016x}]", hash)
}

fn upn_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("UPN regex must compile")
    })
}

/// The profile segment of a user path, in either slash direction.
///
/// The separator may be doubled. These logs embed JSON payloads, and a Windows
/// path inside one arrives JSON-escaped as `C:\\Users\\Someone`; requiring a
/// single separator let every such path through unmasked.
fn user_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // The segment is bounded by the path separator, a quote, or the end of
        // the line -- not by whitespace. Windows permits spaces in profile
        // directory names, and bounding on `\s` masked only the first word:
        // `C:\Users\John Doe\...` leaked "Doe" into the export.
        //
        // The leading `[` exclusion is what makes the projection idempotent:
        // an already-masked `[user:...]` segment must not be masked again.
        Regex::new(
            r"(?i)(?P<prefix>[\\/]{1,2}Users[\\/]{1,2})(?P<user>[^\\/\r\n\x22\[][^\\/\r\n\x22]*)",
        )
        .expect("user path regex must compile")
    })
}

/// A command line or credential value supplied inline after a flag.
///
/// Two properties matter here and both were bugs before:
///
/// * The value must stop at a line break rather than at the end of the string.
///   A CCM record is one *logical* record and routinely contains newlines (see
///   the `multiline-ccm-record` fixture). Anchoring on `$` meant a `-Command`
///   inside a multi-line record matched nothing at all and leaked in full.
/// * The flag vocabulary covers credential-bearing switches, not just
///   `-Command`. A launch record reading `-Password hunter2` is exactly as
///   sensitive as an inline command and was previously exported verbatim.
fn command_line_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<flag>-(?:Command|EncodedCommand|Password|Secret|ClientSecret|Token|AccessToken|ApiKey|Api[-_]?Key|Credential|Authorization)\s+)(?P<value>[^\r\n]+)",
        )
        .expect("command line regex must compile")
    })
}

/// Mask the sensitive spans inside a free-text value.
pub fn redact_text(value: &str) -> String {
    let masked = upn_re().replace_all(value, |caps: &regex::Captures<'_>| {
        stable_token("upn", &caps[0])
    });

    let masked = user_path_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        // Trailing whitespace is not part of the profile name; keeping it out
        // of the hashed value means `C:\Users\John Doe ` and `C:\Users\John Doe`
        // still resolve to the same user.
        let user = caps["user"].trim_end();
        let trailing = &caps["user"][user.len()..];
        format!(
            "{}{}{}",
            &caps["prefix"],
            stable_token("user", user),
            trailing
        )
    });

    command_line_re()
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            let value = caps["value"].trim_end();
            // Already masked: re-masking would hash the token and break
            // idempotence.
            if value.starts_with("[command:") && value.ends_with(']') {
                return format!("{}{}", &caps["flag"], value);
            }
            format!("{}{}", &caps["flag"], stable_token("command", value))
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::redact_text;

    #[test]
    fn a_json_escaped_windows_path_is_masked() {
        // These logs embed JSON payloads; a path inside one is escaped.
        let redacted = redact_text(r#"{"Path":"C:\\Users\\John Doe\\AppData\\Local"}"#);
        assert!(!redacted.contains("John"), "got {redacted:?}");
        assert!(!redacted.contains("Doe"), "got {redacted:?}");
        assert!(redacted.contains(r"AppData"), "got {redacted:?}");
    }

    #[test]
    fn a_json_escaped_path_mask_is_idempotent() {
        let once = redact_text(r#"{"Path":"C:\\Users\\John Doe\\AppData"}"#);
        assert_eq!(once, redact_text(&once));
    }

    #[test]
    fn a_single_separator_path_is_still_masked() {
        let redacted = redact_text(r"C:\Users\adele.vance\a.ps1");
        assert!(!redacted.contains("adele.vance"));
        assert!(redacted.ends_with(r"\a.ps1"));
    }
}
