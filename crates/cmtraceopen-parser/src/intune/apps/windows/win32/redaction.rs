//! Deterministic privacy projection for Win32 app deployment evidence.
//!
//! Win32 records quote install command lines, UPNs, user profile paths, and the
//! account an enforcement ran as. The export projection masks those spans while
//! leaving the diagnostic grammar intact -- signals, phases, return codes, and
//! the app/deployment-type ids a transaction is keyed on -- because removing
//! those would destroy the correlation the export exists to show.
//!
//! Masking is a pure function of the masked text, so the same input always
//! produces the same token and two records that mentioned the same user still
//! visibly mention the same user. The projection is idempotent: a replacement
//! token cannot itself match a rule.
//!
//! Only values classified [`IntuneSensitivity::Sensitive`] are masked. A record
//! the analyzer marked public is exported verbatim.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::evidence::IntuneSensitivity;

use super::models::{Win32Analysis, Win32Observation, Win32Transaction};

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

/// The profile segment of a user path, in either slash direction.
///
/// The segment is bounded by the path separator, a quote, or the end of the
/// line, not by whitespace: Windows permits spaces in profile directory names,
/// and bounding on whitespace masks only the first word. The leading `[`
/// exclusion is what makes the projection idempotent, because an already-masked
/// segment must not be masked again.
fn user_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<prefix>[\\/](?:Users|Documents and Settings)[\\/])(?P<user>[^\\/\r\n\x22\[][^\\/\r\n\x22]*)",
        )
        .expect("user path regex must compile")
    })
}

/// A credential or command value supplied inline after a flag.
///
/// The value stops at a line break rather than at the end of the string: a CCM
/// record is one *logical* record and routinely contains newlines, so anchoring
/// on `$` would leak a secret inside a multi-line record entirely.
fn command_line_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // Two value shapes:
        //  - quoted: `-"..."` or `-'...'` — the value runs to the closing quote,
        //    so spaces inside a quoted secret stay masked.
        //  - unquoted: the value stops at the next whitespace-delimited token,
        //    so a trailing switch like `/quiet` or `-Log X` after the secret is
        //    preserved rather than swallowed into the masked span.
        // Either way the value stops at a line break: a CCM record is one
        // *logical* record and routinely contains newlines, so anchoring on `$`
        // would leak a secret inside a multi-line record entirely.
        Regex::new(
            r"(?i)(?P<flag>[-/](?:Command|EncodedCommand|Password|Secret|ClientSecret|Token|AccessToken|ApiKey|Api[-_]?Key|Credential|Authorization)[\s=:]+)(?P<value>\x22[^\x22\r\n]*\x22|'[^'\r\n]*'|[^\s\r\n]+)",
        )
        .expect("command line regex must compile")
    })
}

/// An account named in an explicit field.
///
/// `RunAsUser = CONTOSO\jsmith` carries an identity that neither the UPN rule
/// nor the path rule matches, and it is exactly the "raw execution context" the
/// output contract requires to be redacted by default.
fn account_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<field>\b(?:RunAsUser|UserName|UserPrincipalName|LoggedOnUser|Account|UserId|Upn)\s*[:=]\s*)(?P<value>[^\s,;\r\n]+)",
        )
        .expect("account field regex must compile")
    })
}

fn already_masked(value: &str, kind: &str) -> bool {
    value.starts_with(&format!("[{kind}:")) && value.ends_with(']')
}

/// Mask the sensitive spans inside a free-text value.
pub fn redact_text(value: &str) -> String {
    let masked = upn_re().replace_all(value, |caps: &regex::Captures<'_>| {
        stable_token("upn", &caps[0])
    });

    let masked = user_path_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        // Trailing whitespace is not part of the profile name; keeping it out of
        // the hashed value means `\Users\John Doe ` and `\Users\John Doe` still
        // resolve to the same user.
        let user = caps["user"].trim_end();
        let trailing = &caps["user"][user.len()..];
        format!(
            "{}{}{}",
            &caps["prefix"],
            stable_token("user", user),
            trailing
        )
    });

    let masked = account_field_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        let value = &caps["value"];
        if already_masked(value, "account") || already_masked(value, "upn") {
            return format!("{}{}", &caps["field"], value);
        }
        format!("{}{}", &caps["field"], stable_token("account", value))
    });

    command_line_re()
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            let value = caps["value"].trim_end();
            if already_masked(value, "command") {
                return format!("{}{}", &caps["flag"], value);
            }
            format!("{}{}", &caps["flag"], stable_token("command", value))
        })
        .into_owned()
}

fn redact_observation(observation: &Win32Observation) -> Win32Observation {
    if observation.context.sensitivity == IntuneSensitivity::Public {
        return observation.clone();
    }
    let mut redacted = observation.clone();
    redacted.message = redact_text(&observation.message);
    // The provenance path is where a profile name reaches the export even when
    // the record text itself is clean.
    redacted.context.provenance.file_path = observation
        .context
        .provenance
        .file_path
        .as_deref()
        .map(redact_text);
    redacted
}

/// Mask the log-derived free text a transaction carries.
///
/// Requirement names come from the record body and can quote a path, a UPN, or
/// a command line, so they go through [`redact_text`]. The correlation keys
/// (`app_id`, `deployment_type_id`, dependency app ids) are identifiers, not
/// free text, and masking them would break the cross-record correlation the
/// export exists to show; `next_evidence_request` is a static string with no
/// record content. Both stay verbatim.
fn redact_transaction(transaction: &Win32Transaction) -> Win32Transaction {
    let mut redacted = transaction.clone();
    redacted.failed_requirements = transaction
        .failed_requirements
        .iter()
        .map(|name| redact_text(name))
        .collect();
    redacted
}

/// Project an analysis into its default-safe export form.
///
/// Everything a transaction is keyed on survives. Only classified-sensitive text
/// is masked, so the projection can be applied before any export without
/// changing what the reduction concluded.
pub fn redacted_export_projection(analysis: &Win32Analysis) -> Win32Analysis {
    Win32Analysis {
        schema_version: analysis.schema_version,
        transactions: analysis
            .transactions
            .iter()
            .map(redact_transaction)
            .collect(),
        observations: analysis
            .observations
            .iter()
            .map(redact_observation)
            .collect(),
        unkeyed_observations: analysis.unkeyed_observations.clone(),
        coverage: analysis.coverage.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upn_is_masked_deterministically() {
        let first = redact_text("Enforcing for adele.vance@contoso.example");
        let second = redact_text("Reported for adele.vance@contoso.example");
        assert!(!first.contains("adele.vance"));
        let token = first.split_whitespace().last().expect("token");
        assert!(second.contains(token), "same UPN must yield the same token");
    }

    #[test]
    fn different_users_get_different_tokens() {
        assert_ne!(
            redact_text("adele.vance@contoso.example"),
            redact_text("alex.wilber@contoso.example")
        );
    }

    #[test]
    fn user_profile_segment_is_masked_but_the_path_shape_survives() {
        let redacted = redact_text(r"C:\Users\adele.vance\AppData\Local\Temp\setup.log");
        assert!(!redacted.contains("adele.vance"));
        assert!(redacted.starts_with(r"C:\Users\"));
        assert!(redacted.ends_with(r"\AppData\Local\Temp\setup.log"));
    }

    #[test]
    fn a_profile_name_containing_a_space_is_fully_masked() {
        let redacted = redact_text(r"C:\Users\John Doe\AppData\Local\Temp\setup.log");
        assert!(!redacted.contains("John"), "got {redacted:?}");
        assert!(!redacted.contains("Doe"), "got {redacted:?}");
    }

    #[test]
    fn an_account_field_is_masked_even_without_an_at_sign() {
        let redacted = redact_text(r"RunAsUser = CONTOSO\jsmith");
        assert!(!redacted.contains("jsmith"), "got {redacted:?}");
        assert!(redacted.starts_with("RunAsUser = "));
    }

    #[test]
    fn inline_credential_values_are_masked_for_every_flag_shape() {
        for (flag, secret) in [
            ("-Password", "hunter2"),
            ("/Password", "hunter2"),
            ("-ApiKey", "abc123def"),
            ("-ClientSecret", "s3cr3tvalue"),
        ] {
            let redacted = redact_text(&format!("setup.exe {flag} {secret} /quiet"));
            assert!(
                !redacted.contains(secret),
                "{flag} leaked its value: {redacted:?}"
            );
        }
    }

    #[test]
    fn a_secret_inside_a_multiline_record_is_still_masked() {
        let record = "Install command line: setup.exe -Password hunter2\nAt line:1 char:1";
        let redacted = redact_text(record);
        assert!(!redacted.contains("hunter2"), "got {redacted:?}");
        assert!(redacted.contains("At line:1 char:1"));
    }

    #[test]
    fn correlation_keys_survive_redaction() {
        let app = "11111111-2222-4333-8444-555555555555";
        let redacted = redact_text(&format!(
            "Installation is done for app with id: {app}, exit code: 1603"
        ));
        assert!(redacted.contains(app), "correlation keys must not be lost");
        assert!(redacted.contains("1603"));
    }

    #[test]
    fn the_projection_is_idempotent() {
        let once = redact_text(
            r"RunAsUser = CONTOSO\jsmith ran C:\Users\jsmith\setup.exe -Password hunter2 for adele.vance@contoso.example",
        );
        assert_eq!(once, redact_text(&once));
    }
}
