//! Deterministic privacy projection for Store app evidence.
//!
//! Store records quote UPNs, user profile paths, and per-user package
//! installation locations. The export projection masks those spans and leaves
//! the diagnostic grammar — signals, phases, error codes, and the package
//! family/product identifiers a transaction is keyed on — intact, because
//! removing those would destroy the correlation the export exists to show.
//!
//! Masking is a pure function of the masked text, so the same input always
//! produces the same token and two records that named the same user still
//! visibly name the same user. The projection is idempotent: a replacement token
//! cannot itself match a rule.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::evidence::{IntuneNamedValue, IntuneSensitivity};

use super::models::{StoreAnalysis, StoreObservation};

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
/// The segment is bounded by a path separator, a quote, or the end of the line
/// rather than by whitespace: Windows permits spaces in profile directory names,
/// and bounding on `\s` would leak everything after the first word. The leading
/// `[` exclusion is what keeps the projection idempotent.
fn user_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)(?P<prefix>[\\/]Users[\\/])(?P<user>[^\\/\r\n\x22\[][^\\/\r\n\x22]*)")
            .expect("user path regex must compile")
    })
}

/// Mask the sensitive spans inside a free-text value.
pub fn redact_text(value: &str) -> String {
    let masked = upn_re().replace_all(value, |caps: &regex::Captures<'_>| {
        stable_token("upn", &caps[0])
    });

    user_path_re()
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            // Trailing whitespace is not part of the profile name, so keeping it
            // out of the hashed value means `\Users\Ada Lovelace ` and
            // `\Users\Ada Lovelace` still resolve to the same person.
            let user = caps["user"].trim_end();
            let trailing = &caps["user"][user.len()..];
            format!("{}{}{}", &caps["prefix"], stable_token("user", user), trailing)
        })
        .into_owned()
}

fn redact_named_data(named_data: &[IntuneNamedValue]) -> Vec<IntuneNamedValue> {
    named_data
        .iter()
        .map(|entry| IntuneNamedValue {
            name: entry.name.clone(),
            value: redact_text(&entry.value),
        })
        .collect()
}

fn redact_observation(observation: &StoreObservation) -> StoreObservation {
    if observation.context.sensitivity == IntuneSensitivity::Public {
        return observation.clone();
    }
    let mut redacted = observation.clone();
    redacted.message = observation.message.as_deref().map(redact_text);
    redacted.named_data = redact_named_data(&observation.named_data);
    redacted.context.provenance.file_path = observation
        .context
        .provenance
        .file_path
        .as_deref()
        .map(redact_text);
    redacted
}

/// A copy of the analysis safe to write to disk or attach to a ticket.
///
/// Findings are re-rendered through the same masking rules because their
/// summaries quote package labels, which can carry a user-supplied display name.
pub fn redacted_export_projection(analysis: &StoreAnalysis) -> StoreAnalysis {
    let mut projected = analysis.clone();
    projected.observations = analysis
        .observations
        .iter()
        .map(redact_observation)
        .collect();
    for finding in &mut projected.findings {
        finding.summary = redact_text(&finding.summary);
    }
    projected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_upn_is_masked_stably() {
        let once = redact_text("Installing for synthetic.user@example.invalid");
        let twice = redact_text("Installing for synthetic.user@example.invalid");
        assert_eq!(once, twice);
        assert!(!once.contains("synthetic.user"));
        assert!(once.contains("[upn:"));
    }

    #[test]
    fn a_profile_path_with_a_space_is_masked_in_full() {
        let masked = redact_text(r"D:\Users\Ada Lovelace\AppData\Local\Packages");
        assert!(!masked.contains("Ada"), "{masked}");
        assert!(!masked.contains("Lovelace"), "{masked}");
        assert!(masked.contains(r"\AppData\Local\Packages"));
    }

    #[test]
    fn masking_is_idempotent() {
        let once = redact_text(r"D:\Users\Ada\App and synthetic.user@example.invalid");
        assert_eq!(redact_text(&once), once);
    }

    #[test]
    fn the_package_identifier_survives_redaction() {
        let masked = redact_text(
            r"D:\Users\Ada\x PackageFamilyName=Contoso.SynthApp_9abcdef01234h failed 0x80073CF9",
        );
        assert!(masked.contains("Contoso.SynthApp_9abcdef01234h"));
        assert!(masked.contains("0x80073CF9"));
    }
}
