//! Deterministic privacy projection for platform-script evidence.
//!
//! Platform-script records quote UPNs, user profile paths, and command lines.
//! The export projection masks those spans while leaving the diagnostic grammar
//! -- signals, phases, exit codes, and the synthetic policy/run GUIDs the
//! transaction is keyed on -- intact, because removing those would destroy the
//! very correlation the export exists to show.
//!
//! Masking is a pure function of the masked text, so the same input always
//! produces the same token and two records that mentioned the same user still
//! visibly mention the same user. The projection is idempotent: replacement
//! tokens cannot themselves match a rule.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{
    ScriptAnalysis, ScriptArtifact, ScriptClassifiedString, ScriptObservation, ScriptSensitivity,
};

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
fn user_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // The leading `[` exclusion is what makes the projection idempotent:
        // an already-masked `[user:...]` segment must not be masked again.
        Regex::new(r"(?i)(?P<prefix>[\\/]Users[\\/])(?P<user>[^\\/\s\x22\[][^\\/\s\x22]*)")
            .expect("user path regex must compile")
    })
}

/// A PowerShell command line supplied inline.
fn command_line_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)(?P<flag>-(?:Command|EncodedCommand)\s+)(?P<value>\S.*)$")
            .expect("command line regex must compile")
    })
}

/// Mask the sensitive spans inside a free-text value.
pub fn redact_text(value: &str) -> String {
    let masked = upn_re().replace_all(value, |caps: &regex::Captures<'_>| {
        stable_token("upn", &caps[0])
    });

    let masked = user_path_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        format!("{}{}", &caps["prefix"], stable_token("user", &caps["user"]))
    });

    command_line_re()
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            let value = &caps["value"];
            // Already masked: re-masking would hash the token and break
            // idempotence.
            if value.starts_with("[command:") && value.ends_with(']') {
                return format!("{}{}", &caps["flag"], value);
            }
            format!("{}{}", &caps["flag"], stable_token("command", value))
        })
        .into_owned()
}

fn redact_classified(value: &ScriptClassifiedString) -> ScriptClassifiedString {
    match value.sensitivity {
        ScriptSensitivity::Public => value.clone(),
        ScriptSensitivity::Sensitive => ScriptClassifiedString {
            value: redact_text(&value.value),
            sensitivity: ScriptSensitivity::Sensitive,
        },
    }
}

fn redact_artifact(artifact: &ScriptArtifact) -> ScriptArtifact {
    ScriptArtifact {
        file_path: artifact.file_path.as_ref().map(redact_classified),
        ..artifact.clone()
    }
}

fn redact_observation(observation: &ScriptObservation) -> ScriptObservation {
    ScriptObservation {
        message: redact_classified(&observation.message),
        ..observation.clone()
    }
}

/// Project an analysis into its default-safe export form.
///
/// Everything a transaction is keyed on survives. Only classified-sensitive
/// text is masked.
pub fn redacted_export_projection(analysis: &ScriptAnalysis) -> ScriptAnalysis {
    let mut coverage = analysis.coverage.clone();
    coverage.artifacts = coverage.artifacts.iter().map(redact_artifact).collect();

    ScriptAnalysis {
        transactions: analysis
            .transactions
            .iter()
            .map(|transaction| {
                let mut redacted = transaction.clone();
                redacted.display_name = transaction.display_name.as_ref().map(redact_classified);
                redacted
            })
            .collect(),
        observations: analysis
            .observations
            .iter()
            .map(redact_observation)
            .collect(),
        unkeyed_observations: analysis.unkeyed_observations.clone(),
        coverage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upn_is_masked_deterministically() {
        let first = redact_text("Running as adele.vance@contoso.example");
        let second = redact_text("Reported for adele.vance@contoso.example");
        assert!(!first.contains("adele.vance"));
        let token = first.split_whitespace().last().unwrap();
        assert!(second.contains(token), "same UPN must yield the same token");
    }

    #[test]
    fn different_users_get_different_tokens() {
        let a = redact_text("adele.vance@contoso.example");
        let b = redact_text("alex.wilber@contoso.example");
        assert_ne!(a, b);
    }

    #[test]
    fn user_profile_segment_is_masked_but_the_path_shape_survives() {
        let redacted = redact_text(r"C:\Users\adele.vance\AppData\Local\Temp\out.txt");
        assert!(!redacted.contains("adele.vance"));
        assert!(redacted.starts_with(r"C:\Users\"));
        assert!(redacted.ends_with(r"\AppData\Local\Temp\out.txt"));
    }

    #[test]
    fn command_line_value_is_masked() {
        let redacted = redact_text("powershell.exe -Command Set-Secret -Value hunter2");
        assert!(!redacted.contains("hunter2"));
        assert!(redacted.contains("-Command "));
    }

    #[test]
    fn policy_guids_survive_redaction() {
        let guid = "11111111-2222-3333-4444-555555555555";
        let redacted = redact_text(&format!(
            r"C:\Program Files (x86)\Microsoft Intune Management Extension\Policies\Scripts\{guid}_{guid}.ps1"
        ));
        assert!(redacted.contains(guid), "correlation keys must not be lost");
    }

    #[test]
    fn projection_is_idempotent() {
        let once = redact_text(r"adele.vance@contoso.example at C:\Users\adele.vance\a.ps1");
        let twice = redact_text(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn public_values_are_left_alone() {
        let value = ScriptClassifiedString::public("adele.vance@contoso.example");
        assert_eq!(
            redact_classified(&value).value,
            "adele.vance@contoso.example"
        );
    }
}
