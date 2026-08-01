//! Deterministic privacy projection for remediation evidence.
//!
//! Remediation records quote script output, user identities, profile paths,
//! command lines, and registry locations. The export projection masks those
//! spans and leaves the diagnostic grammar intact: stages, outcomes, exit codes,
//! evidence references, and the policy/run identifiers a run is keyed on all
//! survive, because removing them would destroy the correlation the export
//! exists to show.
//!
//! Masking is a pure function of the masked text, so the same input always
//! produces the same token and two records that named the same user still
//! visibly name the same user. The projection is idempotent: a replacement
//! token cannot itself match a rule.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::evidence::{IntuneNamedValue, IntuneSensitivity};

use super::models::{RemediationArtifact, RemediationObservation, RemediationRun, RemediationSnapshot};

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
/// rather than by whitespace, because Windows permits spaces in profile
/// directory names. The leading `[` exclusion is what keeps the projection
/// idempotent: an already-masked segment must not be masked again.
fn user_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)(?P<prefix>[\\/]Users[\\/])(?P<user>[^\\/\r\n\x22\[][^\\/\r\n\x22]*)")
            .expect("user path regex must compile")
    })
}

/// A credential or command value supplied inline after a flag.
///
/// The value stops at a line break rather than at the end of the string: a CCM
/// record is one *logical* record and routinely contains newlines, so anchoring
/// on `$` would leak an inline command inside a multi-line record.
fn command_line_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<flag>-(?:Command|EncodedCommand|Password|Secret|ClientSecret|Token|AccessToken|ApiKey|Api[-_]?Key|Credential|Authorization)\s+)(?P<value>[^\r\n]+)",
        )
        .expect("command line regex must compile")
    })
}

/// Captured script output. Arbitrary detection data is the single most likely
/// place for device inventory, user names, and secrets to appear.
fn output_value_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<prefix>\b(?:stdout|stderr|script\s+output|detection\s+output|remediation\s+output|output)\s*[:=]\s*)(?P<value>[^\r\n]+)",
        )
        .expect("output regex must compile")
    })
}

/// A registry location. The hive survives so the shape stays legible; the path
/// under it does not, because remediation scripts key off product- and
/// user-specific subkeys.
fn registry_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<hive>\bHK(?:LM|CU|CR|U|EY_LOCAL_MACHINE|EY_CURRENT_USER|EY_CLASSES_ROOT|EY_USERS)[\\/])(?P<path>[^\s\x22\r\n\[][^\s\x22\r\n]*)",
        )
        .expect("registry path regex must compile")
    })
}

/// Mask an already-tokenized value only once.
fn mask_once(kind: &str, value: &str) -> String {
    let opener = format!("[{kind}:");
    if value.starts_with(&opener) && value.ends_with(']') {
        return value.to_owned();
    }
    stable_token(kind, value)
}

/// Mask the sensitive spans inside a free-text value.
pub fn redact_text(value: &str) -> String {
    let masked = upn_re().replace_all(value, |caps: &regex::Captures<'_>| {
        stable_token("upn", &caps[0])
    });

    let masked = user_path_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        // Trailing whitespace is not part of the profile name, so keeping it out
        // of the hashed value means `\Users\John Doe ` and `\Users\John Doe`
        // still resolve to the same user.
        let user = caps["user"].trim_end();
        let trailing = &caps["user"][user.len()..];
        format!(
            "{}{}{}",
            &caps["prefix"],
            mask_once("user", user),
            trailing
        )
    });

    let masked = registry_path_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        let path = caps["path"].trim_end();
        let trailing = &caps["path"][path.len()..];
        format!("{}{}{}", &caps["hive"], mask_once("registry", path), trailing)
    });

    let masked = command_line_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        let value = caps["value"].trim_end();
        format!("{}{}", &caps["flag"], mask_once("command", value))
    });

    output_value_re()
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            let value = caps["value"].trim_end();
            format!("{}{}", &caps["prefix"], mask_once("output", value))
        })
        .into_owned()
}

fn redact_named_values(values: &[IntuneNamedValue]) -> Vec<IntuneNamedValue> {
    values
        .iter()
        .map(|value| IntuneNamedValue {
            name: value.name.clone(),
            value: redact_text(&value.value),
        })
        .collect()
}

fn redact_observation(observation: &RemediationObservation) -> RemediationObservation {
    if observation.context.sensitivity == IntuneSensitivity::Public {
        return observation.clone();
    }
    let mut redacted = observation.clone();
    redacted.message = redact_text(&observation.message);
    redacted.retained_fields = redact_named_values(&observation.retained_fields);
    redacted.context.provenance.file_path = observation
        .context
        .provenance
        .file_path
        .as_deref()
        .map(redact_text);
    redacted
}

fn redact_artifact(artifact: &RemediationArtifact) -> RemediationArtifact {
    RemediationArtifact {
        file_path: artifact.file_path.as_deref().map(redact_text),
        ..artifact.clone()
    }
}

fn redact_run(run: &RemediationRun) -> RemediationRun {
    RemediationRun {
        retained_facts: redact_named_values(&run.retained_facts),
        ..run.clone()
    }
}

/// Project a snapshot into its default-safe export form.
///
/// Everything a run is keyed on, every outcome, and every evidence reference
/// survives. Only classified-sensitive free text is masked.
pub fn redacted_export_projection(snapshot: &RemediationSnapshot) -> RemediationSnapshot {
    RemediationSnapshot {
        schema_version: snapshot.schema_version,
        artifacts: snapshot.artifacts.iter().map(redact_artifact).collect(),
        runs: snapshot.runs.iter().map(redact_run).collect(),
        observations: snapshot
            .observations
            .iter()
            .map(redact_observation)
            .collect(),
        unkeyed_observations: snapshot.unkeyed_observations.clone(),
        coverage: snapshot.coverage.clone(),
        findings: snapshot.findings.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_upn_is_masked_deterministically() {
        let first = redact_text("Running as adele.vance@contoso.example");
        let second = redact_text("Reported for adele.vance@contoso.example");
        assert!(!first.contains("adele.vance"));
        let token = first.split_whitespace().last().expect("token");
        assert!(second.contains(token), "the same UPN must yield one token");
    }

    #[test]
    fn different_identities_get_different_tokens() {
        assert_ne!(
            redact_text("adele.vance@contoso.example"),
            redact_text("alex.wilber@contoso.example")
        );
    }

    #[test]
    fn a_profile_path_keeps_its_shape_and_loses_its_name() {
        let redacted = redact_text(r"C:\Users\adele.vance\AppData\Local\Temp\detect.out");
        assert!(!redacted.contains("adele.vance"));
        assert!(redacted.starts_with(r"C:\Users\"));
        assert!(redacted.ends_with(r"\AppData\Local\Temp\detect.out"));
    }

    #[test]
    fn a_profile_name_containing_a_space_is_fully_masked() {
        let redacted = redact_text(r"C:\Users\John Doe\AppData\Local\Temp\out.txt");
        assert!(!redacted.contains("John"), "got {redacted:?}");
        assert!(!redacted.contains("Doe"), "got {redacted:?}");
    }

    #[test]
    fn script_output_is_masked_but_the_label_survives() {
        let redacted = redact_text("Detection output: HostName=SYNTH-PC;Owner=synthetic.user");
        assert!(!redacted.contains("SYNTH-PC"));
        assert!(redacted.to_ascii_lowercase().contains("detection output"));
    }

    #[test]
    fn a_registry_path_keeps_its_hive_and_loses_its_key() {
        let redacted = redact_text(r"Reading HKLM\SOFTWARE\Contoso\Agent\State for compliance");
        assert!(!redacted.contains("Contoso"));
        assert!(redacted.contains(r"HKLM\"));
    }

    #[test]
    fn credential_flags_are_masked() {
        for (flag, secret) in [
            ("-Password", "hunter2"),
            ("-ApiKey", "abc123def"),
            ("-ClientSecret", "s3cr3tvalue"),
        ] {
            let redacted = redact_text(&format!("powershell.exe {flag} {secret}"));
            assert!(!redacted.contains(secret), "{flag} leaked: {redacted:?}");
        }
    }

    #[test]
    fn correlation_keys_survive_redaction() {
        let policy = "11111111-2222-3333-4444-555555555555";
        let run = "66666666-7777-8888-9999-000000000000";
        let redacted = redact_text(&format!(
            r"Powershell script is: C:\Windows\IMECache\HealthScripts\{policy}_{run}\detect.ps1"
        ));
        assert!(redacted.contains(policy), "policy id must survive");
        assert!(redacted.contains(run), "run id must survive");
    }

    #[test]
    fn the_projection_is_idempotent() {
        let once = redact_text(
            "adele.vance@contoso.example ran C:\\Users\\adele.vance\\a.ps1 -Password hunter2\nDetection output: Owner=adele",
        );
        assert_eq!(once, redact_text(&once));
    }

    #[test]
    fn a_command_value_is_masked_inside_a_multiline_record() {
        let record = "Launching: powershell.exe -Command Set-Secret hunter2\nAt line:1 char:1";
        let redacted = redact_text(record);
        assert!(!redacted.contains("hunter2"), "got {redacted:?}");
        assert!(redacted.contains("At line:1 char:1"));
    }
}
