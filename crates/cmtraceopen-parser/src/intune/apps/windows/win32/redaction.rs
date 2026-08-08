//! Deterministic privacy projection for Win32 app deployment evidence.
//!
//! Win32 records quote install command lines, UPNs, user profile paths, and the
//! account an enforcement ran as. The export projection masks those spans while
//! leaving the diagnostic grammar intact -- signals, phases, return codes, and
//! the app/deployment-type ids a transaction is keyed on -- because removing
//! those would destroy the correlation the export exists to show.
//!
//! The masking grammar itself lives in
//! [`crate::intune::apps::windows::common::redact_text`], the single owner all
//! Intune Windows analyzers share (as `scripts` does). This module owns only
//! the *projection*: which Win32 fields are classified sensitive is a property
//! of this analyzer's contract, not of the shared grammar. A local fork of the
//! rules previously reintroduced a fixed JSON-escaped-path bug here; one owner
//! is the fix for that class.
//!
//! Only values classified [`IntuneSensitivity::Sensitive`] are masked. A record
//! the analyzer marked public is exported verbatim.

use crate::intune::evidence::IntuneSensitivity;

pub use crate::intune::apps::windows::common::redact_text;

use super::models::{Win32Analysis, Win32Observation, Win32Transaction};

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
    // A requirement name is free text quoted from the record body and can carry
    // a path or UPN; the app/deployment-type/dependency ids are correlation
    // keys and stay verbatim.
    redacted.requirement_name = observation.requirement_name.as_deref().map(redact_text);
    // Retained attributes are uninterpreted record fields; their values are
    // free text, so mask them. The attribute name is the schema label that
    // makes the value interpretable and is left intact.
    redacted.attributes = observation
        .attributes
        .iter()
        .map(|named| crate::intune::evidence::IntuneNamedValue {
            name: named.name.clone(),
            value: redact_text(&named.value),
        })
        .collect();
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
    fn a_json_escaped_profile_path_is_masked() {
        // The local fork lacked the shared module's `[\\/]{1,2}` JSON-escape
        // handling, so a path inside an embedded JSON payload leaked. Pinned
        // here so the fork can never silently come back.
        let redacted = redact_text(r#"{"LogPath":"C:\\Users\\John Doe\\AppData\\Local"}"#);
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
    fn an_account_name_containing_a_space_is_fully_masked() {
        let redacted = redact_text(r"RunAsUser = CONTOSO\John Doe, session 2");
        assert!(!redacted.contains("John"), "got {redacted:?}");
        assert!(!redacted.contains("Doe"), "got {redacted:?}");
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
    fn an_msi_property_credential_is_masked_without_any_sigil() {
        let redacted = redact_text("msiexec /i app.msi PASSWORD=hunter2 /qn");
        assert!(!redacted.contains("hunter2"), "got {redacted:?}");
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
    fn malformed_mask_tokens_are_not_treated_as_already_masked() {
        let redacted = redact_text("setup.exe -Command \"[command:0123456789abcdef] /quiet]\"");
        assert!(!redacted.contains("/quiet"));
        let redacted = redact_text("RunAsUser = [account:0123456789abcdef0]");
        assert!(!redacted.contains("0123456789abcdef0"));
    }

    #[test]
    fn the_projection_is_idempotent() {
        let once = redact_text(
            r"RunAsUser = CONTOSO\jsmith ran C:\Users\jsmith\setup.exe -Password hunter2 for adele.vance@contoso.example",
        );
        assert_eq!(once, redact_text(&once));
    }
}
