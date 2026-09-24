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
    use crate::intune::apps::windows::win32::{analyze_win32_bundle, Win32SourceInput};
    use crate::intune::evidence::IntuneNamedValue;

    // The grammar itself — UPN determinism, path masking, credential flags,
    // malformed token-lookalikes — is tested with its owner in
    // `common::redaction`. This module owns only the projection: which Win32
    // fields are classified sensitive, and that the classification is honored.

    const APP: &str = "11111111-2222-4333-8444-555555555555";
    const UPN: &str = "adele.vance@contoso.example";

    /// One transaction whose observations quote a UPN, reduced for real so the
    /// projection tests run over the same shapes the analyzer emits.
    fn analysis() -> Win32Analysis {
        let workload = format!(
            concat!(
                r#"<![LOG[[Win32App] Processing app policy for app with id: {app} for user {upn}]LOG]!>"#,
                r#"<time="10:15:22.100+000" date="7-31-2026" component="Win32App" "#,
                r#"context="" type="1" thread="12" file="">"#,
                "\n",
                r#"<![LOG[[Win32App] Installation is done for app with id: {app}, exit code: 0]LOG]!>"#,
                r#"<time="10:16:04.900+000" date="7-31-2026" component="Win32App" "#,
                r#"context="" type="1" thread="12" file="">"#,
            ),
            app = APP,
            upn = UPN,
        );
        analyze_win32_bundle(&[Win32SourceInput::captured(
            "app-workload",
            "AppWorkload.log",
            workload,
        )])
    }

    /// A sensitive observation dressed with every free-text field the
    /// projection must mask.
    fn dressed_sensitive_observation() -> Win32Observation {
        let analysis = analysis();
        let mut observation = analysis.observations[0].clone();
        assert_eq!(
            observation.context.sensitivity,
            IntuneSensitivity::Sensitive,
            "win32 observations are sensitive by default"
        );
        observation.context.provenance.file_path =
            Some(r"C:\Users\jsmith\AppData\Local\Temp\AppWorkload.log".to_owned());
        observation.requirement_name = Some(r"File C:\Users\jsmith\flag.txt exists".to_owned());
        observation.attributes = vec![IntuneNamedValue {
            name: "InstallCommandLine".to_owned(),
            value: "setup.exe -Password hunter2".to_owned(),
        }];
        observation
    }

    #[test]
    fn a_sensitive_observation_is_masked_in_every_free_text_field() {
        let observation = dressed_sensitive_observation();
        let redacted = redact_observation(&observation);

        assert!(!redacted.message.contains("adele.vance"), "message leaked");
        assert!(
            !redacted
                .context
                .provenance
                .file_path
                .as_deref()
                .expect("path survives as a masked path")
                .contains("jsmith"),
            "provenance path leaked"
        );
        assert!(
            !redacted
                .requirement_name
                .as_deref()
                .expect("requirement name survives masked")
                .contains("jsmith"),
            "requirement name leaked"
        );
        assert_eq!(redacted.attributes.len(), 1);
        assert_eq!(
            redacted.attributes[0].name, "InstallCommandLine",
            "the attribute name is the schema label and stays intact"
        );
        assert!(
            !redacted.attributes[0].value.contains("hunter2"),
            "attribute value leaked"
        );
        // Correlation keys are not free text and survive verbatim.
        assert_eq!(redacted.observation_id, observation.observation_id);
        assert_eq!(redacted.app_id.as_deref(), Some(APP));
    }

    #[test]
    fn a_public_observation_is_exported_verbatim() {
        let mut observation = dressed_sensitive_observation();
        observation.context.sensitivity = IntuneSensitivity::Public;
        assert_eq!(
            redact_observation(&observation),
            observation,
            "a record the analyzer marked public must not be rewritten"
        );
    }

    #[test]
    fn a_transaction_masks_failed_requirements_but_keeps_its_keys() {
        let analysis = analysis();
        let mut transaction = analysis.transactions[0].clone();
        transaction.failed_requirements = vec![format!(
            r"User file C:\Users\jsmith\flag.txt exists for {UPN}"
        )];

        let redacted = redact_transaction(&transaction);
        assert_eq!(redacted.failed_requirements.len(), 1);
        assert!(
            !redacted.failed_requirements[0].contains("jsmith")
                && !redacted.failed_requirements[0].contains("adele.vance"),
            "failed requirement leaked: {:?}",
            redacted.failed_requirements[0]
        );
        assert_eq!(redacted.key.app_id, transaction.key.app_id);
        assert_eq!(
            redacted.key.deployment_type_id,
            transaction.key.deployment_type_id
        );
        assert_eq!(redacted.observations, transaction.observations);
    }

    #[test]
    fn the_export_projection_is_idempotent() {
        let mut analysis = analysis();
        analysis.observations[0] = dressed_sensitive_observation();
        analysis.transactions[0].failed_requirements = vec![format!(
            r"User file C:\Users\jsmith\flag.txt exists for {UPN}"
        )];

        let once = redacted_export_projection(&analysis);
        let twice = redacted_export_projection(&once);
        assert_eq!(once, twice, "projecting a projection must change nothing");
        assert!(
            !serde_json::to_string(&once)
                .expect("serializes")
                .contains("hunter2"),
            "the projected export must be clean end to end"
        );
    }
}
