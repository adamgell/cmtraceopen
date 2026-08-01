//! Redacted export projection for a shell-script snapshot.
//!
//! Script evidence is the most sensitive material either macOS leaf handles:
//! a script's name is tenant configuration, and any captured output is
//! arbitrary administrator-authored text that routinely contains credentials no
//! pattern rule can recognize. The export therefore withholds output payloads
//! wholesale rather than trying to mask inside them.

use super::models::ShellScriptSnapshot;
use crate::intune::apps::macos::pkg::shared::redaction::{
    redact_label, redact_payload, redact_text,
};

/// Attribute names whose values are script-authored payloads.
///
/// These are withheld entirely rather than pattern-masked. Everything else is
/// agent-authored and safe to mask in place.
const PAYLOAD_ATTRIBUTES: &[&str] = &["Stdout", "Stderr", "Output", "Command", "ScriptPath"];

/// Attribute names carrying a free-text tenant label.
const LABEL_ATTRIBUTES: &[&str] = &["Name", "DisplayName"];

/// Return a copy of `snapshot` safe to write to disk or send to a service.
///
/// Idempotent: exporting an already-exported snapshot changes nothing.
pub fn redacted_export_projection(snapshot: &ShellScriptSnapshot) -> ShellScriptSnapshot {
    let mut projected = snapshot.clone();

    for run in &mut projected.runs {
        run.display_name = run.display_name.as_deref().map(redact_label);

        for attribute in &mut run.attributes {
            let matches = |names: &[&str]| {
                names
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(&attribute.name))
            };

            attribute.value = if matches(PAYLOAD_ATTRIBUTES) {
                // Idempotence: an already-withheld value must not be re-wrapped.
                if attribute.value.starts_with("[payload:") {
                    attribute.value.clone()
                } else {
                    redact_payload(&attribute.value)
                }
            } else if matches(LABEL_ATTRIBUTES) {
                redact_label(&attribute.value)
            } else {
                redact_text(&attribute.value)
            };
        }
    }

    for coverage in &mut projected.coverage {
        coverage.detail = coverage.detail.as_deref().map(redact_text);
    }

    for finding in &mut projected.findings {
        finding.summary = redact_text(&finding.summary);
    }

    projected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::apps::macos::pkg::shared::agent_log::{
        MacAgentArtifactInput, MacAgentCaptureState,
    };
    use crate::intune::apps::macos::shell_scripts::reducer::analyze_shell_script_bundle;

    const POLICY: &str = "11111111-1111-4111-8111-111111111111";
    const RUN: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";

    fn snapshot() -> ShellScriptSnapshot {
        let content = format!(
            "2026-07-29 09:00:00:000 | IntuneMDM-Daemon | I | 1 | Startup | Intune MDM Agent version 2026.07.1 starting\n\
             2026-07-29 09:10:00:000 | IntuneMDM-Daemon | I | 10 | ShellScriptManager | Launching shell script PolicyId={POLICY} RunId={RUN} Name=Set Wallpaper ScriptPath=/Users/jsmith/scripts/a.sh\n\
             2026-07-29 09:10:05:000 | IntuneMDM-Daemon | I | 10 | ShellScriptManager | Captured stdout for PolicyId={POLICY} RunId={RUN} Output=token abc123 for person@contoso.example\n"
        );
        analyze_shell_script_bundle(
            &[MacAgentArtifactInput {
                artifact_id: "daemon-current".to_owned(),
                family: "intuneMdmDaemon".to_owned(),
                file_name: "IntuneMDMDaemon.log".to_owned(),
                sanitized_source_path: None,
                capture_state: MacAgentCaptureState::Captured,
                content: Some(content),
                detail: None,
            }],
            "2026-07-31T00:00:00Z",
        )
    }

    #[test]
    fn captured_output_is_withheld_wholesale() {
        let exported = redacted_export_projection(&snapshot());
        let encoded = serde_json::to_string(&exported).expect("snapshot serializes");
        assert!(!encoded.contains("abc123"));
        assert!(!encoded.contains("person@contoso.example"));
        assert!(encoded.contains("bytes withheld"));
    }

    #[test]
    fn a_home_path_does_not_survive_export() {
        let exported = redacted_export_projection(&snapshot());
        let encoded = serde_json::to_string(&exported).expect("snapshot serializes");
        assert!(!encoded.contains("jsmith"));
    }

    #[test]
    fn the_run_key_survives_export() {
        let exported = redacted_export_projection(&snapshot());
        assert_eq!(exported.runs[0].key.run_id, RUN);
        assert_eq!(exported.runs[0].key.policy_id, POLICY);
    }

    #[test]
    fn export_is_idempotent() {
        let once = redacted_export_projection(&snapshot());
        assert_eq!(redacted_export_projection(&once), once);
    }
}
