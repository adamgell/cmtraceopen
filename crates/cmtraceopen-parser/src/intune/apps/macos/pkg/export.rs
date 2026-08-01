//! Redacted export projection for a package snapshot.
//!
//! The in-memory snapshot retains everything the evidence stated, so a
//! consenting operator can see it. The default *export* must not: an app
//! display name is tenant catalog data, a staged path names a user's disk, and
//! a content URL identifies a tenant's storage.
//!
//! Identifiers a transaction is keyed on survive untouched. Masking them would
//! destroy the correlation the export exists to show, and they are synthetic
//! GUIDs rather than personal data.

use super::models::PkgSnapshot;
use super::shared::redaction::{redact_label, redact_text};

/// Attribute names carrying a free-text tenant label rather than agent prose.
const LABEL_ATTRIBUTES: &[&str] = &["Name", "DisplayName"];

/// Return a copy of `snapshot` safe to write to disk or send to a service.
///
/// Idempotent: exporting an already-exported snapshot changes nothing.
pub fn redacted_export_projection(snapshot: &PkgSnapshot) -> PkgSnapshot {
    let mut projected = snapshot.clone();

    for transaction in &mut projected.transactions {
        // The display name is replaced outright rather than pattern-masked: it
        // is free text from a tenant's catalog, and no rule can decide which
        // part of an arbitrary product name is safe.
        transaction.display_name = transaction.display_name.as_deref().map(redact_label);

        for attribute in &mut transaction.attributes {
            attribute.value = if LABEL_ATTRIBUTES
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&attribute.name))
            {
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
    use crate::intune::apps::macos::pkg::reducer::analyze_pkg_bundle;
    use crate::intune::apps::macos::pkg::shared::agent_log::{
        MacAgentArtifactInput, MacAgentCaptureState,
    };

    const APP: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";

    fn snapshot() -> PkgSnapshot {
        let body = format!(
            "2026-07-29 09:00:00:000 | IntuneMDM-Daemon | I | 1 | Startup | Intune MDM Agent version 2026.07.1 starting\n\
             2026-07-29 09:10:00:000 | IntuneMDM-Daemon | I | 10 | AppInstaller | Received app policy AppId={APP} Type=pkg\n\
             2026-07-29 09:10:01:000 | IntuneMDM-Daemon | I | 10 | AppInstaller | Downloading content for AppId={APP} Url=https://cdn.contoso.example/a.pkg\n"
        );
        analyze_pkg_bundle(
            &[MacAgentArtifactInput {
                artifact_id: "daemon-current".to_owned(),
                family: "intuneMdmDaemon".to_owned(),
                file_name: "IntuneMDMDaemon.log".to_owned(),
                sanitized_source_path: None,
                capture_state: MacAgentCaptureState::Captured,
                content: Some(body),
                detail: None,
            }],
            "2026-07-31T00:00:00Z",
        )
    }

    #[test]
    fn a_content_url_does_not_survive_export() {
        let exported = redacted_export_projection(&snapshot());
        let encoded = serde_json::to_string(&exported).expect("snapshot serializes");
        assert!(!encoded.contains("cdn.contoso.example"));
    }

    #[test]
    fn the_transaction_key_survives_export() {
        let exported = redacted_export_projection(&snapshot());
        assert_eq!(exported.transactions[0].key.app_id, APP);
    }

    #[test]
    fn export_is_idempotent() {
        let once = redacted_export_projection(&snapshot());
        assert_eq!(redacted_export_projection(&once), once);
    }
}
