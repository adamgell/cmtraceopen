//! Message classification for package deployment records.
//!
//! Classification is deliberately narrow. A record contributes a signal only
//! when all three hold:
//!
//! 1. it came from a confirmed Intune agent artifact;
//! 2. its component is one that owns app deployment;
//! 3. its message matches a known phrase **and** states an `AppId` GUID.
//!
//! The third condition is what keeps a transaction honest. A record that
//! describes an install but names no app cannot be keyed, so it is left
//! unclassified rather than attached to whichever transaction happens to be
//! nearest in time.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{PkgAppType, PkgTransactionKey};
use super::shared::agent_log::MacAgentRecord;
use super::shared::fields::{error_code_field, field, fields, guid_field};
use crate::intune::evidence::{
    IntuneErrorCode, IntuneNamedValue, IntuneObservationContext, IntuneSensitivity,
};

/// Components that own macOS app deployment.
///
/// `ShellScriptManager` is deliberately absent: a shell-script record is script
/// evidence and never becomes a package signal, even though both share the
/// agent envelope.
pub const PKG_COMPONENTS: &[&str] = &["AppInstaller", "AppManager"];

/// What a package record asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgSignalKind {
    PolicyReceived,
    ApplicabilityPassed,
    ApplicabilityFailed,
    DownloadStarted,
    DownloadCompleted,
    DownloadFailed,
    Staged,
    ValidationStarted,
    ValidationFailed,
    InstallerLaunched,
    InstallerCompleted,
    DetectionSucceeded,
    DetectionFailed,
    Reported,
    ReportFailed,
    RetryScheduled,
}

/// One classified record, keyed and ready to reduce.
#[derive(Debug, Clone)]
pub struct PkgSignal {
    pub kind: PkgSignalKind,
    pub key: PkgTransactionKey,
    pub display_name: Option<String>,
    pub app_type: Option<PkgAppType>,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
    pub error_code: Option<IntuneErrorCode>,
    pub attributes: Vec<IntuneNamedValue>,
    pub context: IntuneObservationContext,
}

/// Message phrases this grammar revision recognizes, in evaluation order.
///
/// Order matters: `failed to report app status` must be tested before any
/// broader `failed` phrase, or the more specific signal is shadowed.
fn phrase_table() -> &'static [(Regex, PkgSignalKind)] {
    static CELL: OnceLock<Vec<(Regex, PkgSignalKind)>> = OnceLock::new();
    CELL.get_or_init(|| {
        [
            (r"^received app policy\b", PkgSignalKind::PolicyReceived),
            (
                r"^applicability check passed\b",
                PkgSignalKind::ApplicabilityPassed,
            ),
            (
                r"^applicability check failed\b",
                PkgSignalKind::ApplicabilityFailed,
            ),
            (r"^downloading content\b", PkgSignalKind::DownloadStarted),
            (r"^download complete\b", PkgSignalKind::DownloadCompleted),
            (r"^download failed\b", PkgSignalKind::DownloadFailed),
            (r"^staged package\b", PkgSignalKind::Staged),
            (
                r"^validating package signature\b",
                PkgSignalKind::ValidationStarted,
            ),
            (
                r"^signature validation failed\b",
                PkgSignalKind::ValidationFailed,
            ),
            (r"^launching installer\b", PkgSignalKind::InstallerLaunched),
            (r"^installer finished\b", PkgSignalKind::InstallerCompleted),
            (
                r"^detection succeeded\b",
                PkgSignalKind::DetectionSucceeded,
            ),
            (r"^detection failed\b", PkgSignalKind::DetectionFailed),
            (
                r"^failed to report app status\b",
                PkgSignalKind::ReportFailed,
            ),
            (r"^reported app status\b", PkgSignalKind::Reported),
            (r"^scheduling retry\b", PkgSignalKind::RetryScheduled),
        ]
        .into_iter()
        .map(|(pattern, kind)| {
            (
                Regex::new(&format!("(?i){pattern}")).expect("package phrase regex must compile"),
                kind,
            )
        })
        .collect()
    })
}

/// The phrase a message matches, if any.
pub fn classify_message(message: &str) -> Option<PkgSignalKind> {
    phrase_table()
        .iter()
        .find(|(pattern, _)| pattern.is_match(message.trim()))
        .map(|(_, kind)| *kind)
}

/// Whether a record could carry a value needing redaction before export.
fn sensitivity_of(message: &str) -> IntuneSensitivity {
    if message.contains("://") || message.contains("/Users/") {
        IntuneSensitivity::Restricted
    } else {
        IntuneSensitivity::Sensitive
    }
}

/// Classify one record into a package signal.
///
/// Returns `None` for any record this analyzer must not reason about: a foreign
/// component, an unknown phrase, or a phrase with no `AppId` to key on.
pub fn classify_record(
    record: &MacAgentRecord,
    file_path: Option<&str>,
    observed_at_utc: &str,
) -> Option<PkgSignal> {
    if !record.component_is(PKG_COMPONENTS) {
        return None;
    }
    let kind = classify_message(&record.message)?;
    let parsed = fields(&record.message);
    let app_id = guid_field(&parsed, "AppId")?;

    Some(PkgSignal {
        kind,
        key: PkgTransactionKey {
            policy_id: guid_field(&parsed, "PolicyId").map(str::to_owned),
            app_id: app_id.to_ascii_lowercase(),
        },
        display_name: field(&parsed, "Name").map(str::to_owned),
        app_type: field(&parsed, "Type").map(|value| {
            // Case is not normalized away: the raw token is what round-trips
            // when this build does not recognize the type.
            match value.to_ascii_lowercase().as_str() {
                "pkg" => PkgAppType::Pkg,
                "lobpkg" => PkgAppType::LobPkg,
                "dmg" => PkgAppType::Dmg,
                "app" => PkgAppType::AppBundle,
                _ => PkgAppType::Unknown(value.to_owned()),
            }
        }),
        bundle_id: field(&parsed, "BundleId").map(str::to_owned),
        version: field(&parsed, "Version").map(str::to_owned),
        error_code: error_code_field(&parsed, "ExitCode")
            .or_else(|| error_code_field(&parsed, "Error")),
        attributes: parsed,
        context: IntuneObservationContext {
            evidence_ref: record.evidence_ref(),
            provenance: record.provenance(file_path),
            source_timestamp: record.timestamp.clone(),
            observed_at_utc: observed_at_utc.to_owned(),
            sensitivity: sensitivity_of(&record.message),
            parse_state: record.parse_state.clone(),
            access_state: crate::intune::evidence::IntuneAccessState::Available,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::apps::macos::pkg::shared::agent_log::{
        parse_agent_log, MacAgentArtifactInput, MacAgentCaptureState,
    };

    const APP: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";

    fn record(component: &str, message: &str) -> MacAgentRecord {
        let input = MacAgentArtifactInput {
            artifact_id: "a1".to_owned(),
            family: "intuneMdmAgent".to_owned(),
            file_name: "IntuneMDMDaemon.log".to_owned(),
            sanitized_source_path: None,
            capture_state: MacAgentCaptureState::Captured,
            content: Some(format!(
                "2026-07-29 09:10:11:888 | IntuneMDM-Daemon | I | 1 | {component} | {message}"
            )),
            detail: None,
        };
        parse_agent_log(&input).records.remove(0)
    }

    #[test]
    fn a_policy_record_is_classified_and_keyed() {
        let signal = classify_record(
            &record(
                "AppInstaller",
                &format!("Received app policy PolicyId={APP} AppId={APP} Name=Contoso Reader Type=pkg"),
            ),
            None,
            "2026-07-31T00:00:00Z",
        )
        .expect("classified");
        assert_eq!(signal.kind, PkgSignalKind::PolicyReceived);
        assert_eq!(signal.key.app_id, APP);
        assert_eq!(signal.display_name.as_deref(), Some("Contoso Reader"));
        assert_eq!(signal.app_type, Some(PkgAppType::Pkg));
    }

    #[test]
    fn a_record_without_an_app_id_cannot_be_keyed_and_is_dropped() {
        // Time proximity must never substitute for a stated identifier.
        assert!(classify_record(
            &record("AppInstaller", "Installer finished ExitCode=0"),
            None,
            "2026-07-31T00:00:00Z",
        )
        .is_none());
    }

    #[test]
    fn a_shell_script_component_never_produces_a_package_signal() {
        assert!(classify_record(
            &record(
                "ShellScriptManager",
                &format!("Installer finished for AppId={APP} ExitCode=0"),
            ),
            None,
            "2026-07-31T00:00:00Z",
        )
        .is_none());
    }

    #[test]
    fn report_failure_is_matched_before_the_generic_report_phrase() {
        let signal = classify_record(
            &record(
                "AppInstaller",
                &format!("Failed to report app status for AppId={APP} Error=-1005"),
            ),
            None,
            "2026-07-31T00:00:00Z",
        )
        .expect("classified");
        assert_eq!(signal.kind, PkgSignalKind::ReportFailed);
        assert_eq!(
            signal.error_code.expect("code").decimal,
            Some(-1005),
        );
    }

    #[test]
    fn an_unrecognized_app_type_round_trips_verbatim() {
        let signal = classify_record(
            &record(
                "AppInstaller",
                &format!("Received app policy AppId={APP} Type=vpp"),
            ),
            None,
            "2026-07-31T00:00:00Z",
        )
        .expect("classified");
        assert_eq!(signal.app_type, Some(PkgAppType::Unknown("vpp".to_owned())));
    }

    #[test]
    fn a_record_quoting_a_url_is_classified_restricted() {
        let signal = classify_record(
            &record(
                "AppInstaller",
                &format!("Downloading content for AppId={APP} Url=https://cdn.example/a.pkg"),
            ),
            None,
            "2026-07-31T00:00:00Z",
        )
        .expect("classified");
        assert_eq!(signal.context.sensitivity, IntuneSensitivity::Restricted);
    }

    #[test]
    fn an_unknown_phrase_is_not_guessed_at() {
        assert_eq!(classify_message("something entirely new happened"), None);
    }
}
