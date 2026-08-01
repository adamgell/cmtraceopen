//! Message classification for shell-script execution records.
//!
//! A record becomes a signal only when its component owns script execution and
//! its message states **both** a `PolicyId` and a `RunId`. Requiring both is
//! what keeps two runs of the same policy in the same minute apart: they share
//! everything except the run id.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{ShellExecutionContext, ShellScriptRunKey};
use crate::intune::apps::macos::pkg::shared::agent_log::{MacAgentProcess, MacAgentRecord};
use crate::intune::apps::macos::pkg::shared::fields::{error_code_field, field, fields, guid_field};
use crate::intune::evidence::{
    IntuneAccessState, IntuneErrorCode, IntuneNamedValue, IntuneObservationContext,
    IntuneSensitivity,
};

/// Components that own macOS shell-script execution.
///
/// `AppInstaller` is deliberately absent: a package record is app evidence and
/// never becomes a script signal, even though both share the agent envelope.
pub const SHELL_SCRIPT_COMPONENTS: &[&str] = &["ShellScriptManager", "ScriptRunner"];

/// What a shell-script record asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellSignalKind {
    PolicyReceived,
    Scheduled,
    Launched,
    LaunchFailed,
    OutputCaptured,
    OutputEmpty,
    Completed,
    TimedOut,
    RetryScheduled,
    Reported,
    ReportFailed,
}

/// One classified record, keyed and ready to reduce.
#[derive(Debug, Clone)]
pub struct ShellSignal {
    pub kind: ShellSignalKind,
    pub key: ShellScriptRunKey,
    pub display_name: Option<String>,
    pub execution_context: Option<ShellExecutionContext>,
    pub exit_code: Option<IntuneErrorCode>,
    pub error_code: Option<IntuneErrorCode>,
    pub timeout_seconds: Option<u64>,
    pub attributes: Vec<IntuneNamedValue>,
    pub context: IntuneObservationContext,
}

/// Message phrases this grammar revision recognizes, in evaluation order.
///
/// `failed to launch` and `failed to report` precede their positive
/// counterparts so the more specific phrase is not shadowed.
fn phrase_table() -> &'static [(Regex, ShellSignalKind)] {
    static CELL: OnceLock<Vec<(Regex, ShellSignalKind)>> = OnceLock::new();
    CELL.get_or_init(|| {
        [
            (
                r"^received shell script policy\b",
                ShellSignalKind::PolicyReceived,
            ),
            (r"^scheduled shell script\b", ShellSignalKind::Scheduled),
            (
                r"^failed to launch shell script\b",
                ShellSignalKind::LaunchFailed,
            ),
            (r"^launching shell script\b", ShellSignalKind::Launched),
            (r"^captured (?:stdout|stderr)\b", ShellSignalKind::OutputCaptured),
            (
                r"^shell script produced no output\b",
                ShellSignalKind::OutputEmpty,
            ),
            (r"^shell script timed out\b", ShellSignalKind::TimedOut),
            (r"^shell script finished\b", ShellSignalKind::Completed),
            (
                r"^failed to report shell script result\b",
                ShellSignalKind::ReportFailed,
            ),
            (
                r"^reported shell script result\b",
                ShellSignalKind::Reported,
            ),
            (r"^scheduling retry\b", ShellSignalKind::RetryScheduled),
        ]
        .into_iter()
        .map(|(pattern, kind)| {
            (
                Regex::new(&format!("(?i){pattern}"))
                    .expect("shell script phrase regex must compile"),
                kind,
            )
        })
        .collect()
    })
}

/// The phrase a message matches, if any.
pub fn classify_message(message: &str) -> Option<ShellSignalKind> {
    phrase_table()
        .iter()
        .find(|(pattern, _)| pattern.is_match(message.trim()))
        .map(|(_, kind)| *kind)
}

/// The execution context a record states, falling back to the emitting process.
///
/// The stated `Context=` field wins. Only when a record is silent does the
/// process token stand in, because the daemon runs as root and the agent runs
/// in a user session — a structural fact, not a guess about the record.
fn execution_context(
    parsed: &[IntuneNamedValue],
    process: Option<&MacAgentProcess>,
) -> Option<ShellExecutionContext> {
    if let Some(stated) = field(parsed, "Context") {
        return Some(match stated.to_ascii_lowercase().as_str() {
            "system" | "root" => ShellExecutionContext::System,
            "user" => ShellExecutionContext::User,
            _ => ShellExecutionContext::Unknown(stated.to_owned()),
        });
    }
    match process {
        Some(MacAgentProcess::Daemon) => Some(ShellExecutionContext::System),
        Some(MacAgentProcess::Agent) => Some(ShellExecutionContext::User),
        _ => None,
    }
}

fn sensitivity_of(message: &str) -> IntuneSensitivity {
    if message.contains("://") || message.contains("/Users/") {
        IntuneSensitivity::Restricted
    } else {
        IntuneSensitivity::Sensitive
    }
}

/// Classify one record into a shell-script signal.
///
/// Returns `None` for a foreign component, an unknown phrase, or a message
/// missing either half of the run key.
pub fn classify_record(
    record: &MacAgentRecord,
    file_path: Option<&str>,
    observed_at_utc: &str,
) -> Option<ShellSignal> {
    if !record.component_is(SHELL_SCRIPT_COMPONENTS) {
        return None;
    }
    let kind = classify_message(&record.message)?;
    let parsed = fields(&record.message);
    let policy_id = guid_field(&parsed, "PolicyId")?;
    let run_id = guid_field(&parsed, "RunId")?;

    Some(ShellSignal {
        kind,
        key: ShellScriptRunKey {
            policy_id: policy_id.to_ascii_lowercase(),
            run_id: run_id.to_ascii_lowercase(),
        },
        display_name: field(&parsed, "Name").map(str::to_owned),
        execution_context: execution_context(&parsed, record.process.as_ref()),
        exit_code: error_code_field(&parsed, "ExitCode"),
        error_code: error_code_field(&parsed, "Error"),
        timeout_seconds: field(&parsed, "TimeoutSeconds").and_then(|value| value.parse().ok()),
        attributes: parsed,
        context: IntuneObservationContext {
            evidence_ref: record.evidence_ref(),
            provenance: record.provenance(file_path),
            source_timestamp: record.timestamp.clone(),
            observed_at_utc: observed_at_utc.to_owned(),
            sensitivity: sensitivity_of(&record.message),
            parse_state: record.parse_state.clone(),
            access_state: IntuneAccessState::Available,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::apps::macos::pkg::shared::agent_log::{
        parse_agent_log, MacAgentArtifactInput, MacAgentCaptureState,
    };

    const POLICY: &str = "11111111-1111-4111-8111-111111111111";
    const RUN: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";

    fn record(process: &str, component: &str, message: &str) -> MacAgentRecord {
        let input = MacAgentArtifactInput {
            artifact_id: "a1".to_owned(),
            family: "intuneMdmAgent".to_owned(),
            file_name: "IntuneMDMDaemon.log".to_owned(),
            sanitized_source_path: None,
            capture_state: MacAgentCaptureState::Captured,
            content: Some(format!(
                "2026-07-29 09:10:11:888 | {process} | I | 1 | {component} | {message}"
            )),
            detail: None,
        };
        parse_agent_log(&input).records.remove(0)
    }

    fn classify(process: &str, component: &str, message: &str) -> Option<ShellSignal> {
        classify_record(
            &record(process, component, message),
            None,
            "2026-07-31T00:00:00Z",
        )
    }

    #[test]
    fn a_policy_record_is_classified_and_keyed_on_both_identifiers() {
        let signal = classify(
            "IntuneMDM-Daemon",
            "ShellScriptManager",
            &format!("Received shell script policy PolicyId={POLICY} RunId={RUN} Name=Set Wallpaper"),
        )
        .expect("classified");
        assert_eq!(signal.kind, ShellSignalKind::PolicyReceived);
        assert_eq!(signal.key.policy_id, POLICY);
        assert_eq!(signal.key.run_id, RUN);
        assert_eq!(signal.display_name.as_deref(), Some("Set Wallpaper"));
    }

    #[test]
    fn a_record_missing_the_run_id_cannot_be_keyed_and_is_dropped() {
        assert!(classify(
            "IntuneMDM-Daemon",
            "ShellScriptManager",
            &format!("Shell script finished PolicyId={POLICY} ExitCode=0"),
        )
        .is_none());
    }

    #[test]
    fn a_package_component_never_produces_a_script_signal() {
        assert!(classify(
            "IntuneMDM-Daemon",
            "AppInstaller",
            &format!("Shell script finished PolicyId={POLICY} RunId={RUN} ExitCode=0"),
        )
        .is_none());
    }

    #[test]
    fn the_emitting_process_supplies_the_context_only_when_the_record_is_silent() {
        let implied = classify(
            "IntuneMDM-Agent",
            "ShellScriptManager",
            &format!("Launching shell script PolicyId={POLICY} RunId={RUN}"),
        )
        .expect("classified");
        assert_eq!(
            implied.execution_context,
            Some(ShellExecutionContext::User)
        );

        // A stated context always wins over the process inference.
        let stated = classify(
            "IntuneMDM-Agent",
            "ShellScriptManager",
            &format!("Launching shell script PolicyId={POLICY} RunId={RUN} Context=system"),
        )
        .expect("classified");
        assert_eq!(
            stated.execution_context,
            Some(ShellExecutionContext::System)
        );
    }

    #[test]
    fn launch_failure_is_matched_before_the_generic_launch_phrase() {
        let signal = classify(
            "IntuneMDM-Daemon",
            "ShellScriptManager",
            &format!("Failed to launch shell script PolicyId={POLICY} RunId={RUN} Error=-13"),
        )
        .expect("classified");
        assert_eq!(signal.kind, ShellSignalKind::LaunchFailed);
        assert_eq!(signal.error_code.expect("code").decimal, Some(-13));
    }

    #[test]
    fn a_timeout_retains_its_stated_limit() {
        let signal = classify(
            "IntuneMDM-Daemon",
            "ShellScriptManager",
            &format!("Shell script timed out PolicyId={POLICY} RunId={RUN} TimeoutSeconds=600"),
        )
        .expect("classified");
        assert_eq!(signal.timeout_seconds, Some(600));
    }

    #[test]
    fn an_unknown_phrase_is_not_guessed_at() {
        assert_eq!(classify_message("script did something novel"), None);
    }
}
