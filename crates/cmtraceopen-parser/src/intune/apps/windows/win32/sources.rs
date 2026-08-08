//! Source classification for Win32 app deployment evidence.
//!
//! A file name selects a *candidate* source kind. It is never proof on its own:
//! the candidate is only confirmed when the records inside carry a component
//! that belongs to that source. A file called `AppWorkload.log` full of
//! unrelated CCM records classifies as [`Win32SourceKind::Unknown`], which keeps
//! it visible in coverage instead of feeding the reducer.
//!
//! The module also owns the rotation grammar. IME rotates its logs as
//! `Name-1.log`, `Name-20260731-101522.log`, and the underscore-prefixed archive
//! form `_Name.log`; all three have to resolve to the same stem or a rotation
//! would silently classify as an unknown artifact.

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneSourceKind,
};

use super::models::Win32SourceKind;

/// One supplied artifact, before parsing.
///
/// The crate never opens files. Callers read the bytes, decode them, and hand
/// over the text with its original name and path. An artifact the caller could
/// *not* read is still passed in, with a non-`Available` [`IntuneAccessState`]
/// and empty content, because "we looked and it was not there" is a diagnostic
/// fact that "we did not pass it" cannot express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Win32SourceInput {
    pub artifact_id: String,
    /// Original file name, kept separate from the CCM `file=` source-code field.
    pub file_name: String,
    /// Original path. Privacy-sensitive: it commonly contains a profile name.
    pub file_path: Option<String>,
    pub access_state: IntuneAccessState,
    /// Already-decoded text. Empty unless `access_state` is `Available` or `Capped`.
    pub content: String,
    /// When the caller collected the artifact, as RFC 3339 UTC.
    ///
    /// Supplied rather than read from a clock so the analyzer stays pure and its
    /// serialized output stays reproducible.
    pub captured_at_utc: Option<String>,
}

impl Win32SourceInput {
    /// A readable artifact with decoded content.
    pub fn captured(
        artifact_id: impl Into<String>,
        file_name: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            file_name: file_name.into(),
            file_path: None,
            access_state: IntuneAccessState::Available,
            content: content.into(),
            captured_at_utc: None,
        }
    }

    /// An artifact the caller looked for and could not use.
    pub fn unreadable(
        artifact_id: impl Into<String>,
        file_name: impl Into<String>,
        access_state: IntuneAccessState,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            file_name: file_name.into(),
            file_path: None,
            access_state,
            content: String::new(),
            captured_at_utc: None,
        }
    }

    /// Whether there is any text to frame into records.
    pub fn has_content(&self) -> bool {
        matches!(
            self.access_state,
            IntuneAccessState::Available | IntuneAccessState::Capped
        ) && !self.content.is_empty()
    }
}

/// Components that confirm the primary IME log.
const IME_COMPONENTS: &[&str] = &["IntuneManagementExtension", "Win32App", "AppWorkload"];

/// Components that confirm `AppWorkload.log`.
const APP_WORKLOAD_COMPONENTS: &[&str] = &["AppWorkload", "Win32App"];

/// Components that confirm `AppActionProcessor.log`.
const APP_ACTION_PROCESSOR_COMPONENTS: &[&str] = &["AppActionProcessor", "Win32App"];

/// Components that confirm `AgentExecutor.log`.
const AGENT_EXECUTOR_COMPONENTS: &[&str] = &["AgentExecutor"];

/// Extensions that mark an installer-native supplemental artifact.
const INSTALLER_OUTPUT_EXTENSIONS: &[&str] = &[".msi.log", ".psadt.log", ".burn.log", ".output"];

/// Strip a rotation suffix and the `.log` extension.
///
/// Returns the stem and the rotation ordinal when the name identifies one; `0`
/// is the live file. The underscore-prefixed archive form reports `None` rather
/// than `Some(1)`, because it says the file *is* a rotation without saying which
/// one, and claiming an ordinal would make it indistinguishable from `-1`.
pub(super) fn split_rotation(file_name: &str) -> (String, Option<u32>) {
    let trimmed = file_name.trim();
    // Strip the `.log` extension case-insensitively: IME archives are seen as
    // `.log`, `.LOG`, `.Log`, etc. in the wild, and a mixed-case suffix must
    // still resolve to the canonical stem so rotated variants map to one
    // artifact. `strip_suffix` on the lowercased copy gives the boundary, but
    // we slice the original by char count, so a multi-byte name (e.g.
    // "Журнал.log") never splits a UTF-8 sequence.
    let without_ext = {
        let lowered = trimmed.to_ascii_lowercase();
        if lowered.ends_with(".log") {
            // ".log" is 4 ASCII bytes; the char boundary 4 bytes from the end
            // is valid because those 4 bytes are exactly the ASCII suffix.
            &trimmed[..trimmed.len() - 4]
        } else {
            trimmed
        }
    };

    let (without_ext, underscore_archive) = match without_ext.strip_prefix('_') {
        Some(rest) => (rest, true),
        None => (without_ext, false),
    };

    let live_ordinal = if underscore_archive { None } else { Some(0) };

    let Some((stem, suffix)) = without_ext.rsplit_once('-') else {
        return (without_ext.to_string(), live_ordinal);
    };

    if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
        // `-20260731-101522`: a datestamped rotation. The date half identifies
        // it, so check the preceding segment before treating this trailing run
        // of digits as an ordinal.
        if let Some((stem_before_date, date_part)) = stem.rsplit_once('-') {
            if date_part.len() >= 8 && date_part.chars().all(|c| c.is_ascii_digit()) {
                return (stem_before_date.to_string(), None);
            }
        }
        if suffix.len() >= 8 {
            return (stem.to_string(), None);
        }
        if let Ok(ordinal) = suffix.parse::<u32>() {
            return (stem.to_string(), Some(ordinal));
        }
    }

    (without_ext.to_string(), live_ordinal)
}

fn is_installer_output_name(file_name: &str) -> bool {
    let lowered = file_name.trim().to_ascii_lowercase();
    INSTALLER_OUTPUT_EXTENSIONS
        .iter()
        .any(|extension| lowered.ends_with(extension))
}

/// The source kind a file name suggests, before any content is read.
///
/// Exposed so a caller can decide not to parse an artifact at all, which is what
/// the reducer does for installer-native output.
pub fn candidate_source_kind(input: &Win32SourceInput) -> Win32SourceKind {
    if is_installer_output_name(&input.file_name) {
        return Win32SourceKind::InstallerOutput;
    }
    let (stem, _) = split_rotation(&input.file_name);
    match stem.to_ascii_lowercase().as_str() {
        "intunemanagementextension" => Win32SourceKind::IntuneManagementExtension,
        "appworkload" => Win32SourceKind::AppWorkload,
        "appactionprocessor" => Win32SourceKind::AppActionProcessor,
        "agentexecutor" => Win32SourceKind::AgentExecutor,
        _ => Win32SourceKind::Unknown,
    }
}

fn expected_components(candidate: Win32SourceKind) -> &'static [&'static str] {
    match candidate {
        Win32SourceKind::IntuneManagementExtension => IME_COMPONENTS,
        Win32SourceKind::AppWorkload => APP_WORKLOAD_COMPONENTS,
        Win32SourceKind::AppActionProcessor => APP_ACTION_PROCESSOR_COMPONENTS,
        Win32SourceKind::AgentExecutor => AGENT_EXECUTOR_COMPONENTS,
        Win32SourceKind::InstallerOutput | Win32SourceKind::Unknown => &[],
    }
}

/// Does any record component confirm the candidate?
fn components_confirm(candidate: Win32SourceKind, components: &[Option<String>]) -> bool {
    let expected = expected_components(candidate);
    if expected.is_empty() {
        return false;
    }
    components.iter().flatten().any(|component| {
        expected
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(component))
    })
}

/// Classify one artifact from its name and the components actually present in it.
///
/// `components` is every framed record's `component=` attribute, in source order.
/// An artifact with no readable content cannot be confirmed by its records, so it
/// keeps its candidate kind: refusing to name a missing `AppWorkload.log` would
/// destroy the very coverage gap the caller passed it in to express.
pub fn classify_artifact(
    input: &Win32SourceInput,
    components: &[Option<String>],
) -> Win32SourceKind {
    let candidate = candidate_source_kind(input);
    match candidate {
        // Self-identifying by name; there is no CCM component to confirm, and
        // the contents are deliberately never read.
        Win32SourceKind::InstallerOutput => candidate,
        Win32SourceKind::Unknown => Win32SourceKind::Unknown,
        _ if !input.has_content() => candidate,
        _ if components_confirm(candidate, components) => candidate,
        _ => Win32SourceKind::Unknown,
    }
}

/// Map a caller-declared access state onto the shared coverage status.
///
/// Binding these two vocabularies in one place is what stops a bundle declaring
/// an artifact absent and then reporting coverage for it as available.
pub(super) fn coverage_status(access_state: &IntuneAccessState) -> IntuneArtifactStatus {
    match access_state {
        IntuneAccessState::Available => IntuneArtifactStatus::Available,
        IntuneAccessState::Missing => IntuneArtifactStatus::Missing,
        IntuneAccessState::PermissionDenied => IntuneArtifactStatus::PermissionDenied,
        IntuneAccessState::Capped => IntuneArtifactStatus::Capped,
        IntuneAccessState::Skipped => IntuneArtifactStatus::Skipped,
        IntuneAccessState::Failed => IntuneArtifactStatus::ParseFailed,
        IntuneAccessState::Unsupported => IntuneArtifactStatus::Unsupported,
    }
}

/// The shared source kind that matches a Win32 artifact kind.
pub(super) fn intune_source_kind(kind: Win32SourceKind) -> IntuneSourceKind {
    match kind {
        Win32SourceKind::IntuneManagementExtension
        | Win32SourceKind::AppWorkload
        | Win32SourceKind::AppActionProcessor => IntuneSourceKind::ImeLog,
        Win32SourceKind::AgentExecutor => IntuneSourceKind::AgentLog,
        Win32SourceKind::InstallerOutput => IntuneSourceKind::PlainTextLog,
        Win32SourceKind::Unknown => IntuneSourceKind::Unknown("unknown".to_owned()),
    }
}

/// The coverage family a Win32 artifact belongs to.
pub(super) fn coverage_family(kind: Win32SourceKind) -> &'static str {
    match kind {
        Win32SourceKind::IntuneManagementExtension
        | Win32SourceKind::AppWorkload
        | Win32SourceKind::AppActionProcessor
        | Win32SourceKind::AgentExecutor => "ime",
        Win32SourceKind::InstallerOutput => "installer",
        Win32SourceKind::Unknown => "unknown",
    }
}

/// Build the coverage entry for one supplied artifact.
pub(super) fn artifact_coverage(
    input: &Win32SourceInput,
    kind: Win32SourceKind,
    detail: Option<String>,
) -> IntuneArtifactCoverage {
    IntuneArtifactCoverage {
        artifact_id: input.artifact_id.clone(),
        family: coverage_family(kind).to_owned(),
        status: coverage_status(&input.access_state),
        detail,
        observed_at_utc: input.captured_at_utc.clone().unwrap_or_default(),
        evidence: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(file_name: &str) -> Win32SourceInput {
        Win32SourceInput::captured("a1", file_name, "content")
    }

    fn components(values: &[&str]) -> Vec<Option<String>> {
        values.iter().map(|v| Some((*v).to_string())).collect()
    }

    #[test]
    fn app_workload_name_with_a_matching_component_is_confirmed() {
        assert_eq!(
            classify_artifact(&input("AppWorkload.log"), &components(&["Win32App"])),
            Win32SourceKind::AppWorkload
        );
    }

    #[test]
    fn app_workload_name_without_a_matching_component_stays_unknown() {
        // The whole point of the rule: the name alone must not classify.
        assert_eq!(
            classify_artifact(&input("AppWorkload.log"), &components(&["CcmExec"])),
            Win32SourceKind::Unknown
        );
    }

    #[test]
    fn app_action_processor_is_a_distinct_kind() {
        assert_eq!(
            classify_artifact(
                &input("AppActionProcessor.log"),
                &components(&["AppActionProcessor"])
            ),
            Win32SourceKind::AppActionProcessor
        );
    }

    #[test]
    fn an_unreadable_artifact_keeps_its_candidate_kind() {
        // Otherwise a declared-absent AppWorkload.log would classify as Unknown
        // and the coverage gap the caller passed it in to express would vanish.
        let missing = Win32SourceInput::unreadable(
            "aw",
            "AppWorkload.log",
            crate::intune::evidence::IntuneAccessState::Missing,
        );
        assert_eq!(
            classify_artifact(&missing, &[]),
            Win32SourceKind::AppWorkload
        );
    }

    #[test]
    fn installer_output_is_self_identifying_by_name() {
        assert_eq!(
            classify_artifact(&input("Contoso-Setup.msi.log"), &[]),
            Win32SourceKind::InstallerOutput
        );
        assert_eq!(
            candidate_source_kind(&input("PSAppDeployToolkit.psadt.log")),
            Win32SourceKind::InstallerOutput
        );
    }

    #[test]
    fn unrelated_names_stay_unknown_even_with_a_win32_component() {
        assert_eq!(
            classify_artifact(&input("CcmExec.log"), &components(&["Win32App"])),
            Win32SourceKind::Unknown
        );
    }

    #[test]
    fn numeric_rotation_ordinal_is_extracted() {
        assert_eq!(
            split_rotation("AppWorkload-1.log"),
            ("AppWorkload".to_string(), Some(1))
        );
    }

    #[test]
    fn datestamped_rotation_keeps_its_stem_without_an_ordinal() {
        assert_eq!(
            split_rotation("IntuneManagementExtension-20260731-101522.log"),
            ("IntuneManagementExtension".to_string(), None)
        );
    }

    #[test]
    fn underscore_archive_form_is_a_rotation_without_a_trustworthy_ordinal() {
        assert_eq!(
            split_rotation("_AppWorkload.log"),
            ("AppWorkload".to_string(), None)
        );
    }

    #[test]
    fn log_extension_is_stripped_case_insensitively() {
        assert_eq!(
            split_rotation("AppWorkload.Log"),
            ("AppWorkload".to_string(), Some(0))
        );
        assert_eq!(
            split_rotation("IntuneManagementExtension-1.LOG"),
            ("IntuneManagementExtension".to_string(), Some(1))
        );
    }

    #[test]
    fn multibyte_names_do_not_panic_and_keep_their_stem() {
        // "Журнал" is multi-byte UTF-8; slicing by byte index at len-4 would
        // panic if the suffix check were not char-boundary-safe.
        assert_eq!(
            split_rotation("Журнал.log"),
            ("Журнал".to_string(), Some(0))
        );
        // A name whose extension is not exactly `.log` is left untouched.
        assert_eq!(split_rotation("aé.lo"), ("aé.lo".to_string(), Some(0)));
    }

    #[test]
    fn every_access_state_maps_to_exactly_one_coverage_status() {
        for (state, status) in [
            (
                IntuneAccessState::Available,
                IntuneArtifactStatus::Available,
            ),
            (IntuneAccessState::Missing, IntuneArtifactStatus::Missing),
            (
                IntuneAccessState::PermissionDenied,
                IntuneArtifactStatus::PermissionDenied,
            ),
            (IntuneAccessState::Capped, IntuneArtifactStatus::Capped),
            (IntuneAccessState::Skipped, IntuneArtifactStatus::Skipped),
            (IntuneAccessState::Failed, IntuneArtifactStatus::ParseFailed),
            (
                IntuneAccessState::Unsupported,
                IntuneArtifactStatus::Unsupported,
            ),
        ] {
            assert_eq!(coverage_status(&state), status);
        }
    }
}
