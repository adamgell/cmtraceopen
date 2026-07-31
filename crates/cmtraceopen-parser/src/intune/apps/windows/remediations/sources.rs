//! Source classification for remediation evidence.
//!
//! A file name selects a *candidate*; records inside must confirm it. A file
//! called `HealthScripts.log` full of unrelated CCM records classifies as
//! [`RemediationSourceKind::Unknown`], which keeps it visible in coverage
//! instead of feeding the reducer.

use super::models::{RemediationArtifact, RemediationClassifiedString, RemediationSourceKind};

/// One supplied artifact, before parsing.
///
/// The pure crate never opens files. Callers read the bytes, decode them, and
/// hand over the text with its original name and path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationSourceInput {
    pub artifact_id: String,
    pub file_name: String,
    pub file_path: Option<String>,
    pub content: String,
}

const HEALTH_SCRIPTS_COMPONENTS: &[&str] = &["HealthScripts"];
const AGENT_EXECUTOR_COMPONENTS: &[&str] = &["AgentExecutor"];
/// Components that confirm a *file* is the primary IME log. Wider than the
/// record-scope list in `rules.rs` on purpose: any workload's component proves
/// the file's identity, but only some may speak for this workload.
const IME_FILE_COMPONENTS: &[&str] = &[
    "IntuneManagementExtension",
    "PowerShell",
    "Win32App",
    "HealthScripts",
];

/// Strip a rotation suffix and the `.log` extension.
///
/// `_Name` marks an archived copy: a rotation whose ordinal we cannot trust to
/// be sequential, so the ordinal stays `None` rather than pretending to be 1.
/// Strip `suffix` from the end of `value`, ignoring case.
///
/// Windows file names are case-insensitive, so `HealthScripts.Log` and
/// `{policy}_{run}.Output` are the same artifacts as their lowercase forms.
fn strip_suffix_ignore_case<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    let split = value.len().checked_sub(suffix.len())?;
    if !value.is_char_boundary(split) {
        return None;
    }
    let (head, tail) = value.split_at(split);
    tail.eq_ignore_ascii_case(suffix).then_some(head)
}

fn split_rotation(file_name: &str) -> (String, Option<u32>) {
    let trimmed = file_name.trim();
    let without_ext = strip_suffix_ignore_case(trimmed, ".log").unwrap_or(trimmed);

    let (without_ext, underscore_archive) = match without_ext.strip_prefix('_') {
        Some(rest) => (rest, true),
        None => (without_ext, false),
    };
    let live_ordinal = if underscore_archive { None } else { Some(0) };

    let Some((stem, suffix)) = without_ext.rsplit_once('-') else {
        return (without_ext.to_string(), live_ordinal);
    };

    if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
        // `-20260312-101522`: a datestamped rotation. Check the preceding
        // segment before treating this run of digits as an ordinal.
        if let Some((stem2, date_part)) = stem.rsplit_once('-') {
            if date_part.len() >= 8 && date_part.chars().all(|c| c.is_ascii_digit()) {
                return (stem2.to_string(), None);
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

fn is_guid(value: &str) -> bool {
    let groups = [8usize, 4, 4, 4, 12];
    let mut parts = value.split('-');
    for expected in groups {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.len() != expected || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    parts.next().is_none()
}

/// `{policyId}_{runId}.output` / `.error` -- a retained script output artifact.
///
/// The name encodes both halves of a transaction key plus a known extension,
/// which is structure enough to classify on. The contents are raw script output
/// and are deliberately never parsed.
fn output_artifact_key(file_name: &str) -> Option<(String, String)> {
    let trimmed = file_name.trim();
    let stem = strip_suffix_ignore_case(trimmed, ".output")
        .or_else(|| strip_suffix_ignore_case(trimmed, ".error"))?;
    let (policy, run) = stem.split_once('_')?;
    if !is_guid(policy) || !is_guid(run) {
        return None;
    }
    Some((policy.to_ascii_lowercase(), run.to_ascii_lowercase()))
}

/// The transaction key a retained output artifact belongs to, if it is one.
pub fn output_artifact_identity(input: &RemediationSourceInput) -> Option<(String, String)> {
    output_artifact_key(&input.file_name)
}

fn candidate_from_name(file_name: &str) -> RemediationSourceKind {
    if output_artifact_key(file_name).is_some() {
        return RemediationSourceKind::ScriptOutput;
    }
    let (stem, _) = split_rotation(file_name);
    match stem.to_ascii_lowercase().as_str() {
        "healthscripts" => RemediationSourceKind::HealthScripts,
        "agentexecutor" => RemediationSourceKind::AgentExecutor,
        "intunemanagementextension" => RemediationSourceKind::IntuneManagementExtension,
        _ => RemediationSourceKind::Unknown,
    }
}

/// The source kind a file name suggests, before any content is read.
///
/// Exposed so a caller can decide not to parse an artifact at all -- which is
/// what the reducer does for retained script output.
pub fn candidate_source_kind(input: &RemediationSourceInput) -> RemediationSourceKind {
    candidate_from_name(&input.file_name)
}

fn components_confirm(candidate: RemediationSourceKind, components: &[Option<String>]) -> bool {
    let expected: &[&str] = match candidate {
        RemediationSourceKind::HealthScripts => HEALTH_SCRIPTS_COMPONENTS,
        RemediationSourceKind::AgentExecutor => AGENT_EXECUTOR_COMPONENTS,
        RemediationSourceKind::IntuneManagementExtension => IME_FILE_COMPONENTS,
        _ => return false,
    };
    components.iter().flatten().any(|component| {
        expected
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(component))
    })
}

/// Classify one artifact from its name and the components actually present.
pub fn classify_artifact(
    input: &RemediationSourceInput,
    components: &[Option<String>],
) -> RemediationArtifact {
    let candidate = candidate_from_name(&input.file_name);
    let (_, rotation_ordinal) = split_rotation(&input.file_name);

    let source_kind = if candidate == RemediationSourceKind::ScriptOutput {
        // Self-identifying by name; there is no CCM component to confirm.
        candidate
    } else if components_confirm(candidate, components) {
        candidate
    } else {
        RemediationSourceKind::Unknown
    };

    RemediationArtifact {
        artifact_id: input.artifact_id.clone(),
        file_name: input.file_name.clone(),
        file_path: input
            .file_path
            .as_ref()
            .map(|path| RemediationClassifiedString::sensitive(path.clone())),
        source_kind,
        rotation_ordinal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(file_name: &str) -> RemediationSourceInput {
        RemediationSourceInput {
            artifact_id: "a1".to_string(),
            file_name: file_name.to_string(),
            file_path: None,
            content: String::new(),
        }
    }

    fn components(values: &[&str]) -> Vec<Option<String>> {
        values.iter().map(|v| Some((*v).to_string())).collect()
    }

    #[test]
    fn health_scripts_name_with_matching_component_is_confirmed() {
        let artifact =
            classify_artifact(&input("HealthScripts.log"), &components(&["HealthScripts"]));
        assert_eq!(artifact.source_kind, RemediationSourceKind::HealthScripts);
        assert_eq!(artifact.rotation_ordinal, Some(0));
    }

    #[test]
    fn health_scripts_name_without_matching_component_stays_unknown() {
        let artifact = classify_artifact(&input("HealthScripts.log"), &components(&["CcmExec"]));
        assert_eq!(artifact.source_kind, RemediationSourceKind::Unknown);
    }

    #[test]
    fn unrelated_name_is_unknown_even_with_a_remediation_component() {
        let artifact = classify_artifact(&input("CcmExec.log"), &components(&["HealthScripts"]));
        assert_eq!(artifact.source_kind, RemediationSourceKind::Unknown);
    }

    #[test]
    fn underscore_archive_form_has_no_trustworthy_ordinal() {
        let (stem, ordinal) = split_rotation("_HealthScripts.log");
        assert_eq!(stem, "HealthScripts");
        assert_eq!(ordinal, None);
    }

    #[test]
    fn datestamped_rotation_keeps_its_stem() {
        let (stem, ordinal) = split_rotation("HealthScripts-20260312-101522.log");
        assert_eq!(stem, "HealthScripts");
        assert_eq!(ordinal, None);
    }

    #[test]
    fn retained_output_artifact_is_classified_from_its_encoded_identity() {
        let policy = "11111111-1111-4111-8111-111111111111";
        let run = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";
        let artifact = classify_artifact(&input(&format!("{policy}_{run}.output")), &[]);
        assert_eq!(artifact.source_kind, RemediationSourceKind::ScriptOutput);
    }

    #[test]
    fn extensions_match_case_insensitively_like_windows_does() {
        let policy = "11111111-1111-4111-8111-111111111111";
        let run = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";
        assert_eq!(split_rotation("HealthScripts.Log").0, "HealthScripts");
        assert!(output_artifact_key(&format!("{policy}_{run}.Output")).is_some());
        assert!(output_artifact_key(&format!("{policy}_{run}.ERROR")).is_some());
    }

    #[test]
    fn an_ime_log_of_only_health_scripts_records_is_still_confirmed() {
        let artifact = classify_artifact(
            &input("IntuneManagementExtension.log"),
            &components(&["HealthScripts"]),
        );
        assert_eq!(
            artifact.source_kind,
            RemediationSourceKind::IntuneManagementExtension
        );
    }

    #[test]
    fn an_arbitrary_output_file_is_not_a_script_output_artifact() {
        assert_eq!(output_artifact_key("build.output"), None);
        assert_eq!(
            classify_artifact(&input("build.output"), &[]).source_kind,
            RemediationSourceKind::Unknown
        );
    }

    #[test]
    fn file_path_is_classified_sensitive() {
        let mut source = input("HealthScripts.log");
        source.file_path = Some(
            r"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\HealthScripts.log"
                .to_string(),
        );
        let artifact = classify_artifact(&source, &components(&["HealthScripts"]));
        assert_eq!(
            artifact.file_path.unwrap().sensitivity,
            super::super::models::RemediationSensitivity::Sensitive
        );
    }
}
