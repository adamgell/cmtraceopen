//! Source classification for platform-script evidence.
//!
//! A file name selects a *candidate* source kind. It is never proof on its own:
//! the candidate is only confirmed when the records inside carry a component
//! that belongs to that source. A file called `AgentExecutor.log` full of
//! unrelated CCM records classifies as [`ScriptSourceKind::Unknown`], which
//! keeps it visible in coverage instead of feeding the reducer.

use super::models::{ScriptArtifact, ScriptClassifiedString, ScriptSourceKind};

/// One supplied artifact, before parsing.
///
/// The pure crate never opens files. Callers read the bytes, decode them, and
/// hand over the text with its original name and path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptSourceInput {
    pub artifact_id: String,
    pub file_name: String,
    pub file_path: Option<String>,
    pub content: String,
}

/// Components that confirm a primary IME artifact.
const IME_COMPONENTS: &[&str] = &["IntuneManagementExtension", "PowerShell", "Win32App"];

/// Components that confirm an AgentExecutor artifact.
const AGENT_EXECUTOR_COMPONENTS: &[&str] = &["AgentExecutor"];

/// Components that confirm a HealthScripts artifact.
const HEALTH_SCRIPTS_COMPONENTS: &[&str] = &["HealthScripts"];

/// Strip a rotation suffix and the `.log` extension, returning the stem and the
/// rotation ordinal when the name identifies one.
///
/// Recognised shapes, all observed in IME log directories:
/// `AgentExecutor.log`, `AgentExecutor-20260312-101522.log`, `AgentExecutor-1.log`,
/// and the underscore-prefixed archive form `_AgentExecutor.log`.
fn split_rotation(file_name: &str) -> (String, Option<u32>) {
    let trimmed = file_name.trim();
    let without_ext = trimmed
        .strip_suffix(".log")
        .or_else(|| trimmed.strip_suffix(".LOG"))
        .unwrap_or(trimmed);

    // `_Name` marks an archived copy. It says the file is a rotation but not
    // which one, so the ordinal stays `None`; reporting `Some(1)` would make it
    // indistinguishable from an explicit `-1` and mislead ordering.
    let (without_ext, underscore_archive) = match without_ext.strip_prefix('_') {
        Some(rest) => (rest, true),
        None => (without_ext, false),
    };

    let live_ordinal = if underscore_archive { None } else { Some(0) };

    let Some((stem, suffix)) = without_ext.rsplit_once('-') else {
        return (without_ext.to_string(), live_ordinal);
    };

    if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
        // `-20260312-101522`: a datestamped rotation. The date half is what
        // identifies it, so check the preceding segment before deciding this
        // trailing run of digits is an ordinal.
        if let Some((stem2, date_part)) = stem.rsplit_once('-') {
            if date_part.len() >= 8 && date_part.chars().all(|c| c.is_ascii_digit()) {
                return (stem2.to_string(), None);
            }
        }

        // `-20260312`: a bare datestamp.
        if suffix.len() >= 8 {
            return (stem.to_string(), None);
        }

        // `-1`, `-2`: an explicit ordinal.
        if let Ok(ordinal) = suffix.parse::<u32>() {
            return (stem.to_string(), Some(ordinal));
        }
    }

    (without_ext.to_string(), live_ordinal)
}

/// `{policyId}_{runId}.output` / `.error` -- a retained script output artifact.
///
/// Unlike `AgentExecutor.log`, this name is not a bare word that any file could
/// coincidentally carry: it encodes both halves of a transaction key plus a
/// known extension, which is structure enough to classify on. The file's
/// *contents* are raw script stdout/stderr and are deliberately never parsed.
fn output_artifact_key(file_name: &str) -> Option<(String, String)> {
    let trimmed = file_name.trim();
    let stem = trimmed
        .strip_suffix(".output")
        .or_else(|| trimmed.strip_suffix(".error"))
        .or_else(|| trimmed.strip_suffix(".OUTPUT"))
        .or_else(|| trimmed.strip_suffix(".ERROR"))?;

    let (policy, run) = stem.split_once('_')?;
    if !is_guid(policy) || !is_guid(run) {
        return None;
    }
    Some((policy.to_ascii_lowercase(), run.to_ascii_lowercase()))
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

/// The transaction key a retained output artifact belongs to, if it is one.
pub fn output_artifact_identity(input: &ScriptSourceInput) -> Option<(String, String)> {
    output_artifact_key(&input.file_name)
}

/// The source kind a file name suggests, before content confirms it.
fn candidate_from_name(file_name: &str) -> ScriptSourceKind {
    if output_artifact_key(file_name).is_some() {
        return ScriptSourceKind::ScriptOutput;
    }
    let (stem, _) = split_rotation(file_name);
    match stem.to_ascii_lowercase().as_str() {
        "intunemanagementextension" => ScriptSourceKind::IntuneManagementExtension,
        "agentexecutor" => ScriptSourceKind::AgentExecutor,
        "healthscripts" => ScriptSourceKind::HealthScripts,
        _ => ScriptSourceKind::Unknown,
    }
}

/// Does any record component confirm the candidate?
fn components_confirm(candidate: ScriptSourceKind, components: &[Option<String>]) -> bool {
    let expected: &[&str] = match candidate {
        ScriptSourceKind::IntuneManagementExtension => IME_COMPONENTS,
        ScriptSourceKind::AgentExecutor => AGENT_EXECUTOR_COMPONENTS,
        ScriptSourceKind::HealthScripts => HEALTH_SCRIPTS_COMPONENTS,
        _ => return false,
    };

    components.iter().flatten().any(|component| {
        expected
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(component))
    })
}

/// Classify one artifact from its name and the components actually present in it.
///
/// `components` is every record's `component=` attribute, in source order.
pub fn classify_artifact(
    input: &ScriptSourceInput,
    components: &[Option<String>],
) -> ScriptArtifact {
    let candidate = candidate_from_name(&input.file_name);
    let (_, rotation_ordinal) = split_rotation(&input.file_name);

    let source_kind = if candidate == ScriptSourceKind::ScriptOutput {
        // Self-identifying by name; there is no CCM component to confirm.
        candidate
    } else if components_confirm(candidate, components) {
        candidate
    } else {
        ScriptSourceKind::Unknown
    };

    ScriptArtifact {
        artifact_id: input.artifact_id.clone(),
        file_name: input.file_name.clone(),
        file_path: input
            .file_path
            .as_ref()
            .map(|path| ScriptClassifiedString::sensitive(path.clone())),
        source_kind,
        rotation_ordinal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(file_name: &str) -> ScriptSourceInput {
        ScriptSourceInput {
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
    fn agent_executor_name_with_matching_component_is_confirmed() {
        let artifact =
            classify_artifact(&input("AgentExecutor.log"), &components(&["AgentExecutor"]));
        assert_eq!(artifact.source_kind, ScriptSourceKind::AgentExecutor);
        assert_eq!(artifact.rotation_ordinal, Some(0));
    }

    #[test]
    fn agent_executor_name_without_matching_component_stays_unknown() {
        // The whole point of the rule: the name alone must not classify.
        let artifact = classify_artifact(&input("AgentExecutor.log"), &components(&["CcmExec"]));
        assert_eq!(artifact.source_kind, ScriptSourceKind::Unknown);
    }

    #[test]
    fn ime_name_is_confirmed_by_any_expected_component() {
        let artifact = classify_artifact(
            &input("IntuneManagementExtension.log"),
            &components(&["PowerShell"]),
        );
        assert_eq!(
            artifact.source_kind,
            ScriptSourceKind::IntuneManagementExtension
        );
    }

    #[test]
    fn health_scripts_is_classified_but_remains_a_distinct_kind() {
        let artifact =
            classify_artifact(&input("HealthScripts.log"), &components(&["HealthScripts"]));
        assert_eq!(artifact.source_kind, ScriptSourceKind::HealthScripts);
    }

    #[test]
    fn unrelated_name_is_unknown_even_with_a_script_component() {
        let artifact = classify_artifact(&input("CcmExec.log"), &components(&["AgentExecutor"]));
        assert_eq!(artifact.source_kind, ScriptSourceKind::Unknown);
    }

    #[test]
    fn numeric_rotation_ordinal_is_extracted() {
        let (stem, ordinal) = split_rotation("AgentExecutor-1.log");
        assert_eq!(stem, "AgentExecutor");
        assert_eq!(ordinal, Some(1));
    }

    #[test]
    fn datestamped_rotation_has_no_ordinal_but_keeps_its_stem() {
        let (stem, ordinal) = split_rotation("IntuneManagementExtension-20260312-101522.log");
        assert_eq!(stem, "IntuneManagementExtension");
        assert_eq!(ordinal, None);
    }

    #[test]
    fn underscore_archive_form_is_a_rotation_without_a_trustworthy_ordinal() {
        let (stem, ordinal) = split_rotation("_AgentExecutor.log");
        assert_eq!(stem, "AgentExecutor");
        // Not `Some(1)`: that would be indistinguishable from `-1`.
        assert_eq!(ordinal, None);
    }

    #[test]
    fn retained_output_artifact_is_classified_from_its_encoded_identity() {
        let policy = "11111111-1111-4111-8111-111111111111";
        let run = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";
        let artifact = classify_artifact(&input(&format!("{policy}_{run}.output")), &[]);
        assert_eq!(artifact.source_kind, ScriptSourceKind::ScriptOutput);
        assert_eq!(
            output_artifact_key(&format!("{policy}_{run}.error")),
            Some((policy.to_string(), run.to_string()))
        );
    }

    #[test]
    fn an_arbitrary_output_file_is_not_a_script_output_artifact() {
        assert_eq!(output_artifact_key("build.output"), None);
        assert_eq!(output_artifact_key("notaguid_alsonotaguid.output"), None);
        let artifact = classify_artifact(&input("build.output"), &[]);
        assert_eq!(artifact.source_kind, ScriptSourceKind::Unknown);
    }

    #[test]
    fn file_path_is_classified_sensitive() {
        let mut source = input("AgentExecutor.log");
        source.file_path = Some(
            r"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AgentExecutor.log"
                .to_string(),
        );
        let artifact = classify_artifact(&source, &components(&["AgentExecutor"]));
        assert_eq!(
            artifact.file_path.unwrap().sensitivity,
            crate::intune::apps::windows::scripts::ScriptSensitivity::Sensitive
        );
    }
}
