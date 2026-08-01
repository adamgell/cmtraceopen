//! Source classification for remediation evidence.
//!
//! A file name selects a *candidate* source kind; the candidate is confirmed
//! only when the records inside carry a component that belongs to that source.
//! A file called `HealthScripts.log` full of unrelated CCM records classifies as
//! [`RemediationSourceKind::Unknown`], which keeps it visible in coverage
//! instead of feeding the reducer a key it never earned.

use crate::intune::evidence::IntuneAccessState;

use super::models::RemediationSourceKind;

/// One supplied artifact, before parsing.
///
/// The crate never opens files. The caller reads the bytes, decodes them, and
/// hands over the text together with how the collection went, so that an
/// artifact which was missing, capped, or refused stays describable instead of
/// being silently absent from the bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationSourceInput {
    pub artifact_id: String,
    pub file_name: String,
    pub file_path: Option<String>,
    /// When the artifact was collected, in RFC 3339. Used verbatim as the
    /// observation time so that a pure, clock-free parser still reports when
    /// the evidence was seen.
    pub captured_at_utc: Option<String>,
    pub access_state: IntuneAccessState,
    /// `None` for every state that produced no bytes.
    pub content: Option<String>,
}

impl RemediationSourceInput {
    /// A captured artifact with its text.
    pub fn captured(
        artifact_id: impl Into<String>,
        file_name: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            file_name: file_name.into(),
            file_path: None,
            captured_at_utc: None,
            access_state: IntuneAccessState::Available,
            content: Some(content.into()),
        }
    }

    /// An artifact that was expected and not collected.
    pub fn absent(artifact_id: impl Into<String>, file_name: impl Into<String>) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            file_name: file_name.into(),
            file_path: None,
            captured_at_utc: None,
            access_state: IntuneAccessState::Missing,
            content: None,
        }
    }
}

/// Components that confirm a `HealthScripts` artifact.
const HEALTH_SCRIPTS_COMPONENTS: &[&str] = &["HealthScripts"];

/// Components that confirm an `AgentExecutor` artifact.
const AGENT_EXECUTOR_COMPONENTS: &[&str] = &["AgentExecutor"];

/// Components that confirm the shared IME artifact.
const IME_COMPONENTS: &[&str] = &[
    "IntuneManagementExtension",
    "PowerShell",
    "Win32App",
    "HealthScripts",
];

/// Strip a rotation suffix and the `.log` extension.
///
/// Recognised shapes, all observed in IME log directories: `HealthScripts.log`,
/// `HealthScripts-20260312-101522.log`, `HealthScripts-1.log`, and the
/// underscore-prefixed archive form `_HealthScripts.log`.
fn split_rotation(file_name: &str) -> (String, Option<u32>) {
    let trimmed = file_name.trim();
    let without_ext = trimmed
        .strip_suffix(".log")
        .or_else(|| trimmed.strip_suffix(".LOG"))
        .unwrap_or(trimmed);

    // `_Name` marks an archived copy: it proves the file is a rotation but not
    // which one, so the ordinal stays `None`. Reporting `Some(1)` would make it
    // indistinguishable from an explicit `-1`.
    let (without_ext, underscore_archive) = match without_ext.strip_prefix('_') {
        Some(rest) => (rest, true),
        None => (without_ext, false),
    };
    let live_ordinal = if underscore_archive { None } else { Some(0) };

    let Some((stem, suffix)) = without_ext.rsplit_once('-') else {
        return (without_ext.to_string(), live_ordinal);
    };

    if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
        // `-20260312-101522`: a datestamped rotation. The date half identifies
        // it, so check the preceding segment before reading the trailing digits
        // as an ordinal.
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

/// `{policyId}_{runId}.output` / `.error` -- a retained stage output artifact.
///
/// The name encodes both halves of a run key plus a known extension, which is
/// structure enough to classify on. The file's *contents* are raw script
/// stdout/stderr and are deliberately never parsed.
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

/// The run key a retained output artifact belongs to, if it is one.
pub fn output_artifact_identity(input: &RemediationSourceInput) -> Option<(String, String)> {
    output_artifact_key(&input.file_name)
}

fn candidate_from_name(file_name: &str) -> RemediationSourceKind {
    if output_artifact_key(file_name).is_some() {
        return RemediationSourceKind::RemediationOutput;
    }
    let lowered = file_name.trim().to_ascii_lowercase();
    if lowered.ends_with(".policy.json") || lowered == "remediation-policy.json" {
        return RemediationSourceKind::PolicyMetadata;
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
/// Exposed so a caller can decide not to parse an artifact at all, which is
/// what the reducer does for retained stage output and policy metadata.
pub fn candidate_source_kind(input: &RemediationSourceInput) -> RemediationSourceKind {
    candidate_from_name(&input.file_name)
}

/// The rotation ordinal a file name encodes, if any.
pub fn rotation_ordinal(file_name: &str) -> Option<u32> {
    split_rotation(file_name).1
}

fn components_confirm(candidate: RemediationSourceKind, components: &[Option<String>]) -> bool {
    let expected: &[&str] = match candidate {
        RemediationSourceKind::HealthScripts => HEALTH_SCRIPTS_COMPONENTS,
        RemediationSourceKind::AgentExecutor => AGENT_EXECUTOR_COMPONENTS,
        RemediationSourceKind::IntuneManagementExtension => IME_COMPONENTS,
        _ => return false,
    };
    components.iter().flatten().any(|component| {
        expected
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(component))
    })
}

/// Classify one artifact from its name and the components actually present.
///
/// `components` is every framed record's `component=` attribute, in source
/// order. A name-only match is never enough.
pub fn classify_source_kind(
    input: &RemediationSourceInput,
    components: &[Option<String>],
) -> RemediationSourceKind {
    let candidate = candidate_from_name(&input.file_name);
    match candidate {
        // Self-identifying by name: there is no CCM component to confirm.
        RemediationSourceKind::RemediationOutput | RemediationSourceKind::PolicyMetadata => {
            candidate
        }
        RemediationSourceKind::Unknown => RemediationSourceKind::Unknown,
        _ if components_confirm(candidate, components) => candidate,
        _ => RemediationSourceKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(file_name: &str) -> RemediationSourceInput {
        RemediationSourceInput::captured("a1", file_name, "")
    }

    fn components(values: &[&str]) -> Vec<Option<String>> {
        values.iter().map(|v| Some((*v).to_string())).collect()
    }

    #[test]
    fn health_scripts_name_with_matching_component_is_confirmed() {
        assert_eq!(
            classify_source_kind(&input("HealthScripts.log"), &components(&["HealthScripts"])),
            RemediationSourceKind::HealthScripts
        );
    }

    #[test]
    fn health_scripts_name_without_matching_component_stays_unknown() {
        assert_eq!(
            classify_source_kind(&input("HealthScripts.log"), &components(&["CcmExec"])),
            RemediationSourceKind::Unknown
        );
    }

    #[test]
    fn agent_executor_is_confirmed_by_its_own_component_only() {
        assert_eq!(
            classify_source_kind(&input("AgentExecutor.log"), &components(&["AgentExecutor"])),
            RemediationSourceKind::AgentExecutor
        );
        assert_eq!(
            classify_source_kind(&input("AgentExecutor.log"), &components(&["HealthScripts"])),
            RemediationSourceKind::Unknown
        );
    }

    #[test]
    fn an_unrelated_name_is_unknown_even_with_a_remediation_component() {
        assert_eq!(
            classify_source_kind(&input("CcmExec.log"), &components(&["HealthScripts"])),
            RemediationSourceKind::Unknown
        );
    }

    #[test]
    fn retained_output_artifacts_are_classified_from_their_encoded_identity() {
        let policy = "11111111-1111-4111-8111-111111111111";
        let run = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";
        let source = input(&format!("{policy}_{run}.output"));
        assert_eq!(
            classify_source_kind(&source, &[]),
            RemediationSourceKind::RemediationOutput
        );
        assert_eq!(
            output_artifact_identity(&source),
            Some((policy.to_string(), run.to_string()))
        );
    }

    #[test]
    fn an_arbitrary_output_file_is_not_a_retained_artifact() {
        assert_eq!(output_artifact_key("build.output"), None);
        assert_eq!(output_artifact_key("notaguid_alsonotaguid.output"), None);
    }

    #[test]
    fn policy_metadata_is_recognised_by_extension() {
        assert_eq!(
            classify_source_kind(&input("remediation-policy.json"), &[]),
            RemediationSourceKind::PolicyMetadata
        );
        assert_eq!(
            classify_source_kind(&input("contoso.policy.json"), &[]),
            RemediationSourceKind::PolicyMetadata
        );
    }

    #[test]
    fn rotation_shapes_are_split_the_way_the_log_directory_writes_them() {
        assert_eq!(
            split_rotation("HealthScripts.log"),
            ("HealthScripts".to_string(), Some(0))
        );
        assert_eq!(
            split_rotation("HealthScripts-1.log"),
            ("HealthScripts".to_string(), Some(1))
        );
        assert_eq!(
            split_rotation("HealthScripts-20260312-101522.log"),
            ("HealthScripts".to_string(), None)
        );
        // Not `Some(1)`: that would be indistinguishable from an explicit `-1`.
        assert_eq!(
            split_rotation("_HealthScripts.log"),
            ("HealthScripts".to_string(), None)
        );
    }

    #[test]
    fn an_absent_artifact_carries_no_content() {
        let absent = RemediationSourceInput::absent("a2", "AgentExecutor.log");
        assert_eq!(absent.access_state, IntuneAccessState::Missing);
        assert!(absent.content.is_none());
    }
}
