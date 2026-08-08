//! Source classification for Microsoft Store app evidence.
//!
//! Two rules govern this module, both taken directly from the source contract:
//!
//! 1. A file name selects a *candidate* only. It is confirmed when the records
//!    inside carry a CCM component that belongs to that source. A file called
//!    `IntuneManagementExtension.log` holding unrelated records classifies as
//!    [`StoreTextSource::Unknown`] and contributes nothing but coverage.
//! 2. An event is Store evidence only when its provider *and* channel are both
//!    recognized. Text that merely mentions `PackageFamilyName` is not an AppX
//!    deployment record, and a plain-text export with no channel metadata can
//!    never be promoted into one.

use crate::intune::ime_parser::ImeLine;

/// A CCM-framed text artifact this leaf knows how to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreTextSource {
    IntuneManagementExtension,
    AppWorkload,
    /// Not confirmed as Store evidence. Kept visible in coverage.
    Unknown,
}

/// A Windows event channel this leaf knows how to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreEventSource {
    /// AppX deployment operations: stage, register, provision, remove.
    AppxDeployment,
    /// AppX packaging/manifest processing.
    AppxPackaging,
    /// Store acquisition and licensing.
    StoreAgent,
    Unknown,
}

/// CCM components that confirm a primary IME artifact.
const IME_COMPONENTS: &[&str] = &[
    "IntuneManagementExtension",
    "Win32App",
    "StoreApp",
    "MSStoreApp",
];

/// CCM components that confirm an app-workload artifact.
const APP_WORKLOAD_COMPONENTS: &[&str] = &["AppWorkload", "Win32App", "StoreApp", "MSStoreApp"];

/// Providers whose records this build understands, paired with the channel the
/// records must actually have come from.
///
/// The channel is checked as well as the provider because a text export can name
/// a provider in its body without being that provider's log.
const APPX_DEPLOYMENT_PROVIDERS: &[&str] = &[
    "Microsoft-Windows-AppXDeployment-Server",
    "Microsoft-Windows-AppXDeployment",
];
const APPX_PACKAGING_PROVIDERS: &[&str] = &["Microsoft-Windows-AppxPackagingOM"];
const STORE_PROVIDERS: &[&str] = &["Microsoft-Windows-StoreAgent", "Microsoft-Windows-Store"];

const APPX_DEPLOYMENT_CHANNEL_HINTS: &[&str] = &["AppXDeployment", "AppXDeploymentServer"];
const APPX_PACKAGING_CHANNEL_HINTS: &[&str] = &["AppxPackaging"];
const STORE_CHANNEL_HINTS: &[&str] = &["StoreAgent", "Store/"];

/// Strip a rotation suffix and the `.log` extension.
///
/// `IntuneManagementExtension-20260731-101500.log` and
/// `_IntuneManagementExtension.log` are both rotations of the live file; the
/// stem is what selects a candidate.
fn file_stem(file_name: &str) -> String {
    let trimmed = file_name.trim();
    let without_ext = trimmed
        .strip_suffix(".log")
        .or_else(|| trimmed.strip_suffix(".LOG"))
        .unwrap_or(trimmed);
    let without_archive_prefix = without_ext.strip_prefix('_').unwrap_or(without_ext);

    let Some((stem, suffix)) = without_archive_prefix.rsplit_once('-') else {
        return without_archive_prefix.to_owned();
    };
    if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return without_archive_prefix.to_owned();
    }
    // `-20260731-101500`: the date half is the rotation marker, so look one
    // segment further left before deciding this trailing run of digits is one.
    if let Some((earlier, date_part)) = stem.rsplit_once('-') {
        if date_part.len() >= 8 && date_part.chars().all(|c| c.is_ascii_digit()) {
            return earlier.to_owned();
        }
    }
    stem.to_owned()
}

/// The text source a file name suggests, before any content confirms it.
pub fn candidate_text_source(file_name: Option<&str>) -> StoreTextSource {
    let Some(file_name) = file_name else {
        return StoreTextSource::Unknown;
    };
    match file_stem(file_name).to_ascii_lowercase().as_str() {
        "intunemanagementextension" => StoreTextSource::IntuneManagementExtension,
        "appworkload" => StoreTextSource::AppWorkload,
        _ => StoreTextSource::Unknown,
    }
}

fn components_confirm(candidate: StoreTextSource, records: &[ImeLine]) -> bool {
    let expected: &[&str] = match candidate {
        StoreTextSource::IntuneManagementExtension => IME_COMPONENTS,
        StoreTextSource::AppWorkload => APP_WORKLOAD_COMPONENTS,
        StoreTextSource::Unknown => return false,
    };
    records
        .iter()
        .filter_map(|record| record.component.as_ref())
        .any(|component| {
            expected
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(component))
        })
}

/// Confirm a candidate text source against the records actually inside it.
///
/// Returns [`StoreTextSource::Unknown`] when the name suggested nothing, when
/// the content is not CCM framed, or when no record carries a confirming
/// component. All three cases mean the same thing operationally: this artifact
/// cannot be read as Store evidence, and saying so is more useful than parsing
/// it anyway.
pub fn classify_text_artifact(file_name: Option<&str>, records: &[ImeLine]) -> StoreTextSource {
    let candidate = candidate_text_source(file_name);
    if candidate == StoreTextSource::Unknown || records.is_empty() {
        return StoreTextSource::Unknown;
    }
    if components_confirm(candidate, records) {
        candidate
    } else {
        StoreTextSource::Unknown
    }
}

fn matches_any(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(value))
}

fn contains_any(value: &str, hints: &[&str]) -> bool {
    let lowered = value.to_ascii_lowercase();
    hints
        .iter()
        .any(|hint| lowered.contains(&hint.to_ascii_lowercase()))
}

/// Classify one normalized event by its provider and channel together.
pub fn classify_event_source(provider: &str, channel: &str) -> StoreEventSource {
    if matches_any(provider, APPX_DEPLOYMENT_PROVIDERS)
        && contains_any(channel, APPX_DEPLOYMENT_CHANNEL_HINTS)
    {
        return StoreEventSource::AppxDeployment;
    }
    if matches_any(provider, APPX_PACKAGING_PROVIDERS)
        && contains_any(channel, APPX_PACKAGING_CHANNEL_HINTS)
    {
        return StoreEventSource::AppxPackaging;
    }
    if matches_any(provider, STORE_PROVIDERS) && contains_any(channel, STORE_CHANNEL_HINTS) {
        return StoreEventSource::StoreAgent;
    }
    StoreEventSource::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::ime_parser::parse_ime_content;

    fn ccm(component: &str, message: &str) -> String {
        format!(
            r#"<![LOG[{message}]LOG]!><time="10:15:22.100+000" date="7-31-2026" component="{component}" context="" type="1" thread="12" file="store.cs:1">"#
        )
    }

    #[test]
    fn a_rotation_still_selects_the_live_candidate() {
        assert_eq!(
            candidate_text_source(Some("IntuneManagementExtension-20260731-101500.log")),
            StoreTextSource::IntuneManagementExtension
        );
        assert_eq!(
            candidate_text_source(Some("_AppWorkload.log")),
            StoreTextSource::AppWorkload
        );
    }

    #[test]
    fn the_file_name_alone_never_confirms_a_source() {
        let records = parse_ime_content(&ccm("CcmExec", "Store product 9SYNTH000001 evaluated"));
        assert_eq!(
            classify_text_artifact(Some("IntuneManagementExtension.log"), &records),
            StoreTextSource::Unknown
        );
    }

    #[test]
    fn a_confirming_component_promotes_the_candidate() {
        let records = parse_ime_content(&ccm("Win32App", "Store app policy received"));
        assert_eq!(
            classify_text_artifact(Some("IntuneManagementExtension.log"), &records),
            StoreTextSource::IntuneManagementExtension
        );
    }

    /// Negative detection: text that looks like AppX/Store evidence but carries
    /// no CCM framing must not be promoted into a source.
    #[test]
    fn appx_looking_plain_text_is_not_store_evidence() {
        let text = concat!(
            "PackageFamilyName: Contoso.SynthApp_9abcdef01234h\n",
            "Deployment operation Register failed with 0x80073CF9\n",
            "Microsoft-Windows-AppXDeployment-Server\n"
        );
        let records = parse_ime_content(text);
        assert_eq!(
            classify_text_artifact(Some("IntuneManagementExtension.log"), &records),
            StoreTextSource::Unknown,
            "unframed text must never be promoted to a confirmed source"
        );
        assert_eq!(
            classify_text_artifact(Some("AppXDeployment.txt"), &records),
            StoreTextSource::Unknown
        );
    }

    #[test]
    fn an_event_needs_both_a_known_provider_and_a_matching_channel() {
        assert_eq!(
            classify_event_source(
                "Microsoft-Windows-AppXDeployment-Server",
                "Microsoft-Windows-AppXDeploymentServer/Operational"
            ),
            StoreEventSource::AppxDeployment
        );
        // Right provider, wrong channel: a provider name pasted into an
        // unrelated channel proves nothing.
        assert_eq!(
            classify_event_source("Microsoft-Windows-AppXDeployment-Server", "Application"),
            StoreEventSource::Unknown
        );
        assert_eq!(
            classify_event_source(
                "Contoso-Synthetic-Provider",
                "Microsoft-Windows-Store/Operational"
            ),
            StoreEventSource::Unknown
        );
    }

    #[test]
    fn store_and_packaging_channels_are_distinguished() {
        assert_eq!(
            classify_event_source(
                "Microsoft-Windows-StoreAgent",
                "Microsoft-Windows-StoreAgent/Debug"
            ),
            StoreEventSource::StoreAgent
        );
        assert_eq!(
            classify_event_source(
                "Microsoft-Windows-AppxPackagingOM",
                "Microsoft-Windows-AppxPackaging/Operational"
            ),
            StoreEventSource::AppxPackaging
        );
    }
}
