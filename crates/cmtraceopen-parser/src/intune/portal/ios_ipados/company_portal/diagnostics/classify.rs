//! Company Portal source classification and fixture-proven semantics.
//!
//! The documented Microsoft workflow copies *all* Console records, so a capture
//! contains hundreds of processes that have nothing to do with Intune. Filtering
//! is therefore part of the contract, and it is structural: a record is Company
//! Portal evidence only when the Process or Subsystem column names the app.
//!
//! The word `Intune`, `Company Portal`, or a tenant GUID appearing in arbitrary
//! message text is explicitly *not* sufficient. Any process may log those
//! strings, and classifying on them turns an unrelated crash report into
//! "Company Portal evidence".

use std::sync::OnceLock;

use regex::Regex;

use super::models::{ConsoleSemanticKind, ConsoleSemanticSource, ConsoleSourceClass, ConsoleSourceSignal};

/// Process names that identify the Company Portal app or its extensions.
///
/// Compared case-insensitively against the whole column, never as a substring:
/// a substring test would claim `CompanyPortalUninstallerHelperTest` and any
/// other process whose name merely contains one of these.
const COMPANY_PORTAL_PROCESSES: &[&str] = &[
    "CompanyPortal",
    "Company Portal",
    "CompanyPortalExtension",
    "IntuneMAMPolicyExtension",
];

/// Subsystem prefixes that identify Company Portal and the Intune MAM SDK it
/// embeds.
///
/// Prefix-matched on dot boundaries so `com.microsoft.CompanyPortal.Enrollment`
/// matches while a hypothetical `com.microsoft.CompanyPortalClone` does not.
const COMPANY_PORTAL_SUBSYSTEMS: &[&str] = &[
    "com.microsoft.CompanyPortal",
    "com.microsoft.companyportal",
    "com.microsoft.intune.mam",
    "com.microsoft.intune.companyportal",
];

/// Does `subsystem` equal one of the known prefixes or sit beneath it?
fn subsystem_matches(subsystem: &str) -> bool {
    let value = subsystem.trim();
    COMPANY_PORTAL_SUBSYSTEMS.iter().any(|prefix| {
        value.eq_ignore_ascii_case(prefix)
            || (value.len() > prefix.len()
                && value.as_bytes()[prefix.len()] == b'.'
                && value[..prefix.len()].eq_ignore_ascii_case(prefix))
    })
}

fn process_matches(process: &str) -> bool {
    let value = process.trim();
    COMPANY_PORTAL_PROCESSES
        .iter()
        .any(|known| value.eq_ignore_ascii_case(known))
}

/// Classify one record's source from its columns alone.
///
/// Returns [`ConsoleSourceClass::Indeterminate`] when neither column carried a
/// value: the record can then be neither claimed as Company Portal evidence nor
/// dismissed, and it stays visible instead of being silently dropped.
pub(super) fn classify_source(
    process: Option<&str>,
    subsystem: Option<&str>,
) -> (ConsoleSourceClass, Vec<ConsoleSourceSignal>) {
    let process = process.map(str::trim).filter(|value| !value.is_empty());
    let subsystem = subsystem.map(str::trim).filter(|value| !value.is_empty());

    if process.is_none() && subsystem.is_none() {
        return (ConsoleSourceClass::Indeterminate, Vec::new());
    }

    let mut signals = Vec::new();
    if process.is_some_and(process_matches) {
        signals.push(ConsoleSourceSignal::Process);
    }
    if subsystem.is_some_and(subsystem_matches) {
        signals.push(ConsoleSourceSignal::Subsystem);
    }

    if signals.is_empty() {
        (ConsoleSourceClass::Unrelated, signals)
    } else {
        (ConsoleSourceClass::CompanyPortal, signals)
    }
}

/// Category labels that place a Company Portal record in an activity outright.
///
/// Compared case-insensitively against the whole Category column.
const CATEGORY_SEMANTICS: &[(&str, ConsoleSemanticKind)] = &[
    ("authentication", ConsoleSemanticKind::SignInAuth),
    ("auth", ConsoleSemanticKind::SignInAuth),
    ("signin", ConsoleSemanticKind::SignInAuth),
    ("msal", ConsoleSemanticKind::SignInAuth),
    ("enrollment", ConsoleSemanticKind::EnrollmentProfile),
    ("profile", ConsoleSemanticKind::EnrollmentProfile),
    ("mdm", ConsoleSemanticKind::EnrollmentProfile),
    ("sync", ConsoleSemanticKind::SyncCompliance),
    ("compliance", ConsoleSemanticKind::SyncCompliance),
    ("apps", ConsoleSemanticKind::AppDeviceAction),
    ("appcatalog", ConsoleSemanticKind::AppDeviceAction),
    ("deviceaction", ConsoleSemanticKind::AppDeviceAction),
    ("network", ConsoleSemanticKind::NetworkService),
    ("service", ConsoleSemanticKind::NetworkService),
    ("diagnostics", ConsoleSemanticKind::Diagnostic),
    ("telemetry", ConsoleSemanticKind::Diagnostic),
];

/// Message substrings that place a record in an activity when the category did
/// not. Lowercased; the first match in this order wins.
///
/// Deliberately short and specific. Every entry here is proven by a fixture; a
/// keyword that only *usually* means what it looks like belongs nowhere near a
/// classification an operator will act on.
const MESSAGE_SEMANTICS: &[(&str, ConsoleSemanticKind)] = &[
    ("acquiretoken", ConsoleSemanticKind::SignInAuth),
    ("aadsts", ConsoleSemanticKind::SignInAuth),
    ("interactive sign-in", ConsoleSemanticKind::SignInAuth),
    ("mdm profile", ConsoleSemanticKind::EnrollmentProfile),
    ("enrollment session", ConsoleSemanticKind::EnrollmentProfile),
    ("compliance check", ConsoleSemanticKind::SyncCompliance),
    ("device check-in", ConsoleSemanticKind::SyncCompliance),
    ("app install", ConsoleSemanticKind::AppDeviceAction),
    ("device action", ConsoleSemanticKind::AppDeviceAction),
    ("http status", ConsoleSemanticKind::NetworkService),
    ("request failed", ConsoleSemanticKind::NetworkService),
    ("diagnostic report", ConsoleSemanticKind::Diagnostic),
];

/// Place a Company Portal record in a fixture-proven activity, if it is one.
///
/// `None` means "not recognized". It never means the record was unrelated to
/// every activity, and no rule may read it that way.
pub(super) fn classify_semantic(
    category: Option<&str>,
    message: &str,
) -> Option<(ConsoleSemanticKind, ConsoleSemanticSource)> {
    if let Some(category) = category.map(str::trim).filter(|value| !value.is_empty()) {
        let lowered = category.to_lowercase();
        if let Some((_, kind)) = CATEGORY_SEMANTICS
            .iter()
            .find(|(label, _)| *label == lowered)
        {
            return Some((*kind, ConsoleSemanticSource::Category));
        }
    }

    let lowered = message.to_lowercase();
    MESSAGE_SEMANTICS
        .iter()
        .find(|(needle, _)| lowered.contains(needle))
        .map(|(_, kind)| (*kind, ConsoleSemanticSource::Message))
}

/// `Company Portal 5.2026.1 (build 3210)` or `CompanyPortal/5.2026.1`.
fn app_version_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bcompany[ _]?portal[ /]v?(\d+(?:\.\d+){1,3})\b")
            .expect("Company Portal version pattern is valid")
    })
}

/// `iOS 18.4`, `iPadOS 17.6.1`.
fn os_version_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:ios|ipados)\s+v?(\d+(?:\.\d+){0,3})\b")
            .expect("iOS version pattern is valid")
    })
}

/// The Company Portal version a message announces, if any.
pub(super) fn reported_app_version(message: &str) -> Option<String> {
    app_version_pattern()
        .captures(message)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_owned())
}

/// The iOS/iPadOS version a message announces, if any.
pub(super) fn reported_os_version(message: &str) -> Option<String> {
    os_version_pattern()
        .captures(message)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_process_column_verifies_a_record() {
        let (class, signals) = classify_source(Some("CompanyPortal"), Some("com.apple.network"));
        assert_eq!(class, ConsoleSourceClass::CompanyPortal);
        assert_eq!(signals, vec![ConsoleSourceSignal::Process]);
    }

    #[test]
    fn the_subsystem_column_verifies_a_record_logged_by_another_process() {
        let (class, signals) =
            classify_source(Some("CompanyPortalIntents"), Some("com.microsoft.intune.mam.policy"));
        assert_eq!(class, ConsoleSourceClass::CompanyPortal);
        assert_eq!(signals, vec![ConsoleSourceSignal::Subsystem]);
    }

    #[test]
    fn both_columns_are_reported_when_both_match() {
        let (_, signals) = classify_source(
            Some("CompanyPortal"),
            Some("com.microsoft.CompanyPortal.Enrollment"),
        );
        assert_eq!(
            signals,
            vec![ConsoleSourceSignal::Process, ConsoleSourceSignal::Subsystem]
        );
    }

    #[test]
    fn an_unrelated_process_is_not_claimed() {
        let (class, signals) = classify_source(Some("SpringBoard"), Some("com.apple.springboard"));
        assert_eq!(class, ConsoleSourceClass::Unrelated);
        assert!(signals.is_empty());
    }

    #[test]
    fn a_process_that_merely_contains_the_name_is_not_claimed() {
        // Substring matching is the classic mistake here.
        let (class, _) = classify_source(Some("CompanyPortalCloneHelper"), None);
        assert_eq!(class, ConsoleSourceClass::Unrelated);
    }

    #[test]
    fn a_subsystem_that_merely_shares_a_prefix_is_not_claimed() {
        let (class, _) = classify_source(None, Some("com.microsoft.CompanyPortalClone"));
        assert_eq!(class, ConsoleSourceClass::Unrelated);
    }

    #[test]
    fn a_missing_source_column_is_indeterminate_not_unrelated() {
        let (class, _) = classify_source(None, None);
        assert_eq!(class, ConsoleSourceClass::Indeterminate);
        let (class, _) = classify_source(Some("   "), Some(""));
        assert_eq!(class, ConsoleSourceClass::Indeterminate);
    }

    #[test]
    fn the_word_intune_in_a_message_never_classifies_a_record() {
        // The issue calls this out explicitly: text is not a source signature.
        let (class, _) = classify_source(Some("assistantd"), Some("com.apple.siri"));
        assert_eq!(class, ConsoleSourceClass::Unrelated);
    }

    #[test]
    fn a_category_places_a_record_structurally() {
        assert_eq!(
            classify_semantic(Some("Enrollment"), "anything at all"),
            Some((
                ConsoleSemanticKind::EnrollmentProfile,
                ConsoleSemanticSource::Category
            ))
        );
    }

    #[test]
    fn a_message_keyword_is_a_weaker_fallback_and_says_so() {
        assert_eq!(
            classify_semantic(Some("General"), "acquireToken returned AADSTS50076"),
            Some((
                ConsoleSemanticKind::SignInAuth,
                ConsoleSemanticSource::Message
            ))
        );
    }

    #[test]
    fn an_unrecognized_message_stays_an_ordinary_record() {
        assert_eq!(classify_semantic(Some("General"), "warming caches"), None);
        assert_eq!(classify_semantic(None, "warming caches"), None);
    }

    #[test]
    fn version_banners_are_extracted_when_present() {
        assert_eq!(
            reported_app_version("Company Portal 5.2026.1 starting up"),
            Some("5.2026.1".to_owned())
        );
        assert_eq!(
            reported_os_version("running on iPadOS 18.4 (build 22E240)"),
            Some("18.4".to_owned())
        );
        assert_eq!(reported_app_version("no version here"), None);
    }
}
