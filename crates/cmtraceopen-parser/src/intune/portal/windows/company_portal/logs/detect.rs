//! Detection confirmation for Company Portal Windows LocalState logs.
//!
//! # Why a file name is never enough
//!
//! `Log_<n>.log` is a completely generic name — any UWP package can write one
//! into its own `LocalState` folder. The path may therefore only *nominate* a
//! candidate; the claim has to come from record structure. Confirmation
//! requires field 6 to be a hyphenated GUID **and** field 7 to be a
//! dash-separated version triple, which is what a generic
//! `2024-11-15T16:50:07Z INFO something` line can never satisfy.

use super::grammar::parse_record_fields;
use super::models::{
    CompanyPortalGrammarSupport, CompanyPortalLogFileIdentity, CompanyPortalLogFileKind,
};

/// What a single line contributed to the detection decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompanyPortalLineClassification {
    /// The line validated against the `V1` field grammar.
    pub is_record: bool,
    /// The record's app version is one the grammar was derived from.
    pub app_version_is_validated: bool,
}

/// Classify one line for the detection sampler.
///
/// Returns `None` for anything that is not a confirmed record, so the caller's
/// counters only ever rise on structurally proven lines.
pub fn classify_line(line: &str) -> Option<CompanyPortalLineClassification> {
    let fields = parse_record_fields(line)?;
    Some(CompanyPortalLineClassification {
        is_record: true,
        app_version_is_validated: matches!(
            fields.app_version.support,
            CompanyPortalGrammarSupport::Validated
        ),
    })
}

/// Check whether a line matches the Company Portal Windows log record grammar.
///
/// House-convention matcher used by `parser::detect` and by tests.
pub fn matches_company_portal_log_record(line: &str) -> bool {
    classify_line(line).is_some()
}

/// Whether a file name follows a LocalState Company Portal log pattern.
///
/// A *hint only*. `Log_1.log` belongs to every UWP package that wants it.
pub fn is_company_portal_log_file_name(file_name: &str) -> bool {
    !matches!(
        parse_file_identity(file_name).kind,
        CompanyPortalLogFileKind::Unrecognized
    )
}

/// Derive the file identity from a file name.
///
/// Recognizes `Log_<n>.log` (the main app log) and `Log.<BridgeName>_<n>.log`
/// (the ConfigMgr / IME / launcher bridges, which are written by the same
/// logger and share this grammar). Rotation members keep their index so they
/// stay distinct: no published evidence says whether `Log_1` is the newest or
/// the oldest member, so members are never reordered or deduplicated.
pub fn parse_file_identity(file_name: &str) -> CompanyPortalLogFileIdentity {
    let unrecognized = || CompanyPortalLogFileIdentity {
        file_name: file_name.to_string(),
        kind: CompanyPortalLogFileKind::Unrecognized,
        bridge_name: None,
        rotation_index: None,
    };

    let Some(stem) = strip_suffix_ci(file_name, ".log") else {
        return unrecognized();
    };
    let Some(rest) = strip_prefix_ci(stem, "Log") else {
        return unrecognized();
    };

    // `Log_<n>` — the main app log.
    if let Some(index) = rest.strip_prefix('_') {
        return match parse_rotation_index(index) {
            Some(rotation_index) => CompanyPortalLogFileIdentity {
                file_name: file_name.to_string(),
                kind: CompanyPortalLogFileKind::App,
                bridge_name: None,
                rotation_index: Some(rotation_index),
            },
            None => unrecognized(),
        };
    }

    // `Log.<BridgeName>_<n>` — a bridge log.
    let Some(bridge) = rest.strip_prefix('.') else {
        return unrecognized();
    };
    let Some((bridge_name, index)) = bridge.rsplit_once('_') else {
        return unrecognized();
    };
    match (bridge_name.is_empty(), parse_rotation_index(index)) {
        (false, Some(rotation_index)) => CompanyPortalLogFileIdentity {
            file_name: file_name.to_string(),
            kind: CompanyPortalLogFileKind::Bridge,
            bridge_name: Some(bridge_name.to_string()),
            rotation_index: Some(rotation_index),
        },
        _ => unrecognized(),
    }
}

fn parse_rotation_index(raw: &str) -> Option<u32> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

fn strip_prefix_ci<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let candidate = value.get(..prefix.len())?;
    candidate
        .eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
}

fn strip_suffix_ci<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    let split = value.len().checked_sub(suffix.len())?;
    let candidate = value.get(split..)?;
    candidate
        .eq_ignore_ascii_case(suffix)
        .then(|| &value[..split])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_accepts_the_published_record() {
        assert!(matches_company_portal_log_record(
            "2024-11-15T16:50:07.2850341Z  INFO  Event        None                      0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Configuration Manager Trace Listener] started"
        ));
    }

    #[test]
    fn matcher_rejects_generic_and_plain_lines() {
        assert!(!matches_company_portal_log_record("Just plain text"));
        assert!(!matches_company_portal_log_record(
            "2024-01-15 14:30:00 some generic timestamped line"
        ));
        assert!(!matches_company_portal_log_record(
            "2024-11-15T16:50:07.2850341Z  INFO  App started"
        ));
    }

    #[test]
    fn matcher_rejects_a_column_aligned_log_without_guid_and_version_columns() {
        // Seven aligned columns, an ISO instant and a severity token — and it is
        // still refused, because field 6 is not a GUID and field 7 is not a
        // dash-separated triple.
        assert!(!matches_company_portal_log_record(
            "2026-05-04T08:12:31.4410000Z  INFO  Startup  Foreground  0  Shell  1.2.3  session started"
        ));
    }

    #[test]
    fn classification_reports_validated_versus_experimental_app_versions() {
        let validated = classify_line(
            "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  ok",
        )
        .expect("record must classify");
        assert!(validated.app_version_is_validated);

        let experimental = classify_line(
            "2026-02-03T09:15:00.1230000Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  13-4-2  ok",
        )
        .expect("record must classify");
        assert!(!experimental.app_version_is_validated);
    }

    #[test]
    fn app_log_identity_keeps_the_rotation_index() {
        let identity = parse_file_identity("Log_3.log");
        assert_eq!(identity.kind, CompanyPortalLogFileKind::App);
        assert_eq!(identity.rotation_index, Some(3));
        assert_eq!(identity.bridge_name, None);
    }

    #[test]
    fn bridge_log_identity_keeps_the_bridge_name() {
        let identity = parse_file_identity("Log.ConfigurationManagerBridge_1.log");
        assert_eq!(identity.kind, CompanyPortalLogFileKind::Bridge);
        assert_eq!(
            identity.bridge_name.as_deref(),
            Some("ConfigurationManagerBridge")
        );
        assert_eq!(identity.rotation_index, Some(1));
    }

    #[test]
    fn unrelated_file_names_are_unrecognized() {
        for name in [
            "IntuneManagementExtension.log",
            "Log.log",
            "Log_.log",
            "Log_abc.log",
            "Log._1.log",
            "Logger_1.log",
            "Log_1.txt",
        ] {
            assert_eq!(
                parse_file_identity(name).kind,
                CompanyPortalLogFileKind::Unrecognized,
                "{name}"
            );
            assert!(!is_company_portal_log_file_name(name), "{name}");
        }
    }

    #[test]
    fn file_name_matching_is_case_insensitive() {
        assert!(is_company_portal_log_file_name("log_1.LOG"));
        assert!(is_company_portal_log_file_name("LOG.BridgeLauncher_2.log"));
    }
}
