//! Conservative source selection for Company Portal unified-log evidence.
//!
//! The rule this module exists to enforce: **a process name is not evidence, and
//! the word `CompanyPortal` appearing in an arbitrary message is not evidence
//! either.** Any process can log that string, and `os_log` records from an
//! unrelated subsystem routinely mention other applications by name. Selecting
//! on either would pull unrelated records into a Company Portal diagnosis and
//! make a busy device look like a failing one.
//!
//! So relevance requires a *structural* signal:
//!
//! * [`UnifiedLogRelevance::Direct`] — the record's subsystem is a known Company
//!   Portal subsystem. The subsystem is chosen by the emitting binary and cannot
//!   be spoofed by message text.
//! * [`UnifiedLogRelevance::Corroborating`] — the record has no known subsystem,
//!   but its process *and* its sender or process image path both point at a
//!   known Company Portal bundle. Two independent structural fields agreeing is
//!   the weakest signal this module will accept.
//! * [`UnifiedLogRelevance::Unrelated`] — everything else.
//!
//! The allowlists are versioned by [`COMPANY_PORTAL_PREDICATE_VERSION`] and the
//! query string is exposed as [`COMPANY_PORTAL_PREDICATE`], so a capture records
//! *which* selection rule produced it and a later build can tell whether the
//! rule changed. Adding a value to an allowlist is a predicate-version bump, not
//! a silent widening.

use serde::{Deserialize, Serialize};

use super::schema::NormalizedUnifiedLogRecord;

/// Stable identifier of the selection rule below.
pub const COMPANY_PORTAL_PREDICATE_ID: &str = "companyPortalMacosV1";

/// Version of the allowlists. Bump whenever a value is added or removed.
pub const COMPANY_PORTAL_PREDICATE_VERSION: u32 = 1;

/// The `log show` predicate a collector should run to produce a capture that
/// this rule can classify.
///
/// It is deliberately *wider* than the classifier: collecting the process-only
/// records lets [`UnifiedLogRelevance::Unrelated`] be proven rather than assumed,
/// which is what the negative fixture in this leaf's corpus asserts.
pub const COMPANY_PORTAL_PREDICATE: &str = concat!(
    r#"subsystem BEGINSWITH "com.microsoft.CompanyPortal" "#,
    r#"OR subsystem == "com.microsoft.intune" "#,
    r#"OR process == "CompanyPortal" "#,
    r#"OR process == "IntuneMdmAgent" "#,
    r#"OR process == "IntuneMdmDaemon""#
);

/// Subsystems emitted by Company Portal and its Intune agent companions.
///
/// Matching is exact rather than prefixed: a prefix rule would accept a
/// hypothetical `com.microsoft.CompanyPortalTelemetryUploader` that this build
/// has never seen and whose categories it cannot interpret.
const COMPANY_PORTAL_SUBSYSTEMS: [&str; 4] = [
    "com.microsoft.CompanyPortalMac",
    "com.microsoft.CompanyPortal",
    "com.microsoft.intune",
    "com.microsoft.intune.mdmagent",
];

/// Process names that may *corroborate* a bundle-path match.
const COMPANY_PORTAL_PROCESSES: [&str; 4] = [
    "CompanyPortal",
    "Company Portal",
    "IntuneMdmAgent",
    "IntuneMdmDaemon",
];

/// Image-path prefixes belonging to a Company Portal or Intune agent bundle.
const COMPANY_PORTAL_IMAGE_PREFIXES: [&str; 4] = [
    "/Applications/Company Portal.app/",
    "/Library/Intune/",
    "/Library/Application Support/Microsoft/Intune/",
    "/Library/PrivilegedHelperTools/com.microsoft.CompanyPortal",
];

/// How strongly a record belongs to Company Portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UnifiedLogRelevance {
    /// Not Company Portal evidence.
    Unrelated,
    /// Two agreeing structural fields, but no known subsystem.
    Corroborating,
    /// A known Company Portal subsystem.
    Direct,
}

impl UnifiedLogRelevance {
    /// Whether a record with this relevance may contribute to a finding.
    pub fn is_relevant(self) -> bool {
        !matches!(self, Self::Unrelated)
    }
}

/// Metadata describing the selection rule, for provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedLogPredicateDescriptor {
    pub predicate_id: String,
    pub predicate_version: u32,
    pub predicate: String,
}

/// The selection rule this build implements.
pub fn predicate_descriptor() -> UnifiedLogPredicateDescriptor {
    UnifiedLogPredicateDescriptor {
        predicate_id: COMPANY_PORTAL_PREDICATE_ID.to_owned(),
        predicate_version: COMPANY_PORTAL_PREDICATE_VERSION,
        predicate: COMPANY_PORTAL_PREDICATE.to_owned(),
    }
}

/// Classify one record against the rule documented at the top of this module.
pub fn classify_relevance(record: &NormalizedUnifiedLogRecord) -> UnifiedLogRelevance {
    if record
        .subsystem
        .as_deref()
        .is_some_and(is_company_portal_subsystem)
    {
        return UnifiedLogRelevance::Direct;
    }

    let process_matches = record
        .process
        .as_deref()
        .is_some_and(is_company_portal_process);
    let image_matches = [
        record.sender_image_path.as_deref(),
        record.process_image_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(is_company_portal_image_path);

    if process_matches && image_matches {
        return UnifiedLogRelevance::Corroborating;
    }

    UnifiedLogRelevance::Unrelated
}

/// Case-insensitive because reverse-DNS identifiers are compared that way by
/// Apple's own tooling, and a capitalization difference is not a new subsystem.
fn is_company_portal_subsystem(subsystem: &str) -> bool {
    COMPANY_PORTAL_SUBSYSTEMS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(subsystem))
}

fn is_company_portal_process(process: &str) -> bool {
    COMPANY_PORTAL_PROCESSES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(process))
}

fn is_company_portal_image_path(path: &str) -> bool {
    COMPANY_PORTAL_IMAGE_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> NormalizedUnifiedLogRecord {
        NormalizedUnifiedLogRecord::default()
    }

    #[test]
    fn a_known_subsystem_is_direct_evidence() {
        let subject = NormalizedUnifiedLogRecord {
            subsystem: Some("com.microsoft.CompanyPortalMac".to_owned()),
            ..record()
        };
        assert_eq!(classify_relevance(&subject), UnifiedLogRelevance::Direct);
    }

    #[test]
    fn a_process_name_alone_is_not_evidence() {
        // This is the rule the issue calls out by name.
        let subject = NormalizedUnifiedLogRecord {
            process: Some("CompanyPortal".to_owned()),
            subsystem: Some("com.apple.network".to_owned()),
            ..record()
        };
        assert_eq!(classify_relevance(&subject), UnifiedLogRelevance::Unrelated);
    }

    #[test]
    fn the_word_company_portal_in_a_message_is_not_evidence() {
        let subject = NormalizedUnifiedLogRecord {
            process: Some("sshd".to_owned()),
            subsystem: Some("com.apple.securityd".to_owned()),
            event_message: Some("denied access to CompanyPortal keychain item".to_owned()),
            ..record()
        };
        assert_eq!(classify_relevance(&subject), UnifiedLogRelevance::Unrelated);
    }

    #[test]
    fn a_process_plus_a_bundle_path_corroborates() {
        let subject = NormalizedUnifiedLogRecord {
            process: Some("CompanyPortal".to_owned()),
            sender_image_path: Some(
                "/Applications/Company Portal.app/Contents/MacOS/CompanyPortal".to_owned(),
            ),
            ..record()
        };
        assert_eq!(
            classify_relevance(&subject),
            UnifiedLogRelevance::Corroborating
        );
    }

    #[test]
    fn a_bundle_path_without_a_matching_process_is_not_enough() {
        let subject = NormalizedUnifiedLogRecord {
            process: Some("tccd".to_owned()),
            sender_image_path: Some(
                "/Applications/Company Portal.app/Contents/MacOS/CompanyPortal".to_owned(),
            ),
            ..record()
        };
        assert_eq!(classify_relevance(&subject), UnifiedLogRelevance::Unrelated);
    }

    #[test]
    fn a_lookalike_subsystem_is_not_accepted_by_prefix() {
        let subject = NormalizedUnifiedLogRecord {
            subsystem: Some("com.microsoft.CompanyPortalTelemetryUploader".to_owned()),
            ..record()
        };
        assert_eq!(classify_relevance(&subject), UnifiedLogRelevance::Unrelated);
    }

    #[test]
    fn subsystem_matching_ignores_case() {
        let subject = NormalizedUnifiedLogRecord {
            subsystem: Some("COM.MICROSOFT.COMPANYPORTALMAC".to_owned()),
            ..record()
        };
        assert_eq!(classify_relevance(&subject), UnifiedLogRelevance::Direct);
    }

    #[test]
    fn direct_outranks_corroborating_which_outranks_unrelated() {
        // The ordering is relied on when a finding picks its strongest evidence.
        assert!(UnifiedLogRelevance::Direct > UnifiedLogRelevance::Corroborating);
        assert!(UnifiedLogRelevance::Corroborating > UnifiedLogRelevance::Unrelated);
        assert!(!UnifiedLogRelevance::Unrelated.is_relevant());
    }

    #[test]
    fn the_descriptor_reports_the_versioned_rule() {
        let descriptor = predicate_descriptor();
        assert_eq!(descriptor.predicate_id, COMPANY_PORTAL_PREDICATE_ID);
        assert_eq!(descriptor.predicate_version, COMPANY_PORTAL_PREDICATE_VERSION);
        assert!(descriptor.predicate.contains("com.microsoft.CompanyPortal"));
    }
}
