//! Structural Company Portal attribution, plus the narrow semantic evidence that fixtures
//! actually prove.
//!
//! The documented Microsoft workflow copies **all** visible Console records, so a capture is
//! mostly unrelated iOS system noise. Attribution therefore reads only verified structural
//! fields: the emitting process name and the subsystem namespace. The words `Intune` or
//! `CompanyPortal` appearing anywhere in free message text are explicitly *not* a signature,
//! because unrelated daemons legitimately log about them.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{
    PortalConsoleConfidence, PortalConsoleSemanticCategory, PortalConsoleSemanticEvidence,
    PortalConsoleSourceClass, PortalConsoleSourceSignature,
};

/// Process names owned by the iOS / iPadOS Company Portal app.
///
/// The process name carries no space, matching the `CompanyPortal` predicate already used by
/// the native macOS unified-log adapter.
const COMPANY_PORTAL_PROCESSES: &[&str] = &["CompanyPortal"];

/// Root of the Company Portal subsystem namespace (the app's bundle identifier).
const COMPANY_PORTAL_SUBSYSTEM_ROOT: &str = "com.microsoft.CompanyPortal";

/// Attribute a record from its structural source fields alone.
pub(super) fn classify_source(
    process: Option<&str>,
    subsystem: Option<&str>,
) -> (PortalConsoleSourceClass, PortalConsoleSourceSignature) {
    if let Some(process) = process {
        if COMPANY_PORTAL_PROCESSES.contains(&process) {
            return (
                PortalConsoleSourceClass::CompanyPortal,
                PortalConsoleSourceSignature::ProcessName,
            );
        }
    }

    if let Some(subsystem) = subsystem {
        if is_company_portal_subsystem(subsystem) {
            return (
                PortalConsoleSourceClass::CompanyPortal,
                PortalConsoleSourceSignature::SubsystemNamespace,
            );
        }
    }

    (
        PortalConsoleSourceClass::OtherProcess,
        PortalConsoleSourceSignature::None,
    )
}

/// Exact namespace containment, so `com.microsoft.CompanyPortalium` does not match.
fn is_company_portal_subsystem(subsystem: &str) -> bool {
    subsystem == COMPANY_PORTAL_SUBSYSTEM_ROOT
        || subsystem
            .strip_prefix(COMPANY_PORTAL_SUBSYSTEM_ROOT)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Category tokens that map to a semantic bucket.
///
/// Only tokens proven by a fixture appear here. An unmapped category leaves the record
/// ordinary, which is the correct outcome: under-claiming beats a confident wrong label.
const SEMANTIC_CATEGORIES: &[(&str, PortalConsoleSemanticCategory)] = &[
    ("Authentication", PortalConsoleSemanticCategory::SignInAuth),
    ("SignIn", PortalConsoleSemanticCategory::SignInAuth),
    ("MSAL", PortalConsoleSemanticCategory::SignInAuth),
    (
        "Enrollment",
        PortalConsoleSemanticCategory::EnrollmentProfile,
    ),
    ("Profile", PortalConsoleSemanticCategory::EnrollmentProfile),
    ("Sync", PortalConsoleSemanticCategory::SyncCompliance),
    ("Compliance", PortalConsoleSemanticCategory::SyncCompliance),
    (
        "Applications",
        PortalConsoleSemanticCategory::AppDeviceAction,
    ),
    (
        "DeviceActions",
        PortalConsoleSemanticCategory::AppDeviceAction,
    ),
    ("Network", PortalConsoleSemanticCategory::NetworkService),
    ("Service", PortalConsoleSemanticCategory::NetworkService),
    (
        "Diagnostics",
        PortalConsoleSemanticCategory::DiagnosticActivity,
    ),
];

/// Derive semantic evidence from the structural category token.
///
/// Applies only to records already attributed to Company Portal, and reads the category
/// column / subsystem-category token rather than the message body.
pub(super) fn classify_semantics(
    class: &PortalConsoleSourceClass,
    category: Option<&str>,
    versions_known: bool,
) -> Option<PortalConsoleSemanticEvidence> {
    if *class != PortalConsoleSourceClass::CompanyPortal {
        return None;
    }

    let category = category?;
    let matched = SEMANTIC_CATEGORIES
        .iter()
        .find(|(token, _)| *token == category)?;

    Some(PortalConsoleSemanticEvidence {
        category: matched.1,
        matched_category_token: category.to_string(),
        // Without a proven Company Portal / OS version the mapping is still structural but
        // cannot be tied to a validated app build, so it is reported as low confidence.
        confidence: if versions_known {
            PortalConsoleConfidence::High
        } else {
            PortalConsoleConfidence::Low
        },
    })
}

/// A Company Portal / iOS version pair recovered from a version banner.
pub(super) struct VersionBanner {
    pub company_portal_version: String,
    pub os_version: String,
}

/// Recover versions from a strictly anchored Company Portal startup banner.
///
/// Deliberately narrow: the record must already be attributed to Company Portal, sit in the
/// `Diagnostics` category, and match the banner grammar exactly. Anything looser would
/// invent a version out of arbitrary text.
pub(super) fn parse_version_banner(
    class: &PortalConsoleSourceClass,
    category: Option<&str>,
    message: &str,
) -> Option<VersionBanner> {
    if *class != PortalConsoleSourceClass::CompanyPortal || category != Some("Diagnostics") {
        return None;
    }

    let captures = version_banner_pattern().captures(message.trim())?;
    Some(VersionBanner {
        company_portal_version: captures["cp"].to_string(),
        os_version: format!("{} {}", &captures["os"], &captures["osver"]),
    })
}

fn version_banner_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"^Company Portal (?P<cp>\d+\.\d+\.\d+) \(\d+\) starting on (?P<os>iOS|iPadOS) (?P<osver>\d+\.\d+(?:\.\d+)?)$",
        )
        .expect("version banner pattern must compile")
    })
}
