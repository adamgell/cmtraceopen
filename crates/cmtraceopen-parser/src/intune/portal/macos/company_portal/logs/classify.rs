//! Optional normalized evidence classification.
//!
//! Classification is driven by the **structural component field only**, using an
//! explicit table. Every entry in the table is exercised by a committed fixture;
//! components outside the table stay [`PortalEvidenceCategory::Generic`] rather
//! than being guessed from message text. Under-claiming is deliberate: a wrong
//! category is worse than no category.

use super::models::PortalEvidenceCategory;

/// Fixture-proven component to category mapping. Exact, case-sensitive.
const COMPONENT_CATEGORIES: &[(&str, PortalEvidenceCategory)] = &[
    (
        "SignInViewModel",
        PortalEvidenceCategory::SignInAuthentication,
    ),
    (
        "AuthenticationManager",
        PortalEvidenceCategory::SignInAuthentication,
    ),
    (
        "EnrollmentManager",
        PortalEvidenceCategory::EnrollmentProfile,
    ),
    ("SyncManager", PortalEvidenceCategory::SyncCompliance),
    ("ComplianceChecker", PortalEvidenceCategory::SyncCompliance),
    (
        "AppCatalogViewModel",
        PortalEvidenceCategory::AppCatalogAction,
    ),
    ("DeviceActionManager", PortalEvidenceCategory::DeviceAction),
    (
        "NetworkService",
        PortalEvidenceCategory::NetworkServiceResponse,
    ),
    (
        "DiagnosticReportManager",
        PortalEvidenceCategory::DiagnosticReportAction,
    ),
];

/// Classify a record from its structural component field.
///
/// `None` (no structural component, e.g. a malformed record) always yields
/// [`PortalEvidenceCategory::Generic`].
pub fn classify_component(component: Option<&str>) -> PortalEvidenceCategory {
    let Some(component) = component else {
        return PortalEvidenceCategory::Generic;
    };
    COMPONENT_CATEGORIES
        .iter()
        .find(|(name, _)| *name == component)
        .map(|(_, category)| *category)
        .unwrap_or(PortalEvidenceCategory::Generic)
}

/// The component tokens this module is willing to classify. Exposed so tests can
/// assert every one of them is covered by a fixture.
pub fn classified_component_tokens() -> Vec<&'static str> {
    COMPONENT_CATEGORIES.iter().map(|(name, _)| *name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_components_classify() {
        assert_eq!(
            classify_component(Some("SyncManager")),
            PortalEvidenceCategory::SyncCompliance
        );
        assert_eq!(
            classify_component(Some("NetworkService")),
            PortalEvidenceCategory::NetworkServiceResponse
        );
    }

    #[test]
    fn unknown_and_missing_components_stay_generic() {
        assert_eq!(
            classify_component(Some("FutureFeatureManager")),
            PortalEvidenceCategory::Generic
        );
        assert_eq!(
            classify_component(Some("syncmanager")),
            PortalEvidenceCategory::Generic
        );
        assert_eq!(classify_component(None), PortalEvidenceCategory::Generic);
    }
}
