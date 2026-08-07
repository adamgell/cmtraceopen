//! Windows Update for Business evidence under Intune management.
//!
//! Owner: issue #365 of epic #356.
//!
//! # The one thing this module exists to get right
//!
//! "Intune delivered update settings" and "Windows scanned, downloaded, or
//! installed an update" are separate claims, backed by separate providers, and
//! they are modeled as two separate chains:
//!
//! * The **policy chain** ([`PolicyChain`]) reads
//!   `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider`
//!   records, MDM setting reports, and the PolicyManager and WindowsUpdate
//!   policy registry locations. It answers: did the setting arrive, did the CSP
//!   accept it, did anything contend for the node, and what source is the device
//!   pointed at?
//! * The **update chain** ([`UpdateChain`]) reads
//!   `Microsoft-Windows-WindowsUpdateClient` records. It answers: did the client
//!   scan, was anything applicable, did it download, did it install, is a
//!   restart pending?
//!
//! The chains are joined only through [`ChainLinkage`], and only on the one
//! identifier they genuinely share: the update service id. Time proximity never
//! creates a link.
//!
//! Two consequences an implementer must preserve:
//!
//! * An update failure is never reported as an Intune delivery failure merely
//!   because an update ring exists. Execution findings are built from
//!   [`UpdateTransaction::evidence`], which the reducer fills only from
//!   update-client records.
//! * A successful policy application is never reported as a successful patch
//!   install. [`PolicyChainState::Applied`] and [`UpdateChainState::Installed`]
//!   are independent values on independent structures.
//!
//! # Supplemental formats
//!
//! `ReportingEvents.log`, `CBS.log`, and `dism.log` are consumed through this
//! crate's existing generic parsers and are strictly corroborating. A
//! supplemental line is retained only when it names an update explicitly, and it
//! is kept in [`UpdateTransaction::corroborating_evidence`], separate from the
//! update-client evidence that establishes state. Their absence never blocks a
//! conclusion; their presence never becomes one.
//!
//! # Boundary
//!
//! Nothing here reads a file, a registry, an event log, or a clock. Native
//! adapters decode those and supply [`UpdateEvidenceBundle`], whose event and
//! setting-report shapes come from [`crate::intune::normalized`]. That is what
//! keeps this crate `wasm32-unknown-unknown` clean and what makes the whole leaf
//! testable from fixtures with no device present.
//!
//! # Example
//!
//! ```
//! use cmtraceopen_parser::intune::device::windows::updates::{
//!     analyze_update_bundle, parse_update_bundle, PolicyChainState, UpdateChainState,
//! };
//!
//! let bundle = parse_update_bundle("{}").expect("an empty bundle parses");
//! let snapshot = analyze_update_bundle(&bundle);
//!
//! // The two questions stay separately answerable.
//! assert_eq!(snapshot.policy_chain.state, PolicyChainState::NotObserved);
//! assert_eq!(snapshot.update_chain.state, UpdateChainState::NotObserved);
//! ```

mod models;
mod redaction;
mod reducer;
mod rules;
mod sources;

pub use models::*;
pub use redaction::{is_public, redacted_export_projection, REDACTED};
pub use rules::{
    derive_findings, EVIDENCE_FINDING_PREFIX, FINDING_PREFIX, POLICY_FINDING_PREFIX,
    UPDATE_FINDING_PREFIX,
};
pub use sources::{
    classify_event, classify_mdm_event, classify_registry_fact, classify_setting_report,
    classify_update_client_event, error_code, is_update_policy_node, mentions_deferral,
    read_supplemental, source_for_service_id, update_key_from, EventClassification,
    SupplementalReading,
    MDM_DIAGNOSTICS_PROVIDER, NAMED_ADAPTER_OUTCOME, NAMED_ADAPTER_PHASE, NAMED_DEFERRAL_REASON,
    NAMED_ERROR_CODE, NAMED_KB_ARTICLE_IDS, NAMED_NODE_URI, NAMED_SERVICE_GUID,
    NAMED_UNSUPPORTED_VALUE, NAMED_UPDATE_COUNT, NAMED_UPDATE_GUID, NAMED_UPDATE_REVISION,
    NAMED_UPDATE_TITLE, NAMED_WINNING_POLICY_ID, POLICY_MANAGER_UPDATE_KEY,
    UPDATE_SERVICE_URL_VALUE, USE_WU_SERVER_VALUE, WINDOWS_UPDATE_CLIENT_PROVIDER,
    WSUS_AU_POLICY_KEY, WSUS_POLICY_KEY, WSUS_SERVER_VALUE,
};

use thiserror::Error;

/// Why an evidence bundle could not be read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UpdateBundleError {
    #[error("evidence bundle is not valid JSON: {0}")]
    InvalidJson(String),
    #[error(
        "evidence bundle declares schema version {found}, but this build understands {supported}"
    )]
    UnsupportedSchema { found: u32, supported: u32 },
}

/// Parse a serialized evidence bundle.
///
/// A bundle with no `schemaVersion` is read as version 1: the field arrived with
/// this contract, and rejecting an adapter that predates it would discard
/// capture bundles that are otherwise complete.
pub fn parse_update_bundle(json: &str) -> Result<UpdateEvidenceBundle, UpdateBundleError> {
    let mut bundle: UpdateEvidenceBundle = serde_json::from_str(json)
        .map_err(|error| UpdateBundleError::InvalidJson(error.to_string()))?;

    if bundle.schema_version == 0 {
        bundle.schema_version = INTUNE_WINDOWS_UPDATES_SCHEMA_VERSION;
    }
    if bundle.schema_version > INTUNE_WINDOWS_UPDATES_SCHEMA_VERSION {
        return Err(UpdateBundleError::UnsupportedSchema {
            found: bundle.schema_version,
            supported: INTUNE_WINDOWS_UPDATES_SCHEMA_VERSION,
        });
    }
    Ok(bundle)
}

/// Reduce an evidence bundle into an immutable snapshot with findings attached.
pub fn analyze_update_bundle(bundle: &UpdateEvidenceBundle) -> UpdateSnapshot {
    reducer::reduce_bundle(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_without_a_schema_version_is_read_as_version_one() {
        let bundle = parse_update_bundle("{}").expect("an empty bundle parses");
        assert_eq!(bundle.schema_version, INTUNE_WINDOWS_UPDATES_SCHEMA_VERSION);
    }

    #[test]
    fn a_future_schema_version_is_refused_rather_than_misread() {
        let error = parse_update_bundle(r#"{"schemaVersion": 99}"#).unwrap_err();
        assert_eq!(
            error,
            UpdateBundleError::UnsupportedSchema {
                found: 99,
                supported: INTUNE_WINDOWS_UPDATES_SCHEMA_VERSION,
            }
        );
    }

    #[test]
    fn an_empty_bundle_reduces_to_two_unobserved_chains() {
        let snapshot = analyze_update_bundle(&parse_update_bundle("{}").unwrap());
        assert_eq!(snapshot.policy_chain.state, PolicyChainState::NotObserved);
        assert_eq!(snapshot.update_chain.state, UpdateChainState::NotObserved);
        assert_eq!(snapshot.linkage.state, ChainLinkState::NotLinked);
        assert!(snapshot.findings.is_empty());
    }
}
