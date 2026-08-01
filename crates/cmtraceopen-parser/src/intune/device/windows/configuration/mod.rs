//! Intune/MDM configuration policy evidence.
//!
//! Owner: issue #363 of epic #356.
//!
//! Explains whether a configuration setting was delivered, processed by its CSP,
//! applied, rejected, conflicted, superseded, removed, or left unresolved.
//!
//! # The shape of the answer
//!
//! An administrator asking "did this setting apply?" is really asking three
//! questions that routinely have different answers:
//!
//! 1. did the device *receive* a command for the node ([`ConfigurationReceiptState`]),
//! 2. what did the *CSP* do with it ([`ConfigurationLocalState`]),
//! 3. what was *Intune* told ([`ConfigurationServiceState`]).
//!
//! The output keeps all three and only then states a single
//! [`ConfigurationResolution`]. When the device and the service disagree, the
//! resolution is [`ConfigurationResolution::Contradicted`] and both statements
//! are cited; the newer one is never preferred, because the two clocks are not
//! comparable without provenance this crate is rarely given.
//!
//! # Pipeline
//!
//! ```text
//! ConfigurationInput            normalized events + report rows + coverage
//!     -> sources::observation_from_{event,report}   one typed statement per record
//!     -> reduce_configuration                       one transaction per CSP identity
//!     -> derive_findings                            evidence-backed conclusions
//!     -> redacted_configuration_snapshot            default export
//! ```
//!
//! # Boundaries
//!
//! Nothing here reads EVTX, HTML reports, the registry, or Graph. The native
//! adapter decodes those and supplies
//! [`crate::intune::normalized::NormalizedWindowsEvent`] and
//! [`crate::intune::normalized::NormalizedSettingReport`], which keeps this leaf
//! `wasm32-unknown-unknown` clean and testable from fixtures with no device
//! present.

mod identity;
mod models;
mod redaction;
mod reducer;
mod rules;
mod sources;

pub use identity::{
    canonicalize_uri, csp_uri_from_message, policy_uri_from_message, resolve_identity,
    result_token_from_message, source_id_from_message, ConfigurationScope,
    ConfigurationSettingIdentity, IdentityHints,
};
pub use models::{
    evidence_side, ConfigurationDisposition, ConfigurationEventKind, ConfigurationEvidenceSide,
    ConfigurationInput, ConfigurationLocalState, ConfigurationObservation,
    ConfigurationReceiptState, ConfigurationResolution, ConfigurationServiceState,
    ConfigurationSetting, ConfigurationSnapshot, ConfigurationSourceStatement,
    INTUNE_CONFIGURATION_SCHEMA_VERSION,
};
pub use redaction::{looks_like_identity, redacted_configuration_snapshot, redaction_token};
pub use reducer::reduce_configuration;
pub use rules::derive_findings;
pub use sources::{
    build_error_code, classify_event, is_device_side, is_failure, is_service_side,
    observation_from_event, observation_from_report, timestamp_is_reliable,
    EVENT_ID_COMMAND_FAILURE, EVENT_ID_DELETE_POLICY, EVENT_ID_SET_POLICY_INT,
    EVENT_ID_SET_POLICY_STRING, MDM_DIAGNOSTICS_PROVIDER,
};

/// Reduce one evidence bundle and attach the findings derived from it.
///
/// This is the entry point callers want; [`reduce_configuration`] and
/// [`derive_findings`] are exposed separately so a caller that wants to attach
/// supplemental evidence between the two steps can do so without re-parsing.
pub fn analyze_configuration(input: &ConfigurationInput) -> ConfigurationSnapshot {
    let mut snapshot = reduce_configuration(input);
    snapshot.findings = derive_findings(&snapshot);
    snapshot
}
