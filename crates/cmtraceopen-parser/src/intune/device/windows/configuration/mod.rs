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
//! ```
//!
//! [`analyze_configuration`] runs that pipeline and stops there. Its result is
//! **not** redacted: [`ConfigurationSnapshot::redacted`] is `false` and the
//! applied values, node paths, and finding prose are the raw ones. A caller that
//! exports, persists, or transmits a snapshot must pass it through
//! [`redacted_configuration_snapshot`] first; that function is the export
//! projection, not something the analyzer applies on its own. Keeping the two
//! apart is deliberate — a caller correlating two settings by value needs the raw
//! reduction — but it means the redaction step is the caller's obligation and is
//! stated here rather than left to be inferred.
//!
//! The caller owns one more thing: [`ConfigurationInput::analysis_scope`], the
//! identity of this analysis. It is what the redaction tokens are scoped to, so a
//! caller that supplies a per-analysis unique value gets exports that cannot be
//! joined to one another by comparing tokens, and a caller that omits it gets no
//! such boundary. This crate cannot supply it: it is pure and has no clock,
//! entropy, or surviving process state from which to mint an identifier. What the
//! scope does and does not guarantee is stated in full on
//! [`ConfigurationInput::analysis_scope`] and
//! [`ConfigurationSnapshot::analysis_scope`].
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

// The exported surface is the input contract, the snapshot's own type graph, and
// the four entry points. Projection helpers (URI canonicalization, message
// scraping, per-record classification, error-token parsing) stay internal: they
// are how this module reaches its answer, not part of the answer, and exporting
// them would commit the crate to their signatures with no caller asking for them.
pub use identity::{ConfigurationScope, ConfigurationSettingIdentity};
pub use models::{
    ConfigurationDisposition, ConfigurationEventKind, ConfigurationEvidenceSide,
    ConfigurationInput, ConfigurationLocalState, ConfigurationObservation,
    ConfigurationReceiptState, ConfigurationResolution, ConfigurationServiceState,
    ConfigurationSetting, ConfigurationSnapshot, ConfigurationSourceStatement,
    INTUNE_CONFIGURATION_SCHEMA_VERSION,
};
pub use redaction::redacted_configuration_snapshot;
pub use reducer::reduce_configuration;
pub use rules::derive_findings;

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
