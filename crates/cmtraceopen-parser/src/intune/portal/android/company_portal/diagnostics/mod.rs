//! Android Company Portal imported diagnostic artifacts.
//!
//! Owner: issue #371 of epic #356.
//!
//! # This module does not parse Android Company Portal logs
//!
//! It is worth stating plainly, because the module name suggests otherwise.
//! Issue #371 requires that "no stable parser is exposed until an actual
//! sanitized artifact contract is documented", and no such artifact has been
//! obtained. The container layout, member names, record grammar, schema token,
//! encoding, and timestamp format of an Android Company Portal or Microsoft
//! Intune app diagnostic bundle are all **unverified** in this build.
//!
//! [`contract::VERIFIED_CONTRACTS`] is therefore empty, and every result this
//! module can produce reports [`IntuneParseState::Unsupported`] for every
//! member. [`AndroidDiagnosticsSnapshot::records`] is always empty. That is not
//! a gap waiting to be filled in silently; it is the deliverable. Inventing a
//! plausible-looking record grammar and shipping it under this module's name
//! would be worse than shipping nothing, because a wrong parse is
//! indistinguishable from a right one to the administrator reading it.
//!
//! # What this module does do
//!
//! Four things are provable without knowing the record grammar, and all four
//! are implemented and tested:
//!
//! 1. **Enumeration and provenance.** Members are listed, ordered, and given a
//!    [`IntuneObservationContext`] each, so a later build that gains a verified
//!    contract inherits the evidence plumbing rather than rebuilding it.
//! 2. **Import safety.** Traversal, absolute, duplicate, oversized, truncated,
//!    symlinked, and undecodable members are excluded from evidence and
//!    reported. Extraction happens outside this crate (see below), but a host
//!    that fails to report a bad entry does not thereby hide it: the name-level
//!    checks are re-derived here.
//! 3. **Refusal.** A bare `logcat` capture and an unrelated archive are
//!    recognized well enough to be declined. Issue #371 names both as things
//!    that must not be mistaken for Company Portal evidence.
//! 4. **Envelope facts and their caveats.** App, management mode, collection
//!    flow, verbose-logging state, incident ID, and collection time are
//!    recorded as importer-supplied facts with
//!    [`IntuneSourceKind::SuppliedFact`] provenance, and the caveats that
//!    follow from them are emitted as findings: work-profile collection scope,
//!    verbose logging turned off, an unresolvable timestamp, and an incident ID
//!    that is not a receipt.
//!
//! # Platform and purity boundary
//!
//! This module receives an archive **someone else already extracted**. It never
//! opens a file, never sees a `.zip`, never touches ADB, never invokes an app,
//! and never uploads anything. [`AndroidDiagnosticBundleInput`] carries named
//! entries, decoded text, byte counts, and whatever the importer noticed while
//! extracting. Everything here compiles to `wasm32-unknown-unknown` unchanged.
//!
//! # Reading order
//!
//! * [`contract`] is the source contract itself, including what is established
//!   from Microsoft's published collection workflow, what is not, and exactly
//!   what a future contribution must record before a parser can be claimed.
//! * `models` holds the input and output types.
//! * `sources` classifies bundles and members, and is where the "a name is
//!   never proof" rule lives.
//! * `reducer` builds the immutable snapshot.
//! * `rules` derives findings, one `push_*` per rule.
//! * `redaction` produces the deterministic redacted export projection.
//!
//! ```
//! use cmtraceopen_parser::intune::evidence::IntuneArtifactStatus;
//! use cmtraceopen_parser::intune::portal::android::company_portal::diagnostics::{
//!     analyze_android_diagnostic_bundle, AndroidBundleClassification, AndroidDiagnosticApp,
//!     AndroidDiagnosticBundleInput, AndroidDiagnosticMemberInput, AndroidImportLimits,
//!     AndroidSuppliedCollectionFacts,
//! };
//!
//! let snapshot = analyze_android_diagnostic_bundle(&AndroidDiagnosticBundleInput {
//!     bundle_id: "import-1".to_string(),
//!     observed_at_utc: "2026-07-31T00:00:00Z".to_string(),
//!     supplied: AndroidSuppliedCollectionFacts {
//!         app: Some(AndroidDiagnosticApp::CompanyPortal),
//!         ..Default::default()
//!     },
//!     members: vec![AndroidDiagnosticMemberInput {
//!         artifact_id: "member-1".to_string(),
//!         entry_name: "diagnostic_summary.txt".to_string(),
//!         sanitized_entry_path: None,
//!         status: IntuneArtifactStatus::Available,
//!         declared_bytes: 12,
//!         encoding: Some("utf-8".to_string()),
//!         rotation: None,
//!         text: Some("key = value\n".to_string()),
//!         safety_flags: Vec::new(),
//!     }],
//!     limits: AndroidImportLimits::default(),
//! });
//!
//! // Enumerated, never interpreted: no artifact contract is verified yet.
//! assert_eq!(
//!     snapshot.metadata.classification,
//!     AndroidBundleClassification::CandidateUnverifiedContract
//! );
//! assert!(snapshot.records.is_empty());
//! ```
//!
//! [`IntuneParseState::Unsupported`]: crate::intune::evidence::IntuneParseState::Unsupported
//! [`IntuneObservationContext`]: crate::intune::evidence::IntuneObservationContext
//! [`IntuneSourceKind::SuppliedFact`]: crate::intune::evidence::IntuneSourceKind::SuppliedFact

pub mod contract;

mod models;
mod redaction;
mod reducer;
mod rules;
mod sources;

pub use contract::{
    match_verified_contract, verified_contract_count, AndroidCollectionFlow, AndroidDiagnosticApp,
    AndroidManagementMode, AndroidUploadOutcome, AndroidVerboseLoggingState,
    VerifiedArtifactContract, ANDROID_DIAGNOSTICS_FAMILY, ANDROID_DIAGNOSTICS_SCHEMA_VERSION,
    VERIFIED_CONTRACTS,
};
pub use models::{
    access_state_for, AndroidBundleClassification, AndroidDiagnosticBundleInput,
    AndroidDiagnosticMember, AndroidDiagnosticMemberInput, AndroidDiagnosticRecord,
    AndroidDiagnosticReportMetadata, AndroidDiagnosticsSnapshot, AndroidImportLimits,
    AndroidMemberClassification, AndroidMemberSafetyFlag, AndroidSuppliedCollectionFacts,
};
pub use redaction::{
    redact_text, redacted_export_projection, DEVICE_ID_MARKER, EMAIL_MARKER, GUID_MARKER,
    INCIDENT_MARKER, PACKAGE_MARKER, TOKEN_MARKER, URL_MARKER,
};
pub use reducer::{
    analyze_android_diagnostic_bundle, normalize_supplied_timestamp, SUPPLIED_FACTS_SUFFIX,
};
pub use rules::derive_findings;
pub use sources::{
    classify_bundle, classify_member, duplicates_in, is_logcat_capture, lexical_safety_flags,
    safety_flags_for,
};
