//! Intune-managed Microsoft Store app evidence.
//!
//! Owner: issue #358 of epic #356.
//!
//! This is a **semantic analyzer over supplied evidence**, not a log format.
//! Raw IME records are framed by the shared CCM parser
//! ([`crate::intune::ime_parser`]) and Windows events arrive already normalized
//! as [`crate::intune::normalized::NormalizedWindowsEvent`]; only then is
//! anything classified. The module performs no I/O of any kind and pulls in no
//! EVTX or Windows API dependency.
//!
//! # Why the installer family comes first
//!
//! "Microsoft Store app" names a delivery channel, not an installer. Three
//! different grammars arrive through it:
//!
//! * a UWP/AppX/MSIX package registered into one user's context;
//! * the same payload staged and provisioned for the whole device;
//! * a Store-delivered Win32 package, where the Store brokers acquisition and an
//!   ordinary Windows installer does the work.
//!
//! They fail differently, report differently, and are fixed differently. So
//! [`StoreInstallerFamily`] is classified *before* a transaction is reduced, it
//! is a required field on every transaction, and
//! [`StoreInstallerFamily::Unknown`] is an explicit coverage state rather than a
//! default. AppX terminal semantics are never applied to a Store Win32 package,
//! and two different concrete families never merge into one transaction.
//!
//! # What the analyzer will not do
//!
//! * claim Intune caused an OS Store/AppX failure without both Intune intent
//!   evidence and a matching package identifier;
//! * join two records on a display name, a timestamp, or a shared channel;
//! * treat a missing event channel as proof that no deployment was attempted;
//! * guess an outcome from an event id or payload version it has no rule for.
//!
//! ```
//! use cmtraceopen_parser::intune::apps::windows::microsoft_store::{
//!     analyze_store_bundle, StoreArtifactPayload, StoreInstallerFamily, StoreSourceArtifact,
//!     StoreTransactionState,
//! };
//! use cmtraceopen_parser::intune::evidence::{IntuneArtifactStatus, IntuneSourceKind};
//!
//! let ime = concat!(
//!     r#"<![LOG[Store app AppId=11111111-2222-4333-8444-555555555555 "#,
//!     r#"StoreProductId=9WZSYNTH0001 is targeted for this device]LOG]!>"#,
//!     r#"<time="10:15:22.100+000" date="7-31-2026" component="Win32App" "#,
//!     r#"context="" type="1" thread="12" file="store.cs:1">"#,
//! );
//!
//! let analysis = analyze_store_bundle(&[StoreSourceArtifact {
//!     artifact_id: "ime".to_string(),
//!     family: "ime".to_string(),
//!     source_kind: IntuneSourceKind::ImeLog,
//!     status: IntuneArtifactStatus::Available,
//!     detail: None,
//!     observed_at_utc: "2026-07-31T00:00:00Z".to_string(),
//!     file_name: Some("IntuneManagementExtension.log".to_string()),
//!     file_path: None,
//!     payload: Some(StoreArtifactPayload::ImeText { text: ime.to_string() }),
//! }]);
//!
//! // Intune stated an intent. The OS never reported back, so the family stays
//! // unvalidated and no outcome is claimed.
//! assert_eq!(analysis.transactions.len(), 1);
//! assert_eq!(
//!     analysis.transactions[0].installer_family,
//!     StoreInstallerFamily::Unknown
//! );
//! assert_eq!(
//!     analysis.transactions[0].state,
//!     StoreTransactionState::InsufficientEvidence
//! );
//! ```

pub mod models;

mod findings;
mod redaction;
mod reducer;
mod rules;
mod sources;

pub use findings::derive_findings;
pub use models::*;
pub use redaction::{redact_text, redacted_export_projection};
pub use reducer::analyze_store_bundle;
pub use rules::{classify_event, classify_ime_record, parse_error_code, StoreClassification};
pub use sources::{
    candidate_text_source, classify_event_source, classify_text_artifact, StoreEventSource,
    StoreTextSource,
};
