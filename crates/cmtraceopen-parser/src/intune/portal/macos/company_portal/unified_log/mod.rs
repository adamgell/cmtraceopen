//! Apple unified-log evidence relevant to macOS Company Portal.
//!
//! Owner: issue #370 of epic #356.
//!
//! This is a **semantic analyzer over supplied normalized records**, not a log
//! reader. The stable contract consumes the versioned capture document described
//! in [`schema`]; it does not run `log show` and does not decode the binary
//! `.tracev3` store. Both are impossible here by construction — `std::process`
//! and `std::fs` are excluded by the crate's wasm32 invariant — and that
//! exclusion is the point: a macOS-only native adapter owns collection, and the
//! pure crate owns validation and reduction, so every rule below is testable
//! from fixtures with no device present.
//!
//! # What the analyzer will not do
//!
//! - accept a process name, or the word `CompanyPortal` in an arbitrary message,
//!   as evidence that a record belongs to Company Portal (see [`predicate`]);
//! - merge unified-log evidence with a direct Company Portal log on anything
//!   other than an explicit activity, signpost, or request identifier; there is
//!   deliberately no time-based join;
//! - re-sort records by timestamp, which would reorder evidence whose times are
//!   absent, offset-free, or boot-relative;
//! - treat the absence of a signal in a capped, skipped, or predicate-mismatched
//!   capture as proof that the signal never occurred.
//!
//! # Example
//!
//! ```
//! use cmtraceopen_parser::intune::portal::macos::company_portal::unified_log::{
//!     analyze_unified_log_bundle, UnifiedLogCaptureState, UnifiedLogRelevance,
//!     UnifiedLogSourceInput,
//! };
//!
//! let capture = concat!(
//!     r#"{"recordType":"captureHeader","#,
//!     r#""schemaId":"com.cmtraceopen.intune.portal.macos.companyPortal.unifiedLog","#,
//!     r#""schemaVersion":1,"#,
//!     r#""capture":{"predicateId":"companyPortalMacosV1","predicateVersion":1,"#,
//!     r#""collectedAtUtc":"2026-07-14T16:20:00Z"}}"#,
//!     "\n",
//!     r#"{"recordType":"logRecord","sequence":1,"#,
//!     r#""timestamp":"2026-07-14 09:15:02.123456-0700","#,
//!     r#""subsystem":"com.microsoft.CompanyPortalMac","category":"Authentication","#,
//!     r#""messageType":"error","activityIdentifier":8402315,"#,
//!     r#""eventMessage":"token acquisition failed, status -1009"}"#,
//!     "\n",
//! );
//!
//! let analysis = analyze_unified_log_bundle(&[UnifiedLogSourceInput {
//!     artifact_id: "cp-unified-log".to_string(),
//!     file_name: "company-portal-unified-log.ndjson".to_string(),
//!     capture_state: UnifiedLogCaptureState::Captured,
//!     content: Some(capture.to_string()),
//! }]);
//!
//! assert_eq!(analysis.observations.len(), 1);
//! assert_eq!(analysis.observations[0].relevance, UnifiedLogRelevance::Direct);
//! assert_eq!(analysis.activities[0].activity_identifier, 8402315);
//! assert!(analysis
//!     .findings
//!     .iter()
//!     .any(|finding| finding.finding_id == "unified-log-failures-observed"));
//! ```

pub mod schema;

mod models;
mod predicate;
mod redaction;
mod reducer;
mod rules;

pub use models::*;
pub use predicate::{
    classify_relevance, predicate_descriptor, UnifiedLogPredicateDescriptor, UnifiedLogRelevance,
    COMPANY_PORTAL_PREDICATE, COMPANY_PORTAL_PREDICATE_ID, COMPANY_PORTAL_PREDICATE_VERSION,
};
pub use redaction::{redact_text, redacted_export_projection};
pub use reducer::{analyze_unified_log_bundle, UNIFIED_LOG_COVERAGE_FAMILY};
pub use rules::derive_findings;
pub use schema::{
    parse_capture_document, NormalizedUnifiedLogRecord, UnifiedLogCaptureDocument,
    UnifiedLogCaptureMetadata, UnifiedLogParse, UnifiedLogRejectReason, UnifiedLogRejectedLine,
    UNIFIED_LOG_SCHEMA_ID, UNIFIED_LOG_SCHEMA_VERSION,
};
