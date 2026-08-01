//! macOS Company Portal saved diagnostic reports (Help > Save Diagnostic Report).
//!
//! Owner: issue #369 of epic #356.
//!
//! # What this module is, and what it deliberately is not
//!
//! Microsoft documents the *flow* that produces a saved report. It does not
//! document what is inside one, and no sanitized real report is committed to
//! this repository. Issue #369's source-contract gate is explicit about the
//! consequence: do not invent filenames or schema from the UI label.
//!
//! So this module implements the half of the contract that *is* knowable, and
//! says so about the half that is not:
//!
//! * **Knowable.** The import envelope this crate defines
//!   ([`DiagnosticReportImport`]), member path safety, decoded content
//!   structure, coverage for everything unread, and container-level facts the
//!   importer declared. All of it is fixture-backed.
//! * **Not knowable yet.** Which member is the MSAL cache, which is a
//!   configuration property list, what the report's own version field is
//!   called. [`report_schema_support_state`] is
//!   [`DiagnosticsSupportState::SourceContract`] and every analysis carries the
//!   `cp-macos-diagnostics-report-schema-not-fixture-backed` finding, so a
//!   consumer cannot mistake "the module exists" for "the format is supported".
//!
//! A member role other than a structurally confirmed direct log is therefore
//! reported as *declared and unconfirmed*, never promoted to a fact. Direct log
//! members are handed to [`DIRECT_LOG_DELEGATION_TARGET`] (issue #368) rather
//! than re-parsed here.
//!
//! # Input boundary
//!
//! The parser receives an already-opened container: a report envelope plus
//! members whose bytes have already been decompressed and decoded to text.
//!
//! Archive acquisition, decompression limits, symlink handling, encrypted
//! members, and decompression bombs belong to the native import boundary,
//! because that is the layer that writes bytes to a disk. This crate adds no
//! archive dependency and stays `wasm32`-clean.
//!
//! That said, [`check_member_path`] re-checks every member path here as well.
//! A public API that trusts its caller's path hygiene is one careless importer
//! away from a filesystem escape, and a refused member has to surface as
//! coverage rather than vanish.
//!
//! # Pipeline
//!
//! [`reduce_diagnostic_report`] builds an immutable snapshot whose every member
//! carries an [`IntuneObservationContext`](crate::intune::evidence::IntuneObservationContext);
//! [`derive_findings`] then reads only that snapshot.
//! [`analyze_diagnostic_report`] runs both.
//! [`redacted_diagnostic_report_export`] produces the export projection.
//!
//! ```
//! use cmtraceopen_parser::intune::portal::macos::company_portal::diagnostics::{
//!     analyze_diagnostic_report, DeclaredProduct, DiagnosticReportEnvelope,
//!     DiagnosticReportImport, ExtractionOutcome, MemberImportState, ReportContainerKind,
//!     ReportDetection, ReportMemberRole, SuppliedReportMember,
//!     COMPANY_PORTAL_MACOS_DIAGNOSTICS_SCHEMA_VERSION,
//! };
//!
//! let analysis = analyze_diagnostic_report(&DiagnosticReportImport {
//!     schema_version: COMPANY_PORTAL_MACOS_DIAGNOSTICS_SCHEMA_VERSION,
//!     report: DiagnosticReportEnvelope {
//!         report_id: "report-1".to_string(),
//!         declared_product: Some(DeclaredProduct::CompanyPortalMacos),
//!         container_kind: ReportContainerKind::Zip,
//!         declared_report_schema: None,
//!         declared_app_version: None,
//!         collected_at: None,
//!         extraction: ExtractionOutcome::Complete,
//!         extraction_detail: None,
//!         sanitized_source_path: None,
//!         observed_at_utc: "2026-07-31T00:00:00Z".to_string(),
//!     },
//!     members: vec![SuppliedReportMember {
//!         member_id: "portal-log".to_string(),
//!         member_path: "logs/portal.log".to_string(),
//!         declared_role: Some(ReportMemberRole::DirectLog),
//!         declared_bytes: 64,
//!         declared_encoding: Some("utf-8".to_string()),
//!         transcoded_from: None,
//!         import_state: MemberImportState::Decoded,
//!         import_detail: None,
//!         content: Some(
//!             "2026-07-30T09:00:00Z started\n2026-07-30T09:00:01Z finished\n".to_string(),
//!         ),
//!     }],
//! });
//!
//! assert_eq!(analysis.detection, ReportDetection::DeclaredUnconfirmed);
//! // The log is classified and delegated, not re-parsed here.
//! assert_eq!(analysis.delegated_direct_logs().count(), 1);
//! ```

mod classify;
mod import;
mod models;
mod redaction;
mod reducer;
mod rules;

pub use import::{check_member_path, check_member_paths, MemberPathCheck};
pub use models::*;
pub use redaction::{redact_text, redacted_diagnostic_report_export};
pub use reducer::reduce_diagnostic_report;
pub use rules::derive_findings;

/// Reduce a supplied report and attach its derived findings.
///
/// This is the entry point. It is deterministic: the parser has no clock and no
/// I/O, observation time comes from the envelope, and members are sorted by
/// normalized path, so two runs over the same input serialize to the same
/// bytes regardless of the order the importer enumerated the container in.
pub fn analyze_diagnostic_report(import: &DiagnosticReportImport) -> DiagnosticReportSnapshot {
    let mut snapshot = reduce_diagnostic_report(import);
    snapshot.findings = derive_findings(&snapshot);
    snapshot
}
