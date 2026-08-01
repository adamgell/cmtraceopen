//! iOS/iPadOS Company Portal Console diagnostic captures.
//!
//! Owner: issue #372 of epic #356.
//!
//! # What this parses
//!
//! Microsoft's documented iOS/iPadOS troubleshooting workflow has the operator
//! connect the device to a Mac, start a capture in the macOS Console app, enable
//! info and debug messages, reproduce the Company Portal problem, copy **all**
//! visible records, convert them to plain text, and save a `.log` file. This
//! module consumes that imported file and nothing else. It does not touch the
//! device, drive Console, read a sysdiagnose, or decode `.tracev3`; an automated
//! capture belongs to a future native macOS adapter.
//!
//! Because the workflow copies every visible record, an export is a slice of the
//! whole system's log, not of one app's. Three consequences shape everything
//! here.
//!
//! **Filtering is part of the contract.** A record is Company Portal evidence
//! only when the Process or Subsystem column names the app. The word `Intune`
//! in arbitrary message text is explicitly not sufficient, because any process
//! can log it. See [`ConsoleSourceClass`].
//!
//! **The window is partial by construction.** The capture holds only what the
//! operator was recording and copied. No rule in [`derive_findings`] concludes
//! that something did not happen, and the partial window is itself reported as a
//! finding so every other conclusion is read against it.
//!
//! **Time is local wall-clock time.** Console renders the Mac's local clock and
//! the offset is frequently absent from a copied selection. When it is,
//! [`crate::intune::evidence::IntuneTimestampKind::Local`] is reported and
//! `normalized_utc` stays `None`. Assuming UTC would shift the record by hours
//! and leave no evidence that a guess was made.
//!
//! # Shape
//!
//! ```text
//! ConsoleExportInput  ──▶ resolve_layout ──▶ parse_export ──▶ ConsoleRecord
//!                                                               │
//!                        analyze_console_exports ◀──────────────┘
//!                                   │
//!                                   ├──▶ ConsoleDiagnosticsSnapshot
//!                                   └──▶ derive_findings ──▶ IntuneFinding
//! ```
//!
//! Observations carry the shared [`crate::intune::evidence`] envelope, so a
//! record's provenance, timestamp state, privacy class, parse state, and access
//! state travel with it. Findings cite evidence references or coverage gaps and
//! never both nothing.
//!
//! # Privacy
//!
//! The snapshot keeps message text as captured: an administrator reading their
//! own device's log is entitled to it. [`redacted_export_projection`] is the only
//! form that may leave the process, and it masks UPNs, secrets, certificates,
//! URL queries, device paths, GUIDs, and device identifiers behind stable
//! per-analysis tokens so cross-record correlation survives redaction.
//!
//! # Example
//!
//! ```
//! use cmtraceopen_parser::intune::portal::ios_ipados::company_portal::diagnostics::{
//!     analyze_console_exports, ConsoleAnalysisOptions, ConsoleExportInput, ConsoleSourceClass,
//! };
//!
//! let export = concat!(
//!     "Timestamp\tType\tProcess\tPID\tTID\tActivity\tSubsystem\tCategory\tMessage\n",
//!     "2026-03-12 10:15:22.481293-0700\tError\tCompanyPortal\t418\t0x1f4a\t0\t",
//!     "com.microsoft.CompanyPortal\tAuthentication\tacquireToken failed\n",
//!     "2026-03-12 10:15:22.481512-0700\tDefault\tSpringBoard\t60\t0x22\t0\t",
//!     "com.apple.springboard\tDefault\tunrelated noise mentioning Intune\n",
//! );
//!
//! let snapshot = analyze_console_exports(
//!     &[ConsoleExportInput::captured("console-1", "CompanyPortal.log", export)],
//!     &ConsoleAnalysisOptions::observed_at("2026-07-31T00:00:00Z"),
//! );
//!
//! assert_eq!(snapshot.records.len(), 2);
//! assert_eq!(snapshot.totals.company_portal_record_count, 1);
//! assert_eq!(snapshot.records[1].source_class, ConsoleSourceClass::Unrelated);
//! assert!(snapshot
//!     .findings
//!     .iter()
//!     .any(|finding| finding.finding_id == "console-company-portal-sign-in-failure"));
//! ```

mod classify;
mod layout;
mod models;
mod parse;
mod redaction;
mod reducer;
mod rules;

pub use models::*;
pub use redaction::{
    redact_text, redact_with, redacted_export_projection, RedactedText, RedactionLedger,
};
pub use reducer::analyze_console_exports;
pub use rules::derive_findings;
