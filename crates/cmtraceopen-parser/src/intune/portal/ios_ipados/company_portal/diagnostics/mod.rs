//! Company Portal for iOS / iPadOS: imported macOS Console plain-text diagnostics.
//!
//! # Scope
//!
//! Microsoft's documented support workflow for iOS / iPadOS Company Portal problems is:
//! connect the device to a Mac, start a capture in the macOS Console app with info and debug
//! messages enabled, reproduce the problem, copy **all** visible records, and save them as a
//! plain-text `.log` file.
//!
//! This module consumes that imported file and nothing else. It does not access the device,
//! drive the Console app, read a sysdiagnose, or decode `.tracev3` — those are explicit
//! non-goals and belong to a future native macOS adapter.
//!
//! # Why filtering is part of the contract
//!
//! The workflow copies every visible Console record, so a real capture is dominated by
//! unrelated iOS system processes. Every raw record is preserved, and the Company Portal
//! subset is identified from verified structural fields only — the emitting process name and
//! the subsystem namespace. The words `Intune` or `CompanyPortal` appearing in free message
//! text are explicitly *not* sufficient, because unrelated daemons legitimately log about
//! them.
//!
//! # Conservative behaviour
//!
//! * an unregistered header layout is *detected*, not guessed at: records stay verbatim and
//!   are marked [`PortalConsoleParseState::Unsupported`];
//! * a line that anchors as a record but fails validation becomes
//!   [`PortalConsoleParseState::Malformed`] and is never attributed to Company Portal;
//! * a timestamp with no offset yields [`PortalTimestampKind::Local`] and drops the capture
//!   to [`PortalOrderingConfidence::CaptureLocalOnly`]. It is never defaulted to UTC;
//! * semantic evidence covers only fixture-proven categories. Anything else stays an
//!   ordinary record.
//!
//! # Example
//!
//! ```
//! use cmtraceopen_parser::intune::portal::ios_ipados::company_portal::diagnostics::*;
//!
//! let export = "\
//! Timestamp                       Thread     Type        Activity             PID    TTL  \n\
//! 2024-03-15 10:00:00.123456-0700 0x1a2b3    Default     0x0                  312    0    CompanyPortal: (Enrollment) [com.microsoft.CompanyPortal:Enrollment] Starting enrollment\n\
//! 2024-03-15 10:00:00.223456-0700 0x99aa1    Info        0x0                  55     0    SpringBoard: (FrontBoard) [com.apple.FrontBoard:Common] Activating scene\n";
//!
//! let capture = parse_console_export(export);
//! assert_eq!(capture.detection.outcome, PortalConsoleDetectionOutcome::Supported);
//! assert_eq!(capture.totals.total_records, 2);
//! assert_eq!(capture.company_portal_records().len(), 1);
//! ```

mod classify;
mod layout;
mod models;
mod parse;
mod redaction;

pub use models::*;
pub use parse::{
    detect_console_export, parse_console_export, parse_console_export_with_artifact_id,
    DEFAULT_SOURCE_ARTIFACT_ID,
};
pub use redaction::{
    redacted_export_projection, REDACTED_APP_ID, REDACTED_CERTIFICATE, REDACTED_DEVICE_ID,
    REDACTED_EMAIL, REDACTED_GUID, REDACTED_TENANT_ID, REDACTED_TOKEN, REDACTED_URL,
};
