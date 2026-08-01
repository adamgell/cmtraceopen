//! Direct macOS Company Portal application logs.
//!
//! Owner: issue #368 of epic #356.
//!
//! Covers the files a native adapter discovers under
//! `~/Library/Logs/CompanyPortal/`. Direct application logs are a **distinct
//! source kind** from saved diagnostic reports (`super::diagnostics`) and Apple
//! unified-log exports (`super::unified_log`): all three can sit in the same
//! directory, and conflating them produces confident claims about the wrong
//! artifact. [`detection`] refuses the other two rather than guessing.
//!
//! # Boundary
//!
//! This crate performs no filesystem access, archive extraction, or unified-log
//! query. Directory discovery, permission handling, and byte reading live in the
//! native adapter, which hands over [`CompanyPortalLogSource`] values with the
//! text already decoded ([`decode_log_bytes`] implements the repository's UTF-8
//! then Windows-1252 rule and can be called from either side). That boundary is
//! what keeps the crate wasm32-clean and lets the whole reduction be tested from
//! a fixture corpus with no device present.
//!
//! # Shape
//!
//! ```text
//! sources    what the adapter collected, rotation identity, byte decoding
//! detection  is this a direct app log, or another source kind entirely
//! grammar    record grammar, logical multiline framing
//! reducer    artifacts + records -> snapshot, with coverage for what was missed
//! rules      snapshot -> conservative, evidence-citing findings
//! redaction  deterministic, idempotent redacted export projection
//! entries    LogEntry projection for the viewer
//! ```
//!
//! # Two output contracts
//!
//! [`parse_content`] produces `(Vec<LogEntry>, u32)` — the viewer-facing shape
//! every other parser in this repository uses, with lossless message text.
//!
//! [`analyze_company_portal_logs`] produces a [`CompanyPortalLogSnapshot`]: the
//! same records carrying an [`crate::intune::evidence::IntuneObservationContext`]
//! each, plus per-artifact coverage. [`derive_findings`] then reads that snapshot.
//!
//! # What is deliberately not modeled
//!
//! Records are not classified into sign-in, enrollment, sync, catalog, or device
//! actions. Doing that needs a validated message vocabulary from real sanitized
//! corpora across several app versions; without one, a classifier produces
//! confident and wrong workflow claims. Unknown records stay generic Company
//! Portal entries with their text preserved, and the modeled fields
//! (`subsystem`, `category`, `activity_id`) already carry the app's own
//! structural grouping.
//!
//! # Registration
//!
//! Detection is self-contained here rather than wired into
//! `crate::parser::detect`. Adding this leaf therefore cannot change how any
//! existing file is classified, and Company Portal logs keep resolving through
//! the generic timestamped fallback until a follow-up change routes them to
//! [`parse_content`]. [`detect_company_portal_log_content`] is the hook for that
//! change; it reports the sample counts it used so a caller can apply its own
//! threshold without re-scanning the file.

pub mod detection;
pub mod entries;
pub mod grammar;
pub mod models;
pub mod redaction;
pub mod reducer;
pub mod rules;
pub mod sources;

pub use detection::{
    detect_company_portal_log, detect_company_portal_log_content, is_company_portal_log,
    is_company_portal_process,
};
pub use entries::{parse_content, parse_lines};
pub use grammar::{frame_records, is_header_line, parse_header, FramedRecord, HeaderFields};
pub use models::{
    CompanyPortalCaptureState, CompanyPortalClassifiedString, CompanyPortalLogArtifact,
    CompanyPortalLogDetection, CompanyPortalLogRecord, CompanyPortalLogRejection,
    CompanyPortalLogSnapshot, CompanyPortalLogStats, CompanyPortalRecordProfile,
    CompanyPortalRotation, CompanyPortalRotationKind, CompanyPortalSeverity,
    CompanyPortalSeverityCounts, COMPANY_PORTAL_LOG_SCHEMA_VERSION, SUPPORTED_APP_VERSION_MAJORS,
};
pub use redaction::redacted_company_portal_log_export;
pub use reducer::{
    analyze_company_portal_logs, is_supported_app_version, COMPANY_PORTAL_APP_LOG_SOURCE_KIND,
    COMPANY_PORTAL_LOG_FAMILY,
};
pub use rules::derive_findings;
pub use sources::{decode_log_bytes, CompanyPortalLogSource, DecodedLog};
