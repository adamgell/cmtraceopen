//! Direct Company Portal application logs on macOS.
//!
//! # Source contract
//!
//! Company Portal writes to `~/Library/Logs/CompanyPortal/CompanyPortal.log`
//! (rotated siblings `CompanyPortal-<n>.log` / `CompanyPortal.log.<n>`) using
//! the Microsoft macOS house grammar already implemented generically in
//! [`crate::parser::intune_macos`]:
//!
//! ```text
//! YYYY-MM-DD HH:MM:SS:mmm | Process | S | ThreadID | Component | Message
//! ```
//!
//! Generic handling loses the Company Portal identity: an `IntuneMdmAgent` log
//! and a Company Portal log parse identically. This module makes Company Portal
//! a *distinct, confirmed* source kind.
//!
//! # Detection rules
//!
//! * A path under `~/Library/Logs/CompanyPortal` is a **hint only**.
//! * Confirmation requires record **structure** (a well-formed record head) plus
//!   the structural process field being exactly one of
//!   [`COMPANY_PORTAL_PROCESS_TOKENS`]. The word `CompanyPortal` appearing in
//!   free message text never confirms anything — an `IntuneMdmAgent` log that
//!   mentions Company Portal is classified as
//!   [`PortalSourceKind::IntuneMacosOtherProcessLog`].
//! * Apple unified-log ndjson exports and saved diagnostic-report summaries are
//!   recognized and rejected as their own source kinds.
//!
//! # Framing
//!
//! Records are logical, not physical: a line that is not a record start is a
//! continuation and attaches to the preceding record. A line that *looks* like a
//! record start (leading `YYYY-MM-DD HH:MM`) but does not satisfy the full
//! grammar becomes its own malformed record, and continuation text appearing
//! before any record head becomes an unframed record. Nothing is dropped: every
//! physical line is either inside a record or counted as blank, and the coverage
//! layer accounts for all of them.
//!
//! # Severity
//!
//! Severity comes from the structural severity field only. Message text is never
//! sniffed for severity. Records without a structural severity field default to
//! [`Severity::Info`](crate::models::log_entry::Severity::Info) and are reported
//! through coverage instead.

mod classify;
mod detect;
mod grammar;
mod models;
mod parse;
mod redaction;
mod rotation;

pub use classify::*;
pub use detect::*;
pub use grammar::*;
pub use models::*;
pub use parse::*;
pub use redaction::*;
pub use rotation::*;
