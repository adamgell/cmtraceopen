//! Company Portal Windows LocalState application logs.
//!
//! Reads `%LOCALAPPDATA%\Packages\Microsoft.CompanyPortal_8wekyb3d8bbwe\LocalState\Log_<n>.log`
//! and the sibling `Log.<BridgeName>_<n>.log` bridge logs, which are written by
//! the same logger and share the record grammar.
//!
//! # Evidence basis and its limitation
//!
//! Microsoft documents the path and the `Log_<n>.log` file pattern but not the
//! record grammar. Exactly **one** verbatim record has ever been published, from
//! Company Portal app version `12-0-0`. The grammar in [`grammar`] is derived
//! from that record and is therefore version-scoped from the start:
//!
//! - records are read with [`CompanyPortalGrammarVersion::V1`];
//! - a record whose app version is outside the validated set still parses with
//!   `V1` but downgrades the document to
//!   [`CompanyPortalGrammarSupport::Experimental`] and
//!   [`CompanyPortalConfidence::Low`];
//! - confidence never reaches `High`, because that would require a second app
//!   version captured from a real device.
//!
//! Encoding, newline style, rotation ordering, the full severity vocabulary,
//! and whether payloads genuinely span lines are all unproven from public
//! evidence. Each is handled defensively rather than assumed; see [`framing`]
//! for the continuation rule and [`detect`] for the rotation-index handling.
//!
//! # Two projections
//!
//! - [`parse_lines`] produces `LogEntry` records for the log viewer. Local
//!   rendering, never redacted.
//! - [`parse_log_document`] produces the canonical evidence document and is
//!   **redacted by default**;
//!   [`parse_log_document_preserving_local_values`] is the explicit opt-out.
//!
//! There is deliberately no semantic phase/outcome classification: none of the
//! Company Portal workflows (sign-in, enrollment, catalog, compliance, sync,
//! device actions, support) is proven by the available evidence, so unknown
//! messages stay ordinary parsed log records.

mod detect;
mod document;
mod entries;
mod framing;
mod grammar;
mod models;
mod redaction;

pub use detect::*;
pub use document::*;
pub use entries::*;
// Tailing needs the record-start predicate; keep grammar implementation details
// crate-private so they are not a semver surface.
pub use grammar::looks_like_record_start;
pub use models::*;
pub use redaction::*;
