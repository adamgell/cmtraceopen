//! Company Portal evidence from Apple unified-log captures (macOS).
//!
//! # Scope
//!
//! This module consumes a **versioned normalized capture** produced by native
//! macOS code and reduces it to Company Portal evidence. It is a pure,
//! wasm-compatible contract:
//!
//! * it never runs `log show`;
//! * it never touches the filesystem, the network, or a device;
//! * it never decodes the binary `.tracev3` store.
//!
//! Collection lives in macOS-only code outside this crate, which already runs
//! `log show --predicate <p> --style ndjson` and can emit the schema described
//! in [`schema`] and [`models`]. That schema is a superset of the raw
//! `log show` ndjson fields, adding timezone/boot-relative metadata,
//! activity/signpost identifiers, capture predicate and window, host and app
//! versions, collection time, coverage, redaction metadata, and source sequence.
//!
//! # Pipeline
//!
//! ```text
//! capture text ──> ingest ──────> PortalUnifiedLogCaptureSet
//!                  (validate,     (records + explicit coverage)
//!                   never drop)
//!                                        │
//!                                        ▼
//!                              selection + reduce ──> PortalUnifiedLogReduction
//!                              (conservative           (evidence, activities,
//!                               predicate)              coverage, provenance)
//!                                        │
//!                          ┌─────────────┴─────────────┐
//!                          ▼                           ▼
//!                    correlation                   redaction
//!               (explicit keys only;         (deterministic, stable
//!                time never merges)           placeholder tokens)
//! ```
//!
//! # Invariants
//!
//! * Exact source sequence is preserved; nothing is re-sorted by timestamp.
//! * Malformed lines, unknown schema versions, capped or permission-denied
//!   collection, unselected records, and degraded timestamps all surface as
//!   [`models::PortalCoverageEntry`], never as silent drops.
//! * A process name alone never selects a record, and the words
//!   `CompanyPortal` or `Intune` in a message body never select a record.
//! * A merge with a direct Company Portal log requires an explicit shared
//!   identifier or a documented relationship; a shared timestamp never merges.

pub mod correlation;
pub mod ingest;
pub mod models;
pub mod redaction;
pub mod reduce;
pub mod schema;
pub mod selection;

pub use correlation::*;
pub use ingest::*;
pub use models::*;
pub use redaction::*;
pub use reduce::*;
pub use schema::*;
pub use selection::*;
