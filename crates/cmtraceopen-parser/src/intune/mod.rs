//! Intune log parsing and workload diagnostics.
//!
//! Two generations of module live here side by side.
//!
//! The flat modules (`event_tracker`, `download_stats`, `policy_parser`,
//! `guid_registry`, `timeline`, `ime_parser`, `models`) are the original
//! IME-centered surface. They remain public and behavior-compatible.
//!
//! The workload namespaces (`apps`, `enrollment`, `device`, `portal`) are the
//! family described by epic #356, organized by what an administrator is actually
//! troubleshooting rather than by which log file happens to hold the evidence.
//! Leaves that are not yet implemented are reserved slots, each owned by exactly
//! one child issue and filled in by that issue's own pull request.
//!
//! `evidence` and `normalized` hold the contracts shared across those leaves.
//! They live here, not inside any one leaf, so that the child issues can be
//! implemented and merged in any order.
//!
//! `ccm` stays the shared raw CMTrace-compatible grammar used by both IME and
//! SCCM. Nothing in this tree adds a second raw CCM parser.

pub mod apps;
pub mod device;
pub mod download_stats;
pub mod enrollment;
pub mod event_tracker;
pub mod evidence;
pub mod guid_registry;
pub mod ime_parser;
pub mod models;
pub mod normalized;
pub mod policy_parser;
pub mod portal;
pub mod timeline;
