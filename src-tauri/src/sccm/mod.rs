//! Reader-only native SCCM diagnostic manifest boundary.
//!
//! The pure diagnostic models and reducers remain in `cmtraceopen-parser`.
//! This module validates native bundle provenance and projects it into those
//! pure contracts without changing the generic collection manifest.

mod contract;
mod discovery;
mod manifest;
// This destination-only primitive intentionally has no production caller until
// native enumeration can supply a non-forgeable, handle-bound source token.
#[allow(dead_code)]
mod private_fs;

pub use cmtraceopen_parser::sccm::{SccmCoverageState, SccmRole, SccmRotation};
pub use contract::*;
pub use discovery::*;
pub use manifest::*;
