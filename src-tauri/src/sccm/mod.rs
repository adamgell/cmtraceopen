//! Reader-only native SCCM diagnostic manifest boundary.
//!
//! The pure diagnostic models and reducers remain in `cmtraceopen-parser`.
//! This module validates native bundle provenance and projects it into those
//! pure contracts without changing the generic collection manifest.

pub mod collector;
mod contract;
mod discovery;
mod manifest;
mod private_fs;

pub use cmtraceopen_parser::sccm::{SccmCoverageState, SccmRole, SccmRotation};
pub use contract::*;
pub use discovery::*;
pub use manifest::*;
