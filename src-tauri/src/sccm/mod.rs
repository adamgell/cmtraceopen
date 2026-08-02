//! Bounded native SCCM diagnostic capture.
//!
//! This module owns native discovery and the SCCM-only manifest extension.
//! It intentionally does not alter the generic collector manifest contract.

mod bundle;
mod intake;
mod manifest;

pub use bundle::*;
pub use cmtraceopen_parser::sccm::{SccmCoverageState, SccmRole, SccmRotation};
pub use intake::*;
pub use manifest::*;
