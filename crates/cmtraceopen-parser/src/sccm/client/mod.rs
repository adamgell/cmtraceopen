//! Pure SCCM client diagnostics.
//!
//! This module accepts already-supplied metadata. Native discovery and capture
//! remain outside `cmtraceopen-parser`.

mod intake;
mod policy;

pub use intake::*;
pub use policy::*;
