//! Intune workload diagnostics and shared evidence contracts.
//! Raw CCM record framing lives in `crate::parser::ccm`.

pub mod apps;
pub(crate) mod common;
pub mod device;
pub mod enrollment;
pub mod evidence;
pub mod normalized;
pub mod portal;
