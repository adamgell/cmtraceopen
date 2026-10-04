// Workload APIs have canonical ownership in the pure parser. Native event
// acquisition stays here because it uses OS APIs.
pub use cmtraceopen_parser::intune::{apps, device, enrollment, evidence, normalized, portal};

#[cfg(feature = "intune-diagnostics")]
pub mod eventlog_win32;
#[cfg(feature = "intune-diagnostics")]
pub mod evtx_parser;
