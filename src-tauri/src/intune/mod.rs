// Pure analyzer modules live in cmtraceopen-parser::intune and are re-exported
// here so existing references like `crate::intune::models::*` and
// `app_lib::intune::*` keep resolving unchanged.
//
// Native-only readers (evtx_parser, eventlog_win32) stay in src-tauri because
// they depend on the `evtx` crate and Windows event-log APIs — neither of
// which belong in a wasm-compatible library.

pub use cmtraceopen_parser::intune::{
    download_stats, event_tracker, guid_registry, ime_parser, models, policy_parser, timeline,
};

#[cfg(feature = "intune-diagnostics")]
pub mod eventlog_win32;
#[cfg(feature = "intune-diagnostics")]
pub mod evtx_parser;
