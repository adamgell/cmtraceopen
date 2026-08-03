// Pure analyzer modules live in cmtraceopen-parser::intune and are re-exported
// here so existing references like `crate::intune::models::*` and
// `app_lib::intune::*` keep resolving unchanged.
//
// Native-only readers (evtx_parser, eventlog_win32) stay in src-tauri because
// they depend on the `evtx` crate and Windows event-log APIs — neither of
// which belong in a wasm-compatible library.
//
// The epic #356 workload namespaces are re-exported as roots, not leaf by leaf.
// Rust resolves paths transitively through a re-exported module, so
// `app_lib::intune::device::windows::configuration` resolves as soon as `device`
// is listed here. That is what keeps the child issues of #356 from ever needing
// to edit this file.

pub use cmtraceopen_parser::intune::{
    apps, device, download_stats, enrollment, event_tracker, evidence, guid_registry, ime_parser,
    models, normalized, policy_parser, portal, timeline,
};

#[cfg(feature = "intune-diagnostics")]
pub mod eventlog_win32;
#[cfg(feature = "intune-diagnostics")]
pub mod evtx_parser;
