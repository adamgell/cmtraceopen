// cmtraceopen-parser
//
// Pure-Rust log-format parsing, error-code database, and entry models.
// Consumed natively by src-tauri (desktop) and, later, by the
// cmtraceopen-web WASM build and the api-server crate.
//
// Invariant: this crate compiles to both native and wasm32-unknown-unknown.
// No Tauri, no tokio, no notify, no evtx, no windows/winreg, no rayon, no filesystem I/O.

pub mod error_db;
pub mod intune;
pub mod models;
pub mod parser;
