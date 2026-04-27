// Pure pieces (types, embedded profile catalog, env-var expansion) live in
// cmtraceopen-parser::collector. Re-exported here so existing references like
// `crate::collector::types::CollectionProfile` and
// `crate::collector::profile::get_profile_by_id` keep resolving unchanged.
//
// Native modules (artifacts.rs: fs + glob, engine.rs: Tauri Emitter,
// manifest.rs: std::fs + AppError) stay in src-tauri because they touch the
// filesystem or the Tauri runtime — concerns that don't belong in the
// wasm-compatible parser crate.

pub use cmtraceopen_parser::collector::{env_expand, profile, types};

pub mod artifacts;
pub mod engine;
pub mod manifest;
