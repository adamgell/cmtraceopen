// common-wire
//
// Shared protocol types (DTOs) used by the api-server, the Windows agent, and
// eventually the web viewer. Platform-agnostic, wasm-safe, no Tauri or native
// dependencies.
//
// This crate is intentionally empty in the Phase 3 scaffold MVP. DTOs for the
// bundle-ingest protocol, device registry, and session queries land in
// subsequent commits once the api-server actually routes them.

#![forbid(unsafe_code)]
