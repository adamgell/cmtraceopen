// api-server library root.
//
// Exposes the Axum router builder so integration tests can drive the server
// in-process without binding to a real port. The `cmtraceopen-api` binary
// in `src/main.rs` is a thin runtime wrapper around this library.

#![forbid(unsafe_code)]

pub mod config;
pub mod routes;

use axum::Router;

/// Build the Axum router with all routes attached.
///
/// This is the composition root — future modules (ingest, devices, sessions,
/// auth middleware, CORS, tracing layers) plug in here.
pub fn router() -> Router {
    Router::new().merge(routes::health::router())
}
