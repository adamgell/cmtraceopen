use axum::{routing::get, Json, Router};
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Readiness is identical to liveness while there are no external deps wired
/// up. Once the server connects to Postgres / object store, `/readyz` will do
/// a real dependency probe and `/healthz` stays shallow.
async fn readyz() -> Json<HealthResponse> {
    healthz().await
}

pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
}
