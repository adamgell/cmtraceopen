//! DTOs mirroring `contract/openapi.yaml`.
//!
//! Hand-written for now — keep in sync with the contract, or replace this crate
//! with code generated from the OpenAPI spec (see contract/README.md).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub healthy: bool,
    pub tenant_id: Option<String>,
    pub last_sync_utc: Option<String>,
    pub cloud: Option<Cloud>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Cloud {
    Commercial,
    #[serde(rename = "GCC")]
    Gcc,
    #[serde(rename = "GCCHigh")]
    GccHigh,
    DoD,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: String,
    pub actor: Option<String>,
    pub action: String,
    pub object_type: String,
    pub object_id: String,
    pub object_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriftRecord {
    pub object_id: String,
    pub base_snapshot_id: Option<String>,
    pub head_snapshot_id: Option<String>,
    pub changes: Vec<DriftChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriftChange {
    pub path: String,
    pub kind: DriftKind,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DriftKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub kind: SearchKind,
    pub id: String,
    pub score: Option<f64>,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SearchKind {
    AuditEvent,
    ConfigSnapshot,
}
