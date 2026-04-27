use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Collection profile types (deserialized from embedded JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionProfile {
    pub profile_name: String,
    pub profile_version: String,
    pub logs: Vec<LogCollectionItem>,
    pub registry: Vec<RegistryCollectionItem>,
    pub event_logs: Vec<EventLogCollectionItem>,
    pub exports: Vec<FileExportItem>,
    pub commands: Vec<CommandCollectionItem>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogCollectionItem {
    pub id: String,
    pub family: String,
    pub source_pattern: String,
    pub destination_folder: String,
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryCollectionItem {
    pub id: String,
    pub family: String,
    pub path: String,
    pub file_name: String,
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogCollectionItem {
    pub id: String,
    pub family: String,
    pub source_pattern: String,
    pub destination_folder: String,
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileExportItem {
    pub id: String,
    pub family: String,
    pub source_path: String,
    pub destination_folder: String,
    pub file_name: Option<String>,
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandCollectionItem {
    pub id: String,
    pub family: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub file_name: String,
    pub timeout_secs: Option<u64>,
    pub notes: String,
}

// ---------------------------------------------------------------------------
// Result types (returned to frontend)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionResult {
    pub bundle_path: String,
    pub bundle_id: String,
    pub artifact_counts: ArtifactCounts,
    pub duration_ms: u64,
    pub gaps: Vec<CollectionGap>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactCounts {
    pub collected: u32,
    pub missing: u32,
    pub failed: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionGap {
    pub artifact_id: String,
    pub category: String,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Progress event payload (emitted to frontend via Tauri events)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionProgressPayload {
    pub request_id: String,
    pub message: String,
    pub current_item: Option<String>,
    pub completed_items: usize,
    pub total_items: usize,
}

// ---------------------------------------------------------------------------
// Per-artifact result (thread-safe aggregation)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactResult {
    pub id: String,
    pub category: String,
    pub status: ArtifactStatus,
    pub file_path: Option<String>,
    pub error: Option<String>,
    pub bytes_copied: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ArtifactStatus {
    Collected,
    Missing,
    Failed,
}
