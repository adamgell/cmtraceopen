use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of clustering analysis for a log file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterResult {
    pub clusters: Vec<Cluster>,
    pub anomaly_entry_ids: Vec<u64>,
    pub total_entries: usize,
    pub clustered_entries: usize,
    pub processing_time_ms: u64,
}

/// A single cluster of semantically similar log entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cluster {
    pub id: u32,
    pub label: String,
    pub entry_ids: Vec<u64>,
    pub representative_message: String,
    pub size: usize,
}

/// Persistent state for a clustering session, enabling incremental updates.
pub struct ClusteringSession {
    pub result: ClusterResult,
    pub centroids: Vec<Vec<f32>>,
    pub epsilon: f32,
    pub chunk_embeddings: Vec<(Vec<u64>, Vec<f32>)>, // (entry_ids, embedding) per chunk
}

/// A chunk of temporally adjacent log entries for embedding.
#[derive(Debug, Clone)]
pub struct EmbeddingChunk {
    pub text: String,
    pub entry_ids: Vec<u64>,
    pub anchor_id: u64,
}

/// Configuration for clustering parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusteringConfig {
    pub window_size: usize,
    pub epsilon: f32,
    pub min_points: usize,
}

impl Default for ClusteringConfig {
    fn default() -> Self {
        Self {
            window_size: 3,
            epsilon: 0.3,
            min_points: 3,
        }
    }
}

/// Result of incremental cluster assignment for tail entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncrementalClusterResult {
    pub assignments: HashMap<u64, u32>, // entry_id -> cluster_id
    pub new_anomaly_ids: Vec<u64>,
    pub updated_clusters: Vec<Cluster>,
}

/// Progress event emitted during clustering analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusteringProgress {
    pub stage: String,
    pub message: String,
    pub percent: Option<f32>,
}
