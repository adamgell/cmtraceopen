use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use serde::Serialize;
use tauri::{async_runtime, AppHandle, Emitter, State};

use crate::clustering::chunker;
use crate::clustering::cluster::{compute_centroid, dbscan_cluster};
use crate::clustering::embedder::Embedder;
use crate::clustering::incremental::assign_to_existing_clusters;
use crate::clustering::model_manager;
use crate::clustering::models::{
    ClusterResult, ClusterableEntry, ClusteringConfig, ClusteringSession,
    ClusteringSourceSummary, IncrementalClusterResult, MultiSourceCluster,
    MultiSourceClusterResult,
};
use crate::parser;
use crate::state::app_state::AppState;

const CLUSTERING_PROGRESS_EVENT: &str = "clustering-progress";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClusteringProgressPayload {
    stage: String,
    message: String,
    percent: Option<f32>,
}

fn emit_progress(app: &AppHandle, stage: &str, message: &str, percent: Option<f32>) {
    let _ = app.emit(
        CLUSTERING_PROGRESS_EVENT,
        ClusteringProgressPayload {
            stage: stage.to_string(),
            message: message.to_string(),
            percent,
        },
    );
}

/// Run embedding + DBSCAN clustering on the log entries for the given file.
///
/// Re-parses the file to get entries (since entries live in the frontend,
/// not in AppState).
#[tauri::command]
pub async fn analyze_clusters(
    path: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ClusterResult, String> {
    let file_path = PathBuf::from(&path);

    // Verify the file is tracked in state
    {
        let open_files = state
            .open_files
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        if !open_files.contains_key(&file_path) {
            return Err(format!("File not open: {}", path));
        }
    }

    let path_for_parse = path.clone();
    let result = async_runtime::spawn_blocking(move || {
        analyze_clusters_blocking(&path_for_parse, &app)
    })
    .await
    .map_err(|e| format!("Clustering task failed: {}", e))??;

    // Store the session in state
    {
        let mut sessions = state
            .clustering_sessions
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        sessions.insert(file_path, result.1);
    }

    Ok(result.0)
}

fn analyze_clusters_blocking(
    path: &str,
    app: &AppHandle,
) -> Result<(ClusterResult, ClusteringSession), String> {
    let started = Instant::now();
    let config = ClusteringConfig::default();

    // Stage 0: Re-parse the file to get entries
    emit_progress(app, "parsing", "Parsing log file...", Some(0.0));
    let (parse_result, _parser_selection) = parser::parse_file(path)?;
    let entries = parse_result.entries;

    if entries.is_empty() {
        return Err("No log entries to cluster".to_string());
    }

    // Stage 1: Ensure model is available
    emit_progress(app, "model", "Checking embedding model...", Some(5.0));
    let (model_path, tokenizer_path) = model_manager::ensure_model(|msg, pct| {
        emit_progress(app, "model", msg, Some(pct * 0.1 + 5.0));
    })?;

    // Stage 2: Initialize embedder
    emit_progress(app, "init", "Initializing embedding engine...", Some(15.0));
    let mut embedder = Embedder::new(&model_path, &tokenizer_path)?;

    // Stage 3: Chunk entries
    emit_progress(app, "chunking", "Grouping log entries into chunks...", Some(18.0));
    let chunks = chunker::chunk_entries_with_stride(&entries, config.window_size, config.stride);
    let num_chunks = chunks.len();
    emit_progress(
        app,
        "chunking",
        &format!("Created {} chunks from {} entries", num_chunks, entries.len()),
        Some(20.0),
    );

    // Stage 4: Compute embeddings in batches
    emit_progress(app, "embedding", "Computing embeddings...", Some(20.0));
    let texts: Vec<String> = chunks.iter().map(|c| c.text.clone()).collect();

    let batch_size = 256;
    let mut all_embeddings: Vec<Vec<f32>> = Vec::with_capacity(texts.len());
    let total_batches = (texts.len() + batch_size - 1) / batch_size;

    for (batch_idx, batch) in texts.chunks(batch_size).enumerate() {
        let batch_vec: Vec<String> = batch.to_vec();
        let batch_embeddings = embedder.embed_batch(&batch_vec)?;
        all_embeddings.extend(batch_embeddings);

        let pct = 20.0 + ((batch_idx + 1) as f32 / total_batches.max(1) as f32) * 55.0;
        emit_progress(
            app,
            "embedding",
            &format!(
                "Embedded {}/{} chunks",
                all_embeddings.len().min(num_chunks),
                num_chunks
            ),
            Some(pct),
        );
    }

    // Stage 5: Cluster
    emit_progress(app, "clustering", "Running DBSCAN clustering...", Some(80.0));

    let messages: HashMap<u64, String> = entries
        .iter()
        .map(|e| (e.id, e.message.clone()))
        .collect();

    let (clusters, anomaly_entry_ids) =
        dbscan_cluster(&chunks, &all_embeddings, &messages, config.epsilon, config.min_points);

    let clustered_entries: usize = clusters.iter().map(|c| c.size).sum();
    let processing_time_ms = started.elapsed().as_millis() as u64;

    // Build centroids for incremental mode
    let centroids: Vec<Vec<f32>> = clusters
        .iter()
        .map(|cluster| {
            let cluster_chunk_indices: Vec<usize> = chunks
                .iter()
                .enumerate()
                .filter(|(_, chunk)| {
                    chunk.entry_ids.iter().any(|id| cluster.entry_ids.contains(id))
                })
                .map(|(i, _)| i)
                .collect();
            compute_centroid(cluster_chunk_indices.iter().map(|&i| &all_embeddings[i]))
        })
        .collect();

    let chunk_embeddings: Vec<(Vec<u64>, Vec<f32>)> = chunks
        .iter()
        .zip(all_embeddings.iter())
        .map(|(chunk, emb)| (chunk.entry_ids.clone(), emb.clone()))
        .collect();

    let result = ClusterResult {
        clusters: clusters.clone(),
        anomaly_entry_ids: anomaly_entry_ids.clone(),
        total_entries: entries.len(),
        clustered_entries,
        processing_time_ms,
    };

    let session = ClusteringSession {
        result: result.clone(),
        centroids,
        epsilon: config.epsilon,
        chunk_embeddings,
    };

    emit_progress(
        app,
        "complete",
        &format!(
            "Found {} clusters and {} anomalies in {:.1}s",
            result.clusters.len(),
            result.anomaly_entry_ids.len(),
            processing_time_ms as f32 / 1000.0
        ),
        Some(100.0),
    );

    Ok((result, session))
}

/// Get cached cluster results for a file.
#[tauri::command]
pub fn get_cluster_summary(
    path: String,
    state: State<'_, AppState>,
) -> Result<Option<ClusterResult>, String> {
    let file_path = PathBuf::from(&path);
    let sessions = state
        .clustering_sessions
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;

    Ok(sessions.get(&file_path).map(|s| s.result.clone()))
}

/// Get anomaly entry IDs for a file.
#[tauri::command]
pub fn get_anomalies(
    path: String,
    state: State<'_, AppState>,
) -> Result<Vec<u64>, String> {
    let file_path = PathBuf::from(&path);
    let sessions = state
        .clustering_sessions
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;

    Ok(sessions
        .get(&file_path)
        .map(|s| s.result.anomaly_entry_ids.clone())
        .unwrap_or_default())
}

/// Run embedding + DBSCAN clustering on entries from all workspace sources.
///
/// The frontend collects text data from every workspace (log entries, Intune
/// events/diagnostics, DSRegCmd diagnostics/event logs) into a flat
/// `Vec<ClusterableEntry>` and sends it here.  The backend chunks, embeds,
/// clusters, and returns results with per-cluster source breakdowns.
#[tauri::command]
pub async fn analyze_all_sources(
    entries: Vec<ClusterableEntry>,
    app: AppHandle,
) -> Result<MultiSourceClusterResult, String> {
    if entries.is_empty() {
        return Err("No entries to cluster".to_string());
    }

    let result = async_runtime::spawn_blocking(move || {
        analyze_all_sources_blocking(&entries, &app)
    })
    .await
    .map_err(|e| format!("Clustering task failed: {}", e))??;

    Ok(result)
}

fn analyze_all_sources_blocking(
    entries: &[ClusterableEntry],
    app: &AppHandle,
) -> Result<MultiSourceClusterResult, String> {
    let started = Instant::now();
    let config = ClusteringConfig::default();

    // Build source summary
    let mut source_counts: HashMap<String, usize> = HashMap::new();
    for entry in entries {
        *source_counts.entry(entry.source.clone()).or_default() += 1;
    }
    let sources: Vec<ClusteringSourceSummary> = source_counts
        .iter()
        .map(|(source, &count)| ClusteringSourceSummary {
            source: source.clone(),
            count,
        })
        .collect();

    emit_progress(
        app,
        "parsing",
        &format!("Collected {} entries from {} sources", entries.len(), sources.len()),
        Some(0.0),
    );

    // Stage 1: Ensure model is available
    emit_progress(app, "model", "Checking embedding model...", Some(5.0));
    let (model_path, tokenizer_path) = model_manager::ensure_model(|msg, pct| {
        emit_progress(app, "model", msg, Some(pct * 0.1 + 5.0));
    })?;

    // Stage 2: Initialize embedder
    emit_progress(app, "init", "Initializing embedding engine...", Some(15.0));
    let mut embedder = Embedder::new(&model_path, &tokenizer_path)?;

    // Stage 3: Chunk entries
    emit_progress(app, "chunking", "Grouping entries into chunks...", Some(18.0));
    let chunks = chunker::chunk_clusterable_entries(entries, config.window_size, config.stride);
    let num_chunks = chunks.len();
    emit_progress(
        app,
        "chunking",
        &format!("Created {} chunks from {} entries", num_chunks, entries.len()),
        Some(20.0),
    );

    // Stage 4: Compute embeddings in batches
    emit_progress(app, "embedding", "Computing embeddings...", Some(20.0));
    let texts: Vec<String> = chunks.iter().map(|c| c.text.clone()).collect();

    let batch_size = 256;
    let mut all_embeddings: Vec<Vec<f32>> = Vec::with_capacity(texts.len());
    let total_batches = (texts.len() + batch_size - 1) / batch_size;

    for (batch_idx, batch) in texts.chunks(batch_size).enumerate() {
        let batch_vec: Vec<String> = batch.to_vec();
        let batch_embeddings = embedder.embed_batch(&batch_vec)?;
        all_embeddings.extend(batch_embeddings);

        let pct = 20.0 + ((batch_idx + 1) as f32 / total_batches.max(1) as f32) * 55.0;
        emit_progress(
            app,
            "embedding",
            &format!(
                "Embedded {}/{} chunks",
                all_embeddings.len().min(num_chunks),
                num_chunks
            ),
            Some(pct),
        );
    }

    // Stage 5: Cluster
    emit_progress(app, "clustering", "Running DBSCAN clustering...", Some(80.0));

    let messages: HashMap<u64, String> = entries
        .iter()
        .map(|e| (e.id, e.message.clone()))
        .collect();

    let entry_source_map: HashMap<u64, String> = entries
        .iter()
        .map(|e| (e.id, e.source.clone()))
        .collect();

    let (clusters, anomaly_entry_ids) =
        dbscan_cluster(&chunks, &all_embeddings, &messages, config.epsilon, config.min_points);

    // Convert Cluster -> MultiSourceCluster with source breakdowns
    let multi_clusters: Vec<MultiSourceCluster> = clusters
        .into_iter()
        .map(|c| {
            let mut breakdown: HashMap<String, usize> = HashMap::new();
            for &eid in &c.entry_ids {
                if let Some(src) = entry_source_map.get(&eid) {
                    *breakdown.entry(src.clone()).or_default() += 1;
                }
            }
            let source_breakdown: Vec<ClusteringSourceSummary> = breakdown
                .into_iter()
                .map(|(source, count)| ClusteringSourceSummary { source, count })
                .collect();

            MultiSourceCluster {
                id: c.id,
                label: c.label,
                entry_ids: c.entry_ids,
                representative_message: c.representative_message,
                size: c.size,
                source_breakdown,
            }
        })
        .collect();

    let clustered_entries: usize = multi_clusters.iter().map(|c| c.size).sum();
    let processing_time_ms = started.elapsed().as_millis() as u64;

    // Collect anomaly entries with full info
    let anomaly_entries: Vec<ClusterableEntry> = entries
        .iter()
        .filter(|e| anomaly_entry_ids.contains(&e.id))
        .cloned()
        .collect();

    let result = MultiSourceClusterResult {
        clusters: multi_clusters,
        anomaly_entry_ids: anomaly_entry_ids.clone(),
        anomaly_entries,
        total_entries: entries.len(),
        clustered_entries,
        processing_time_ms,
        sources,
    };

    emit_progress(
        app,
        "complete",
        &format!(
            "Found {} clusters and {} anomalies across {} sources in {:.1}s",
            result.clusters.len(),
            result.anomaly_entry_ids.len(),
            result.sources.len(),
            processing_time_ms as f32 / 1000.0
        ),
        Some(100.0),
    );

    Ok(result)
}

/// Incrementally assign new tail entries to existing clusters.
///
/// The frontend sends the new entries (received from tail events).
/// Context for chunking comes from the most recent chunk embeddings
/// stored in the session.
#[tauri::command]
pub async fn assign_tail_entries_to_clusters(
    path: String,
    new_entries: Vec<crate::models::log_entry::LogEntry>,
    state: State<'_, AppState>,
) -> Result<IncrementalClusterResult, String> {
    let file_path = PathBuf::from(&path);

    if new_entries.is_empty() {
        return Ok(IncrementalClusterResult {
            assignments: HashMap::new(),
            new_anomaly_ids: Vec::new(),
            updated_clusters: Vec::new(),
        });
    }

    // Clone session data so we can release the lock before expensive work
    let session_snapshot = {
        let sessions = state
            .clustering_sessions
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        sessions
            .get(&file_path)
            .ok_or_else(|| "No clustering session for this file".to_string())?
            .clone()
    };
    // Lock is released here

    // Expensive: model loading + embedding computation (no lock held)
    let (model_path, tokenizer_path) = model_manager::ensure_model(|_, _| {})?;
    let mut embedder = Embedder::new(&model_path, &tokenizer_path)?;
    let texts: Vec<String> = new_entries.iter().map(|e| e.message.clone()).collect();
    let embeddings = embedder.embed_batch(&texts)?;
    let new_entry_ids: Vec<u64> = new_entries.iter().map(|e| e.id).collect();

    // Assign using the snapshot (read-only centroid comparison)
    let mut session_for_assign = session_snapshot;
    let result = assign_to_existing_clusters(&new_entry_ids, &embeddings, &mut session_for_assign);

    // Briefly re-acquire lock to persist updated session state
    {
        let mut sessions = state
            .clustering_sessions
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        if let Some(session) = sessions.get_mut(&file_path) {
            session.result = session_for_assign.result;
            session.centroids = session_for_assign.centroids;
            session.chunk_embeddings = session_for_assign.chunk_embeddings;
        }
    }

    Ok(result)
}
