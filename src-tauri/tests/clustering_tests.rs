//! Unit tests for the clustering module.
//!
//! These tests use mock embeddings to test the clustering pipeline
//! without requiring the ONNX model. Run with:
//!   cargo test --features clustering -- clustering

#![cfg(feature = "clustering")]

use std::collections::HashMap;

use app_lib::clustering::chunker::{chunk_entries, chunk_tail_entries};
use app_lib::clustering::cluster::{compute_centroid, dbscan_cluster};
use app_lib::clustering::incremental::assign_to_existing_clusters;
use app_lib::clustering::models::{ClusteringSession, ClusterResult, EmbeddingChunk};
use app_lib::models::log_entry::{LogEntry, LogFormat, Severity};

fn make_entry(id: u64, message: &str) -> LogEntry {
    LogEntry {
        id,
        line_number: id as u32,
        message: message.to_string(),
        component: None,
        timestamp: None,
        timestamp_display: None,
        severity: Severity::Info,
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Plain,
        file_path: "test.log".to_string(),
        timezone_offset: None,
    }
}

/// Creates a normalized random-ish embedding vector with a known direction.
fn make_embedding(cluster_seed: u32, variation: u32) -> Vec<f32> {
    let mut v = vec![0.0f32; 384];
    // Set a few dimensions based on the cluster seed to create distinct clusters
    let base = (cluster_seed * 50) as usize;
    for i in 0..50 {
        let idx = (base + i) % 384;
        v[idx] = 1.0 + (variation as f32 * 0.01);
    }
    // L2 normalize
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for val in &mut v {
            *val /= norm;
        }
    }
    v
}

#[test]
fn test_chunker_basic() {
    let entries: Vec<LogEntry> = (0..10)
        .map(|i| make_entry(i, &format!("Log line {}", i)))
        .collect();

    let chunks = chunk_entries(&entries, 3);
    assert_eq!(chunks.len(), 8); // 10 - 3 + 1

    // First chunk
    assert_eq!(chunks[0].entry_ids, vec![0, 1, 2]);
    assert_eq!(chunks[0].anchor_id, 1); // middle entry
    assert!(chunks[0].text.contains("Log line 0"));
    assert!(chunks[0].text.contains("Log line 1"));
    assert!(chunks[0].text.contains("Log line 2"));

    // Last chunk
    assert_eq!(chunks[7].entry_ids, vec![7, 8, 9]);
    assert_eq!(chunks[7].anchor_id, 8);
}

#[test]
fn test_chunker_empty() {
    let chunks = chunk_entries(&[], 3);
    assert!(chunks.is_empty());
}

#[test]
fn test_chunker_fewer_than_window() {
    let entries: Vec<LogEntry> = (0..2)
        .map(|i| make_entry(i, &format!("Line {}", i)))
        .collect();
    let chunks = chunk_entries(&entries, 5);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].entry_ids, vec![0, 1]);
}

#[test]
fn test_chunker_single_entry() {
    let entries = vec![make_entry(0, "Single")];
    let chunks = chunk_entries(&entries, 3);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].entry_ids, vec![0]);
    assert_eq!(chunks[0].anchor_id, 0);
}

#[test]
fn test_tail_chunker() {
    let existing: Vec<LogEntry> = (0..5)
        .map(|i| make_entry(i, &format!("old {}", i)))
        .collect();
    let new_entries: Vec<LogEntry> = (5..8)
        .map(|i| make_entry(i, &format!("new {}", i)))
        .collect();

    let chunks = chunk_tail_entries(&existing, &new_entries, 3);

    // All chunks should contain at least one new entry
    for chunk in &chunks {
        assert!(
            chunk.entry_ids.iter().any(|&id| id >= 5),
            "Chunk should contain at least one new entry: {:?}",
            chunk.entry_ids
        );
    }
}

#[test]
fn test_dbscan_distinct_clusters() {
    // Create 3 distinct clusters of embeddings
    let mut chunks = Vec::new();
    let mut embeddings = Vec::new();
    let mut messages = HashMap::new();

    // Cluster A: 5 entries about "certificate"
    for i in 0..5u64 {
        let msg = format!("Certificate enrollment for device {}", i);
        chunks.push(EmbeddingChunk {
            text: msg.clone(),
            entry_ids: vec![i],
            anchor_id: i,
        });
        embeddings.push(make_embedding(0, i as u32));
        messages.insert(i, msg);
    }

    // Cluster B: 5 entries about "download"
    for i in 5..10u64 {
        let msg = format!("Content download progress {}", i);
        chunks.push(EmbeddingChunk {
            text: msg.clone(),
            entry_ids: vec![i],
            anchor_id: i,
        });
        embeddings.push(make_embedding(1, i as u32));
        messages.insert(i, msg);
    }

    // Cluster C: 5 entries about "policy"
    for i in 10..15u64 {
        let msg = format!("Policy evaluation complete {}", i);
        chunks.push(EmbeddingChunk {
            text: msg.clone(),
            entry_ids: vec![i],
            anchor_id: i,
        });
        embeddings.push(make_embedding(2, i as u32));
        messages.insert(i, msg);
    }

    // One anomaly: completely different embedding
    let anomaly_id = 15u64;
    chunks.push(EmbeddingChunk {
        text: "Unexpected critical failure".to_string(),
        entry_ids: vec![anomaly_id],
        anchor_id: anomaly_id,
    });
    let mut anomaly_emb = vec![0.0f32; 384];
    anomaly_emb[383] = 1.0; // Completely different direction
    embeddings.push(anomaly_emb);
    messages.insert(anomaly_id, "Unexpected critical failure".to_string());

    let (clusters, anomalies) = dbscan_cluster(&chunks, &embeddings, &messages, 0.3, 3);

    assert_eq!(clusters.len(), 3, "Should find 3 clusters");
    assert!(
        anomalies.contains(&anomaly_id),
        "Entry {} should be flagged as anomaly",
        anomaly_id
    );

    // Each cluster should have 5 entries
    for cluster in &clusters {
        assert_eq!(cluster.size, 5, "Cluster '{}' should have 5 entries", cluster.label);
    }
}

#[test]
fn test_dbscan_all_noise() {
    // All embeddings are completely different
    let mut chunks = Vec::new();
    let mut embeddings = Vec::new();
    let messages = HashMap::new();

    for i in 0..5u64 {
        chunks.push(EmbeddingChunk {
            text: format!("line {}", i),
            entry_ids: vec![i],
            anchor_id: i,
        });
        let mut emb = vec![0.0f32; 384];
        emb[i as usize] = 1.0; // Each pointing in a different direction
        embeddings.push(emb);
    }

    let (clusters, anomalies) = dbscan_cluster(&chunks, &embeddings, &messages, 0.1, 3);

    assert!(clusters.is_empty(), "Should find no clusters");
    assert_eq!(anomalies.len(), 5, "All entries should be anomalies");
}

#[test]
fn test_compute_centroid() {
    let emb1 = vec![1.0f32, 0.0, 0.0];
    let emb2 = vec![0.0f32, 1.0, 0.0];
    let embeddings = vec![emb1, emb2];

    let centroid = compute_centroid(embeddings.iter());

    // Mean is [0.5, 0.5, 0.0], normalized to [1/sqrt(2), 1/sqrt(2), 0]
    let expected_val = 1.0 / 2.0f32.sqrt();
    assert!((centroid[0] - expected_val).abs() < 1e-5);
    assert!((centroid[1] - expected_val).abs() < 1e-5);
    assert!((centroid[2] - 0.0).abs() < 1e-5);
}

#[test]
fn test_incremental_assignment() {
    // Set up a session with 2 clusters
    let centroid_a = {
        let mut v = vec![0.0f32; 384];
        for i in 0..50 {
            v[i] = 1.0;
        }
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        for val in &mut v {
            *val /= norm;
        }
        v
    };

    let centroid_b = {
        let mut v = vec![0.0f32; 384];
        for i in 50..100 {
            v[i] = 1.0;
        }
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        for val in &mut v {
            *val /= norm;
        }
        v
    };

    let mut session = ClusteringSession {
        result: ClusterResult {
            clusters: vec![
                app_lib::clustering::models::Cluster {
                    id: 0,
                    label: "cluster A".to_string(),
                    entry_ids: vec![0, 1, 2],
                    representative_message: "test".to_string(),
                    size: 3,
                },
                app_lib::clustering::models::Cluster {
                    id: 1,
                    label: "cluster B".to_string(),
                    entry_ids: vec![3, 4, 5],
                    representative_message: "test".to_string(),
                    size: 3,
                },
            ],
            anomaly_entry_ids: vec![],
            total_entries: 6,
            clustered_entries: 6,
            processing_time_ms: 100,
        },
        centroids: vec![centroid_a.clone(), centroid_b.clone()],
        epsilon: 0.3,
        chunk_embeddings: vec![],
    };

    // New entry close to cluster A
    let new_entry_ids = vec![10u64];
    let new_embeddings = vec![centroid_a.clone()]; // Same direction as cluster A

    let result = assign_to_existing_clusters(&new_entry_ids, &new_embeddings, &mut session);

    assert!(
        result.assignments.contains_key(&10),
        "Entry 10 should be assigned to a cluster"
    );
    assert_eq!(
        result.assignments[&10], 0,
        "Entry 10 should be assigned to cluster A (id 0)"
    );
    assert!(result.new_anomaly_ids.is_empty());

    // New entry far from all clusters
    let mut far_emb = vec![0.0f32; 384];
    far_emb[383] = 1.0;
    let result2 = assign_to_existing_clusters(&[20], &[far_emb], &mut session);

    assert!(
        result2.new_anomaly_ids.contains(&20),
        "Entry 20 should be flagged as anomaly"
    );
}
