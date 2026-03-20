use std::collections::HashMap;

use super::cluster::compute_centroid;
use super::embedder::cosine_similarity;
use super::models::{ClusteringSession, IncrementalClusterResult};

/// Assigns new entry embeddings to existing clusters or flags them as anomalies.
///
/// For each new embedding, computes cosine similarity to all cluster centroids.
/// If the best similarity exceeds the threshold (1.0 - epsilon), the entry is
/// assigned to that cluster. Otherwise, it's flagged as a new anomaly.
pub fn assign_to_existing_clusters(
    new_entry_ids: &[u64],
    new_embeddings: &[Vec<f32>],
    session: &mut ClusteringSession,
) -> IncrementalClusterResult {
    let threshold = 1.0 - session.epsilon;
    let mut assignments: HashMap<u64, u32> = HashMap::new();
    let mut new_anomaly_ids: Vec<u64> = Vec::new();

    for (idx, embedding) in new_embeddings.iter().enumerate() {
        let entry_id = new_entry_ids[idx];

        if session.centroids.is_empty() {
            new_anomaly_ids.push(entry_id);
            continue;
        }

        // Find nearest cluster centroid
        let mut best_cluster: Option<(u32, f32)> = None;
        for (cluster_idx, centroid) in session.centroids.iter().enumerate() {
            let sim = cosine_similarity(embedding, centroid);
            if let Some((_, best_sim)) = best_cluster {
                if sim > best_sim {
                    best_cluster = Some((cluster_idx as u32, sim));
                }
            } else {
                best_cluster = Some((cluster_idx as u32, sim));
            }
        }

        if let Some((cluster_id, sim)) = best_cluster {
            if sim >= threshold {
                assignments.insert(entry_id, cluster_id);

                // Update session: add entry to cluster
                if let Some(cluster) = session
                    .result
                    .clusters
                    .iter_mut()
                    .find(|c| c.id == cluster_id)
                {
                    cluster.entry_ids.push(entry_id);
                    cluster.size += 1;
                }

                // Store the embedding for future centroid recalculation
                session.chunk_embeddings.push((vec![entry_id], embedding.clone()));
            } else {
                new_anomaly_ids.push(entry_id);
                session.result.anomaly_entry_ids.push(entry_id);
            }
        } else {
            new_anomaly_ids.push(entry_id);
            session.result.anomaly_entry_ids.push(entry_id);
        }
    }

    // Recalculate centroids for updated clusters
    let updated_cluster_ids: Vec<u32> = assignments.values().copied().collect();
    for &cluster_id in &updated_cluster_ids {
        let cluster_entry_ids: std::collections::HashSet<u64> = session
            .result
            .clusters
            .iter()
            .find(|c| c.id == cluster_id)
            .map(|c| c.entry_ids.iter().copied().collect())
            .unwrap_or_default();

        // Recompute centroid from all chunk embeddings that overlap with this cluster
        let relevant_embeddings: Vec<&Vec<f32>> = session
            .chunk_embeddings
            .iter()
            .filter(|(ids, _)| ids.iter().any(|id| cluster_entry_ids.contains(id)))
            .map(|(_, emb)| emb)
            .collect();

        if !relevant_embeddings.is_empty() {
            let new_centroid = compute_centroid(relevant_embeddings.into_iter());
            if let Some(centroid) = session.centroids.get_mut(cluster_id as usize) {
                *centroid = new_centroid;
            }
        }
    }

    let updated_clusters = session
        .result
        .clusters
        .iter()
        .filter(|c| updated_cluster_ids.contains(&c.id))
        .cloned()
        .collect();

    IncrementalClusterResult {
        assignments,
        new_anomaly_ids,
        updated_clusters,
    }
}
