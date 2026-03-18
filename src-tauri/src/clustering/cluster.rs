use std::collections::{HashMap, HashSet};

use once_cell::sync::Lazy;
use rayon::prelude::*;

use super::embedder::{cosine_similarity, EMBEDDING_DIM};
use super::models::{Cluster, EmbeddingChunk};

/// A set of common English stopwords to exclude from cluster labels.
static STOPWORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had",
        "do", "does", "did", "will", "would", "could", "should", "may", "might", "shall", "can",
        "to", "of", "in", "for", "on", "with", "at", "by", "from", "as", "into", "through",
        "during", "before", "after", "above", "below", "between", "out", "off", "over", "under",
        "again", "further", "then", "once", "and", "but", "or", "nor", "not", "no", "so", "if",
        "than", "too", "very", "just", "about", "up", "it", "its", "this", "that", "these",
        "those", "i", "me", "my", "we", "our", "you", "your", "he", "him", "his", "she", "her",
        "they", "them", "their", "what", "which", "who", "whom", "all", "each", "every", "both",
        "more", "most", "other", "some", "such", "only", "own", "same",
        "log", "line", "entry", "message", "info", "error", "warning",
    ]
    .into_iter()
    .collect()
});

/// Runs DBSCAN clustering on embeddings and returns clusters + anomaly IDs.
///
/// Uses a precomputed neighbor list (parallel cosine similarity) so the
/// DBSCAN inner loop does O(1) neighbor lookups instead of O(n) scans.
pub fn dbscan_cluster(
    chunks: &[EmbeddingChunk],
    embeddings: &[Vec<f32>],
    messages: &HashMap<u64, String>,
    epsilon: f32,
    min_points: usize,
) -> (Vec<Cluster>, Vec<u64>) {
    let n = embeddings.len();
    if n == 0 {
        return (Vec::new(), Vec::new());
    }

    // ── Precompute neighbor lists in parallel ──────────────────────────────
    // For each point, store the indices of all points within epsilon cosine
    // distance. This turns region_query from O(n) to O(1) during DBSCAN.
    let similarity_threshold = 1.0 - epsilon;

    let neighbors: Vec<Vec<usize>> = (0..n)
        .into_par_iter()
        .map(|i| {
            let target = &embeddings[i];
            let mut nb = Vec::new();
            for j in 0..n {
                if cosine_similarity(target, &embeddings[j]) >= similarity_threshold {
                    nb.push(j);
                }
            }
            nb
        })
        .collect();

    // ── DBSCAN with precomputed neighbors ─────────────────────────────────
    let mut labels = vec![-1i32; n]; // -1 = unvisited, -2 = noise
    let mut cluster_id: i32 = 0;

    for i in 0..n {
        if labels[i] != -1 {
            continue;
        }

        if neighbors[i].len() < min_points {
            labels[i] = -2; // noise
            continue;
        }

        // Start a new cluster
        labels[i] = cluster_id;
        let mut seed_set: HashSet<usize> =
            neighbors[i].iter().copied().filter(|&j| j != i).collect();
        let mut queue: Vec<usize> = seed_set.iter().copied().collect();
        let mut idx = 0;

        while idx < queue.len() {
            let q = queue[idx];
            if labels[q] == -2 {
                labels[q] = cluster_id; // Change noise to border point
            }
            if labels[q] != -1 {
                idx += 1;
                continue;
            }
            labels[q] = cluster_id;

            if neighbors[q].len() >= min_points {
                for &nb in &neighbors[q] {
                    if !seed_set.contains(&nb) && labels[nb] <= -1 {
                        seed_set.insert(nb);
                        queue.push(nb);
                    }
                }
            }
            idx += 1;
        }

        cluster_id += 1;
    }

    // ── Build clusters from labels ────────────────────────────────────────
    let mut cluster_chunks: HashMap<i32, Vec<usize>> = HashMap::new();
    let mut noise_indices = Vec::new();

    for (i, &label) in labels.iter().enumerate() {
        if label >= 0 {
            cluster_chunks.entry(label).or_default().push(i);
        } else {
            noise_indices.push(i);
        }
    }

    let mut clusters: Vec<Cluster> = cluster_chunks
        .par_iter()
        .map(|(&cid, chunk_indices)| {
            let mut entry_ids: Vec<u64> = chunk_indices
                .iter()
                .flat_map(|&ci| chunks[ci].entry_ids.iter().copied())
                .collect::<HashSet<u64>>()
                .into_iter()
                .collect();
            entry_ids.sort();

            let centroid = compute_centroid(chunk_indices.iter().map(|&i| &embeddings[i]));
            let best_chunk_idx = chunk_indices
                .iter()
                .max_by(|&&a, &&b| {
                    cosine_similarity(&embeddings[a], &centroid)
                        .partial_cmp(&cosine_similarity(&embeddings[b], &centroid))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .copied()
                .unwrap_or(chunk_indices[0]);

            let representative_id = chunks[best_chunk_idx].anchor_id;
            let representative_message = messages
                .get(&representative_id)
                .cloned()
                .unwrap_or_default();

            let label = generate_cluster_label(&entry_ids, messages);

            Cluster {
                id: cid as u32,
                label,
                size: entry_ids.len(),
                entry_ids,
                representative_message,
            }
        })
        .collect();

    // Sort clusters by size descending and reassign sequential IDs
    clusters.sort_by(|a, b| b.size.cmp(&a.size));
    for (i, cluster) in clusters.iter_mut().enumerate() {
        cluster.id = i as u32;
    }

    // Anomaly entry IDs = entries from noise chunks not in any cluster
    let clustered_ids: HashSet<u64> = clusters
        .iter()
        .flat_map(|c| c.entry_ids.iter().copied())
        .collect();
    let mut anomaly_ids: Vec<u64> = noise_indices
        .iter()
        .flat_map(|&ci| chunks[ci].entry_ids.iter().copied())
        .filter(|id| !clustered_ids.contains(id))
        .collect::<HashSet<u64>>()
        .into_iter()
        .collect();
    anomaly_ids.sort();

    (clusters, anomaly_ids)
}

/// Computes the mean centroid of a set of embeddings, then L2-normalizes it.
pub fn compute_centroid<'a>(embeddings: impl Iterator<Item = &'a Vec<f32>>) -> Vec<f32> {
    let mut sum = vec![0.0f32; EMBEDDING_DIM];
    let mut count = 0usize;

    for emb in embeddings {
        for (s, &v) in sum.iter_mut().zip(emb.iter()) {
            *s += v;
        }
        count += 1;
    }

    if count > 0 {
        let count_f = count as f32;
        for s in &mut sum {
            *s /= count_f;
        }
    }

    // L2 normalize
    let norm: f32 = sum.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 0.0 {
        for s in &mut sum {
            *s /= norm;
        }
    }

    sum
}

/// Generates a human-readable label for a cluster from its entries' messages.
fn generate_cluster_label(entry_ids: &[u64], messages: &HashMap<u64, String>) -> String {
    let mut token_counts: HashMap<String, usize> = HashMap::new();

    for id in entry_ids {
        if let Some(msg) = messages.get(id) {
            for token in msg.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-') {
                let lower = token.to_lowercase();
                if lower.len() >= 3 && !STOPWORDS.contains(lower.as_str()) {
                    *token_counts.entry(lower).or_default() += 1;
                }
            }
        }
    }

    let mut tokens: Vec<(String, usize)> = token_counts.into_iter().collect();
    tokens.sort_by(|a, b| b.1.cmp(&a.1));

    let top_tokens: Vec<&str> = tokens.iter().take(4).map(|(t, _)| t.as_str()).collect();

    if top_tokens.is_empty() {
        "unlabeled cluster".to_string()
    } else {
        top_tokens.join(", ")
    }
}
