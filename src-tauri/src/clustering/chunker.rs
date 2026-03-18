use crate::models::log_entry::LogEntry;

use super::models::{ClusterableEntry, EmbeddingChunk};

/// Groups temporally adjacent log entries into overlapping chunks for embedding.
///
/// Each chunk concatenates `window_size` adjacent entries' messages with newlines.
/// The anchor entry (used as the chunk's representative) is the middle entry.
/// Uses a sliding window with stride 1.
pub fn chunk_entries(entries: &[LogEntry], window_size: usize) -> Vec<EmbeddingChunk> {
    chunk_entries_with_stride(entries, window_size, 1)
}

pub fn chunk_entries_with_stride(
    entries: &[LogEntry],
    window_size: usize,
    stride: usize,
) -> Vec<EmbeddingChunk> {
    if entries.is_empty() {
        return Vec::new();
    }

    let window_size = window_size.max(1);
    let stride = stride.max(1);

    if entries.len() <= window_size {
        let text = entries
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let entry_ids: Vec<u64> = entries.iter().map(|e| e.id).collect();
        let anchor_id = entry_ids[entry_ids.len() / 2];
        return vec![EmbeddingChunk {
            text,
            entry_ids,
            anchor_id,
        }];
    }

    let num_chunks = (entries.len() - window_size) / stride + 1;
    let mut chunks = Vec::with_capacity(num_chunks);

    let mut i = 0;
    while i + window_size <= entries.len() {
        let window = &entries[i..i + window_size];
        let text = window
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let entry_ids: Vec<u64> = window.iter().map(|e| e.id).collect();
        let anchor_id = entry_ids[entry_ids.len() / 2];

        chunks.push(EmbeddingChunk {
            text,
            entry_ids,
            anchor_id,
        });
        i += stride;
    }

    chunks
}

/// Creates chunks for tail mode: forms new chunks from the last entries of the
/// existing set plus each new entry.
pub fn chunk_tail_entries(
    last_entries: &[LogEntry],
    new_entries: &[LogEntry],
    window_size: usize,
) -> Vec<EmbeddingChunk> {
    if new_entries.is_empty() {
        return Vec::new();
    }

    let window_size = window_size.max(1);
    let context_needed = window_size.saturating_sub(1);

    // Build a combined view of context + new entries
    let context_start = last_entries.len().saturating_sub(context_needed);
    let context = &last_entries[context_start..];

    let combined: Vec<&LogEntry> = context.iter().chain(new_entries.iter()).collect();

    let mut chunks = Vec::new();
    // Start creating windows from the first new entry's position
    let first_new_idx = context.len();

    for i in 0..combined.len() {
        let end = i + window_size;
        if end > combined.len() {
            break;
        }
        // Only include windows that contain at least one new entry
        if i + window_size - 1 < first_new_idx {
            continue;
        }

        let window = &combined[i..end];
        let text = window
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let entry_ids: Vec<u64> = window.iter().map(|e| e.id).collect();
        let anchor_id = entry_ids[entry_ids.len() / 2];

        chunks.push(EmbeddingChunk {
            text,
            entry_ids,
            anchor_id,
        });
    }

    chunks
}

/// Groups ClusterableEntry items into overlapping chunks for embedding.
/// Same sliding-window approach as chunk_entries but operates on the generic type.
pub fn chunk_clusterable_entries(
    entries: &[ClusterableEntry],
    window_size: usize,
    stride: usize,
) -> Vec<EmbeddingChunk> {
    if entries.is_empty() {
        return Vec::new();
    }

    let window_size = window_size.max(1);
    let stride = stride.max(1);

    if entries.len() <= window_size {
        let text = entries
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let entry_ids: Vec<u64> = entries.iter().map(|e| e.id).collect();
        let anchor_id = entry_ids[entry_ids.len() / 2];
        return vec![EmbeddingChunk {
            text,
            entry_ids,
            anchor_id,
        }];
    }

    let num_chunks = (entries.len() - window_size) / stride + 1;
    let mut chunks = Vec::with_capacity(num_chunks);

    let mut i = 0;
    while i + window_size <= entries.len() {
        let window = &entries[i..i + window_size];
        let text = window
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let entry_ids: Vec<u64> = window.iter().map(|e| e.id).collect();
        let anchor_id = entry_ids[entry_ids.len() / 2];

        chunks.push(EmbeddingChunk {
            text,
            entry_ids,
            anchor_id,
        });
        i += stride;
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::{LogEntry, LogFormat, Severity};

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

    #[test]
    fn test_chunk_entries_basic() {
        let entries: Vec<LogEntry> = (0..5).map(|i| make_entry(i, &format!("line {}", i))).collect();
        let chunks = chunk_entries(&entries, 3);
        assert_eq!(chunks.len(), 3); // 5 - 3 + 1 = 3

        assert_eq!(chunks[0].text, "line 0\nline 1\nline 2");
        assert_eq!(chunks[0].anchor_id, 1);
        assert_eq!(chunks[0].entry_ids, vec![0, 1, 2]);

        assert_eq!(chunks[2].text, "line 2\nline 3\nline 4");
        assert_eq!(chunks[2].anchor_id, 3);
    }

    #[test]
    fn test_chunk_entries_empty() {
        let chunks = chunk_entries(&[], 3);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_chunk_entries_fewer_than_window() {
        let entries: Vec<LogEntry> = (0..2).map(|i| make_entry(i, &format!("line {}", i))).collect();
        let chunks = chunk_entries(&entries, 3);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, "line 0\nline 1");
    }

    #[test]
    fn test_chunk_tail_entries() {
        let existing: Vec<LogEntry> = (0..5).map(|i| make_entry(i, &format!("old {}", i))).collect();
        let new_entries: Vec<LogEntry> = (5..7).map(|i| make_entry(i, &format!("new {}", i))).collect();

        let chunks = chunk_tail_entries(&existing, &new_entries, 3);
        // Should have chunks covering new entries
        assert!(!chunks.is_empty());
        // All chunks should contain at least one new entry id
        for chunk in &chunks {
            assert!(chunk.entry_ids.iter().any(|&id| id >= 5));
        }
    }
}
