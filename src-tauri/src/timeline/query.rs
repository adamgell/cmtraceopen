use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::models::log_entry::LogEntry;
use crate::parser::ResolvedParser;
use crate::timeline::models::*;
use crate::timeline::store::Timeline;

/// Read raw bytes of a single log entry starting at byte_offset, trimming at
/// the first newline. Works for single-line formats and newline-terminated
/// logical records. 64 KiB upper bound.
fn read_entry_raw(path: &Path, byte_offset: u64) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(byte_offset))?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        buf.truncate(pos + 1);
    }
    Ok(buf)
}

/// Materialize a full LogEntry from its EntryIndex. Runs the source parser
/// over the raw bytes at byte_offset.
pub fn materialize_log_entry(
    path: &Path,
    parser: &ResolvedParser,
    ei: &EntryIndex,
) -> Option<LogEntry> {
    let raw = read_entry_raw(path, ei.byte_offset).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    parser.parse_one_line(&text, ei.line_number).ok()
}

/// Materialize just the message text — cheap path for GUID scanning.
pub fn materialize_msg(
    path: &Path,
    parser: &ResolvedParser,
    ei: &EntryIndex,
) -> Option<String> {
    materialize_log_entry(path, parser, ei).map(|e| e.message)
}

/// A parsed source — holds path and parser for materialization.
pub struct SourceRuntime {
    pub path: std::path::PathBuf,
    pub parser: ResolvedParser,
}

pub struct QueryContext<'a> {
    pub timeline: &'a Timeline,
    pub runtimes: &'a HashMap<u16, SourceRuntime>,
}

/// Return entries within [range_start, range_end] inclusive, filtered by optional
/// source set, paged by (offset, limit). Sorted by timestamp_ms, ties broken by
/// (source_idx, line_number / entry_ref) for stability.
pub fn query_timeline_entries(
    ctx: &QueryContext<'_>,
    range_ms: Option<(i64, i64)>,
    source_filter: Option<&std::collections::HashSet<u16>>,
    offset: u64,
    limit: u32,
) -> Vec<TimelineEntry> {
    let mut view: Vec<(i64, u16, u32, bool)> = Vec::new();
    let (lo, hi) = range_ms.unwrap_or((i64::MIN, i64::MAX));

    for (src, idx_vec) in &ctx.timeline.indexes {
        if let Some(f) = source_filter {
            if !f.contains(src) {
                continue;
            }
        }
        for (eref, ei) in idx_vec.iter().enumerate() {
            if ei.timestamp_ms >= lo && ei.timestamp_ms <= hi {
                view.push((ei.timestamp_ms, *src, eref as u32, false));
            }
        }
    }
    for (src, ev_vec) in &ctx.timeline.ime_events {
        if let Some(f) = source_filter {
            if !f.contains(src) {
                continue;
            }
        }
        for (eref, ev) in ev_vec.iter().enumerate() {
            if let Some(ts) = ev.start_time_epoch_ms() {
                if ts >= lo && ts <= hi {
                    view.push((ts, *src, eref as u32, true));
                }
            }
        }
    }
    view.sort_by_key(|k| (k.0, k.1, k.2));

    let end = (offset + limit as u64).min(view.len() as u64) as usize;
    let start = (offset as usize).min(view.len());
    let slice = &view[start..end];

    let mut out = Vec::with_capacity(slice.len());
    for (_ts, src, eref, is_ime) in slice {
        if *is_ime {
            let ev = ctx
                .timeline
                .ime_events
                .get(src)
                .and_then(|v| v.get(*eref as usize))
                .cloned();
            if let Some(ev) = ev {
                out.push(TimelineEntry::ImeEvent {
                    source_idx: *src,
                    event: ev,
                });
            }
        } else {
            let ei = ctx
                .timeline
                .indexes
                .get(src)
                .and_then(|v| v.get(*eref as usize));
            let rt = ctx.runtimes.get(src);
            if let (Some(ei), Some(rt)) = (ei, rt) {
                if let Some(entry) = materialize_log_entry(&rt.path, &rt.parser, ei) {
                    out.push(TimelineEntry::Log {
                        source_idx: *src,
                        entry,
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests_mat {
    use super::*;
    use std::io::Write;

    #[test]
    fn reads_first_line_at_offset_zero() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.log");
        let mut f = File::create(&p).unwrap();
        writeln!(f, "line-zero").unwrap();
        writeln!(f, "line-one").unwrap();
        let raw = read_entry_raw(&p, 0).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("line-zero"));
    }

    #[test]
    fn reads_from_mid_file_offset() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.log");
        let mut f = File::create(&p).unwrap();
        writeln!(f, "abc").unwrap();
        writeln!(f, "defg").unwrap();
        let raw = read_entry_raw(&p, 4).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("defg"));
    }
}
