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
                    event: Box::new(ev),
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
                        entry: Box::new(entry),
                    });
                }
            }
        }
    }
    out
}

pub fn query_lane_buckets(
    timeline: &Timeline,
    bucket_count: u32,
    range_ms: Option<(i64, i64)>,
) -> Vec<LaneBucket> {
    let (lo, hi) = range_ms.unwrap_or(timeline.bundle.time_range_ms);
    let span = (hi - lo).max(1);
    let bucket_count = bucket_count.max(1) as i64;
    let step = ((span as f64) / (bucket_count as f64)).ceil() as i64;

    let mut out: Vec<LaneBucket> = Vec::new();

    for src in timeline.bundle.sources.iter() {
        let mut buckets: Vec<(u32, u32, u32)> = vec![(0, 0, 0); bucket_count as usize];
        if let Some(idx_vec) = timeline.indexes.get(&src.idx) {
            for ei in idx_vec {
                if ei.timestamp_ms < lo || ei.timestamp_ms > hi {
                    continue;
                }
                let bi = (((ei.timestamp_ms - lo) / step).min(bucket_count - 1)) as usize;
                buckets[bi].0 += 1;
                match ei.severity {
                    crate::models::log_entry::Severity::Error => buckets[bi].1 += 1,
                    crate::models::log_entry::Severity::Warning => buckets[bi].2 += 1,
                    _ => {}
                }
            }
        }
        if let Some(evs) = timeline.ime_events.get(&src.idx) {
            for ev in evs {
                if let Some(ts) = ev.start_time_epoch_ms() {
                    if ts < lo || ts > hi {
                        continue;
                    }
                    let bi = (((ts - lo) / step).min(bucket_count - 1)) as usize;
                    buckets[bi].0 += 1;
                    if ev.status_is_failed() {
                        buckets[bi].1 += 1;
                    }
                }
            }
        }
        for (i, (total, errs, warns)) in buckets.into_iter().enumerate() {
            if total == 0 {
                continue;
            }
            let start = lo + step * (i as i64);
            let end = (start + step).min(hi);
            out.push(LaneBucket {
                source_idx: src.idx,
                ts_start_ms: start,
                ts_end_ms: end,
                total_count: total,
                error_count: errs,
                warn_count: warns,
            });
        }
    }
    out
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentSignalDetail {
    pub source_idx: u16,
    pub source_name: String,
    pub ts_ms: i64,
    pub kind: SignalKind,
    pub correlation_id: Option<String>,
    pub line_number: u32,
    pub preview: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentDetail {
    pub incident: Incident,
    pub signals: Vec<IncidentSignalDetail>,
    pub per_source_signal_counts: std::collections::HashMap<String, u32>,
}

pub fn query_incident_details(
    ctx: &QueryContext<'_>,
    incident_id: u32,
) -> Option<IncidentDetail> {
    let incident = ctx
        .timeline
        .bundle
        .incidents
        .iter()
        .find(|i| i.id == incident_id)?
        .clone();

    let (lo, hi) = (incident.ts_start_ms, incident.ts_end_ms);
    let mut sigs: Vec<IncidentSignalDetail> = Vec::new();
    let mut counts: std::collections::HashMap<String, u32> = Default::default();

    for s in &ctx.timeline.raw_signals {
        if s.ts_ms < lo || s.ts_ms > hi {
            continue;
        }
        if !ctx
            .timeline
            .bundle
            .tunables
            .enabled_signal_kinds
            .contains(&s.kind)
        {
            continue;
        }

        let name = ctx
            .timeline
            .bundle
            .sources
            .iter()
            .find(|m| m.idx == s.source_idx)
            .map(|m| m.display_name.clone())
            .unwrap_or_else(|| format!("src{}", s.source_idx));
        *counts.entry(name.clone()).or_insert(0) += 1;

        let (line_number, preview) = match ctx.runtimes.get(&s.source_idx) {
            Some(rt) => {
                let ei = ctx
                    .timeline
                    .indexes
                    .get(&s.source_idx)
                    .and_then(|v| v.get(s.entry_ref as usize));
                if let Some(ei) = ei {
                    let msg = materialize_msg(&rt.path, &rt.parser, ei).unwrap_or_default();
                    (ei.line_number, truncate(&msg, 200))
                } else {
                    (0, String::new())
                }
            }
            None => {
                let evs = ctx.timeline.ime_events.get(&s.source_idx);
                let ev = evs.and_then(|v| v.get(s.entry_ref as usize));
                let preview = ev.map(|e| format!("{:?}", e)).unwrap_or_default();
                (0, truncate(&preview, 200))
            }
        };
        sigs.push(IncidentSignalDetail {
            source_idx: s.source_idx,
            source_name: name,
            ts_ms: s.ts_ms,
            kind: s.kind,
            correlation_id: s.correlation_id.clone(),
            line_number,
            preview,
        });
    }

    Some(IncidentDetail {
        incident,
        signals: sigs,
        per_source_signal_counts: counts,
    })
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
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

#[cfg(test)]
mod tests_buckets {
    use super::*;
    use crate::models::log_entry::{ParserKind, Severity};

    fn mk_source(idx: u16) -> TimelineSourceMeta {
        TimelineSourceMeta {
            idx,
            kind: TimelineSourceKind::LogFile {
                parser_kind: ParserKind::Plain,
            },
            path: format!("/tmp/src{idx}.log"),
            display_name: format!("src{idx}"),
            color: "#000".into(),
            entry_count: 0,
        }
    }

    fn mk_ei(ts: i64, sev: Severity, src: u16, line: u32) -> EntryIndex {
        EntryIndex {
            timestamp_ms: ts,
            severity: sev,
            source_idx: src,
            byte_offset: 0,
            line_number: line,
            signal_flags: 0,
        }
    }

    #[test]
    fn buckets_cover_full_range_and_counts_match() {
        let mut indexes = HashMap::new();
        indexes.insert(
            0u16,
            vec![
                mk_ei(100, Severity::Info, 0, 1),
                mk_ei(500, Severity::Error, 0, 2),
                mk_ei(900, Severity::Info, 0, 3),
            ],
        );
        let tl = Timeline {
            bundle: TimelineBundle {
                id: "t".into(),
                sources: vec![mk_source(0)],
                time_range_ms: (100, 900),
                total_entries: 3,
                incidents: vec![],
                denied_guids: vec![],
                errors: vec![],
                tunables: Default::default(),
            },
            indexes,
            ime_events: HashMap::new(),
            raw_signals: vec![],
        };

        let buckets = query_lane_buckets(&tl, 10, None);
        let total: u32 = buckets.iter().map(|b| b.total_count).sum();
        let errors: u32 = buckets.iter().map(|b| b.error_count).sum();
        assert_eq!(total, 3);
        assert_eq!(errors, 1);
        // All buckets should belong to source 0.
        assert!(buckets.iter().all(|b| b.source_idx == 0));
    }

    #[test]
    fn empty_buckets_are_omitted() {
        let mut indexes = HashMap::new();
        indexes.insert(0u16, Vec::<EntryIndex>::new());
        let tl = Timeline {
            bundle: TimelineBundle {
                id: "t".into(),
                sources: vec![mk_source(0)],
                time_range_ms: (0, 1000),
                total_entries: 0,
                incidents: vec![],
                denied_guids: vec![],
                errors: vec![],
                tunables: Default::default(),
            },
            indexes,
            ime_events: HashMap::new(),
            raw_signals: vec![],
        };

        let buckets = query_lane_buckets(&tl, 10, None);
        assert!(buckets.is_empty());
    }
}
