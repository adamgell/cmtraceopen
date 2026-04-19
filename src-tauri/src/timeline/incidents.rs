use std::collections::{HashMap, HashSet};

use crate::intune::models::IntuneEvent;
use crate::models::log_entry::Severity;
use crate::timeline::models::*;

/// Walk per-source indexes and IME events, emit raw signals, sort by ts_ms.
pub fn emit_signals(
    indexes: &HashMap<u16, Vec<EntryIndex>>,
    ime_events: &HashMap<u16, Vec<IntuneEvent>>,
    enabled: &[SignalKind],
) -> Vec<Signal> {
    let want_err = enabled.contains(&SignalKind::ErrorSeverity);
    let want_code = enabled.contains(&SignalKind::KnownErrorCode);
    let want_ime = enabled.contains(&SignalKind::ImeFailed);

    let mut out: Vec<Signal> = Vec::new();

    for (src_idx, idx_vec) in indexes {
        for (entry_ref, ei) in idx_vec.iter().enumerate() {
            let entry_ref = entry_ref as u32;
            if want_err && matches!(ei.severity, Severity::Error) {
                out.push(Signal {
                    source_idx: *src_idx,
                    entry_ref,
                    ts_ms: ei.timestamp_ms,
                    kind: SignalKind::ErrorSeverity,
                    correlation_id: None,
                });
            }
            if want_code && (ei.signal_flags & SIGNAL_FLAG_HAS_ERROR_CODE) != 0 {
                out.push(Signal {
                    source_idx: *src_idx,
                    entry_ref,
                    ts_ms: ei.timestamp_ms,
                    kind: SignalKind::KnownErrorCode,
                    correlation_id: None,
                });
            }
        }
    }

    if want_ime {
        for (src_idx, evs) in ime_events {
            for (entry_ref, ev) in evs.iter().enumerate() {
                if ev.status_is_failed() {
                    if let Some(ts) = ev.start_time_epoch_ms() {
                        out.push(Signal {
                            source_idx: *src_idx,
                            entry_ref: entry_ref as u32,
                            ts_ms: ts,
                            kind: SignalKind::ImeFailed,
                            correlation_id: None,
                        });
                    }
                }
            }
        }
    }

    out.sort_by_key(|s| s.ts_ms);
    out
}

/// A raw cluster of signals. Not yet qualified/scored.
#[derive(Debug, Clone)]
pub struct Cluster {
    pub signals: Vec<Signal>,
    pub ts_start_ms: i64,
    pub ts_end_ms: i64,
}

/// Cluster signals using a sliding window. Signals must be sorted by ts_ms.
/// A new signal is added to the current cluster iff its ts_ms is within
/// `window_ms` of the cluster's current end time AND its ts_ms - ts_start <= max_span_ms.
pub fn cluster_signals(
    signals: &[Signal],
    window_ms: i64,
    max_span_ms: i64,
) -> Vec<Cluster> {
    let mut out: Vec<Cluster> = Vec::new();
    for s in signals {
        match out.last_mut() {
            Some(cur)
                if s.ts_ms - cur.ts_end_ms <= window_ms
                    && s.ts_ms - cur.ts_start_ms <= max_span_ms =>
            {
                cur.ts_end_ms = s.ts_ms;
                cur.signals.push(s.clone());
            }
            _ => out.push(Cluster {
                ts_start_ms: s.ts_ms,
                ts_end_ms: s.ts_ms,
                signals: vec![s.clone()],
            }),
        }
    }
    out
}

pub struct QualifyInputs<'a> {
    pub clusters: &'a [Cluster],
    pub ime_events: &'a HashMap<u16, Vec<IntuneEvent>>,
    pub materialize_msg: &'a dyn Fn(u16, u32) -> Option<String>,
    pub denied_guids: &'a HashSet<String>,
    pub min_source_count: u8,
}

pub fn qualify(inp: QualifyInputs<'_>) -> Vec<Incident> {
    let mut out: Vec<Incident> = Vec::new();
    let mut next_id: u32 = 1;

    for c in inp.clusters {
        let mut sources: HashSet<u16> = HashSet::new();
        for s in &c.signals {
            sources.insert(s.source_idx);
        }
        if (sources.len() as u8) < inp.min_source_count {
            continue;
        }

        let anchor_sig = c.signals.iter().find(|s| s.kind == SignalKind::ImeFailed);
        let (anchor_event_ref, anchor_guid) = match anchor_sig {
            Some(a) => {
                let ev = inp
                    .ime_events
                    .get(&a.source_idx)
                    .and_then(|v| v.get(a.entry_ref as usize));
                let g = ev
                    .and_then(|e| e.anchor_guid())
                    .and_then(crate::timeline::correlation::normalize_guid);
                (
                    Some((a.source_idx, a.entry_ref)),
                    g.filter(|g| !inp.denied_guids.contains(g)),
                )
            }
            None => (None, None),
        };

        let mut guid_match_count: u32 = 0;
        let mut stamped_signals: Vec<Signal> = c.signals.clone();
        if let Some(g) = &anchor_guid {
            for s in stamped_signals.iter_mut() {
                if Some(s.source_idx) == anchor_sig.map(|a| a.source_idx)
                    && Some(s.entry_ref) == anchor_sig.map(|a| a.entry_ref)
                {
                    continue;
                }
                if let Some(msg) = (inp.materialize_msg)(s.source_idx, s.entry_ref) {
                    let guids = crate::timeline::correlation::extract_guids(&msg);
                    if guids.iter().any(|gm| gm == g) {
                        s.correlation_id = Some(g.clone());
                        guid_match_count += 1;
                    }
                }
            }
        }

        let source_count = sources.len() as u8;
        let confidence = score(source_count, stamped_signals.len() as u32, guid_match_count);
        let summary = summarize(&stamped_signals, anchor_event_ref, inp.ime_events);

        out.push(Incident {
            id: next_id,
            ts_start_ms: c.ts_start_ms,
            ts_end_ms: c.ts_end_ms,
            signal_count: stamped_signals.len() as u32,
            source_count,
            confidence,
            anchor_event_ref,
            anchor_guid,
            summary,
        });
        next_id += 1;
    }
    out
}

fn score(source_count: u8, signal_count: u32, guid_match: u32) -> f32 {
    let base: f32 = match source_count {
        0..=1 => 0.0,
        2 => 0.5,
        3 => 0.75,
        _ => 0.85,
    };
    let guid_boost = (guid_match.min(3) as f32) * 0.08;
    let density_boost = ((signal_count.saturating_sub(3) as f32).min(10.0)) * 0.01;
    (base + guid_boost + density_boost).min(1.0)
}

fn summarize(
    signals: &[Signal],
    anchor_ref: Option<(u16, u32)>,
    ime_events: &HashMap<u16, Vec<IntuneEvent>>,
) -> String {
    if let Some((sidx, eref)) = anchor_ref {
        if let Some(ev) = ime_events.get(&sidx).and_then(|v| v.get(eref as usize)) {
            let name = ev.display_name().unwrap_or("(unknown)");
            let kind = ev.event_kind_label().unwrap_or("Operation");
            return format!("{} failed: {}", kind, name);
        }
    }
    let errs = signals.len();
    let srcs: HashSet<u16> = signals.iter().map(|s| s.source_idx).collect();
    format!("{} signals across {} sources", errs, srcs.len())
}

/// Full detection pipeline.
pub fn detect_incidents(
    indexes: &HashMap<u16, Vec<EntryIndex>>,
    ime_events: &HashMap<u16, Vec<IntuneEvent>>,
    tunables: &TimelineTunables,
    denied_guids: &HashSet<String>,
    materialize_msg: &dyn Fn(u16, u32) -> Option<String>,
) -> (Vec<Signal>, Vec<Incident>) {
    let signals = emit_signals(indexes, ime_events, &tunables.enabled_signal_kinds);
    let clusters = cluster_signals(
        &signals,
        tunables.overlap_window_ms,
        tunables.max_incident_span_ms,
    );
    let incidents = qualify(QualifyInputs {
        clusters: &clusters,
        ime_events,
        materialize_msg,
        denied_guids,
        min_source_count: tunables.min_source_count,
    });
    (signals, incidents)
}

pub fn redetect_from_signals(
    signals: &[Signal],
    ime_events: &HashMap<u16, Vec<IntuneEvent>>,
    tunables: &TimelineTunables,
    denied_guids: &HashSet<String>,
    materialize_msg: &dyn Fn(u16, u32) -> Option<String>,
) -> Vec<Incident> {
    let filtered: Vec<Signal> = signals
        .iter()
        .filter(|s| tunables.enabled_signal_kinds.contains(&s.kind))
        .cloned()
        .collect();
    let clusters = cluster_signals(
        &filtered,
        tunables.overlap_window_ms,
        tunables.max_incident_span_ms,
    );
    qualify(QualifyInputs {
        clusters: &clusters,
        ime_events,
        materialize_msg,
        denied_guids,
        min_source_count: tunables.min_source_count,
    })
}

#[cfg(test)]
mod tests_emit {
    use super::*;

    fn ei(ts: i64, sev: Severity, flags: u8, src: u16, line: u32) -> EntryIndex {
        EntryIndex {
            timestamp_ms: ts,
            severity: sev,
            source_idx: src,
            byte_offset: 0,
            line_number: line,
            signal_flags: flags,
        }
    }

    #[test]
    fn emits_error_severity_signal() {
        let mut idx = HashMap::new();
        idx.insert(0, vec![ei(100, Severity::Error, 0, 0, 1)]);
        let sigs = emit_signals(&idx, &HashMap::new(), &[SignalKind::ErrorSeverity]);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::ErrorSeverity);
    }

    #[test]
    fn emits_error_code_signal_independent_of_severity() {
        let mut idx = HashMap::new();
        idx.insert(
            0,
            vec![ei(100, Severity::Info, SIGNAL_FLAG_HAS_ERROR_CODE, 0, 1)],
        );
        let sigs = emit_signals(&idx, &HashMap::new(), &[SignalKind::KnownErrorCode]);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::KnownErrorCode);
    }

    #[test]
    fn disabled_kinds_are_skipped() {
        let mut idx = HashMap::new();
        idx.insert(
            0,
            vec![ei(100, Severity::Error, SIGNAL_FLAG_HAS_ERROR_CODE, 0, 1)],
        );
        let sigs = emit_signals(&idx, &HashMap::new(), &[SignalKind::KnownErrorCode]);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::KnownErrorCode);
    }

    #[test]
    fn signals_are_sorted_by_ts() {
        let mut idx = HashMap::new();
        idx.insert(
            0,
            vec![
                ei(300, Severity::Error, 0, 0, 1),
                ei(100, Severity::Error, 0, 0, 2),
                ei(200, Severity::Error, 0, 0, 3),
            ],
        );
        let sigs = emit_signals(&idx, &HashMap::new(), &[SignalKind::ErrorSeverity]);
        let ts: Vec<i64> = sigs.iter().map(|s| s.ts_ms).collect();
        assert_eq!(ts, vec![100, 200, 300]);
    }
}

#[cfg(test)]
mod tests_cluster {
    use super::*;

    fn sig(ts: i64, src: u16, entry_ref: u32) -> Signal {
        Signal {
            source_idx: src,
            entry_ref,
            ts_ms: ts,
            kind: SignalKind::ErrorSeverity,
            correlation_id: None,
        }
    }

    #[test]
    fn singleton_cluster() {
        let sigs = vec![sig(100, 0, 1)];
        let clusters = cluster_signals(&sigs, 5_000, 60_000);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].signals.len(), 1);
        assert_eq!(clusters[0].ts_start_ms, 100);
        assert_eq!(clusters[0].ts_end_ms, 100);
    }

    #[test]
    fn window_coalesce() {
        let sigs = vec![sig(100, 0, 1), sig(2_000, 1, 1), sig(4_000, 0, 2)];
        let clusters = cluster_signals(&sigs, 5_000, 60_000);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].signals.len(), 3);
        assert_eq!(clusters[0].ts_start_ms, 100);
        assert_eq!(clusters[0].ts_end_ms, 4_000);
    }

    #[test]
    fn gap_beyond_window_splits() {
        let sigs = vec![sig(100, 0, 1), sig(10_000, 1, 1)];
        let clusters = cluster_signals(&sigs, 5_000, 60_000);
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0].signals.len(), 1);
        assert_eq!(clusters[1].signals.len(), 1);
    }

    #[test]
    fn transitive_merge_via_sliding_end() {
        // Each signal is within window of the previous end, but the first and
        // last are > window apart. Sliding should still merge them.
        let sigs = vec![sig(0, 0, 1), sig(4_000, 1, 1), sig(8_000, 0, 2)];
        let clusters = cluster_signals(&sigs, 5_000, 60_000);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].signals.len(), 3);
    }

    #[test]
    fn max_span_cap_cuts_cluster() {
        // Signals continuously within window_ms, but the span from first to
        // next would exceed max_span_ms, so we must split.
        let sigs = vec![sig(0, 0, 1), sig(4_000, 1, 1), sig(8_000, 0, 2)];
        let clusters = cluster_signals(&sigs, 5_000, 5_000);
        assert!(clusters.len() >= 2);
        // Ensure the total number of signals is preserved.
        let total: usize = clusters.iter().map(|c| c.signals.len()).sum();
        assert_eq!(total, 3);
    }
}

#[cfg(test)]
mod tests_qualify {
    use super::*;

    fn sig(ts: i64, src: u16, entry_ref: u32, kind: SignalKind) -> Signal {
        Signal {
            source_idx: src,
            entry_ref,
            ts_ms: ts,
            kind,
            correlation_id: None,
        }
    }

    fn noop_materialize(_s: u16, _r: u32) -> Option<String> {
        None
    }

    #[test]
    fn single_source_cluster_discarded() {
        let cluster = Cluster {
            ts_start_ms: 0,
            ts_end_ms: 1_000,
            signals: vec![
                sig(0, 0, 1, SignalKind::ErrorSeverity),
                sig(1_000, 0, 2, SignalKind::ErrorSeverity),
            ],
        };
        let clusters = vec![cluster];
        let incidents = qualify(QualifyInputs {
            clusters: &clusters,
            ime_events: &HashMap::new(),
            materialize_msg: &noop_materialize,
            denied_guids: &HashSet::new(),
            min_source_count: 2,
        });
        assert!(incidents.is_empty());
    }

    #[test]
    fn two_source_cluster_emits_incident() {
        let cluster = Cluster {
            ts_start_ms: 0,
            ts_end_ms: 1_000,
            signals: vec![
                sig(0, 0, 1, SignalKind::ErrorSeverity),
                sig(1_000, 1, 1, SignalKind::ErrorSeverity),
            ],
        };
        let clusters = vec![cluster];
        let incidents = qualify(QualifyInputs {
            clusters: &clusters,
            ime_events: &HashMap::new(),
            materialize_msg: &noop_materialize,
            denied_guids: &HashSet::new(),
            min_source_count: 2,
        });
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].source_count, 2);
        assert!((incidents[0].confidence - 0.5).abs() < 1e-4);
    }
}

#[cfg(test)]
mod tests_detect {
    use super::*;

    fn ei(ts: i64, sev: Severity, flags: u8, src: u16, line: u32) -> EntryIndex {
        EntryIndex {
            timestamp_ms: ts,
            severity: sev,
            source_idx: src,
            byte_offset: 0,
            line_number: line,
            signal_flags: flags,
        }
    }

    fn noop_materialize(_s: u16, _r: u32) -> Option<String> {
        None
    }

    #[test]
    fn two_sources_one_incident_no_anchor() {
        let mut indexes: HashMap<u16, Vec<EntryIndex>> = HashMap::new();
        indexes.insert(0, vec![ei(1_000, Severity::Error, 0, 0, 1)]);
        indexes.insert(1, vec![ei(2_000, Severity::Error, 0, 1, 1)]);

        let t = TimelineTunables::default();
        let denied: HashSet<String> = HashSet::new();

        let (signals, incidents) = detect_incidents(
            &indexes,
            &HashMap::new(),
            &t,
            &denied,
            &noop_materialize,
        );

        assert_eq!(signals.len(), 2);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].source_count, 2);
        assert!(incidents[0].anchor_event_ref.is_none());
        assert!(incidents[0].anchor_guid.is_none());
    }

    #[test]
    fn narrower_window_splits_into_two_incidents() {
        let mut indexes: HashMap<u16, Vec<EntryIndex>> = HashMap::new();
        indexes.insert(
            0,
            vec![
                ei(0, Severity::Error, 0, 0, 1),
                ei(10_000, Severity::Error, 0, 0, 2),
            ],
        );
        indexes.insert(
            1,
            vec![
                ei(500, Severity::Error, 0, 1, 1),
                ei(10_500, Severity::Error, 0, 1, 2),
            ],
        );

        let t = TimelineTunables {
            overlap_window_ms: 1_000,
            ..TimelineTunables::default()
        };
        let denied: HashSet<String> = HashSet::new();

        let (_signals, incidents) = detect_incidents(
            &indexes,
            &HashMap::new(),
            &t,
            &denied,
            &noop_materialize,
        );

        assert_eq!(
            incidents.len(),
            2,
            "expected two incidents, got {:?}",
            incidents
        );
    }
}
