use std::collections::HashMap;

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
