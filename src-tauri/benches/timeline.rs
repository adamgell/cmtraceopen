use std::collections::{HashMap, HashSet};

use app_lib::timeline::incidents::detect_incidents;
use app_lib::timeline::models::*;
use app_lib::timeline::query::query_lane_buckets;
use app_lib::timeline::store::Timeline;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn make_index(source_idx: u16, n: usize, offset_ms: i64) -> Vec<EntryIndex> {
    (0..n)
        .map(|i| EntryIndex {
            timestamp_ms: (i as i64) * 3 + offset_ms,
            severity: if i % 100 == 0 {
                Severity::Error
            } else {
                Severity::Info
            },
            source_idx,
            byte_offset: 0,
            line_number: (i + 1) as u32,
            signal_flags: 0,
        })
        .collect()
}

fn bench_detect(c: &mut Criterion) {
    for &n in &[10_000usize, 100_000, 1_000_000] {
        let mut idx = HashMap::new();
        idx.insert(0u16, make_index(0, n, 0));
        idx.insert(1u16, make_index(1, n, 1));
        let t = TimelineTunables::default();
        c.bench_with_input(BenchmarkId::new("detect_incidents", n), &idx, |b, idx| {
            b.iter(|| {
                let _ = detect_incidents(
                    idx,
                    &HashMap::new(),
                    &t,
                    &HashSet::new(),
                    &|_, _| None,
                );
            })
        });
    }
}

fn bench_buckets(c: &mut Criterion) {
    let mut idx = HashMap::new();
    idx.insert(0u16, make_index(0, 1_000_000, 0));
    let tl = Timeline {
        bundle: TimelineBundle {
            id: "bench".into(),
            sources: vec![TimelineSourceMeta {
                idx: 0,
                path: "x".into(),
                display_name: "x".into(),
                color: "#111".into(),
                entry_count: 1_000_000,
                kind: TimelineSourceKind::LogFile {
                    parser_kind: ParserKind::Plain,
                },
            }],
            time_range_ms: (0, 3_000_000),
            total_entries: 1_000_000,
            incidents: vec![],
            denied_guids: vec![],
            errors: vec![],
            tunables: Default::default(),
        },
        indexes: idx,
        ime_events: HashMap::new(),
        raw_signals: vec![],
    };
    c.bench_function("query_lane_buckets_1M_500", |b| {
        b.iter(|| {
            let _ = query_lane_buckets(&tl, 500, None);
        });
    });
}

criterion_group!(benches, bench_detect, bench_buckets);
criterion_main!(benches);
