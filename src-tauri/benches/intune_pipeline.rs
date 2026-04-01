use std::fs;
use std::time::Duration;

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

#[path = "../tests/common/mod.rs"]
mod common;

const INTUNE_BENCH_PAIR_COUNT: usize = 10_000;

fn configured_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(8))
}

fn bench_intune_pipeline(c: &mut Criterion) {
    let fixture = common::build_intune_bench_file(INTUNE_BENCH_PAIR_COUNT);
    let source_file = fixture.path_string();
    let fixture_path = fixture.path().to_path_buf();
    let content = fs::read_to_string(&fixture_path).expect("benchmark fixture should be readable");

    validate_fixture(&fixture, &source_file, &content);

    let lines = app_lib::intune::ime_parser::parse_ime_content(&content);
    let events = app_lib::intune::event_tracker::extract_events(&lines, &source_file, &app_lib::intune::guid_registry::GuidRegistry::new());

    let mut group = c.benchmark_group("intune_pipeline");

    group.throughput(Throughput::Elements(fixture.logical_record_count as u64));
    group.bench_function(
        BenchmarkId::new("read", fixture.logical_record_count),
        |b| {
            b.iter(|| {
                let content = fs::read_to_string(black_box(&fixture_path))
                    .expect("benchmark fixture should be readable");
                assert_eq!(content.len(), fixture.file_size_bytes, "Expected benchmark read phase to load the full fixture");
                black_box(content)
            });
        },
    );

    group.throughput(Throughput::Elements(fixture.logical_record_count as u64));
    group.bench_function(
        BenchmarkId::new("ime_parse", fixture.logical_record_count),
        |b| {
            b.iter(|| {
                let lines = app_lib::intune::ime_parser::parse_ime_content(black_box(&content));
                assert_eq!(lines.len(), fixture.logical_record_count, "Expected IME parse to emit one logical record per synthetic line");
                black_box(lines)
            });
        },
    );

    group.throughput(Throughput::Elements(fixture.logical_record_count as u64));
    group.bench_function(
        BenchmarkId::new("event_extraction", fixture.logical_record_count),
        |b| {
            b.iter(|| {
                let registry = app_lib::intune::guid_registry::GuidRegistry::new();
                let events = app_lib::intune::event_tracker::extract_events(
                    black_box(lines.as_slice()),
                    black_box(&source_file),
                    &registry,
                );
                assert_eq!(events.len(), fixture.expected_event_count, "Expected one paired content-download event per app");
                black_box(events)
            });
        },
    );

    group.throughput(Throughput::Elements(fixture.expected_event_count as u64));
    group.bench_function(
        BenchmarkId::new("timeline", fixture.expected_event_count),
        |b| {
            b.iter_batched(
                || events.clone(),
                |events| {
                    let timeline = app_lib::intune::timeline::build_timeline(events);
                    assert_eq!(timeline.len(), fixture.expected_timeline_count, "Expected timeline to preserve one event per app after deduplication");
                    black_box(timeline)
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.throughput(Throughput::Elements(fixture.logical_record_count as u64));
    group.bench_function(
        BenchmarkId::new("downloads", fixture.logical_record_count),
        |b| {
            b.iter(|| {
                let dl_registry = app_lib::intune::guid_registry::GuidRegistry::new();
                let downloads = app_lib::intune::download_stats::extract_downloads(
                    black_box(lines.as_slice()),
                    black_box(&source_file),
                    &dl_registry,
                );
                assert_eq!(downloads.len(), fixture.expected_download_count, "Expected one download summary per app");
                black_box(downloads)
            });
        },
    );

    group.throughput(Throughput::Elements(fixture.logical_record_count as u64));
    group.bench_function(
        BenchmarkId::new("total", fixture.logical_record_count),
        |b| {
            b.iter(|| {
                let content = fs::read_to_string(black_box(&fixture_path))
                    .expect("benchmark fixture should be readable");
                assert_eq!(content.len(), fixture.file_size_bytes, "Expected benchmark total phase to load the full fixture");

                let lines = app_lib::intune::ime_parser::parse_ime_content(&content);
                assert_eq!(lines.len(), fixture.logical_record_count, "Expected IME parse to emit one logical record per synthetic line");

                let events = app_lib::intune::event_tracker::extract_events(&lines, &source_file, &app_lib::intune::guid_registry::GuidRegistry::new());
                assert_eq!(events.len(), fixture.expected_event_count, "Expected one paired content-download event per app");

                let timeline = app_lib::intune::timeline::build_timeline(events);
                assert_eq!(timeline.len(), fixture.expected_timeline_count, "Expected timeline to preserve one event per app after deduplication");

                let downloads = app_lib::intune::download_stats::extract_downloads(&lines, &source_file, &app_lib::intune::guid_registry::GuidRegistry::new());
                assert_eq!(downloads.len(), fixture.expected_download_count, "Expected one download summary per app");

                black_box((timeline, downloads))
            });
        },
    );

    group.finish();
}

fn validate_fixture(fixture: &common::IntuneBenchFixture, source_file: &str, content: &str) {
    assert_eq!(content.len(), fixture.file_size_bytes, "Expected synthetic IME benchmark fixture size to remain stable");

    let lines = app_lib::intune::ime_parser::parse_ime_content(content);
    assert_eq!(lines.len(), fixture.logical_record_count, "Expected all synthetic IME logical records to parse");

    let events = app_lib::intune::event_tracker::extract_events(&lines, source_file, &app_lib::intune::guid_registry::GuidRegistry::new());
    assert_eq!(events.len(), fixture.expected_event_count, "Expected one paired content-download event per app");

    let timeline = app_lib::intune::timeline::build_timeline(events);
    assert_eq!(timeline.len(), fixture.expected_timeline_count, "Expected timeline deduplication to preserve one event per app");

    let downloads = app_lib::intune::download_stats::extract_downloads(&lines, source_file, &app_lib::intune::guid_registry::GuidRegistry::new());
    assert_eq!(downloads.len(), fixture.expected_download_count, "Expected one download summary per app");
}

criterion_group! {
    name = benches;
    config = configured_criterion();
    targets = bench_intune_pipeline
}
criterion_main!(benches);