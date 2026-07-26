use std::fs;
mod common;

#[test]
fn synthetic_ccm_benchmark_fixture_parses_all_records() {
    let bench_file = common::build_ccm_bench_file(2_048);
    let path = bench_file.path_string();
    let content = fs::read_to_string(&path).unwrap();
    let result = app_lib::parser::parse_file(&path);

    assert_eq!(
        content.lines().count(),
        2_048,
        "Expected all benchmark lines to be readable"
    );

    match result {
        Ok((r, _date_order)) => {
            assert_eq!(
                r.entries.len(),
                2_048,
                "Expected all benchmark entries parsed"
            );
            assert_eq!(
                r.parse_errors, 0,
                "Expected the synthetic CCM fixture to parse cleanly"
            );
        }
        Err(e) => panic!("Parse failed: {}", e),
    }
}

#[test]
#[cfg(feature = "intune-diagnostics")]
fn synthetic_intune_benchmark_fixture_matches_pipeline_counts() {
    let bench_file = common::build_intune_bench_file(1_024);
    let path = bench_file.path_string();
    let content = fs::read_to_string(bench_file.path()).unwrap();
    let lines = app_lib::intune::ime_parser::parse_ime_content(&content);
    assert_eq!(
        content.len(),
        bench_file.file_size_bytes,
        "Expected synthetic IME fixture size to remain stable"
    );
    assert_eq!(
        lines.len(),
        bench_file.logical_record_count,
        "Expected all IME logical records parsed"
    );

    let registry = app_lib::intune::guid_registry::GuidRegistry::new();
    let events = app_lib::intune::event_tracker::extract_events(&lines, &path, &registry);
    assert_eq!(
        events.len(),
        bench_file.expected_event_count,
        "Expected one paired content-download event per app"
    );

    let timeline = app_lib::intune::timeline::build_timeline(events);
    assert_eq!(
        timeline.len(),
        bench_file.expected_timeline_count,
        "Expected timeline deduplication to preserve one event per app"
    );

    let downloads = app_lib::intune::download_stats::extract_downloads(&lines, &path, &registry);
    assert_eq!(
        downloads.len(),
        bench_file.expected_download_count,
        "Expected one download summary per app"
    );
}
