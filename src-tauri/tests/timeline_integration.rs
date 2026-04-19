use app_lib::timeline::builder::{build_timeline, SourceRequest, DEFAULT_ENTRY_LIMIT};
use app_lib::timeline::query::*;

fn fixture(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/timeline/scenario_win32app_failure")
        .join(rel);
    p.to_string_lossy().into_owned()
}

#[test]
fn win32app_failure_yields_multi_source_incident() {
    let requests = vec![
        SourceRequest {
            path: fixture("AgentExecutor.log"),
            display_name: None,
        },
        SourceRequest {
            path: fixture("IntuneManagementExtension.log"),
            display_name: None,
        },
    ];
    let (timeline, runtimes) = build_timeline(&requests, DEFAULT_ENTRY_LIMIT, Vec::new())
        .expect("build ok");

    assert!(
        !timeline.bundle.incidents.is_empty(),
        "expected at least one incident"
    );
    let top = &timeline.bundle.incidents[0];
    assert!(top.source_count >= 2, "source_count was {}", top.source_count);
    assert!(top.confidence >= 0.5, "low confidence: {}", top.confidence);
    if let Some(g) = &top.anchor_guid {
        // Tenant GUID must not leak through as the anchor for an incident.
        assert!(
            !g.starts_with("ff000000"),
            "tenant GUID leaked as anchor"
        );
    }

    let buckets = query_lane_buckets(&timeline, 50, None);
    assert!(!buckets.is_empty(), "expected at least one lane bucket");
    let ctx = QueryContext {
        timeline: &timeline,
        runtimes: &runtimes,
    };
    let entries = query_timeline_entries(&ctx, None, None, 0, 100);
    assert!(!entries.is_empty(), "expected materialized entries");
}
