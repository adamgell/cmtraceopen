//! How long applying one map to one event takes.
//!
//! The map engine runs once per record, so this is multiplied by the channel size: a million-record
//! scan pays it a million times. The benchmark exists because the path expressions and `%Name%`
//! placeholders in a map are constant for its whole life, and the applier used to rebuild both for
//! every record.
//!
//! Measured on an M-series mac against the Security 4624 fixture, comparing re-parsing per record
//! against the compiled cache:
//!
//! | | per record | per 10k records |
//! |---|---|---|
//! | re-parsing each time | 5.20 us | 49.0 ms |
//! | compiled once | 1.91 us | 18.9 ms |
//!
//! Run with `cargo bench --bench eventmap_apply` from `crates/cmtraceopen-parser`.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use cmtraceopen_parser::eventmap::{apply_map, EventMap, EventNode};

/// A map shaped like the upstream Security 4624: several bindings, multi-placeholder templates.
const SECURITY_4624: &str = include_str!("../tests/fixtures/eventmap/security-4624.json");

fn event() -> EventNode {
    EventNode::new("Event").with_child(
        EventNode::new("EventData")
            .with_child(
                EventNode::new("Data")
                    .with_attribute("Name", "SubjectUserName")
                    .with_text("adam"),
            )
            .with_child(
                EventNode::new("Data")
                    .with_attribute("Name", "SubjectDomainName")
                    .with_text("CONTOSO"),
            )
            .with_child(
                EventNode::new("Data")
                    .with_attribute("Name", "TargetUserName")
                    .with_text("svc-backup"),
            )
            .with_child(
                EventNode::new("Data")
                    .with_attribute("Name", "IpAddress")
                    .with_text("10.0.0.7"),
            )
            .with_child(
                EventNode::new("Data")
                    .with_attribute("Name", "LogonType")
                    .with_text("10"),
            ),
    )
}

fn apply_one_record(c: &mut Criterion) {
    let map: EventMap = serde_json::from_str(SECURITY_4624).expect("fixture parses");
    let event = event();

    // Warm the compiled cache the way a real scan does: the first record pays for the parse, and
    // every record after it reuses the result. Measuring from cold would report the one-off cost
    // rather than the per-record cost that actually multiplies.
    let _ = apply_map(&map, &event);

    c.bench_function("apply_map/security-4624/one record", |b| {
        b.iter(|| black_box(apply_map(black_box(&map), black_box(&event))));
    });
}

fn apply_a_channel(c: &mut Criterion) {
    let map: EventMap = serde_json::from_str(SECURITY_4624).expect("fixture parses");
    let event = event();
    let _ = apply_map(&map, &event);

    // Ten thousand records is a small channel; the point is the shape of the curve, not the total.
    c.bench_function("apply_map/security-4624/10k records", |b| {
        b.iter(|| {
            for _ in 0..10_000 {
                black_box(apply_map(black_box(&map), black_box(&event)));
            }
        });
    });
}

criterion_group!(benches, apply_one_record, apply_a_channel);
criterion_main!(benches);
