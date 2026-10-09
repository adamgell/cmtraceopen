//! Generates the correlation edge fixtures that the frontend chain model tests consume.
//!
//! The frontend test `src/workspaces/event-log/evtx-correlation-chains.test.ts` must run the chain
//! model on edges the backend REALLY emits, not on hand-built shapes. This test builds identity
//! shapes through the public `correlate_observations` API and writes the resulting edges, in the
//! exact serde shape the frontend decodes (`TimelineCorrelationEdge`), to a JSON file.
//!
//! Regenerate (from the repo root; the path must be absolute because cargo runs tests in the crate dir):
//!
//! ```text
//! CMTRACE_CORRELATION_FIXTURES_OUTPUT=$PWD/src/workspaces/event-log/__fixtures__/correlation-edges.json \
//! CMTRACE_CORRELATION_FIXTURES_COMMIT=$(git rev-parse --short HEAD) \
//!   cargo test --locked -p cmtraceopen-parser --test correlation_chain_fixtures -- --ignored --nocapture
//! ```
//!
//! Without `CMTRACE_CORRELATION_FIXTURES_OUTPUT` the test prints a skip line and passes.

use cmtraceopen_parser::unified_timeline::{
    correlate_observations, TimelineCorrelationKey, TimelineCorrelationKeyKind,
    TimelineCorrelationObservation, TimelineCoverageGap,
};
use serde_json::{json, Map, Value};

use TimelineCorrelationKeyKind::{ActivityId, Secondary, SessionId, UserId};

const OUTPUT_ENV: &str = "CMTRACE_CORRELATION_FIXTURES_OUTPUT";
const COMMIT_ENV: &str = "CMTRACE_CORRELATION_FIXTURES_COMMIT";

/// The origin id of record `n`, in the id format the Live event source emits.
fn id(record: u32) -> String {
    format!("source4:Live|machine10:DESKTOP-01|channel6:System|record{record}")
}

fn keys(spec: &[(TimelineCorrelationKeyKind, &str)]) -> Vec<TimelineCorrelationKey> {
    spec.iter()
        .map(|(kind, value)| TimelineCorrelationKey {
            kind: kind.clone(),
            value: (*value).to_string(),
        })
        .collect()
}

fn obs(
    record: u32,
    exact: &[(TimelineCorrelationKeyKind, &str)],
) -> TimelineCorrelationObservation {
    TimelineCorrelationObservation {
        origin_id: id(record),
        machine: Some("DESKTOP-01".to_string()),
        exact_keys: keys(exact),
        secondary_keys: Vec::new(),
        coverage_gaps: Vec::new(),
    }
}

fn secondary_obs(record: u32, value: &str) -> TimelineCorrelationObservation {
    TimelineCorrelationObservation {
        secondary_keys: keys(&[(Secondary, value)]),
        ..obs(record, &[])
    }
}

/// Records `first..=last`, each carrying only the given exact keys.
fn run(
    first: u32,
    last: u32,
    exact: &[(TimelineCorrelationKeyKind, &str)],
) -> Vec<TimelineCorrelationObservation> {
    (first..=last).map(|record| obs(record, exact)).collect()
}

fn scenario(
    scenarios: &mut Map<String, Value>,
    name: &str,
    description: &str,
    observations: &[TimelineCorrelationObservation],
) {
    let (edges, coverage_gaps) = correlate_observations(observations);
    scenarios.insert(
        name.to_string(),
        json!({
            "description": description,
            "edges": edges,
            "coverageGaps": coverage_gaps,
        }),
    );
}

fn build_scenarios() -> Map<String, Value> {
    let mut s = Map::new();

    scenario(
        &mut s,
        "exactPair",
        "Records 1 and 2 share ActivityId x and nothing else.",
        &run(1, 2, &[(ActivityId, "x")]),
    );
    scenario(
        &mut s,
        "group3",
        "Records 1, 2 and 3 share ActivityId x.",
        &run(1, 3, &[(ActivityId, "x")]),
    );
    scenario(
        &mut s,
        "group4",
        "Records 1 to 4 share ActivityId x.",
        &run(1, 4, &[(ActivityId, "x")]),
    );
    scenario(
        &mut s,
        "sharedPair",
        "Groups {1,2,3} (ActivityId x) and {2,3,4} (SessionId y) share the pair {2,3}.",
        &[
            obs(1, &[(ActivityId, "x")]),
            obs(2, &[(ActivityId, "x"), (SessionId, "y")]),
            obs(3, &[(ActivityId, "x"), (SessionId, "y")]),
            obs(4, &[(SessionId, "y")]),
        ],
    );
    scenario(
        &mut s,
        "sharedMember",
        "Groups {1,2,3} (ActivityId x) and {3,4,5} (SessionId y) share only record 3.",
        &[
            obs(1, &[(ActivityId, "x")]),
            obs(2, &[(ActivityId, "x")]),
            obs(3, &[(ActivityId, "x"), (SessionId, "y")]),
            obs(4, &[(SessionId, "y")]),
            obs(5, &[(SessionId, "y")]),
        ],
    );
    scenario(
        &mut s,
        "pairAndGroupDisjoint",
        "Pair {1,2} (ActivityId x) beside a larger group {3,4,5} (ActivityId z), sharing nothing.",
        &[
            obs(1, &[(ActivityId, "x")]),
            obs(2, &[(ActivityId, "x")]),
            obs(3, &[(ActivityId, "z")]),
            obs(4, &[(ActivityId, "z")]),
            obs(5, &[(ActivityId, "z")]),
        ],
    );
    scenario(
        &mut s,
        "pairInsideGroup",
        "Pair {1,2} (SessionId y) nested inside the larger group {1,2,3,4} (ActivityId x).",
        &[
            obs(1, &[(ActivityId, "x"), (SessionId, "y")]),
            obs(2, &[(ActivityId, "x"), (SessionId, "y")]),
            obs(3, &[(ActivityId, "x")]),
            obs(4, &[(ActivityId, "x")]),
        ],
    );
    scenario(
        &mut s,
        "exactChain3",
        "Pairs {1,2} (ActivityId x) and {2,3} (SessionId y): an exact chain of three, as a backend would have to emit it.",
        &[
            obs(1, &[(ActivityId, "x")]),
            obs(2, &[(ActivityId, "x"), (SessionId, "y")]),
            obs(3, &[(SessionId, "y")]),
        ],
    );
    scenario(
        &mut s,
        "secondaryPair",
        "Records 1 and 2 share only a secondary key.",
        &[secondary_obs(1, "s"), secondary_obs(2, "s")],
    );
    scenario(
        &mut s,
        "secondaryGroup3",
        "Records 1, 2 and 3 share only a secondary key.",
        &[
            secondary_obs(1, "s"),
            secondary_obs(2, "s"),
            secondary_obs(3, "s"),
        ],
    );
    let mut gapped = run(1, 2, &[(ActivityId, "x")]);
    gapped[0].coverage_gaps.push(TimelineCoverageGap {
        source: "Live".to_string(),
        reason: "channel Security was not collected".to_string(),
    });
    scenario(
        &mut s,
        "gappedPair",
        "Records 1 and 2 share ActivityId x, and record 1 carries a source coverage gap.",
        &gapped,
    );

    // Over-256 fan-out: record 1 shares the SYSTEM SID with 300 other records, so that UserId
    // group is skipped for exceeding the 256-member limit. The pair {1,2} then stays exact.
    let mut fan = vec![
        obs(1, &[(ActivityId, "x"), (UserId, "s-1-5-18")]),
        obs(2, &[(ActivityId, "x")]),
    ];
    fan.extend((3..303).map(|record| obs(record, &[(UserId, "s-1-5-18")])));
    scenario(
        &mut s,
        "fanOut",
        "Pair {1,2} (ActivityId x); record 1 also shares UserId S-1-5-18 with 300 other records (over the 256-member limit).",
        &fan,
    );
    let mut below = vec![
        obs(1, &[(ActivityId, "x"), (UserId, "s-1-5-18")]),
        obs(2, &[(ActivityId, "x")]),
    ];
    below.extend((3..6).map(|record| obs(record, &[(UserId, "s-1-5-18")])));
    scenario(
        &mut s,
        "belowFanOut",
        "The fanOut shape with only 3 other UserId members, below the 256-member limit.",
        &below,
    );
    for (name, others) in [("bothSystem300", 300_u32), ("bothSystem3", 3_u32)] {
        let mut v = run(1, 2, &[(ActivityId, "x"), (UserId, "s-1-5-18")]);
        v.extend((3..3 + others).map(|record| obs(record, &[(UserId, "s-1-5-18")])));
        scenario(
            &mut s,
            name,
            &format!(
                "Pair {{1,2}} (ActivityId x) where BOTH endpoints also carry UserId S-1-5-18, shared with {others} other records."
            ),
            &v,
        );
    }
    s
}

#[test]
#[ignore = "fixture generator; set CMTRACE_CORRELATION_FIXTURES_OUTPUT and run with --ignored"]
fn generate_correlation_chain_fixtures() {
    let Ok(path) = std::env::var(OUTPUT_ENV) else {
        println!("skipping correlation fixture generation: {OUTPUT_ENV} is not set");
        return;
    };
    let commit = std::env::var(COMMIT_ENV).unwrap_or_else(|_| "unknown".to_string());
    let document = json!({
        "provenance": {
            "generator": "crates/cmtraceopen-parser/tests/correlation_chain_fixtures.rs",
            "api": "cmtraceopen_parser::unified_timeline::correlate_observations",
            "parserCommit": commit,
            "regenerate": format!(
                "{OUTPUT_ENV}=$PWD/src/workspaces/event-log/__fixtures__/correlation-edges.json {COMMIT_ENV}=$(git rev-parse --short HEAD) cargo test --locked -p cmtraceopen-parser --test correlation_chain_fixtures -- --ignored --nocapture"
            ),
            "note": "Edges are the real backend output, serialized exactly as the frontend decodes TimelineCorrelationEdge. Do not edit by hand."
        },
        "scenarios": build_scenarios(),
    });
    let mut text = serde_json::to_string_pretty(&document).expect("fixture serializes");
    text.push('\n');
    std::fs::write(&path, text).expect("fixture file is writable");
    println!("wrote correlation fixtures to {path}");
}

/// The always-on guard: the shapes the frontend tests lean on must keep their backend behavior, so
/// a parser change that alters them fails here before it silently stales the committed JSON.
#[test]
fn scenario_shapes_match_the_documented_backend_behavior() {
    let scenarios = build_scenarios();
    let edges = |name: &str| scenarios[name]["edges"].as_array().expect("edges").len();
    assert_eq!(edges("exactPair"), 1);
    assert_eq!(edges("group3"), 3);
    assert_eq!(edges("group4"), 6);
    assert_eq!(edges("exactChain3"), 2);
    let strengths = |name: &str| -> Vec<String> {
        scenarios[name]["edges"]
            .as_array()
            .expect("edges")
            .iter()
            .map(|edge| edge["strength"].as_str().expect("strength").to_string())
            .collect()
    };
    assert_eq!(strengths("exactPair"), ["exact"]);
    assert!(strengths("group3").iter().all(|s| s == "ambiguous"));
    // An "exact chain" of three is never emitted: the middle record has two exact neighbours.
    assert!(strengths("exactChain3").iter().all(|s| s == "ambiguous"));
}
