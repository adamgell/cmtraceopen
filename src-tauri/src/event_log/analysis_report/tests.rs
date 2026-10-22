use super::safe::{cut_chars, escape, flatten, token_len_at, Doc, Redactor, Safe};
use super::{collect, collect_chains, REPORT_CHAIN_ROW_CAP};
use super::{
    render_report, render_report_within, EngineNotes, EventLogAnalysisReportRequest, ReportInput,
    ReportSnapshot, MAX_REPORT_BYTES, REPORT_EVENT_ROW_CAP,
};
use crate::event_log::analysis_session::EventLogAnalysisSessionStatus;
use cmtraceopen_parser::diagnosis::{
    CoverageGap, CoverageState, DiagnosisFinding, DiagnosisSummary, EventEvidenceRef, EvidenceRef,
    FindingClass, FindingConfidence, FindingSeverity, TextLogEvidenceRef,
};
use cmtraceopen_parser::intune::apps::windows::common::redact_field_value;
use cmtraceopen_parser::unified_timeline::{
    origin_id, TimelineCorrelationConfidence, TimelineCorrelationCoverage,
    TimelineCorrelationCoverageState, TimelineCorrelationEdge, TimelineCorrelationEvidence,
    TimelineCorrelationKey, TimelineCorrelationKeyKind, TimelineCorrelationStrength,
    TimelineCoverageGap, TimelineItem, TimelineOrigin, TimelineSeverity, UnifiedTimeline,
    UnplacedItem, UnplacedReason,
};
use serde_json::json;
use std::collections::{BTreeSet, HashMap};

fn redactor(names: &[&str]) -> Redactor {
    let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    Redactor::new(&names)
}

fn host(name: &str) -> String {
    redact_field_value("host", name)
}

#[test]
fn escape_neutralizes_markdown_and_html_syntax() {
    assert_eq!(
        escape(r"a | b <i> [x](y) `c` *d* _e_ & #f !g ~h (k)"),
        r"a \| b \<i\> \[x\]\(y) \`c\` \*d\* \_e\_ \& \#f \!g \~h (k)"
    );
    assert_eq!(escape(r"C:\dir"), r"C:\\dir");
}

#[test]
fn a_replacement_token_passes_through_escape_and_a_lookalike_does_not() {
    assert_eq!(escape("[host:0123456789abcdef]"), "[host:0123456789abcdef]");
    // 15 hex digits: not a token.
    assert_eq!(
        escape("[host:0123456789abcde]"),
        r"\[host:0123456789abcde\]"
    );
    // A token followed by a link target must not become a link.
    assert_eq!(
        escape("[host:0123456789abcdef](http://x)"),
        r"[host:0123456789abcdef]\(http://x)"
    );
    assert_eq!(token_len_at("x[user:00ff00ff00ff00ff]", 1), Some(23));
    assert_eq!(token_len_at("[Host:0123456789abcdef]", 0), None);
    assert_eq!(token_len_at("[host:0123456789abcdeg]", 0), None);
}

#[test]
fn text_is_redacted_before_it_is_escaped() {
    // Escaping first turns `user_0001@...` into `user\_0001@...`, and the UPN pattern then
    // matches only from the underscore on, leaving `user` in the output.
    let out = redactor(&[]).text("contact user_0001@example.invalid today", 240);
    assert!(out.as_str().contains("[upn:"), "{}", out.as_str());
    assert!(!out.as_str().contains("user"), "{}", out.as_str());
    assert!(
        !out.as_str().contains("example.invalid"),
        "{}",
        out.as_str()
    );
}

#[test]
fn text_is_cut_after_it_is_redacted() {
    // The UPN straddles character 240 and the cut falls before its first dot. Cut first, the
    // pattern sees `user0001@subdomain-with-long` (no top-level label) and leaves it; redact
    // first, the whole UPN is one 22-character token that fits before the cut.
    let raw = format!(
        "{} user0001@subdomain-with-long-name.example.invalid tail",
        "x".repeat(211)
    );
    let out = redactor(&[]).text(&raw, 240);
    assert!(out.as_str().contains("[upn:"), "{}", out.as_str());
    assert!(!out.as_str().contains("user0001"), "{}", out.as_str());
}

#[test]
fn a_cut_never_lands_inside_a_token() {
    let raw = format!("{}[host:0123456789abcdef] after", "a".repeat(236));
    let cut = cut_chars(&raw, 240);
    assert_eq!(cut, format!("{}...", "a".repeat(236)));
    assert_eq!(cut_chars("short", 240), "short");
    // Characters are counted, not bytes, and the look-back for a token never splits one.
    assert_eq!(
        cut_chars("\u{e9}\u{e9}\u{e9}\u{e9}", 3),
        "\u{e9}\u{e9}\u{e9}..."
    );
    let wide = "\u{4e2d}".repeat(100);
    assert_eq!(
        cut_chars(&wide, 80),
        format!("{}...", "\u{4e2d}".repeat(80))
    );
}

#[test]
fn flatten_collapses_whitespace_and_strips_format_characters() {
    assert_eq!(flatten("a\r\n\tb\u{202e}c\u{200b}d\u{0}e  f"), "a bcd e f");
    assert_eq!(flatten("  lead and trail  "), "lead and trail");
}

#[test]
fn known_machines_are_replaced_longest_first_at_name_boundaries() {
    let r = redactor(&["HOST-0001", "HOST-0001.example.invalid"]);
    // Longest first: the full name is one token, not a token plus a domain tail.
    let out = r.text("see host-0001.example.invalid now", 240);
    assert_eq!(
        out.as_str(),
        format!("see {} now", host("HOST-0001.example.invalid"))
    );
    // Name boundaries: a longer identifier that contains the name is left alone.
    let out = r.text("XHOST-0001Y HOST-00012 HOST-0001", 240);
    assert_eq!(
        out.as_str(),
        format!("XHOST-0001Y HOST-00012 {}", host("HOST-0001"))
    );
}

#[test]
fn a_machine_name_continues_only_on_alphanumerics() {
    let r = redactor(&["HOST-0002"]);
    // A dash or an underscore beside the name is punctuation: collector file names and evtx
    // basenames carry the machine this way, and an identifier-style boundary left them readable.
    assert_eq!(
        r.text("collector-20261018-101010-HOST-0002-4242.log", 240)
            .as_str(),
        format!("collector-20261018-101010-{}-4242.log", host("HOST-0002"))
    );
    assert_eq!(
        r.text("HOST-0002_System.evtx", 240).as_str(),
        format!(r"{}\_System.evtx", host("HOST-0002"))
    );
    // A letter or a digit still makes it a longer name.
    assert_eq!(
        r.text("XHOST-0002Y HOST-00022 HOST-0002a", 240).as_str(),
        "XHOST-0002Y HOST-00022 HOST-0002a"
    );
}

#[test]
fn machine_matching_ignores_ascii_case_and_leaves_tokens_alone() {
    let r = redactor(&["Host-0007", "host"]);
    let out = r.text("HOST-0007 and [host:0123456789abcdef] and host", 240);
    assert_eq!(
        out.as_str(),
        format!(
            "{} and [host:0123456789abcdef] and {}",
            host("Host-0007"),
            host("host")
        )
    );
}

#[test]
fn short_machine_names_are_skipped_counted_and_still_tokenized_in_the_header() {
    let r = redactor(&["ab", "HOST-0001"]);
    assert_eq!(r.skipped_short(), 1);
    assert_eq!(
        r.text("ab HOST-0001", 240).as_str(),
        format!("ab {}", host("HOST-0001"))
    );
    assert_eq!(r.machine("ab").as_str(), host("ab"));
}

#[test]
fn the_machine_token_is_the_diagnosis_token() {
    let r = redactor(&["HOST-0001"]);
    let token = r.machine("HOST-0001");
    assert!(token.as_str().starts_with("[host:"));
    assert_eq!(token.as_str(), host("HOST-0001"));
}

#[test]
fn utc_has_milliseconds_and_a_zulu_suffix_and_marks_what_no_calendar_holds() {
    assert_eq!(
        Safe::utc(1_791_282_047_123).as_str(),
        "2026-10-06T10:20:47.123Z"
    );
    assert_eq!(Safe::utc(i64::MAX).as_str(), "time unavailable");
    assert_eq!(Safe::utc(i64::MIN).as_str(), "time unavailable");
}

#[test]
fn the_document_refuses_to_exceed_its_cap() {
    let mut doc = Doc::new();
    doc.lit("0123456789").nl();
    assert_eq!(doc.finish(11).unwrap(), "0123456789\n");
    let mut doc = Doc::new();
    doc.lit("0123456789").nl();
    assert!(doc.finish(10).is_err());
    assert_eq!(MAX_REPORT_BYTES, 2 * 1024 * 1024);
}

// ---- the request, the scope block and the events table ------------------------------------

const FIXTURE_NOW_MS: i64 = 1_791_282_047_123;

fn request_json() -> serde_json::Value {
    json!({
        "sessionId": "test-session",
        "expectedRevision": 3,
        "generatedAtMs": FIXTURE_NOW_MS,
        "coverageGaps": [],
        "chains": null,
        "scope": {
            "sourceMode": "files",
            "loadedRecordCount": 10,
            "eventRecordCount": 10,
            "archiveTextRecordCount": 0,
            "textLogEntryCount": 0,
            "levelMix": [
                {"level": "Error", "count": 4},
                {"level": "Information", "count": 6}
            ],
            "topEventIds": [
                {"eventId": 100, "count": 6},
                {"eventId": 7, "count": 4}
            ],
            "distinctEventIdCount": 2,
            "filters": {
                "levels": ["Critical", "Error", "Warning", "Information", "Verbose"],
                "channelsSelected": ["Application"],
                "channelsHeld": 1,
                "eventIdSelectors": [],
                "timeWindow": "all",
                "timeRange": null,
                "searchActive": false,
                "quickFilterActive": false,
                "recordScope": null
            }
        }
    })
}

fn request_from(value: serde_json::Value) -> EventLogAnalysisReportRequest {
    serde_json::from_value(value).expect("the request parses")
}

fn base_request() -> EventLogAnalysisReportRequest {
    request_from(request_json())
}

fn status(event_items: u64, log_items: u64) -> EventLogAnalysisSessionStatus {
    EventLogAnalysisSessionStatus {
        session_id: "test-session".to_owned(),
        revision: 3,
        total_items: event_items + log_items,
        event_items,
        log_items,
        total_unplaced: 0,
        total_edges: 0,
        total_coverage_gaps: 0,
        finalized: true,
    }
}

#[allow(clippy::too_many_arguments)]
fn event_item(
    timestamp_ms: i64,
    severity: TimelineSeverity,
    event_id: u32,
    channel: &str,
    provider: &str,
    machine: Option<&str>,
    record: u64,
    message: &str,
) -> TimelineItem {
    TimelineItem {
        timestamp_ms,
        severity,
        message: message.to_owned(),
        origin: TimelineOrigin::Event {
            stable_id: format!("source8:test.evtx|machine0:|channel0:|record{record}"),
            source: "test.evtx".to_owned(),
            machine: machine.map(str::to_owned),
            bundle: None,
            channel: channel.to_owned(),
            provider: provider.to_owned(),
            process_id: None,
            activity_id: None,
            related_activity_id: None,
            session_id: None,
            device_id: None,
            user_id: None,
            process_start_time: None,
            identity_conflicts: Vec::new(),
            event_id,
            record_id: record,
            record_id_text: Some(record.to_string()),
        },
    }
}

fn plain_item(index: u64) -> TimelineItem {
    event_item(
        FIXTURE_NOW_MS + index as i64 * 1000,
        TimelineSeverity::Info,
        100,
        "Application",
        "Ordinary.Provider",
        Some("HOST-0001"),
        index + 1,
        "An ordinary message.",
    )
}

fn snapshot_of(rows: Vec<TimelineItem>, placed: u64) -> ReportSnapshot {
    let mut machines = BTreeSet::new();
    for row in &rows {
        if let TimelineOrigin::Event {
            machine: Some(machine),
            ..
        } = &row.origin
        {
            machines.insert(machine.clone());
        }
    }
    ReportSnapshot {
        status: status(placed, 0),
        event_rows: rows,
        unplaced_events: 0,
        unplaced_text_lines: 0,
        span_ms: Some((FIXTURE_NOW_MS, FIXTURE_NOW_MS + 1000)),
        machines,
        engine_notes: EngineNotes::default(),
        entries: HashMap::new(),
        chains: Vec::new(),
    }
}

fn render(request: &EventLogAnalysisReportRequest, snapshot: &ReportSnapshot) -> String {
    render_with(request, snapshot, &DiagnosisSummary::default())
}

fn render_with(
    request: &EventLogAnalysisReportRequest,
    snapshot: &ReportSnapshot,
    summary: &DiagnosisSummary,
) -> String {
    render_report(&ReportInput {
        request,
        snapshot,
        summary,
    })
    .expect("the report renders")
}

/// Whether `needle` is in the report, whether or not Markdown escaping broke it up. A leak
/// assertion on the escaped text would pass for `user\_0001`, which is the same leak.
fn leaks(report: &str, needle: &str) -> bool {
    report
        .replace('\\', "")
        .to_lowercase()
        .contains(&needle.to_lowercase())
}

fn table_rows(report: &str) -> usize {
    report
        .lines()
        .filter(|line| line.starts_with("| 2026-"))
        .count()
}

#[test]
fn the_request_contract_parses_and_refuses_text_it_has_no_field_for() {
    base_request()
        .validate()
        .expect("the base request is valid");
    for window in ["1h", "24h", "7d", "30d", "all"] {
        let mut value = request_json();
        value["scope"]["filters"]["timeWindow"] = json!(window);
        request_from(value);
    }
    let mut value = request_json();
    value["scope"]["filters"]["eventIdSelectors"] = json!([
        {"kind": "single", "id": 4624},
        {"kind": "range", "low": 4625, "high": 4630}
    ]);
    request_from(value).validate().expect("selectors are valid");

    // No field carries what the operator typed, a title or a record: an attempt to send one
    // is refused at the type, at every level.
    for (path, key) in [
        ("", "searchText"),
        ("scope", "chainTitle"),
        ("scope.filters", "searchText"),
        ("scope.filters", "quickFilterText"),
        ("scope.filters", "recordScopeTitle"),
    ] {
        let mut value = request_json();
        let target = path
            .split('.')
            .filter(|part| !part.is_empty())
            .fold(&mut value, |node, part| &mut node[part]);
        target[key] = json!("fixture text");
        assert!(
            serde_json::from_value::<EventLogAnalysisReportRequest>(value).is_err(),
            "{path}.{key} was accepted"
        );
    }
    let mut value = request_json();
    value["scope"]["filters"]["timeWindow"] = json!("2h");
    assert!(serde_json::from_value::<EventLogAnalysisReportRequest>(value).is_err());
}

#[test]
fn validation_refuses_what_cannot_be_true() {
    type Change = fn(&mut serde_json::Value);
    let cases: [(&str, Change); 9] = [
        ("level counts exceed", |v| {
            v["scope"]["levelMix"][0]["count"] = json!(7);
        }),
        ("a level is counted twice", |v| {
            v["scope"]["levelMix"][1]["level"] = json!("Error");
        }),
        ("event ID counts exceed", |v| {
            v["scope"]["topEventIds"][0]["count"] = json!(9);
        }),
        ("an event ID is counted twice", |v| {
            v["scope"]["topEventIds"][1]["eventId"] = json!(100);
        }),
        ("distinct event ID count is impossible", |v| {
            v["scope"]["distinctEventIdCount"] = json!(1);
        }),
        ("distinct event ID count is impossible", |v| {
            v["scope"]["distinctEventIdCount"] = json!(11);
        }),
        ("selectors are impossible", |v| {
            v["scope"]["filters"]["eventIdSelectors"] =
                json!([{"kind": "range", "low": 9, "high": 3}]);
        }),
        ("channel list is too large", |v| {
            v["scope"]["filters"]["channelsSelected"] = json!(["c".repeat(513)]);
        }),
        ("ends before it starts", |v| {
            v["scope"]["filters"]["timeRange"] = json!({"startMs": 9, "endMs": 3});
        }),
    ];
    for (expected, change) in cases {
        let mut value = request_json();
        change(&mut value);
        let error = request_from(value).validate().expect_err(expected);
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

#[test]
fn the_events_table_lists_at_most_the_cap_and_counts_the_rest() {
    let request = base_request();
    // (rows the snapshot holds, events the session placed, rows printed, closing sentence)
    let cases: [(u64, u64, usize, &str); 6] = [
        (0, 0, 0, "No event in scope is placed on the timeline."),
        (499, 499, 499, "All 499 placed events are listed."),
        (500, 500, 500, "All 500 placed events are listed."),
        (
            500,
            501,
            500,
            "Showing the first 500 of 501 placed events; 1 omitted.",
        ),
        (
            501,
            501,
            500,
            "Showing the first 500 of 501 placed events; 1 omitted.",
        ),
        (
            600,
            1200,
            500,
            "Showing the first 500 of 1200 placed events; 700 omitted.",
        ),
    ];
    assert_eq!(REPORT_EVENT_ROW_CAP, 500);
    for (held, placed, printed, sentence) in cases {
        let rows = (0..held).map(plain_item).collect();
        let report = render(&request, &snapshot_of(rows, placed));
        assert_eq!(table_rows(&report), printed, "{held} held, {placed} placed");
        assert!(report.contains(sentence), "{sentence}\n{report}");
    }
}

#[test]
fn every_cell_of_the_events_table_is_redacted() {
    let message = concat!(
        "Sign-in by user0001@example.invalid from HOST-0002 ",
        "SID S-1-5-21-1000000001-1000000002-1000000003-1001 ",
        "TenantId=00000000-0000-4000-8000-000000000001 ",
        r"profile C:\Users\user0001\AppData\Local\Temp\a.log"
    );
    let item = event_item(
        FIXTURE_NOW_MS,
        TimelineSeverity::Error,
        1001,
        "Microsoft-Windows-Fixture/Admin for HOST-0002",
        r"Vendor C:\Users\user0001\x",
        Some("HOST-0002"),
        1,
        message,
    );
    let report = render(&base_request(), &snapshot_of(vec![item], 1));
    for leak in [
        "HOST-0002",
        "user0001",
        "example.invalid",
        "S-1-5-21-1000000001",
        "00000000-0000-4000-8000-000000000001",
    ] {
        assert!(!leaks(&report, leak), "{leak} leaked:\n{report}");
    }
    // `TenantId=` is a sensitive label, so the export pass masks its value whole.
    for token in [
        "[host:",
        "[upn:",
        "[sid:",
        r"\[sensitive:TenantId\]",
        "[user:",
    ] {
        assert!(report.contains(token), "{token} missing:\n{report}");
    }
    assert_eq!(table_rows(&report), 1);
}

#[test]
fn a_report_of_five_hundred_long_rows_is_redacted_per_field_not_as_a_document() {
    // Over 256 KiB in all: redacting the assembled document would replace it with the
    // oversize marker, so the redaction has to be per field.
    let message = format!("user_0001@example.invalid {}", "word ".repeat(60));
    let rows: Vec<TimelineItem> = (0..500)
        .map(|index| {
            event_item(
                FIXTURE_NOW_MS + index,
                TimelineSeverity::Warning,
                100,
                &format!("Microsoft-Windows-{}/Operational", "Channel-".repeat(20)),
                &format!("Microsoft-Windows-{}", "Provider-".repeat(20)),
                Some("HOST-0001"),
                index as u64 + 1,
                &message,
            )
        })
        .collect();
    let report = render(&base_request(), &snapshot_of(rows, 500));
    assert!(report.len() > 256 * 1024, "{}", report.len());
    assert!(!report.contains("oversized text omitted"));
    assert_eq!(table_rows(&report), 500);
    assert_eq!(report.matches("[upn:").count(), 500);
}

#[test]
fn the_scope_block_counts_what_is_unplaced_and_flags_counts_that_disagree() {
    let request = base_request();
    let mut snapshot = snapshot_of((0..8).map(plain_item).collect(), 8);
    snapshot.unplaced_events = 2;
    snapshot.unplaced_text_lines = 3;
    let report = render(&request, &snapshot);
    assert!(report.contains(
        "- Events in scope without a usable timestamp, not placed and not listed below: 2"
    ));
    assert!(report.contains("- Text lines without a usable timestamp, not placed: 3"));
    assert!(!report.contains("The session holds"), "{report}");

    snapshot.unplaced_events = 1;
    let report = render(&request, &snapshot);
    assert!(report.contains(
        "The session holds 9 events and the app counted 10 in scope. The two counts are \
         shown as each side reported them."
    ));
}

#[test]
fn a_narrowed_scope_is_disclosed_and_an_unnarrowed_one_is_not() {
    let mut value = request_json();
    value["scope"]["loadedRecordCount"] = json!(100);
    value["scope"]["textLogEntryCount"] = json!(4);
    let report = render(&request_from(value), &snapshot_of(Vec::new(), 0));
    assert!(report.contains("computed over the events in scope only"));
    assert!(report.contains("- Text logs are not scoped."));

    let mut value = request_json();
    value["scope"]["loadedRecordCount"] = json!(100);
    let report = render(&request_from(value), &snapshot_of(Vec::new(), 0));
    assert!(report.contains("computed over the events in scope only"));
    assert!(!report.contains("Text logs are not scoped."));

    let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
    assert!(!report.contains("computed over the events in scope only"));
}

#[test]
fn machines_are_listed_as_tokens_and_their_absence_is_said_precisely() {
    let mut rows = vec![plain_item(0)];
    rows.push(event_item(
        FIXTURE_NOW_MS,
        TimelineSeverity::Info,
        1,
        "Application",
        "P",
        Some("HOST-0002"),
        9,
        "m",
    ));
    let report = render(&base_request(), &snapshot_of(rows, 2));
    let expected = {
        let mut tokens = [host("HOST-0001"), host("HOST-0002")];
        tokens.sort();
        format!("- Machines (2): {}, {}", tokens[0], tokens[1])
    };
    assert!(report.contains(&expected), "{report}");
    assert!(!report.contains("HOST-000"), "{report}");

    let mut anonymous = snapshot_of(vec![plain_item(0)], 1);
    anonymous.machines.clear();
    let report = render(&base_request(), &anonymous);
    assert!(report.contains("- Machines: no entry in the session records a machine name"));

    let empty = snapshot_of(Vec::new(), 0);
    let report = render(&base_request(), &empty);
    assert!(report.contains("- Machines: the session holds no entries"));

    let mut short = snapshot_of(vec![plain_item(0)], 1);
    short.machines.insert("ab".to_owned());
    let report = render(&base_request(), &short);
    assert!(report.contains("shorter than 3 characters, not searched for in free text: 1"));
}

#[test]
fn the_aggregates_are_the_apps_counts_and_say_what_they_do_not_cover() {
    let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
    assert!(report.contains("Top 2 of 2 distinct event IDs."));
    assert!(report.contains("| 100 | 6 |"));
    assert!(report.contains("| Error | 4 |"));
    assert!(!report.contains("The level counts cover"));

    let mut value = request_json();
    value["scope"]["distinctEventIdCount"] = json!(null);
    value["scope"]["levelMix"][0]["count"] = json!(3);
    let report = render(&request_from(value), &snapshot_of(Vec::new(), 0));
    assert!(report.contains("the number of distinct IDs was not counted"));
    assert!(report.contains("The level counts cover 9 of the 10 events in scope."));

    let mut value = request_json();
    value["scope"]["eventRecordCount"] = json!(0);
    value["scope"]["levelMix"] = json!([]);
    value["scope"]["topEventIds"] = json!([]);
    value["scope"]["distinctEventIdCount"] = json!(0);
    let report = render(&request_from(value), &snapshot_of(Vec::new(), 0));
    assert_eq!(report.matches("No events are in scope.").count(), 2);
}

#[test]
fn filters_are_typed_and_what_the_operator_typed_is_never_printed() {
    let mut value = request_json();
    value["scope"]["filters"]["searchActive"] = json!(true);
    value["scope"]["filters"]["quickFilterActive"] = json!(true);
    value["scope"]["filters"]["recordScope"] = json!("chain");
    value["scope"]["filters"]["levels"] = json!(["Critical", "Error"]);
    value["scope"]["filters"]["eventIdSelectors"] = json!([
        {"kind": "single", "id": 4624},
        {"kind": "range", "low": 4625, "high": 4630}
    ]);
    value["scope"]["filters"]["timeRange"] =
        json!({"startMs": FIXTURE_NOW_MS, "endMs": FIXTURE_NOW_MS + 60_000});
    value["scope"]["filters"]["timeWindow"] = json!("7d");
    let report = render(&request_from(value), &snapshot_of(Vec::new(), 0));
    assert!(report.contains("  - Levels: Critical, Error"));
    assert!(report.contains("  - Event IDs: 4624, 4625 to 4630"));
    assert!(report.contains("  - Time window: last 7 days"));
    assert!(report.contains(
        "  - Brushed time range: 2026-10-06T10:20:47.123Z to 2026-10-06T10:21:47.123Z \
         (start included, end excluded)"
    ));
    assert!(report.contains("  - Text search: active (its text is not included in this report)"));
    assert!(report.contains("  - Quick filter: active (its text is not included in this report)"));
    assert!(report.contains("  - Record scope: limited to the events one chain contains"));
    assert!(report.contains("  - Channels: 1 of 1 loaded channels selected: Application"));
}

#[test]
fn times_are_utc_and_one_no_calendar_holds_is_marked_not_shown_as_1970() {
    let item = event_item(
        i64::MAX,
        TimelineSeverity::Info,
        1,
        "Application",
        "P",
        None,
        1,
        "m",
    );
    let report = render(&base_request(), &snapshot_of(vec![item], 1));
    assert!(
        report.contains("| time unavailable | Information | 1 |"),
        "{report}"
    );
    assert!(!report.contains("1970"));
    assert!(report.contains("- Generated: 2026-10-06T10:20:47.123Z"));
    assert!(report.contains("All times are UTC (ISO 8601)."));
}

#[test]
fn a_report_over_its_cap_is_an_error_and_never_a_shorter_file() {
    let request = base_request();
    let snapshot = snapshot_of((0..50).map(plain_item).collect(), 50);
    let summary = DiagnosisSummary::default();
    let input = ReportInput {
        request: &request,
        snapshot: &snapshot,
        summary: &summary,
    };
    let full = render_report_within(&input, MAX_REPORT_BYTES).expect("within the cap");
    assert!(render_report_within(&input, full.len()).is_ok());
    let error = render_report_within(&input, full.len() - 1).expect_err("one byte over");
    assert!(error.contains("not written"), "{error}");
}

#[test]
fn the_banner_says_where_the_known_machine_names_come_from() {
    // The report only knows the machines its own entries record. It cannot know the machines of
    // events that are loaded in the app but outside the session.
    let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
    assert!(
        report.contains("machine names recorded by the events in this report"),
        "{report}"
    );
    assert!(!report.contains("found in the loaded events"), "{report}");
}

#[test]
fn the_report_is_deterministic_and_does_not_claim_to_be_free_of_identifiers() {
    let request = base_request();
    let snapshot = snapshot_of((0..20).map(plain_item).collect(), 20);
    let first = render(&request, &snapshot);
    assert_eq!(first, render(&request, &snapshot));
    assert!(first.contains("Free text can still contain identifiers that no pattern recognizes"));
    assert!(first.starts_with("# Event Logs report\n"));
    assert!(!first.to_lowercase().contains("no sensitive"));
}

// ---- findings and coverage ----------------------------------------------------------------

fn finding(
    id: &str,
    class: FindingClass,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    title: &str,
) -> DiagnosisFinding {
    DiagnosisFinding {
        finding_id: id.to_owned(),
        class,
        severity,
        confidence,
        title: title.to_owned(),
        summary: format!("{title} summary."),
        evidence: Vec::new(),
        coverage_gaps: Vec::new(),
        recommended_checks: Vec::new(),
    }
}

fn event_evidence(
    event_id: u32,
    channel: Option<&str>,
    record_id_text: Option<&str>,
    record_id: u64,
    fallback: Option<&str>,
) -> EvidenceRef {
    EvidenceRef::Event(EventEvidenceRef {
        source: r"C:\Cases\CASE-0001\System.evtx".to_owned(),
        provider: "Fixture.Provider".to_owned(),
        event_id,
        record_id,
        record_id_text: record_id_text.map(str::to_owned),
        fallback_identity: fallback.map(str::to_owned),
        machine: Some("HOST-0004".to_owned()),
        channel: channel.map(str::to_owned),
        activity_id: None,
    })
}

fn gap(source: &str, state: CoverageState, detail: &str) -> CoverageGap {
    CoverageGap {
        id: format!("coverage:{source}:{detail}"),
        source: source.to_owned(),
        state,
        detail: detail.to_owned(),
        evidence: Vec::new(),
    }
}

fn summary_of(findings: Vec<DiagnosisFinding>, gaps: Vec<CoverageGap>) -> DiagnosisSummary {
    let mut summary = DiagnosisSummary {
        findings,
        coverage_gaps: gaps,
        ..DiagnosisSummary::default()
    };
    summary.overview.actionable_finding_count = summary
        .findings
        .iter()
        .filter(|finding| !matches!(finding.class, FindingClass::CoverageGap))
        .count();
    summary.overview.coverage_gap_count = summary.coverage_gaps.len();
    summary.overview.finding_count = summary.findings.len();
    summary
}

#[test]
fn findings_are_listed_by_severity_then_confidence_with_bounded_evidence() {
    let mut first = finding(
        "a",
        FindingClass::LikelyContributor,
        FindingSeverity::Warning,
        FindingConfidence::High,
        "Warning high",
    );
    let mut second = finding(
        "b",
        FindingClass::ConfirmedFailure,
        FindingSeverity::Critical,
        FindingConfidence::Low,
        "Critical low",
    );
    let third = finding(
        "c",
        FindingClass::Symptom,
        FindingSeverity::Warning,
        FindingConfidence::Medium,
        "Warning medium",
    );
    let coverage = finding(
        "d",
        FindingClass::CoverageGap,
        FindingSeverity::Critical,
        FindingConfidence::High,
        "A coverage gap is never an actionable finding",
    );
    first.evidence = vec![
        event_evidence(
            76,
            Some("DeviceManagement/Admin"),
            Some("88456"),
            88456,
            None,
        ),
        event_evidence(77, None, Some("000"), 0, Some("deadbeefcafe")),
        event_evidence(78, Some("System"), None, 12, None),
        event_evidence(79, Some("System"), None, 0, None),
        EvidenceRef::TextLog(TextLogEvidenceRef {
            source: "IntuneManagementExtension.log".to_owned(),
            file_path: r"C:\Cases\CASE-0001\Logs\IntuneManagementExtension.log".to_owned(),
            line_number: 42,
            entry_id: 7,
        }),
    ];
    second.recommended_checks = vec!["Check one.".to_owned(), "Check two.".to_owned()];
    let summary = summary_of(vec![first, second, third, coverage], Vec::new());
    let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);

    let position = |needle: &str| report.find(needle).unwrap_or(usize::MAX);
    assert!(position("### Critical low") < position("### Warning high"));
    assert!(position("### Warning high") < position("### Warning medium"));
    assert!(!report.contains("never an actionable finding"));
    assert!(report.contains("The engine reported 3 actionable findings."));
    assert!(report.contains("- Class: confirmed failure; severity: critical; confidence: low"));
    assert!(report.contains("- Summary: Critical low summary."));
    assert!(report.contains(
        "- Evidence: 76 \u{b7} DeviceManagement/Admin \u{b7} record 88456; \
         77 \u{b7} Fixture.Provider \u{b7} ref deadbeef; \
         78 \u{b7} System \u{b7} record 12; and 2 more"
    ));
    assert!(report.contains("- Recommended check: Check one.; and 1 more checks"));
    // Evidence is named by event, channel and record: never by source path or machine.
    assert!(!report.contains("CASE-0001"));
    assert!(!report.contains("HOST-0004"));
}

#[test]
fn evidence_without_a_record_number_says_so_and_a_text_log_is_named_by_its_file() {
    let mut one = finding(
        "a",
        FindingClass::Symptom,
        FindingSeverity::Info,
        FindingConfidence::Unknown,
        "Evidence labels",
    );
    one.evidence = vec![
        event_evidence(79, Some("System"), None, 0, None),
        EvidenceRef::TextLog(TextLogEvidenceRef {
            source: "x".to_owned(),
            file_path: r"C:\Cases\CASE-0001\Logs\IntuneManagementExtension.log".to_owned(),
            line_number: 42,
            entry_id: 7,
        }),
    ];
    let report = render_with(
        &base_request(),
        &snapshot_of(Vec::new(), 0),
        &summary_of(vec![one], Vec::new()),
    );
    assert!(report.contains(
        "- Evidence: 79 \u{b7} System \u{b7} no record ID; \
         IntuneManagementExtension.log \u{b7} line 42"
    ));
    assert!(!report.contains("CASE-0001"));
}

#[test]
fn an_unprojected_summary_is_redacted_by_the_renderer_itself() {
    // Only the diagnosis projection removes an XML element's content and replaces a machine
    // the evidence names. The renderer's own redaction cannot know either, so a renderer that
    // trusted its caller to project would print both.
    let mut one = finding(
        "a",
        FindingClass::ConfirmedFailure,
        FindingSeverity::Error,
        FindingConfidence::High,
        "Enrollment failed",
    );
    one.summary =
        "DESKTOP-JANE rejected <Password>xml-secret-0001</Password> during enrollment".to_owned();
    one.evidence = vec![EvidenceRef::Event(EventEvidenceRef {
        source: "s".to_owned(),
        provider: "p".to_owned(),
        event_id: 1,
        record_id: 1,
        record_id_text: Some("1".to_owned()),
        fallback_identity: None,
        machine: Some("DESKTOP-JANE".to_owned()),
        channel: None,
        activity_id: None,
    })];
    let summary = summary_of(vec![one], Vec::new());
    let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
    assert!(!report.contains("xml-secret-0001"), "{report}");
    assert!(!report.contains("DESKTOP-JANE"), "{report}");
    assert!(report.contains("### Enrollment failed"));
}

#[test]
fn the_engines_headline_is_printed_and_no_issues_is_never_composed() {
    let mut summary = summary_of(
        Vec::new(),
        vec![gap(
            "Security",
            CoverageState::AccessDenied,
            "Access is denied.",
        )],
    );
    summary.overview.outcome = "insufficientEvidence".to_owned();
    summary.overview.headline =
        "Evidence is insufficient to determine whether issues are present.".to_owned();
    let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
    assert!(report.contains(
        "Engine summary: Evidence is insufficient to determine whether issues are present."
    ));
    assert!(report.contains(
        "The engine reported no actionable findings in the events it read. Coverage gaps \
         listed above limit what that means."
    ));
    assert!(!report.contains("No issues detected"));

    // With no gap the engine's own words are printed, as the engine's.
    let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
    assert!(report.contains("Engine summary: No issues detected."));
    assert!(report.contains("The engine reported no actionable findings in the events it read.\n"));
}

#[test]
fn a_bounded_response_is_stated_with_both_counts() {
    let mut summary = summary_of(
        vec![finding(
            "a",
            FindingClass::Symptom,
            FindingSeverity::Info,
            FindingConfidence::Low,
            "Only one",
        )],
        vec![gap("Security", CoverageState::Capped, "Capped.")],
    );
    summary.overview.actionable_finding_count = 5;
    summary.overview.coverage_gap_count = 9;
    let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
    assert!(report.contains(
        "The engine counted 5 actionable findings and sent 1 of them: its response is bounded."
    ));
    assert!(report.contains(
        "- The engine counted 9 coverage gaps and sent 1 of them: its response is bounded."
    ));
}

#[test]
fn coverage_gaps_are_listed_by_state_and_timeline_gaps_are_counted_and_never_named() {
    let timeline_source =
        "timeline:source9:test.evtx|machine9:HOST-0003|channel11:Application|record5";
    let summary = summary_of(
        Vec::new(),
        vec![
            gap("Security", CoverageState::AccessDenied, "Access is denied."),
            gap(
                r"C:\Cases\ACME-0001\Archive.evtx",
                CoverageState::Unsupported,
                "The file could not be read.",
            ),
            gap(
                timeline_source,
                CoverageState::Skipped,
                "multiple exact identity candidates remain: source9:test.evtx|machine9:HOST-0003",
            ),
            gap(
                "timeline:correlation",
                CoverageState::Capped,
                "correlation edge output budget reached",
            ),
            gap(
                "timeline:timeline-correlation-projection",
                CoverageState::Capped,
                "correlation input limit reached",
            ),
        ],
    );
    let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
    assert!(report.contains("- Coverage gaps the engine listed (2):"));
    assert!(report.contains("  - access denied: Security: Access is denied."));
    assert!(report.contains("  - unsupported: Archive.evtx: The file could not be read."));
    assert!(report.contains(
        "- Correlation and timeline coverage gaps: 3 (capped 2, skipped 1). Their details \
         name individual events, so they are counted here and not listed."
    ));
    for leak in [
        "HOST-0003",
        "ACME-0001",
        "test.evtx",
        "record5",
        "identity candidates",
    ] {
        assert!(!leaks(&report, leak), "{leak} leaked:\n{report}");
    }
}

#[test]
fn what_the_engine_shortened_is_stated_and_a_clean_run_states_nothing_it_did_not_see() {
    let mut snapshot = snapshot_of(Vec::new(), 0);
    let report = render(&base_request(), &snapshot);
    assert!(!report.contains("shortened some event messages"));
    assert!(!report.contains("compacted oversized"));
    assert!(!report.contains("reduced before the session read them"));
    assert!(report.contains(
        "- The engine listed no coverage gap. A channel that was not loaded or not selected \
         is not a gap and does not appear here."
    ));

    snapshot.engine_notes = EngineNotes {
        messages_shortened: true,
        items_compacted: true,
        transport_projected: true,
    };
    let report = render(&base_request(), &snapshot);
    assert!(report.contains("shortened some event messages to stay inside its message budget"));
    assert!(report.contains("compacted oversized list-view fields of some timeline items"));
    assert!(report.contains("reduced before the session read them"));
}

#[test]
fn finding_text_is_redacted_cut_and_single_line() {
    let mut one = finding(
        "a",
        FindingClass::Symptom,
        FindingSeverity::Info,
        FindingConfidence::Low,
        "T",
    );
    one.title = format!(
        "Title\nwith | pipe and user_0001@example.invalid {}",
        "t".repeat(400)
    );
    one.summary = format!("{}\r\nsecond line", "s".repeat(2000));
    let summary = summary_of(vec![one], Vec::new());
    let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
    let heading = report
        .lines()
        .find(|line| line.starts_with("### "))
        .unwrap();
    assert!(heading.contains(r"with \| pipe"), "{heading}");
    assert!(heading.contains("[upn:"));
    assert!(!leaks(heading, "user_0001"));
    assert!(heading.ends_with("..."));
    let summary_line = report
        .lines()
        .find(|line| line.starts_with("- Summary: "))
        .unwrap();
    assert!(
        summary_line.chars().count() < 1_020,
        "{}",
        summary_line.len()
    );
    assert!(!summary_line.contains("second line"));
}

// ---- chains and the nearby statement -------------------------------------------------------

const GUID_A: &str = "00000000-0000-4000-8000-0000000000a1";

fn stable(record: u64) -> String {
    format!(
        "source30:C:\\Cases\\CASE-0002\\A.evtx|machine9:HOST-0005|channel30:Fixture/Admin|record{record}"
    )
}

fn chain_item(record: u64, event_id: u32, offset_s: i64, message: &str) -> TimelineItem {
    let mut item = event_item(
        FIXTURE_NOW_MS + offset_s * 1000,
        TimelineSeverity::Info,
        event_id,
        "Microsoft-Windows-Fixture/Admin",
        "Fixture.Provider",
        Some("HOST-0005"),
        record,
        message,
    );
    if let TimelineOrigin::Event { stable_id, .. } = &mut item.origin {
        *stable_id = stable(record);
    }
    item
}

fn edge(
    from: &str,
    to: &str,
    kind: TimelineCorrelationKeyKind,
    field: &str,
    value: &str,
    strength: TimelineCorrelationStrength,
) -> TimelineCorrelationEdge {
    TimelineCorrelationEdge {
        id: format!("edge|{from}|{to}|{field}|{value}"),
        from_id: from.to_owned(),
        to_id: Some(to.to_owned()),
        key: TimelineCorrelationKey {
            kind,
            value: value.to_owned(),
        },
        strength,
        confidence: TimelineCorrelationConfidence::High,
        candidate_ids: Vec::new(),
        evidence: vec![
            TimelineCorrelationEvidence {
                origin_id: from.to_owned(),
                field: field.to_owned(),
                value: value.to_owned(),
            },
            TimelineCorrelationEvidence {
                origin_id: to.to_owned(),
                field: field.to_owned(),
                value: value.to_owned(),
            },
        ],
        coverage: TimelineCorrelationCoverage {
            state: TimelineCorrelationCoverageState::Covered,
            gap: None,
        },
    }
}

fn exact_edge(from: &str, to: &str, value: &str) -> TimelineCorrelationEdge {
    edge(
        from,
        to,
        TimelineCorrelationKeyKind::ActivityId,
        "activityId",
        value,
        TimelineCorrelationStrength::Exact,
    )
}

fn timeline_of(items: Vec<TimelineItem>, edges: Vec<TimelineCorrelationEdge>) -> UnifiedTimeline {
    UnifiedTimeline {
        items,
        unplaced: Vec::new(),
        edges,
        coverage_gaps: Vec::new(),
    }
}

fn row(strength: &str, members: &[String], pairs: serde_json::Value) -> serde_json::Value {
    json!({
        "strength": strength,
        "memberCount": members.len(),
        "memberIds": members,
        "pairs": pairs,
    })
}

fn pair(left: &str, right: &str, keys: &[(&str, &str)]) -> serde_json::Value {
    json!({
        "left": left,
        "right": right,
        "keys": keys
            .iter()
            .map(|(kind, value)| json!({"kind": kind, "value": value}))
            .collect::<Vec<_>>(),
    })
}

fn chains_value(
    loaded: u64,
    counts: (u64, u64, u64, u64),
    rows: Vec<serde_json::Value>,
) -> serde_json::Value {
    json!({
        "loadedEdgeCount": loaded,
        "correlationGaps": {"global": false, "previewCut": false},
        "counts": {
            "exact": counts.0,
            "candidate": counts.1,
            "ambiguous": counts.2,
            "coverageBlocked": counts.3
        },
        "rows": rows,
    })
}

fn chain_report_for(
    timeline: &UnifiedTimeline,
    chains: serde_json::Value,
) -> Result<String, String> {
    let mut value = request_json();
    value["chains"] = chains;
    let request = request_from(value);
    request.validate()?;
    let (chains, entries) = collect_chains(timeline, request.chains.as_ref().unwrap())?;
    let mut snapshot = snapshot_of(Vec::new(), 0);
    snapshot.machines.insert("HOST-0005".to_owned());
    snapshot.status.total_edges = timeline.edges.len() as u64;
    snapshot.entries = entries;
    snapshot.chains = chains;
    render_report(&ReportInput {
        request: &request,
        snapshot: &snapshot,
        summary: &DiagnosisSummary::default(),
    })
}

fn two_event_timeline() -> (UnifiedTimeline, String, String) {
    let (a, b) = (stable(1), stable(2));
    let timeline = timeline_of(
        vec![
            chain_item(1, 76, 0, "Enrollment started on HOST-0005."),
            chain_item(2, 77, 9, "Enrollment failed."),
        ],
        vec![exact_edge(&a, &b, GUID_A)],
    );
    (timeline, a, b)
}

fn section<'a>(report: &'a str, heading: &str) -> &'a str {
    let start = report.find(heading).expect("the section exists");
    let rest = &report[start + heading.len()..];
    &report[start..start + heading.len() + rest.find("\n## ").unwrap_or(rest.len())]
}

#[test]
fn a_chain_is_confirmed_against_the_sessions_edges_and_rendered_from_them() {
    let (timeline, a, b) = two_event_timeline();
    let chains = chains_value(
        1,
        (1, 0, 0, 0),
        vec![row(
            "exact",
            &[a.clone(), b.clone()],
            json!([pair(&a, &b, &[("activityId", GUID_A)])]),
        )],
    );
    let report = chain_report_for(&timeline, chains).expect("the chain renders");
    assert!(report.contains("### Chain 1: Exact, 2 entries"), "{report}");
    assert!(report.contains("- Links rest on: ActivityId"));
    assert!(report.contains("- Link evidence (2 lines):"));
    assert!(report.contains(&format!(
        "  - 76 \u{b7} Microsoft-Windows-Fixture/Admin \u{b7} record 1: ActivityId = {GUID_A}"
    )));
    assert!(report.contains(
        "- Span of the listed entries on the timeline: 2026-10-06T10:20:47.123Z to \
         2026-10-06T10:20:56.123Z"
    ));
    assert_eq!(table_rows(section(&report, "## Correlation chains")), 2);
    // The message names the machine; ids carry the machine and a source path.
    assert!(report.contains(&format!("Enrollment started on {}.", host("HOST-0005"))));
    for leak in ["HOST-0005", "CASE-0002", "A.evtx", "machine9", "record1"] {
        assert!(!leaks(&report, leak), "{leak} leaked:\n{report}");
    }
}

#[test]
fn a_reference_the_session_does_not_hold_is_refused_and_named_nowhere() {
    let (timeline, a, b) = two_event_timeline();
    let members = [a.clone(), b.clone()];
    let wrong_value = chains_value(
        1,
        (1, 0, 0, 0),
        vec![row(
            "exact",
            &members,
            json!([pair(
                &a,
                &b,
                &[("activityId", "00000000-0000-4000-8000-0000000000ff")]
            )]),
        )],
    );
    let wrong_kind = chains_value(
        1,
        (1, 0, 0, 0),
        vec![row(
            "exact",
            &members,
            json!([pair(&a, &b, &[("sessionId", GUID_A)])]),
        )],
    );
    let wrong_pair = chains_value(
        1,
        (1, 0, 0, 0),
        vec![row(
            "exact",
            &members,
            json!([pair(&a, &stable(3), &[("activityId", GUID_A)])]),
        )],
    );
    for chains in [wrong_value, wrong_kind, wrong_pair] {
        let error = chain_report_for(&timeline, chains).expect_err("refused");
        assert!(error.contains("does not hold"), "{error}");
        for name in ["HOST-0005", "CASE-0002", GUID_A, "ff"] {
            assert!(!error.contains(name), "{name} in {error}");
        }
    }
    // The pair may be written either way round.
    let reversed = chains_value(
        1,
        (1, 0, 0, 0),
        vec![row(
            "exact",
            &members,
            json!([pair(&b, &a, &[("activityId", GUID_A)])]),
        )],
    );
    assert!(chain_report_for(&timeline, reversed).is_ok());
}

#[test]
fn a_relation_the_engine_calls_ambiguous_or_blocked_is_never_a_chain_link() {
    let (a, b) = (stable(1), stable(2));
    let items = vec![chain_item(1, 76, 0, "m"), chain_item(2, 77, 9, "m")];
    let mut ambiguous = exact_edge(&a, &b, GUID_A);
    ambiguous.strength = TimelineCorrelationStrength::Ambiguous;
    let mut blocked = exact_edge(&a, &b, GUID_A);
    blocked.coverage.state = TimelineCorrelationCoverageState::Gap;
    for bad in [ambiguous, blocked] {
        let timeline = timeline_of(items.clone(), vec![bad]);
        let chains = chains_value(
            1,
            (0, 1, 0, 0),
            vec![row(
                "candidate",
                &[a.clone(), b.clone()],
                json!([pair(&a, &b, &[("activityId", GUID_A)])]),
            )],
        );
        let error = chain_report_for(&timeline, chains).expect_err("refused");
        assert!(error.contains("ambiguous or coverage blocked"), "{error}");
    }
}

#[test]
fn a_chain_is_never_stronger_than_the_edges_it_rests_on() {
    let (a, b) = (stable(1), stable(2));
    let items = vec![chain_item(1, 76, 0, "m"), chain_item(2, 77, 9, "m")];
    let members = [a.clone(), b.clone()];
    let candidate_edge = edge(
        &a,
        &b,
        TimelineCorrelationKeyKind::ActivityId,
        "activityId",
        GUID_A,
        TimelineCorrelationStrength::Candidate,
    );
    let secondary_edge = edge(
        &a,
        &b,
        TimelineCorrelationKeyKind::Secondary,
        "secondary",
        "pid-1",
        TimelineCorrelationStrength::Exact,
    );
    let weak = [
        (candidate_edge.clone(), ("activityId", GUID_A)),
        (secondary_edge.clone(), ("secondary", "pid-1")),
    ];
    for (weaker, key) in weak {
        let timeline = timeline_of(items.clone(), vec![weaker]);
        let exact = chains_value(
            1,
            (1, 0, 0, 0),
            vec![row("exact", &members, json!([pair(&a, &b, &[key])]))],
        );
        let error = chain_report_for(&timeline, exact).expect_err("refused");
        assert!(error.contains("does not label Exact"), "{error}");
    }
    // The same edges are fine under a Candidate row, which prints as Candidate.
    let timeline = timeline_of(items, vec![candidate_edge, secondary_edge]);
    let candidate = chains_value(
        2,
        (0, 1, 0, 0),
        vec![row(
            "candidate",
            &members,
            json!([pair(
                &a,
                &b,
                &[("activityId", GUID_A), ("secondary", "pid-1")]
            )]),
        )],
    );
    let report = chain_report_for(&timeline, candidate).expect("renders");
    assert!(report.contains("### Chain 1: Candidate, 2 entries"));
    assert!(!report.contains("### Chain 1: Exact"));
    assert!(report.contains("- Links rest on: ActivityId, secondary identifier"));
}

#[test]
fn identifier_values_follow_the_print_policy() {
    let (a, b, c) = (stable(1), stable(2), stable(3));
    let provider_value = format!("source30:C:\\Cases\\CASE-0002\\A.evtx|provider|HOST-0005|1|{b}");
    let timeline = timeline_of(
        vec![
            chain_item(1, 76, 0, "m"),
            chain_item(2, 77, 9, "m"),
            chain_item(3, 78, 20, "m"),
        ],
        vec![
            exact_edge(&a, &b, GUID_A),
            edge(
                &a,
                &b,
                TimelineCorrelationKeyKind::DeviceId,
                "deviceId",
                "DEVICE-0001",
                TimelineCorrelationStrength::Exact,
            ),
            edge(
                &a,
                &b,
                TimelineCorrelationKeyKind::UserId,
                "userId",
                "user_0001",
                TimelineCorrelationStrength::Exact,
            ),
            // A device value no redaction pattern recognizes (it starts with a parenthesis):
            // the projection leaves it as written, so only the report's own guard stops it.
            edge(
                &a,
                &b,
                TimelineCorrelationKeyKind::DeviceId,
                "deviceId",
                "(unpatterned-device)",
                TimelineCorrelationStrength::Exact,
            ),
            edge(
                &b,
                &c,
                TimelineCorrelationKeyKind::ProviderChannelEventRecord,
                "providerChannelEventRecord",
                &provider_value,
                TimelineCorrelationStrength::Exact,
            ),
            edge(
                &b,
                &c,
                TimelineCorrelationKeyKind::Secondary,
                "secondary",
                "HOST-0005|pid-9",
                TimelineCorrelationStrength::Candidate,
            ),
        ],
    );
    let chains = chains_value(
        6,
        (1, 1, 0, 0),
        vec![
            row(
                "exact",
                &[a.clone(), b.clone()],
                json!([pair(
                    &a,
                    &b,
                    &[
                        ("activityId", GUID_A),
                        ("deviceId", "DEVICE-0001"),
                        ("userId", "user_0001"),
                        ("deviceId", "(unpatterned-device)")
                    ]
                )]),
            ),
            row(
                "candidate",
                &[b.clone(), c.clone()],
                json!([pair(
                    &b,
                    &c,
                    &[
                        ("providerChannelEventRecord", provider_value.as_str()),
                        ("secondary", "HOST-0005|pid-9")
                    ]
                )]),
            ),
        ],
    );
    let report = chain_report_for(&timeline, chains).expect("renders");
    for leak in [
        "DEVICE-0001",
        "user_0001",
        "CASE-0002",
        "HOST-0005",
        "pid-9",
        "unpatterned-device",
    ] {
        assert!(!leaks(&report, leak), "{leak} leaked:\n{report}");
    }
    assert!(report.contains(&format!("ActivityId = {GUID_A}")));
    let values = |word: &str| -> Vec<String> {
        report
            .lines()
            .filter_map(|line| line.split(&format!(": {word} = ")).nth(1))
            .map(str::to_owned)
            .collect()
    };
    let is_token =
        |value: &String| value.starts_with('[') && value.ends_with(']') && value.len() > 18;
    // A person or device identifier is printed only as the token the projection made of it,
    // and a value the projection could not mask is not printed at all.
    let users = values("UserId");
    assert!(users.len() == 2 && users.iter().all(is_token), "{users:?}");
    let devices = values("DeviceId");
    assert!(devices.iter().any(is_token), "{devices:?}");
    assert!(devices.contains(&"(masked)".to_owned()), "{devices:?}");
    assert!(report.contains(": provider, channel and record (value not printed)"));
    assert!(report.contains(": secondary identifier (value not printed)"));
}

#[test]
fn the_ladder_says_what_the_chain_list_can_and_cannot_support() {
    let (timeline, a, b) = two_event_timeline();
    let members = [a.clone(), b.clone()];
    let one_row = || {
        row(
            "exact",
            &members,
            json!([pair(&a, &b, &[("activityId", GUID_A)])]),
        )
    };

    let complete =
        chain_report_for(&timeline, chains_value(1, (1, 0, 2, 3), vec![one_row()])).unwrap();
    assert!(complete.contains(
        "- Chains listed: 1 of 1 Exact or Candidate chains the app built (Exact 1, Candidate 0)."
    ));
    assert!(complete.contains("- Built from all 1 correlation edges of the events in scope."));
    assert!(complete.contains(
        "- Not listed as chains (counts only): 2 Ambiguous and 3 Coverage blocked relations."
    ));
    assert!(!complete.contains("may exist"));

    let empty = timeline_of(Vec::new(), Vec::new());
    let none = chain_report_for(&empty, chains_value(0, (0, 0, 0, 0), Vec::new())).unwrap();
    assert!(none.contains(
        "- The engine produced no Exact or Candidate link among the events in scope. Events \
         outside the scope were not considered."
    ));

    // Edges the app did not load: a shortfall is stated with both numbers, and an empty list
    // is not read as "no chains".
    let three_edges = timeline_of(
        Vec::new(),
        vec![
            exact_edge("x1", "x2", "v1"),
            exact_edge("x3", "x4", "v2"),
            exact_edge("x5", "x6", "v3"),
        ],
    );
    let short = chain_report_for(&three_edges, chains_value(1, (0, 0, 0, 0), Vec::new())).unwrap();
    assert!(short.contains(
        "- Built from 1 of 3 correlation edges (2 not loaded), so more chains may exist."
    ));
    assert!(short.contains(
        "- No Exact or Candidate chain is listed. The correlation input is incomplete, so \
         this does not show that none exist."
    ));
    assert!(!short.contains("The engine produced no Exact or Candidate link"));
    assert!(short.contains("(counts only, at least): 0 Ambiguous"));

    // The engine's own gaps make an empty list unprovable even when every edge was loaded.
    for gap in ["global", "previewCut"] {
        let mut chains = chains_value(0, (0, 0, 0, 0), Vec::new());
        chains["correlationGaps"][gap] = json!(true);
        let report = chain_report_for(&empty, chains).unwrap();
        assert!(report.contains("did not correlate every event"), "{gap}");
        assert!(!report.contains("The engine produced no Exact or Candidate link"));
        assert!(report.contains("(counts only, at least)"));
    }

    // The app and the session disagree about the edge count.
    let disagree = chain_report_for(&empty, chains_value(4, (0, 0, 0, 0), Vec::new())).unwrap();
    assert!(disagree.contains(
        "- The app reported 4 loaded correlation edges and the session holds 0, so this list \
         cannot be trusted as complete."
    ));

    // Fewer rows than chains: the rest are counted, and nothing says none exist.
    let capped =
        chain_report_for(&timeline, chains_value(1, (3, 0, 0, 0), vec![one_row()])).unwrap();
    assert!(capped.contains("- Chains listed: 1 of 3 Exact or Candidate chains"));
    assert!(capped.contains("The app lists at most 100 chains; 2 are not listed."));
}

#[test]
fn chains_that_were_not_loaded_are_never_reported_as_none() {
    let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
    let chains = section(&report, "## Correlation chains");
    assert!(chains.contains("Correlation chains were not loaded when this report was made."));
    assert!(chains.contains("that says nothing about whether any exist"));
    for claim in [
        "no Exact or Candidate",
        "Chains listed",
        "0 Exact",
        "Built from",
    ] {
        assert!(!chains.contains(claim), "{claim}");
    }
}

#[test]
fn members_and_evidence_are_capped_and_the_rest_counted() {
    let ids: Vec<String> = (1..=50).map(stable).collect();
    let items: Vec<TimelineItem> = (1..=50)
        .map(|record| chain_item(record, 100 + record as u32, record as i64, "m"))
        .collect();
    let edges: Vec<TimelineCorrelationEdge> = (0..5)
        .map(|index| exact_edge(&ids[index], &ids[index + 1], &format!("guid-{index}")))
        .collect();
    let pairs: Vec<serde_json::Value> = (0..5)
        .map(|index| {
            let value = format!("guid-{index}");
            pair(
                &ids[index],
                &ids[index + 1],
                &[("activityId", value.as_str())],
            )
        })
        .collect();
    let timeline = timeline_of(items, edges);
    let chains = chains_value(5, (1, 0, 0, 0), vec![row("exact", &ids, json!(pairs))]);
    let report = chain_report_for(&timeline, chains).expect("renders");
    assert!(report.contains("### Chain 1: Exact, 50 entries"));
    assert!(report.contains("- Link evidence (10 lines):"));
    assert!(report.contains("  - and 2 more evidence lines"));
    assert_eq!(report.matches("\n  - 10").count(), 8);
    assert_eq!(table_rows(section(&report, "## Correlation chains")), 12);
    assert!(report.contains("and 38 more listed entries on the timeline, not shown here"));
}

#[test]
fn entries_the_session_cannot_place_are_counted_and_never_listed() {
    let (mut timeline, a, b) = two_event_timeline();
    let placeless = stable(7);
    timeline.unplaced.push(UnplacedItem {
        origin: chain_item(7, 99, 0, "m").origin,
        reason: UnplacedReason::MissingTimestamp,
    });
    let missing = stable(8);
    let members = [a.clone(), placeless.clone(), missing.clone()];
    let chains = chains_value(
        1,
        (1, 0, 0, 0),
        vec![row(
            "exact",
            &members,
            json!([pair(&a, &b, &[("activityId", GUID_A)])]),
        )],
    );
    let report = chain_report_for(&timeline, chains).expect("renders");
    assert!(report.contains(
        "- Entries: 3 in the chain; the app listed 3. Of those listed, 1 are on the placed \
         timeline, 1 have no usable timestamp and 1 are not in this session."
    ));
    assert_eq!(table_rows(section(&report, "## Correlation chains")), 1);
}

#[test]
fn a_text_log_member_is_named_by_its_file_and_line_only() {
    let (mut timeline, a, _) = two_event_timeline();
    let log_origin = TimelineOrigin::Log {
        file: r"C:\Cases\CASE-0002\Logs\IntuneManagementExtension.log".to_owned(),
        component: Some("Sync".to_owned()),
        line: 12,
        source: "IntuneManagementExtension.log".to_owned(),
        machine: Some("HOST-0005".to_owned()),
        bundle: None,
        record_id: 12,
    };
    let log_id = origin_id(&log_origin);
    timeline.items.push(TimelineItem {
        timestamp_ms: FIXTURE_NOW_MS + 3000,
        severity: TimelineSeverity::Warning,
        message: "Policy sync retried on HOST-0005.".to_owned(),
        origin: log_origin,
    });
    timeline.edges.push(exact_edge(
        &a,
        &log_id,
        "00000000-0000-4000-8000-0000000000b2",
    ));
    let chains = chains_value(
        2,
        (1, 0, 0, 0),
        vec![row(
            "exact",
            &[a.clone(), log_id.clone()],
            json!([pair(
                &a,
                &log_id,
                &[("activityId", "00000000-0000-4000-8000-0000000000b2")]
            )]),
        )],
    );
    let report = chain_report_for(&timeline, chains).expect("renders");
    assert!(report.contains("| log line 12 | IntuneManagementExtension.log | Sync |"));
    assert!(report.contains("IntuneManagementExtension.log \u{b7} line 12: ActivityId ="));
    for leak in ["CASE-0002", "HOST-0005", "Logs\\"] {
        assert!(!leaks(&report, leak), "{leak} leaked:\n{report}");
    }
}

#[test]
fn nearby_context_is_stated_as_not_produced_and_never_as_none() {
    let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
    let nearby = section(&report, "## Nearby, not linked");
    assert_eq!(
        nearby.trim_end(),
        "## Nearby, not linked\n\nNearby context is not produced in this version of the \
         report. This section says nothing about whether nearby events exist, and nothing in \
         this report links two entries by time alone."
    );
    let lower = nearby.to_lowercase();
    for forbidden in ["none", "no nearby", "empty", "0 "] {
        assert!(!lower.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn chain_references_are_bounded_before_any_work_is_done() {
    let (_, a, b) = two_event_timeline();
    let ok_row = || {
        row(
            "exact",
            &[a.clone(), b.clone()],
            json!([pair(&a, &b, &[("activityId", GUID_A)])]),
        )
    };
    let cases: Vec<(&str, serde_json::Value)> = vec![
        (
            "too many chain rows",
            chains_value(
                1,
                (200, 0, 0, 0),
                (0..=REPORT_CHAIN_ROW_CAP).map(|_| ok_row()).collect(),
            ),
        ),
        (
            "more rows than chains counted",
            chains_value(1, (0, 0, 0, 0), vec![ok_row()]),
        ),
        ("too many references", {
            let ids: Vec<String> = (0..51).map(|index| format!("id-{index}")).collect();
            chains_value(1, (1, 0, 0, 0), vec![row("exact", &ids, json!([]))])
        }),
        ("lists more members than it has", {
            let mut value = ok_row();
            value["memberCount"] = json!(1);
            chains_value(1, (1, 0, 0, 0), vec![value])
        }),
        ("a pair is impossible", {
            chains_value(
                1,
                (1, 0, 0, 0),
                vec![row(
                    "exact",
                    &[a.clone(), b.clone()],
                    json!([pair(&a, &a, &[("activityId", GUID_A)])]),
                )],
            )
        }),
        ("a pair is impossible", {
            chains_value(
                1,
                (1, 0, 0, 0),
                vec![row(
                    "exact",
                    &[a.clone(), b.clone()],
                    json!([pair(&a, &b, &[])]),
                )],
            )
        }),
        ("an identifier is too long", {
            let long = "x".repeat(2049);
            chains_value(
                1,
                (1, 0, 0, 0),
                vec![row("exact", &[long.clone(), b.clone()], json!([]))],
            )
        }),
    ];
    for (expected, chains) in cases {
        let mut value = request_json();
        value["chains"] = chains;
        let error = request_from(value).validate().expect_err(expected);
        assert!(error.contains(expected), "{expected}: {error}");
    }
    // A row may not claim a strength the type does not have.
    let mut value = request_json();
    value["chains"] = chains_value(1, (1, 0, 0, 0), vec![row("ambiguous", &[], json!([]))]);
    assert!(serde_json::from_value::<EventLogAnalysisReportRequest>(value).is_err());
}

#[test]
fn tokens_the_projection_wrote_are_not_rewritten_by_the_export_pass() {
    // The export pass reads `[account:` as a key named Account and masks what follows it, so
    // running it over projected text would turn the token into `[account:[sensitive:..]]`.
    let mut one = finding(
        "a",
        FindingClass::Symptom,
        FindingSeverity::Info,
        FindingConfidence::Low,
        "Sign-in",
    );
    one.summary = "UserName=jdoe-0001 was rejected".to_owned();
    let summary = summary_of(vec![one], Vec::new());
    let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
    let line = report
        .lines()
        .find(|line| line.starts_with("- Summary: "))
        .unwrap();
    assert!(!line.contains("jdoe-0001"), "{line}");
    assert!(!line.contains("sensitive"), "{line}");
    // The account rule takes the rest of the line as the value, so the token covers it all.
    assert_eq!(
        *line,
        format!(
            "- Summary: UserName={}",
            redact_field_value("account", "jdoe-0001 was rejected")
        )
    );
}

#[test]
fn a_gap_the_engine_lists_once_per_event_is_written_once_with_its_count() {
    let same = |detail: &str| gap("MDM enrollment", CoverageState::Absent, detail);
    let mut gaps: Vec<CoverageGap> = (0..3)
        .map(|index| {
            let mut one = same("No status.");
            one.id = format!("coverage:{index}");
            one
        })
        .collect();
    gaps.push(same("A different detail."));
    let report = render_with(
        &base_request(),
        &snapshot_of(Vec::new(), 0),
        &summary_of(Vec::new(), gaps),
    );
    assert!(report.contains("- Coverage gaps the engine listed (4):"));
    assert!(report.contains("  - absent: MDM enrollment: No status. (3 gaps)\n"));
    assert!(report.contains("  - absent: MDM enrollment: A different detail.\n"));
}

#[test]
fn collect_gathers_the_rows_machines_unplaced_split_and_the_engines_compaction_notes() {
    let mut timeline = timeline_of(
        (0..600)
            .map(|index| chain_item(index + 1, 100, index as i64, "m"))
            .collect(),
        Vec::new(),
    );
    let log_origin = TimelineOrigin::Log {
        file: "a.log".to_owned(),
        component: None,
        line: 1,
        source: "a.log".to_owned(),
        machine: Some("HOST-0006".to_owned()),
        bundle: None,
        record_id: 1,
    };
    timeline.items.push(TimelineItem {
        timestamp_ms: FIXTURE_NOW_MS,
        severity: TimelineSeverity::Info,
        message: "log line".to_owned(),
        origin: log_origin.clone(),
    });
    for origin in [chain_item(900, 1, 0, "m").origin, log_origin] {
        timeline.unplaced.push(UnplacedItem {
            origin,
            reason: UnplacedReason::MissingTimestamp,
        });
    }
    for source in [
        "timeline-message-projection",
        "timeline-item-projection",
        "timeline-transport-projection",
    ] {
        timeline.coverage_gaps.push(TimelineCoverageGap {
            source: source.to_owned(),
            reason: "counts only".to_owned(),
        });
    }
    let snapshot = collect(&timeline, status(600, 1), &base_request()).expect("collects");
    assert_eq!(snapshot.event_rows.len(), REPORT_EVENT_ROW_CAP);
    assert!(snapshot
        .event_rows
        .iter()
        .all(|item| matches!(item.origin, TimelineOrigin::Event { .. })));
    assert_eq!(snapshot.unplaced_events, 1);
    assert_eq!(snapshot.unplaced_text_lines, 1);
    assert_eq!(
        snapshot
            .machines
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["HOST-0005", "HOST-0006"]
    );
    assert!(snapshot.span_ms.is_some());
    assert_eq!(
        snapshot.engine_notes,
        EngineNotes {
            messages_shortened: true,
            items_compacted: true,
            transport_projected: true,
        }
    );

    timeline.coverage_gaps.clear();
    let clean = collect(&timeline, status(600, 1), &base_request()).expect("collects");
    assert_eq!(clean.engine_notes, EngineNotes::default());
    assert!(clean.entries.is_empty() && clean.chains.is_empty());
}
