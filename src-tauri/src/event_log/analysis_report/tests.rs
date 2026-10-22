use super::safe::{
    cut_chars, escape, flatten, strip_invisible, strip_summary, token_len_at, Doc, Projected,
    Redactor, Safe,
};
use super::{collect, REPORT_CHAIN_ROW_CAP};
use super::{
    render_report, render_report_within, EngineNotes, EventLogAnalysisReportRequest, ReportInput,
    ReportSnapshot, MAX_REPORT_BYTES, REPORT_EVENT_ROW_CAP,
};
use crate::event_log::analysis_session::EventLogAnalysisSessionStatus;
use cmtraceopen_parser::diagnosis::{
    adapt_timeline_edge, CoverageGap, CoverageState, DiagnosisFinding, DiagnosisSummary,
    ErrorToken, EventDiagnosis, EventEvidenceRef, EventFamily, EvidenceRef, FindingClass,
    FindingConfidence, FindingSeverity, TextLogEvidenceRef,
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

/// One character from every class of the invisible set. The endpoints of both variation selector
/// ranges are here, so a range that is one short at either end is caught.
const INVISIBLE_SAMPLES: [(&str, char); 26] = [
    ("zero width space", '\u{200b}'),
    ("zero width non-joiner", '\u{200c}'),
    ("zero width joiner", '\u{200d}'),
    ("word joiner", '\u{2060}'),
    ("byte order mark", '\u{feff}'),
    ("soft hyphen", '\u{ad}'),
    ("right-to-left override", '\u{202e}'),
    ("left-to-right isolate", '\u{2066}'),
    ("arabic letter mark", '\u{61c}'),
    ("arabic number sign", '\u{600}'),
    ("mongolian vowel separator", '\u{180e}'),
    ("tag latin small letter a", '\u{e0061}'),
    ("combining grapheme joiner", '\u{34f}'),
    ("hangul choseong filler", '\u{115f}'),
    ("hangul jungseong filler", '\u{1160}'),
    ("hangul filler", '\u{3164}'),
    ("halfwidth hangul filler", '\u{ffa0}'),
    ("variation selector 1", '\u{fe00}'),
    ("variation selector 16", '\u{fe0f}'),
    ("variation selector 17", '\u{e0100}'),
    ("variation selector 256", '\u{e01ef}'),
    ("khmer vowel inherent aq", '\u{17b4}'),
    ("khmer vowel inherent aa", '\u{17b5}'),
    ("mongolian free variation selector one", '\u{180b}'),
    ("mongolian free variation selector three", '\u{180d}'),
    ("mongolian free variation selector four", '\u{180f}'),
];

#[test]
fn flatten_keeps_deleting_every_invisible_class_as_a_guard() {
    for (name, mark) in INVISIBLE_SAMPLES {
        assert_eq!(flatten(&format!("a{mark}b")), "ab", "{name}");
    }
}

#[test]
fn stripping_removes_each_invisible_class_and_leaves_ordinary_text() {
    for (name, mark) in INVISIBLE_SAMPLES {
        assert_eq!(strip_invisible(&format!("a{mark}b")), "ab", "{name}");
    }
    // Whitespace, control characters and ordinary punctuation are not invisible characters.
    let visible = "a b\tc\nd-e_f.g:h/i\\j\u{a0}k\u{e9}\u{4e2d}";
    assert_eq!(strip_invisible(visible), visible);
}

/// A summary with a marked string in every string field the report could read, and every other
/// kind of value a summary holds.
fn marked_summary(mark: &str) -> DiagnosisSummary {
    let marked = |name: &str| format!("{name}{mark}x");
    let event = || {
        EvidenceRef::Event(EventEvidenceRef {
            source: marked("source"),
            provider: marked("provider"),
            event_id: 7,
            record_id: 8,
            record_id_text: Some(marked("record")),
            fallback_identity: Some(marked("fallback")),
            machine: Some(marked("machine")),
            channel: Some(marked("channel")),
            activity_id: Some(marked("activity")),
        })
    };
    let text_log = || {
        EvidenceRef::TextLog(TextLogEvidenceRef {
            source: marked("log"),
            file_path: marked("path"),
            line_number: 9,
            entry_id: 10,
        })
    };
    let mut one = finding(
        &marked("id"),
        FindingClass::ConfirmedFailure,
        FindingSeverity::Error,
        FindingConfidence::High,
        &marked("title"),
    );
    one.summary = marked("summary");
    one.evidence = vec![event(), text_log(), EvidenceRef::DsregcmdRaw(marked("raw"))];
    one.recommended_checks = vec![marked("check one"), marked("check two")];
    one.coverage_gaps = vec![gap(
        &marked("nested source"),
        CoverageState::Capped,
        &marked("nested detail"),
    )];
    let mut top_gap = gap(
        &marked("gap source"),
        CoverageState::AccessDenied,
        &marked("gap detail"),
    );
    top_gap.evidence = vec![event()];
    let mut summary = summary_of(vec![one.clone()], vec![top_gap]);
    summary.evidence = vec![event(), text_log()];
    summary.correlations = vec![adapt_timeline_edge(&exact_edge(
        &marked("left"),
        &marked("right"),
        &marked("value"),
    ))];
    summary.events = vec![EventDiagnosis {
        evidence: vec![event()],
        family: EventFamily::Other,
        findings: vec![one],
        error_tokens: vec![ErrorToken {
            raw: marked("0x80070005"),
            decimal: Some(2_147_942_405),
            hex: Some(marked("0x80070005")),
            malformed: false,
            found: true,
            description: Some(marked("description")),
            category: Some(marked("category")),
        }],
    }];
    summary.overview.outcome = marked("outcome");
    summary.overview.headline = marked("headline");
    summary
}

#[test]
fn stripping_a_summary_removes_the_characters_from_every_string_and_changes_nothing_else() {
    let clean = marked_summary("");
    // The control: with nothing to remove, the copy is the summary.
    assert_eq!(strip_summary(&clean).expect("strips"), clean);
    for (name, mark) in INVISIBLE_SAMPLES {
        let stripped = strip_summary(&marked_summary(&mark.to_string())).expect("strips");
        assert_eq!(stripped, clean, "{name}");
    }
}

#[test]
fn an_invisible_character_cannot_hide_an_identifier_from_the_text_redaction() {
    // The character sits inside the machine name and inside the SID. The comparison is with the
    // same text without it, which is itself redacted: a leak that both texts shared would not
    // make them differ, so the control is checked first.
    let r = redactor(&["HOST-0002"]);
    let with = |mark: &str| {
        format!(
            "Sync with HOST{mark}-0002 failed for \
             S-1-5-21-1000000001-1000000002-1000000003-{mark}1001 today"
        )
    };
    let clean = r.text(&with(""), 240);
    assert!(clean.as_str().contains(&host("HOST-0002")), "{clean:?}");
    assert!(clean.as_str().contains("[sid:"), "{clean:?}");
    assert!(!clean.as_str().contains("1000000001"), "{clean:?}");
    for (name, mark) in INVISIBLE_SAMPLES {
        assert_eq!(r.text(&with(&mark.to_string()), 240), clean, "{name}");
    }
}

#[test]
fn an_invisible_character_in_an_event_row_cannot_hide_an_identifier_from_the_report() {
    // The same text through the events table, where the message and the channel cell are
    // session text: the whole report is the clean report, and the clean report is redacted.
    let report_with = |mark: &str| {
        let item = event_item(
            FIXTURE_NOW_MS,
            TimelineSeverity::Error,
            1001,
            &format!("Microsoft-Windows-Fixture/HOST{mark}-0002"),
            "Fixture.Provider",
            Some("HOST-0002"),
            1,
            &format!(
                "Sync with HOST{mark}-0002 failed for \
                 S-1-5-21-1000000001-1000000002-1000000003-{mark}1001"
            ),
        );
        render(&base_request(), &snapshot_of(vec![item], 1))
    };
    let clean = report_with("");
    assert!(!leaks(&clean, "HOST-0002"), "{clean}");
    assert!(!clean.contains("1000000001"), "{clean}");
    assert!(clean.contains("[sid:"), "{clean}");
    // The machine's token is in the channel cell and in the message, besides the header.
    assert_eq!(clean.matches(&host("HOST-0002")).count(), 3, "{clean}");
    for (name, mark) in INVISIBLE_SAMPLES {
        assert_eq!(report_with(&mark.to_string()), clean, "{name}");
    }
}

#[test]
fn an_invisible_character_cannot_hide_an_identifier_from_the_diagnosis_projection() {
    // HOST-0007 is named only by the evidence's machine field, so only the projection knows it:
    // the report's own machine list is empty. The character is also inside that field.
    let report_with = |mark: &str| {
        let mut one = finding(
            "a",
            FindingClass::Symptom,
            FindingSeverity::Info,
            FindingConfidence::Low,
            "Sign-in",
        );
        one.summary = format!(
            "Sync with HOST{mark}-0007 failed for \
             S-1-5-21-1000000001-1000000002-1000000003-{mark}1001"
        );
        one.evidence = vec![EvidenceRef::Event(EventEvidenceRef {
            source: "s".to_owned(),
            provider: format!("Vendor.HOST{mark}-0007.Provider"),
            event_id: 1,
            record_id: 1,
            record_id_text: Some("1".to_owned()),
            fallback_identity: None,
            machine: Some(format!("HOST{mark}-0007")),
            channel: None,
            activity_id: None,
        })];
        render_with(
            &base_request(),
            &snapshot_of(Vec::new(), 0),
            &summary_of(vec![one], Vec::new()),
        )
    };
    let clean = report_with("");
    assert!(!leaks(&clean, "HOST-0007"), "{clean}");
    assert_eq!(clean.matches(&host("HOST-0007")).count(), 2, "{clean}");
    assert!(clean.contains("[sid:"), "{clean}");
    assert!(!clean.contains("1000000001"), "{clean}");
    for (name, mark) in INVISIBLE_SAMPLES {
        assert_eq!(report_with(&mark.to_string()), clean, "{name}");
    }
}

#[test]
fn a_machine_name_that_carries_an_invisible_character_is_known_by_what_it_reads_as() {
    let marked = "HOST\u{200b}-0003";
    let r = redactor(&[marked]);
    assert_eq!(r.skipped_short(), 0);
    assert_eq!(
        r.text("see HOST-0003 now", 240).as_str(),
        format!("see {} now", host("HOST-0003"))
    );
    // The header and the text carry one token for it, the token of the name as it reads.
    assert_eq!(r.machine(marked).as_str(), host("HOST-0003"));
    let item = event_item(
        FIXTURE_NOW_MS,
        TimelineSeverity::Info,
        1,
        "Application",
        "P",
        Some(marked),
        1,
        "m",
    );
    let report = render(&base_request(), &snapshot_of(vec![item], 1));
    assert!(
        report.contains(&format!("- Machines (1): {}\n", host("HOST-0003"))),
        "{report}"
    );
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
        "remoteMachine": null,
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
        holds_link: false,
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
fn projected_text_is_sliced_by_characters_and_by_path_segment() {
    let mut summary = DiagnosisSummary::default();
    summary.overview.headline = "\u{e9}\u{e9}\u{e9}\u{4e2d}x".to_owned();
    let projected = Projected::new(summary).expect("projects");
    let headline = projected.root().text(|summary| &summary.overview.headline);
    assert_eq!(headline.first_chars(3).as_str(), "\u{e9}\u{e9}\u{e9}");
    assert_eq!(
        headline.first_chars(4).as_str(),
        "\u{e9}\u{e9}\u{e9}\u{4e2d}"
    );
    assert_eq!(headline.first_chars(5).as_str(), headline.as_str());
    assert_eq!(headline.first_chars(0).as_str(), "");
    assert_eq!(headline.as_str(), "\u{e9}\u{e9}\u{e9}\u{4e2d}x");

    let mut summary = DiagnosisSummary::default();
    summary.overview.headline = r"C:\Cases/CASE-0001\Sync.log".to_owned();
    let projected = Projected::new(summary).expect("projects");
    let path = projected.root().text(|summary| &summary.overview.headline);
    assert_eq!(path.file_name().as_str(), "Sync.log");
}

#[test]
fn a_path_is_reduced_to_its_last_segment_whichever_separator_it_uses() {
    for path in [
        r"C:\Cases\CASE-0001\Logs\Sync.log",
        "/home/case0001/Logs/Sync.log",
        "C:/Cases/CASE-0001/Sync.log",
        r"C:\Cases/CASE-0001\Sync.log",
        "Sync.log",
    ] {
        // A text-log evidence reference reaches the report through the projected summary.
        let mut one = finding(
            "a",
            FindingClass::Symptom,
            FindingSeverity::Info,
            FindingConfidence::Low,
            "Sync",
        );
        one.evidence = vec![EvidenceRef::TextLog(TextLogEvidenceRef {
            source: "x".to_owned(),
            file_path: path.to_owned(),
            line_number: 42,
            entry_id: 1,
        })];
        let report = render_with(
            &base_request(),
            &snapshot_of(Vec::new(), 0),
            &summary_of(vec![one], Vec::new()),
        );
        assert!(
            report.contains("- Evidence: Sync.log \u{b7} line 42\n"),
            "{path}\n{report}"
        );
        // A text-log line in the events table reaches it as session text.
        let origin = TimelineOrigin::Log {
            file: path.to_owned(),
            component: None,
            line: 12,
            source: "Sync.log".to_owned(),
            machine: None,
            bundle: None,
            record_id: 12,
        };
        let item = TimelineItem {
            timestamp_ms: FIXTURE_NOW_MS,
            severity: TimelineSeverity::Info,
            message: "m".to_owned(),
            origin,
        };
        let report = render(&base_request(), &snapshot_of(vec![item], 1));
        assert!(
            report.contains("| log line 12 | Sync.log |  | m |"),
            "{path}\n{report}"
        );
        assert!(
            !leaks(&report, "CASE-0001") && !leaks(&report, "case0001"),
            "{path}"
        );
    }
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
    // The snapshot is what `collect` makes of the timeline, as the command makes it.
    let mut session = status(timeline.items.len() as u64, 0);
    session.total_edges = timeline.edges.len() as u64;
    let snapshot = collect(timeline, session, &request)?;
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
fn a_user_id_that_is_a_sid_is_a_token_or_masked_and_never_raw() {
    // The timeline reads a record's user_sid as its user id when it has none, so a relation can
    // rest on a userId whose value is a SID. Its line is a token or "(masked)", never the SID.
    let sid = "S-1-5-21-1000000001-1000000002-1000000003-1002";
    let (a, b) = (stable(1), stable(2));
    let timeline = timeline_of(
        vec![chain_item(1, 76, 0, "m"), chain_item(2, 77, 9, "m")],
        vec![edge(
            &a,
            &b,
            TimelineCorrelationKeyKind::UserId,
            "userId",
            sid,
            TimelineCorrelationStrength::Exact,
        )],
    );
    let chains = chains_value(
        1,
        (1, 0, 0, 0),
        vec![row(
            "exact",
            &[a.clone(), b.clone()],
            json!([pair(&a, &b, &[("userId", sid)])]),
        )],
    );
    let report = chain_report_for(&timeline, chains).expect("renders");
    let values: Vec<&str> = report
        .lines()
        .filter_map(|line| line.split(": UserId = ").nth(1))
        .collect();
    assert_eq!(values.len(), 2, "one line for each entry: {report}");
    for value in values {
        let token = value.starts_with("[sid:") && value.ends_with(']') && value.len() == 22;
        assert!(token || value == "(masked)", "{value}");
    }
    assert!(!leaks(&report, sid) && !leaks(&report, "1000000003-1002"));
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
    // is not read as "no chains". The three relations are ambiguous, so none is a link.
    let ambiguous = |from: &str, to: &str, value: &str| {
        let mut one = exact_edge(from, to, value);
        one.strength = TimelineCorrelationStrength::Ambiguous;
        one
    };
    let three_edges = timeline_of(
        Vec::new(),
        vec![
            ambiguous("x1", "x2", "v1"),
            ambiguous("x3", "x4", "v2"),
            ambiguous("x5", "x6", "v3"),
        ],
    );
    let short = chain_report_for(&three_edges, chains_value(1, (0, 0, 1, 0), Vec::new())).unwrap();
    assert!(short.contains(
        "- Built from 1 of 3 correlation edges (2 not loaded), so more chains may exist."
    ));
    assert!(short.contains(
        "- No Exact or Candidate chain is listed. The correlation input is incomplete, so \
         this does not show that none exist."
    ));
    assert!(!short.contains("The engine produced no Exact or Candidate link"));
    assert!(short.contains("(counts only, at least): 1 Ambiguous"));

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

const NO_LINK_SENTENCE: &str = "The engine produced no Exact or Candidate link";

#[test]
fn counts_of_none_are_refused_when_the_app_says_it_loaded_every_edge_and_the_session_holds_a_link()
{
    // The app says it read every edge and its counts say there is no chain, while the session's
    // own edges say there is a link. The app's model is stale, so the report would be saying
    // what the engine did not.
    let (a, b) = (stable(1), stable(2));
    let items = vec![chain_item(1, 76, 0, "m"), chain_item(2, 77, 9, "m")];
    let covered = |strength: TimelineCorrelationStrength| {
        edge(
            &a,
            &b,
            TimelineCorrelationKeyKind::ActivityId,
            "activityId",
            GUID_A,
            strength,
        )
    };
    for (name, strength) in [
        ("an Exact link", TimelineCorrelationStrength::Exact),
        ("a Candidate link", TimelineCorrelationStrength::Candidate),
    ] {
        let timeline = timeline_of(items.clone(), vec![covered(strength)]);
        // Every edge loaded (1 of 1), with and without the engine's own correlation gaps.
        for gap in [None, Some("global"), Some("previewCut")] {
            let mut chains = chains_value(1, (0, 0, 0, 0), Vec::new());
            if let Some(gap) = gap {
                chains["correlationGaps"][gap] = json!(true);
            }
            let error = chain_report_for(&timeline, chains).expect_err(name);
            assert_links_mismatch(&error, name);
            for leaked in ["HOST-0005", "CASE-0002", "machine9", GUID_A] {
                assert!(!error.contains(leaked), "{name}: {leaked} in {error}");
            }
        }
        // A chain listed for it is not a contradiction.
        let strength_word = if name.contains("Exact") {
            "exact"
        } else {
            "candidate"
        };
        let counts = if strength_word == "exact" {
            (1, 0, 0, 0)
        } else {
            (0, 1, 0, 0)
        };
        let listed = row(
            strength_word,
            &[a.clone(), b.clone()],
            json!([pair(&a, &b, &[("activityId", GUID_A)])]),
        );
        let report = chain_report_for(&timeline, chains_value(1, counts, vec![listed]))
            .expect("a listed chain renders");
        assert!(!report.contains(NO_LINK_SENTENCE), "{report}");
    }
}

#[test]
fn a_partial_edge_load_renders_with_at_least_wording_and_never_says_no_link() {
    // The app loaded fewer edges than the session holds, so its counts of none are true of what
    // it read. The report says so, and never says the engine produced no link.
    let (a, b) = (stable(1), stable(2));
    let items = vec![chain_item(1, 76, 0, "m"), chain_item(2, 77, 9, "m")];
    for strength in [
        TimelineCorrelationStrength::Exact,
        TimelineCorrelationStrength::Candidate,
    ] {
        let linked = edge(
            &a,
            &b,
            TimelineCorrelationKeyKind::ActivityId,
            "activityId",
            GUID_A,
            strength,
        );
        let timeline = timeline_of(items.clone(), vec![linked]);
        let report = chain_report_for(&timeline, chains_value(0, (0, 0, 0, 0), Vec::new()))
            .expect("a partial load is not a stale model");
        let chains = section(&report, "## Correlation chains");
        assert!(
            chains.contains(
                "- Built from 0 of 1 correlation edges (1 not loaded), so more chains may exist."
            ),
            "{chains}"
        );
        assert!(
            chains.contains(
                "- No Exact or Candidate chain is listed. The correlation input is incomplete, \
                 so this does not show that none exist."
            ),
            "{chains}"
        );
        assert!(chains.contains("(counts only, at least)"), "{chains}");
        assert!(!report.contains(NO_LINK_SENTENCE), "{report}");
    }
    // More edges loaded than the session holds is not a complete load either.
    let timeline = timeline_of(items, vec![exact_edge(&a, &b, GUID_A)]);
    let report = chain_report_for(&timeline, chains_value(2, (0, 0, 0, 0), Vec::new()))
        .expect("a load that disagrees with the session is not a stale model either");
    assert!(report.contains("so this list cannot be trusted as complete."));
    assert!(!report.contains(NO_LINK_SENTENCE), "{report}");
}

#[test]
fn what_the_engine_does_not_call_a_link_does_not_make_counts_of_none_stale() {
    let (a, b) = (stable(1), stable(2));
    let items = vec![chain_item(1, 76, 0, "m"), chain_item(2, 77, 9, "m")];
    let mut ambiguous = exact_edge(&a, &b, GUID_A);
    ambiguous.strength = TimelineCorrelationStrength::Ambiguous;
    let mut blocked = exact_edge(&a, &b, GUID_A);
    blocked.coverage.state = TimelineCorrelationCoverageState::Gap;
    let mut unresolved = exact_edge(&a, &b, GUID_A);
    unresolved.to_id = None;
    for (name, not_a_link) in [
        ("an Ambiguous relation", ambiguous),
        ("a Coverage blocked relation", blocked),
        ("an edge that ends nowhere", unresolved),
    ] {
        let timeline = timeline_of(items.clone(), vec![not_a_link]);
        let report = chain_report_for(&timeline, chains_value(1, (0, 0, 1, 0), Vec::new()))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(report.contains(NO_LINK_SENTENCE), "{name}\n{report}");
    }
}

#[test]
fn collect_records_whether_the_session_holds_a_link() {
    let (a, b) = (stable(1), stable(2));
    let items = vec![chain_item(1, 76, 0, "m"), chain_item(2, 77, 9, "m")];
    let request = base_request();
    let holds = |edges: Vec<TimelineCorrelationEdge>| {
        collect(&timeline_of(items.clone(), edges), status(2, 0), &request)
            .expect("collects")
            .holds_link
    };
    assert!(!holds(Vec::new()));
    assert!(holds(vec![exact_edge(&a, &b, GUID_A)]));
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

/// A chain of `count` entries, each tied to the next by an edge of its own.
fn chain_of(count: u64) -> (UnifiedTimeline, Vec<String>, Vec<serde_json::Value>) {
    let ids: Vec<String> = (1..=count).map(stable).collect();
    let items: Vec<TimelineItem> = (1..=count)
        .map(|record| chain_item(record, 100 + record as u32, record as i64, "m"))
        .collect();
    let links = ids.len() - 1;
    let edges: Vec<TimelineCorrelationEdge> = (0..links)
        .map(|index| exact_edge(&ids[index], &ids[index + 1], &format!("guid-{index}")))
        .collect();
    let pairs: Vec<serde_json::Value> = (0..links)
        .map(|index| {
            let value = format!("guid-{index}");
            pair(
                &ids[index],
                &ids[index + 1],
                &[("activityId", value.as_str())],
            )
        })
        .collect();
    (timeline_of(items, edges), ids, pairs)
}

/// What a chain row that does not match the session's links is refused with. It is not the
/// message of a stale revision or a missing session, which asks for the report to be run again.
const LINKS_MISMATCH: &str =
    "The report request does not match this analysis session's links, so no report was written.";

fn assert_links_mismatch(error: &str, context: &str) {
    assert_eq!(error, LINKS_MISMATCH, "{context}");
    assert!(
        !error.contains("Run the report again"),
        "{context}: {error}"
    );
}

#[test]
fn a_capped_chain_lists_only_confirmed_members_and_attributes_the_full_count() {
    // The app sends 50 members and a spanning set of 49 pairs, and says the chain has 80.
    let (timeline, ids, pairs) = chain_of(50);
    let mut capped = row("exact", &ids, json!(pairs));
    capped["memberCount"] = json!(80);
    let report =
        chain_report_for(&timeline, chains_value(49, (1, 0, 0, 0), vec![capped])).expect("renders");
    let chains = section(&report, "## Correlation chains");
    // The heading counts the entries the session confirmed. The model's own count is its own.
    assert!(
        chains.contains("### Chain 1: Exact, 50 entries\n"),
        "{chains}"
    );
    assert!(
        chains.contains(
            "### Chain 1: Exact, 50 entries\n\nThe chain model counts 80 entries in all; 30 are \
             not listed.\n"
        ),
        "{chains}"
    );
    assert!(chains.contains(
        "- Entries listed: 50. Of those, 50 are on the placed timeline, 0 have no usable \
         timestamp and 0 are not in this session."
    ));
    assert!(chains.contains("- Link evidence (98 lines):"));
    assert!(chains.contains("  - and 90 more evidence lines"));
    assert_eq!(table_rows(chains), 12);
    assert!(chains.contains("and 38 more listed entries on the timeline, not shown here"));

    // Without a shortfall there is nothing to attribute.
    let (timeline, ids, pairs) = chain_of(50);
    let whole = row("exact", &ids, json!(pairs));
    let report =
        chain_report_for(&timeline, chains_value(49, (1, 0, 0, 0), vec![whole])).expect("renders");
    assert!(report.contains("### Chain 1: Exact, 50 entries\n"));
    assert!(!report.contains("The chain model counts"), "{report}");
}

#[test]
fn a_chain_row_without_a_pair_confirms_nothing_and_is_refused() {
    let (timeline, a, b) = two_event_timeline();
    // A row that lists members but no pair, and a row that lists nothing at all: neither
    // confirms a chain, so neither is printed as one.
    for members in [vec![a, b], Vec::new()] {
        let chains = chains_value(1, (1, 0, 0, 0), vec![row("exact", &members, json!([]))]);
        let error = chain_report_for(&timeline, chains).expect_err("refused");
        assert_links_mismatch(&error, "a row without a pair");
        for name in ["HOST-0005", "CASE-0002", "machine9", GUID_A] {
            assert!(!error.contains(name), "{name} in {error}");
        }
    }
}

#[test]
fn a_row_whose_pairs_do_not_connect_is_refused() {
    // Two unrelated links the session does hold, (a, b) and (c, d), merged into one row: every
    // pair and every member is confirmed, but the row would print one chain of four entries,
    // which implies a link between a and c that the engine never produced.
    let (mut timeline, a, b) = two_event_timeline();
    let (c, d) = (stable(3), stable(4));
    timeline.items.push(chain_item(3, 78, 20, "m"));
    timeline.items.push(chain_item(4, 79, 30, "m"));
    timeline
        .edges
        .push(exact_edge(&c, &d, "00000000-0000-4000-8000-0000000000c4"));
    let pairs = json!([
        pair(&a, &b, &[("activityId", GUID_A)]),
        pair(
            &c,
            &d,
            &[("activityId", "00000000-0000-4000-8000-0000000000c4")]
        ),
    ]);
    let members = vec![a.clone(), b.clone(), c.clone(), d.clone()];
    let chains = chains_value(1, (1, 0, 0, 0), vec![row("exact", &members, pairs)]);
    let error = chain_report_for(&timeline, chains).expect_err("refused");
    assert_links_mismatch(&error, "a row of two separate chains");
}

#[test]
fn a_member_no_pair_of_its_row_touches_is_refused() {
    // The session holds the entry. The row names it as a member, but none of the row's pairs
    // ends at it, so nothing confirms it belongs to this chain.
    let (mut timeline, a, b) = two_event_timeline();
    let (c, d) = (stable(3), stable(4));
    timeline.items.push(chain_item(3, 78, 20, "m"));
    timeline.items.push(chain_item(4, 79, 30, "m"));
    // `c` has an edge of its own elsewhere: it is in the session's edges, just not in this row.
    timeline
        .edges
        .push(exact_edge(&b, &c, "00000000-0000-4000-8000-0000000000b3"));
    let one_pair = json!([pair(&a, &b, &[("activityId", GUID_A)])]);
    let cases = [
        (
            "an entry with no edge",
            vec![a.clone(), b.clone(), d.clone()],
        ),
        (
            "an entry with an edge outside the row",
            vec![a.clone(), b.clone(), c.clone()],
        ),
        (
            "an id the session does not hold",
            vec![a.clone(), b.clone(), stable(9)],
        ),
        ("a duplicated member", vec![a.clone(), a.clone(), b.clone()]),
    ];
    for (name, members) in cases {
        let chains = chains_value(
            2,
            (1, 0, 0, 0),
            vec![row("exact", &members, one_pair.clone())],
        );
        let error = chain_report_for(&timeline, chains).expect_err(name);
        assert_links_mismatch(&error, name);
        for leaked in ["HOST-0005", "CASE-0002", "record3", "record4"] {
            assert!(!error.contains(leaked), "{name}: {leaked} in {error}");
        }
    }
    // With the pair that touches it, the third entry is a member.
    let three = [a.clone(), b.clone(), c.clone()];
    let pairs = json!([
        pair(&a, &b, &[("activityId", GUID_A)]),
        pair(
            &b,
            &c,
            &[("activityId", "00000000-0000-4000-8000-0000000000b3")]
        )
    ]);
    let chains = chains_value(2, (1, 0, 0, 0), vec![row("exact", &three, pairs)]);
    let report = chain_report_for(&timeline, chains).expect("renders");
    assert!(
        report.contains("### Chain 1: Exact, 3 entries\n"),
        "{report}"
    );
}

#[test]
fn a_member_count_below_the_listed_members_is_refused() {
    let (timeline, a, b) = two_event_timeline();
    let mut value = row(
        "exact",
        &[a.clone(), b.clone()],
        json!([pair(&a, &b, &[("activityId", GUID_A)])]),
    );
    value["memberCount"] = json!(1);
    let chains = chains_value(1, (1, 0, 0, 0), vec![value]);
    // The request is refused before the session is read ...
    let error = chain_report_for(&timeline, chains.clone()).expect_err("refused");
    assert!(error.contains("lists more members than it has"), "{error}");
    // ... and a renderer handed the same rows without that check refuses too, instead of
    // counting a shortfall that is not there.
    let mut request_value = request_json();
    request_value["chains"] = chains;
    let request = request_from(request_value);
    let snapshot = collect(&timeline, status(2, 0), &request).expect("collects");
    let error = render_report(&ReportInput {
        request: &request,
        snapshot: &snapshot,
        summary: &DiagnosisSummary::default(),
    })
    .expect_err("refused");
    assert!(error.contains("lists more members than it has"), "{error}");
}

#[test]
fn entries_the_session_cannot_place_are_counted_and_never_listed() {
    // Each member is the end of a pair the session confirms. One is placed, one has no time,
    // and one is named by an edge but is not an entry of this session.
    let (mut timeline, a, b) = two_event_timeline();
    let placeless = stable(7);
    timeline.unplaced.push(UnplacedItem {
        origin: chain_item(7, 99, 0, "m").origin,
        reason: UnplacedReason::MissingTimestamp,
    });
    let missing = stable(8);
    let (v2, v3) = (
        "00000000-0000-4000-8000-0000000000b2",
        "00000000-0000-4000-8000-0000000000b3",
    );
    timeline.edges.push(exact_edge(&a, &placeless, v2));
    timeline.edges.push(exact_edge(&a, &missing, v3));
    let members = [a.clone(), b.clone(), placeless.clone(), missing.clone()];
    let chains = chains_value(
        3,
        (1, 0, 0, 0),
        vec![row(
            "exact",
            &members,
            json!([
                pair(&a, &b, &[("activityId", GUID_A)]),
                pair(&a, &placeless, &[("activityId", v2)]),
                pair(&a, &missing, &[("activityId", v3)]),
            ]),
        )],
    );
    let report = chain_report_for(&timeline, chains).expect("renders");
    assert!(
        report.contains("### Chain 1: Exact, 4 entries\n"),
        "{report}"
    );
    assert!(report.contains(
        "- Entries listed: 4. Of those, 2 are on the placed timeline, 1 have no usable \
         timestamp and 1 are not in this session."
    ));
    assert_eq!(table_rows(section(&report, "## Correlation chains")), 2);
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

fn spanning_pair(index: usize) -> serde_json::Value {
    pair(
        &format!("id-{index}"),
        &format!("id-{}", index + 1),
        &[("activityId", GUID_A)],
    )
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
        ("too many references", {
            let pairs: Vec<serde_json::Value> = (0..65).map(spanning_pair).collect();
            chains_value(1, (1, 0, 0, 0), vec![row("exact", &[], json!(pairs))])
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
    // The caps are inclusive: 50 members and the 64 pairs that span them are a valid chain row.
    let ids: Vec<String> = (0..50).map(|index| format!("id-{index}")).collect();
    let pairs: Vec<serde_json::Value> = (0..64).map(spanning_pair).collect();
    let mut value = request_json();
    value["chains"] = chains_value(1, (1, 0, 0, 0), vec![row("exact", &ids, json!(pairs))]);
    request_from(value)
        .validate()
        .expect("the capped chain row is valid");
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

/// The lines under "Coverage gaps the engine listed", without their indent.
fn coverage_lines(report: &str) -> Vec<&str> {
    let start = report
        .find("- Coverage gaps the engine listed (")
        .expect("the gaps are listed");
    report[start..]
        .lines()
        .skip(1)
        .take_while(|line| line.starts_with("  - "))
        .map(|line| &line[4..])
        .collect()
}

#[test]
fn coverage_sources_that_differ_are_never_printed_alike() {
    // Two live channels share their last segment, so a source reduced to it printed both as
    // "Operational" and folded them into one line with a count of two.
    let gaps = vec![
        gap(
            "Microsoft-Windows-AAD/Operational",
            CoverageState::AccessDenied,
            "Access is denied.",
        ),
        gap(
            "Microsoft-Windows-Sysmon/Operational",
            CoverageState::AccessDenied,
            "Access is denied.",
        ),
        gap("Security", CoverageState::AccessDenied, "Access is denied."),
    ];
    let report = render_with(
        &base_request(),
        &snapshot_of(Vec::new(), 0),
        &summary_of(Vec::new(), gaps),
    );
    assert_eq!(
        coverage_lines(&report),
        [
            "access denied: Microsoft-Windows-AAD/Operational: Access is denied.",
            "access denied: Microsoft-Windows-Sysmon/Operational: Access is denied.",
            "access denied: Security: Access is denied.",
        ]
    );
}

#[test]
fn files_with_one_name_in_two_folders_are_two_gaps_and_a_path_shows_its_file_name() {
    let denied = |source: &str| gap(source, CoverageState::AccessDenied, "Access is denied.");
    let gaps = vec![
        denied(r"C:\Cases\CASE-0001\System.evtx"),
        denied(r"C:\Cases\CASE-0002\System.evtx"),
        denied("/home/case0003/System.evtx"),
        denied("Cases/CASE-0004/System.evtx"),
        denied("C:/Cases/CASE-0005/System.evtx"),
        denied("/var/log/messages"),
        denied(r"C:\Cases\CASE-0006\Archive"),
        denied("Cases/CASE-0007/Export.jsonl"),
    ];
    let report = render_with(
        &base_request(),
        &snapshot_of(Vec::new(), 0),
        &summary_of(Vec::new(), gaps),
    );
    assert!(
        report.contains("- Coverage gaps the engine listed (8):"),
        "{report}"
    );
    // Each file is its own line, whatever it is called: nothing folds two sources together.
    let lines = coverage_lines(&report);
    assert_eq!(lines.len(), 8, "{lines:?}");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("System.evtx"))
            .count(),
        5
    );
    assert!(lines.contains(&"access denied: messages: Access is denied."));
    assert!(lines.contains(&"access denied: Archive: Access is denied."));
    assert!(lines.contains(&"access denied: Export.jsonl: Access is denied."));
    assert!(!report.contains(" gaps)"), "{report}");
    for folder in [
        "CASE-0001",
        "CASE-0002",
        "case0003",
        "CASE-0004",
        "CASE-0005",
        "CASE-0006",
        "CASE-0007",
        "/var/log",
    ] {
        assert!(!leaks(&report, folder), "{folder} leaked:\n{report}");
    }
}

#[test]
fn a_remote_host_prefix_of_a_coverage_source_is_never_printed_as_written() {
    let denied = |source: &str| gap(source, CoverageState::AccessDenied, "Access is denied.");
    let gaps = vec![
        denied("HOST-0003/Microsoft-Windows-AAD/Operational"),
        denied("HOST-0003/Microsoft-Windows-Sysmon/Operational"),
        denied("HOST-0009/Microsoft-Windows-AAD/Operational"),
        denied("HOST-0009/Security"),
        denied("HOST-0003/Custom Channel"),
    ];
    // HOST-0003 delivered events, so the session knows it. HOST-0009 delivered nothing.
    let mut snapshot = snapshot_of(Vec::new(), 0);
    snapshot.machines.insert("HOST-0003".to_owned());
    let report = render_with(&base_request(), &snapshot, &summary_of(Vec::new(), gaps));
    let (known, unknown) = (host("HOST-0003"), host("HOST-0009"));
    assert_eq!(
        coverage_lines(&report),
        [
            format!("access denied: {known}/Microsoft-Windows-AAD/Operational: Access is denied."),
            format!(
                "access denied: {known}/Microsoft-Windows-Sysmon/Operational: Access is denied."
            ),
            format!(
                "access denied: {unknown}/Microsoft-Windows-AAD/Operational: Access is denied."
            ),
            format!("access denied: {unknown}/Security: Access is denied."),
            format!("access denied: {known}/Custom Channel: Access is denied."),
        ]
    );
    assert!(
        !leaks(&report, "HOST-0003") && !leaks(&report, "HOST-0009"),
        "{report}"
    );
}

#[test]
fn a_remote_host_before_any_of_the_classic_logs_is_a_machine_token_whatever_its_case() {
    let classic = [
        "Application",
        "Security",
        "Setup",
        "System",
        "ForwardedEvents",
        "HardwareEvents",
        "Windows PowerShell",
        "Internet Explorer",
        "Key Management Service",
    ];
    let gaps: Vec<CoverageGap> = classic
        .iter()
        .map(|name| {
            gap(
                &format!("HOST-0009/{}", name.to_lowercase()),
                CoverageState::AccessDenied,
                "Access is denied.",
            )
        })
        .collect();
    let report = render_with(
        &base_request(),
        &snapshot_of(Vec::new(), 0),
        &summary_of(Vec::new(), gaps),
    );
    let unknown = host("HOST-0009");
    let expected: Vec<String> = classic
        .iter()
        .map(|name| {
            format!(
                "access denied: {unknown}/{}: Access is denied.",
                name.to_lowercase()
            )
        })
        .collect();
    assert_eq!(coverage_lines(&report), expected);
    assert!(!leaks(&report, "HOST-0009"), "{report}");
}

#[test]
fn a_remote_host_the_request_does_not_name_is_printed_as_written_before_a_custom_channel() {
    // The limit, pinned for a request with no remote machine. `host/Channel` and
    // `Provider/Type` have the same shape, so a host that delivered no event and fronts a
    // channel that is not one of Windows' classic logs cannot be told from a provider.
    let gaps = vec![gap(
        "HOST-0009/Custom Channel",
        CoverageState::AccessDenied,
        "Access is denied.",
    )];
    let report = render_with(
        &base_request(),
        &snapshot_of(Vec::new(), 0),
        &summary_of(Vec::new(), gaps),
    );
    assert_eq!(
        coverage_lines(&report),
        ["access denied: HOST-0009/Custom Channel: Access is denied."]
    );
}

/// A report whose source is remote: the host is named by the request, and appears in a coverage
/// source, in a gap detail, in a finding and in an event's text. No origin records it.
fn remote_report(remote_machine: serde_json::Value) -> String {
    let mut value = request_json();
    value["remoteMachine"] = remote_machine;
    let mut one = finding(
        "a",
        FindingClass::Symptom,
        FindingSeverity::Info,
        FindingConfidence::Low,
        "Query",
    );
    one.summary = "The query to HOST-0009 returned nothing.".to_owned();
    let gaps = vec![gap(
        "HOST-0009/Custom Channel",
        CoverageState::AccessDenied,
        "cannot open remote session to HOST-0009: The RPC server is unavailable.",
    )];
    let item = event_item(
        FIXTURE_NOW_MS,
        TimelineSeverity::Error,
        1001,
        "Application",
        "Fixture.Provider",
        Some("HOST-0001"),
        1,
        "Forwarded from HOST-0009 by the collector.",
    );
    render_with(
        &request_from(value),
        &snapshot_of(vec![item], 1),
        &summary_of(vec![one], gaps),
    )
}

#[test]
fn the_remote_machine_the_request_names_is_a_known_machine_wherever_it_appears() {
    let report = remote_report(json!("HOST-0009"));
    let token = host("HOST-0009");
    assert_eq!(
        coverage_lines(&report),
        [format!(
            "access denied: {token}/Custom Channel: cannot open remote session to {token}: \
             The RPC server is unavailable."
        )]
    );
    assert!(
        report.contains(&format!(
            "- Summary: The query to {token} returned nothing."
        )),
        "{report}"
    );
    assert!(
        report.contains(&format!("Forwarded from {token} by the collector.")),
        "{report}"
    );
    assert!(!leaks(&report, "HOST-0009"), "{report}");
    // Named or not, the host is not an origin of the session, so the header does not list it.
    assert!(report.contains(&format!("- Machines (1): {}\n", host("HOST-0001"))));
}

#[test]
fn a_request_without_a_remote_machine_keeps_the_text_as_it_was() {
    // `null` and an absent key both mean a local source: nothing is added to what is known.
    let report = remote_report(json!(null));
    assert!(
        report.contains("cannot open remote session to HOST-0009:"),
        "{report}"
    );
    assert!(report.contains("- Summary: The query to HOST-0009 returned nothing."));
    assert!(report.contains("Forwarded from HOST-0009 by the collector."));
    assert!(
        coverage_lines(&report)[0].starts_with("access denied: HOST-0009/Custom Channel: "),
        "{report}"
    );
    let mut value = request_json();
    value.as_object_mut().unwrap().remove("remoteMachine");
    assert!(request_from(value).remote_machine.is_none());
}

#[test]
fn the_remote_machine_is_bounded_and_read_by_what_it_reads_as() {
    let with = |remote: serde_json::Value| {
        let mut value = request_json();
        value["remoteMachine"] = remote;
        value
    };
    request_from(with(json!("HOST-0009")))
        .validate()
        .expect("a name is valid");
    request_from(with(json!("h".repeat(255))))
        .validate()
        .expect("the longest name is valid");
    for (name, remote) in [
        ("a name over the cap", json!("h".repeat(256))),
        ("an empty name", json!("")),
        ("a blank name", json!("  \t")),
    ] {
        let error = request_from(with(remote)).validate().expect_err(name);
        assert!(error.contains("remote machine"), "{name}: {error}");
    }
    // Not a string, and not a key the type has.
    assert!(
        serde_json::from_value::<EventLogAnalysisReportRequest>(with(json!(7))).is_err(),
        "a number was accepted"
    );
    let mut value = request_json();
    value["remoteMachineName"] = json!("HOST-0009");
    assert!(serde_json::from_value::<EventLogAnalysisReportRequest>(value).is_err());
    // An invisible character inside the name does not keep it from matching the same name.
    let report = remote_report(json!("HOST\u{200b}-0009"));
    assert!(!leaks(&report, "HOST-0009"), "{report}");
    assert!(report.contains(&format!("Forwarded from {} by", host("HOST-0009"))));
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
