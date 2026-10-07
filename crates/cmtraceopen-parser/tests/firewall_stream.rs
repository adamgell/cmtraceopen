use cmtraceopen_parser::{
    models::{firewall::*, log_entry::LogEntry},
    parser::{firewall_stream::*, windows_firewall::MAX_FIREWALL_LINE_BYTES},
};
const FIXTURE: &str = include_str!("fixtures/issue_814/firewall-local-18-fields.log");
fn apply(rows: &mut Vec<LogEntry>, delta: FirewallDelta) -> FirewallCoverage {
    rows.extend(delta.entries);
    for r in delta.replacements {
        let old = rows
            .iter_mut()
            .find(|e| e.id == r.expected_id && e.line_number == r.expected_line_number)
            .expect("stable replacement target");
        *old = r.entry;
    }
    delta.coverage
}
fn snapshot(text: &str) -> (Vec<LogEntry>, FirewallCoverage) {
    let mut s = FirewallStream::new(0, 1);
    let mut rows = vec![];
    apply(&mut rows, s.push_text(text, "synthetic"));
    let c = apply(&mut rows, s.snapshot_eof("synthetic"));
    (rows, c)
}
#[test]
fn firewall_snapshot_and_all_text_splits_converge() {
    let text=format!("\0\0\n\n{}\r\n#Fields: action date time info\r\n#Time Format: UTC\r\nINFO-EVENTS-LOST 2042-03-04 01:02:03 123",FIXTURE.replace('\n',"\r\n"));
    let (expected, coverage) = snapshot(&text);
    for split in 0..=text.len() {
        if !text.is_char_boundary(split) {
            continue;
        }
        let mut stream = FirewallStream::new(0, 1);
        let mut rows = vec![];
        apply(&mut rows, stream.push_text(&text[..split], "synthetic"));
        apply(&mut rows, stream.snapshot_eof("synthetic"));
        for ch in text[split..].chars() {
            apply(&mut rows, stream.push_text(&ch.to_string(), "synthetic"));
        }
        let actual = apply(&mut rows, stream.snapshot_eof("synthetic"));
        assert_eq!(
            serde_json::to_value(&rows).unwrap(),
            serde_json::to_value(&expected).unwrap(),
            "split {split}"
        );
        assert_eq!(actual, coverage, "coverage split {split}");
    }
}
#[test]
fn firewall_eof_extension_replaces_full_row_and_coverage() {
    let header = FIXTURE.lines().take(5).collect::<Vec<_>>().join("\n") + "\n";
    let raw = FIXTURE.lines().nth(5).unwrap();
    let cut = raw.len() - 4;
    let mut stream = FirewallStream::new(77, 1);
    let mut rows = vec![];
    apply(
        &mut rows,
        stream.push_text(&(header.clone() + &raw[..cut]), "synthetic"),
    );
    let c = apply(&mut rows, stream.snapshot_eof("synthetic"));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, 77);
    // The partial ordinary row maps missing PID as malformed, until append repairs it.
    let c2 = apply(
        &mut rows,
        stream.push_text(&(raw[cut..].to_owned() + "\n"), "synthetic"),
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, 77);
    assert_eq!(rows[0].line_number, 6);
    assert_eq!(c2.parse_errors(), 0);
    assert_eq!(c2.malformed.lines, Vec::<u32>::new());
    assert!(c.parse_errors() >= c2.parse_errors());
    assert_eq!(rows[0].firewall.as_ref().unwrap().raw_line, raw);
}
#[test]
fn firewall_padding_overlong_recovery_and_bounds() {
    let header = FIXTURE.lines().take(5).collect::<Vec<_>>().join("\n") + "\n";
    for n in [1, 4096, 1024 * 1024] {
        let mut stream = FirewallStream::new(0, 1);
        let mut rows = vec![];
        apply(&mut rows, stream.push_text(&header, "synthetic"));
        let c = apply(&mut rows, stream.push_text(&"\0".repeat(n), "synthetic"));
        assert_eq!(c.padding.count, n as u64);
        assert!(stream.retained_text_bytes() <= MAX_FIREWALL_LINE_BYTES);
        for _ in 0..8 {
            apply(
                &mut rows,
                stream.push_text(&"x".repeat(32_768), "synthetic"),
            );
            assert!(stream.retained_text_bytes() <= MAX_FIREWALL_LINE_BYTES);
        }
        let c = apply(&mut rows, stream.snapshot_eof("synthetic"));
        assert_eq!(c.parse_errors(), 1);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].firewall.as_ref().unwrap().truncated);
        let raw = FIXTURE.lines().nth(5).unwrap();
        let c = apply(
            &mut rows,
            stream.push_text(&format!("\n{raw}\n"), "synthetic"),
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(c.parse_errors(), 1);
        assert_eq!(c.oversized.count, 1);
        assert_eq!(rows[1].line_number, 7);
    }
}
#[test]
fn firewall_header_eof_and_generation_reset_do_not_finalize_old_text() {
    let mut s = FirewallStream::new(10, 1);
    s.push_text("#Time Format: U", "synthetic");
    assert!(s.snapshot_eof("synthetic").entries.is_empty());
    assert_eq!(s.context().time_basis, FirewallTimeBasis::Unknown);
    s.push_text("TC\r", "synthetic");
    assert_eq!(s.context().time_basis, FirewallTimeBasis::Unknown);
    s.push_text("\n", "synthetic");
    assert_eq!(s.context().time_basis, FirewallTimeBasis::Utc);
    s.push_text("partial", "synthetic");
    s.snapshot_eof("synthetic");
    let next = s.next_id();
    s.reset_generation(next);
    assert_eq!(s.context().time_basis, FirewallTimeBasis::Unknown);
    let delta = s.push_text(&(FIXTURE.to_owned() + "\n"), "synthetic");
    assert_eq!(delta.entries[0].id, next);
    assert_eq!(delta.entries[0].line_number, 6);
    assert_eq!(delta.coverage.parse_errors(), 0);
}
#[test]
fn firewall_loss_count_extension_replaces_instead_of_accumulates() {
    let mut s = FirewallStream::new(0, 1);
    let mut rows = vec![];
    apply(
        &mut rows,
        s.push_text(
            "#Fields: date time action info\n2042-04-05 06:07:13 INFO-EVENTS-LOST 2",
            "synthetic",
        ),
    );
    assert_eq!(
        apply(&mut rows, s.snapshot_eof("synthetic"))
            .lost_events
            .count,
        2
    );
    assert_eq!(
        apply(&mut rows, s.push_text("3", "synthetic"))
            .lost_events
            .count,
        23
    );
    assert_eq!(
        apply(&mut rows, s.push_text("\n", "synthetic"))
            .lost_events
            .count,
        23
    );
    assert_eq!(rows.len(), 1);
}
#[test]
fn firewall_interior_nul_is_not_fused() {
    let text = FIXTURE.replace("ALLOW", "AL\0LOW");
    let (rows, c) = snapshot(&text);
    assert_eq!(c.parse_errors(), 1);
    assert!(rows[0].firewall.as_ref().unwrap().fields.is_empty());
    assert!(rows[0]
        .firewall
        .as_ref()
        .unwrap()
        .raw_line
        .contains("AL\0LOW"));
}

#[test]
fn firewall_checkpoint_clone_keeps_allocation_bounded() {
    let mut s = FirewallStream::new(0, 1);
    s.push_text(&"x".repeat(40_000), "");
    let mut candidate = s.clone();
    candidate.push_text(&"x".repeat(25_536), "");
    assert!(candidate.retained_text_bytes() <= MAX_FIREWALL_LINE_BYTES);
}
#[test]
fn firewall_cap_boundary_counts_one_exclusive_error() {
    for n in [65_535, 65_536, 65_537] {
        let (_, c) = snapshot(&("x".repeat(n) + "\n"));
        assert_eq!(c.parse_errors(), 1);
        assert_eq!(c.oversized.count, u64::from(n > 65_536));
        assert_eq!(c.malformed.count, u64::from(n <= 65_536));
    }
}
#[test]
fn firewall_provisional_samples_do_not_subtract_saturated_committed_counts() {
    let mut s = FirewallStream::new(0, 1);
    let mut rows = vec![];
    apply(&mut rows,s.push_text("#Fields: date time action info\n2042-04-05 06:07:13 INFO-EVENTS-LOST 18446744073709551615\n2042-04-05 06:07:14 INFO-EVENTS-LOST 1","synthetic"));
    let c = apply(&mut rows, s.snapshot_eof("synthetic"));
    assert_eq!(c.lost_events.count, u64::MAX);
    assert_eq!(c.lost_events.lines, vec![2, 3]);
    let c = apply(&mut rows, s.push_text("x\n", "synthetic"));
    assert_eq!(c.lost_events.count, u64::MAX);
    assert_eq!(c.lost_events.lines, vec![2]);
    assert_eq!(c.unknown_loss_count.count, 1);
}
