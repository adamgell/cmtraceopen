//! Chrono's Unix local zone honors TZ. Use a fresh process for each zone so
//! neither the process environment nor Chrono's cache races another test.
#![cfg(unix)]

use chrono::{Local, LocalResult, NaiveDate, TimeZone};
use cmtraceopen_parser::parser::ccm::logical::{parse_ime_content, parse_ime_entries};
use std::process::Command;

fn in_timezone(test_name: &str, zone: &str, test: impl FnOnce()) {
    if let Ok(child_zone) = std::env::var("CMTRACE_IME_TEST_ZONE") {
        if child_zone == zone {
            test();
        }
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            test_name,
            "--nocapture",
            "--test-threads=1",
            "--format=pretty",
            "--color=never",
        ])
        .env("TZ", zone)
        .env("CMTRACE_IME_TEST_ZONE", zone)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{test_name} in {zone}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected_pass = format!("test {test_name} ... ok");
    assert!(
        stdout.lines().any(|line| line == expected_pass)
            && stdout
                .lines()
                .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")),
        "{test_name} did not run exactly one intended test in {zone}:\n{stdout}"
    );
}

#[test]
#[should_panic(expected = "did not run exactly one intended test")]
fn timezone_child_rejects_nonmatching_test_name() {
    in_timezone("stale_ime_timezone_test_name", "UTC", || {
        panic!("a nonexistent test cannot run");
    });
}

fn record(date: &str, time: &str) -> String {
    // Transform only the date/time attributes of a committed IME exemplar.
    let anchor = include_str!("fixtures/intune/apps/windows/win32/complete-success/evidence/ime-current/current/IntuneManagementExtension.log")
        .lines()
        .next()
        .unwrap();
    let mut record = anchor.to_owned();
    for (key, value) in [("date", date), ("time", time)] {
        let start = record.find(&format!("{key}=\"")).unwrap() + key.len() + 2;
        let end = start + record[start..].find('"').unwrap();
        record.replace_range(start..end, value);
    }
    record
}

#[test]
fn record_date_offsets_for_winter_and_summer() {
    for (zone, winter, summer) in [
        ("Europe/London", 0, 60),
        ("America/New_York", -300, -240),
        ("UTC", 0, 0),
    ] {
        in_timezone("record_date_offsets_for_winter_and_summer", zone, || {
            for (month, offset) in [(1, winter), (7, summer)] {
                let content = record(&format!("{month}-15-2026"), "12:34:56.789");
                let wall = NaiveDate::from_ymd_opt(2026, month, 15)
                    .unwrap()
                    .and_hms_milli_opt(12, 34, 56, 789)
                    .unwrap();
                let expected = wall.and_utc().timestamp_millis() - offset * 60_000;
                let (entries, errors) =
                    parse_ime_entries(&content, "IntuneManagementExtension.log");
                assert_eq!(errors, 0);
                assert_eq!(entries.len(), 1);
                assert_eq!(
                    entries[0].timestamp,
                    Some(expected),
                    "{zone}, month {month}"
                );
                assert_eq!(entries[0].timezone_offset, None);
                let display = format!("{month:02}-15-2026 12:34:56.789");
                assert_eq!(
                    entries[0].timestamp_display.as_deref(),
                    Some(display.as_str())
                );
                let lines = parse_ime_content(&content);
                assert_eq!(lines[0].timezone_offset, None);
                let utc = chrono::DateTime::from_timestamp_millis(expected)
                    .unwrap()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                assert_eq!(lines[0].timestamp_utc.as_deref(), Some(utc.as_str()));
            }
        });
    }
}

#[test]
fn gap_and_fold_keep_current_offset_fallback() {
    in_timezone(
        "gap_and_fold_keep_current_offset_fallback",
        "Europe/London",
        || {
            for (month, day, minute, gap) in
                [(3, 29, 30, true), (3, 29, 45, true), (10, 25, 30, false)]
            {
                let wall = NaiveDate::from_ymd_opt(2026, month, day)
                    .unwrap()
                    .and_hms_opt(1, minute, 0)
                    .unwrap();
                let mapping = Local.from_local_datetime(&wall);
                if gap {
                    assert!(matches!(mapping, LocalResult::None));
                } else {
                    assert!(matches!(mapping, LocalResult::Ambiguous(..)));
                }
                let content = record(
                    &format!("{month}-{day}-2026"),
                    &format!("01:{minute}:00.000"),
                );
                let offset_before = Local::now().offset().local_minus_utc() / 60;
                let (entries, errors) =
                    parse_ime_entries(&content, "IntuneManagementExtension.log");
                let offset_after = Local::now().offset().local_minus_utc() / 60;
                assert_eq!(errors, 0);
                assert_eq!(entries.len(), 1);
                assert!(
                    [offset_before, offset_after].into_iter().any(|offset| {
                        entries[0].timestamp
                            == Some(wall.and_utc().timestamp_millis() - i64::from(offset) * 60_000)
                    }),
                    "fallback changed for {wall}: {:?}",
                    entries[0].timestamp
                );
                assert_eq!(entries[0].timezone_offset, None);
                // ImeLine's separate UTC rendering policy is pre-existing: gaps
                // render the wall clock as UTC, folds pick the earliest occurrence.
                let utc = mapping
                    .earliest()
                    .map(|value| value.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|| wall.and_utc())
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                let lines = parse_ime_content(&content);
                assert_eq!(lines[0].timestamp_utc.as_deref(), Some(utc.as_str()));
                assert_eq!(lines[0].timezone_offset, None);
            }
        },
    );
}

#[test]
fn explicit_source_offsets_remain_authoritative() {
    for zone in ["Europe/London", "America/New_York", "UTC"] {
        in_timezone("explicit_source_offsets_remain_authoritative", zone, || {
            for (month, day) in [(1, 15), (7, 15), (3, 29), (10, 25)] {
                for offset in [-240, 0, 330] {
                    let content = record(
                        &format!("{month}-{day}-2026"),
                        &format!("01:30:00.123{offset:+04}"),
                    );
                    let wall = NaiveDate::from_ymd_opt(2026, month, day)
                        .unwrap()
                        .and_hms_milli_opt(1, 30, 0, 123)
                        .unwrap();
                    let expected = wall.and_utc().timestamp_millis() - i64::from(offset) * 60_000;
                    let (entries, errors) =
                        parse_ime_entries(&content, "IntuneManagementExtension.log");
                    assert_eq!(errors, 0);
                    assert_eq!(entries[0].timestamp, Some(expected));
                    assert_eq!(entries[0].timezone_offset, Some(offset));
                    let lines = parse_ime_content(&content);
                    assert_eq!(lines[0].timezone_offset, Some(offset));
                    let utc = chrono::DateTime::from_timestamp_millis(expected)
                        .unwrap()
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                    assert_eq!(lines[0].timestamp_utc.as_deref(), Some(utc.as_str()));
                }
            }
        });
    }
}

#[test]
fn invalid_or_missing_clocks_retain_records_without_epochs() {
    for zone in ["Europe/London", "UTC"] {
        in_timezone(
            "invalid_or_missing_clocks_retain_records_without_epochs",
            zone,
            || {
                for content in [
                    record("2-30-2026", "01:30:00.000"),
                    record("1-15-2026", "25:30:00.000"),
                    record("", "01:30:00.000"),
                    record("1-15-2026", ""),
                    record("1-15-2026", "01:30:00.000").replace("date=\"1-15-2026\"", ""),
                    record("1-15-2026", "01:30:00.000").replace("time=\"01:30:00.000\"", ""),
                ] {
                    let (entries, _) = parse_ime_entries(&content, "IntuneManagementExtension.log");
                    assert_eq!(entries.len(), 1);
                    assert_eq!(entries[0].timestamp, None);
                    assert_eq!(entries[0].timezone_offset, None);
                    let lines = parse_ime_content(&content);
                    assert_eq!(lines.len(), 1);
                    assert_eq!(lines[0].timestamp_utc, None);
                }
            },
        );
    }
}
