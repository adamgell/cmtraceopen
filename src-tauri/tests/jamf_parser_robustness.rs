#![cfg(feature = "macos-diag")]

//! Malformed-input contract for the JAMF log parsers.
//!
//! Real `jamf.log` and `selfservice.log` files can contain non-UTF-8 bytes and
//! can be caught mid-write. The parsers must degrade gracefully: keep every
//! decodable event, never abort the file, and never silently stop early.

use std::io::Write;
use std::path::{Path, PathBuf};

use app_lib::jamf::connect::parse_connect_log_impl;
use app_lib::jamf::policy_log::parse_policy_log_impl;
use app_lib::jamf::self_service::parse_self_service_log_impl;

fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("cmtrace_jamf_{name}"));
    let mut f = std::fs::File::create(&path).expect("create fixture");
    f.write_all(bytes).expect("write fixture");
    path
}

#[test]
fn policy_log_survives_invalid_utf8_and_keeps_all_lines() {
    // 0xFF / 0xFE are not valid UTF-8. Previously `read_line` returned
    // ErrorKind::InvalidData and the entire parse failed.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"Wed Apr 29 13:23:04 host jamf[1]: Executing Policy First\n");
    bytes.extend_from_slice(b"Wed Apr 29 13:23:05 host jamf[1]: Executing Policy Ba\xFF\xFEd\n");
    bytes.extend_from_slice(b"Wed Apr 29 13:23:06 host jamf[1]: Executing Policy Third\n");
    let path = write_temp("policy_bad_utf8.log", &bytes);

    let result = parse_policy_log_impl(&path).expect("must not fail on invalid UTF-8");
    assert_eq!(result.total_lines, 3);
    assert_eq!(
        result.events.len(),
        3,
        "every line must still yield an event"
    );
    assert_eq!(result.unparsed_lines, 0);

    let names: Vec<&str> = result
        .events
        .iter()
        .filter_map(|e| e.policy_name.as_deref())
        .collect();
    assert_eq!(names[0], "First");
    assert_eq!(names[2], "Third");
    assert!(
        names[1].starts_with("Ba"),
        "decoded lossily: {:?}",
        names[1]
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn policy_log_offsets_locate_the_original_line() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"Wed Apr 29 13:23:04 host jamf[1]: Executing Policy Alpha\n");
    bytes.extend_from_slice(b"Wed Apr 29 13:23:05 host jamf[1]: Executing Policy Beta\n");
    let path = write_temp("policy_offsets.log", &bytes);

    let result = parse_policy_log_impl(&path).expect("parse");
    let raw = std::fs::read(&path).expect("read back");
    for event in &result.events {
        let start = event.raw_line_offset as usize;
        let end = start + event.raw_line.len();
        assert_eq!(
            &raw[start..end],
            event.raw_line.as_bytes(),
            "raw_line_offset must point at the line it came from"
        );
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn policy_log_tolerates_a_truncated_final_line() {
    let bytes = b"Wed Apr 29 13:23:04 host jamf[1]: Executing Policy Complete\nWed Apr 29 13:23:0";
    let path = write_temp("policy_truncated.log", bytes);

    let result = parse_policy_log_impl(&path).expect("parse");
    assert_eq!(result.total_lines, 2);
    assert_eq!(result.events.len(), 1);
    assert_eq!(
        result.unparsed_lines, 1,
        "the partial line is counted, not fatal"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn self_service_does_not_truncate_after_invalid_utf8() {
    // Previously `map_while(Result::ok)` stopped at the bad line, returning 1 of
    // 4 events with no error.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"[2026-04-29 09:12:03] Request: getPolicies\n");
    bytes.extend_from_slice(b"[2026-04-29 09:12:04] Request: getBa\xFFdEndpoint\n");
    bytes.extend_from_slice(b"[2026-04-29 09:12:05] Binary Request: triggerPolicy\n");
    bytes.extend_from_slice(b"[2026-04-29 09:12:06] Binary Request: doRecon\n");
    let path = write_temp("self_service_bad_utf8.log", &bytes);

    let events = parse_self_service_log_impl(&path).expect("parse");
    assert_eq!(events.len(), 4, "must not stop at the malformed line");
    assert_eq!(events[2].action, "triggerPolicy");
    assert_eq!(events[3].action, "doRecon");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn connect_does_not_truncate_after_invalid_utf8() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"2026-04-29T09:12:03+0000 [INFO] [Login] User a@b.com in\n");
    bytes.extend_from_slice(b"2026-04-29T09:12:04+0000 [WARN] [Sync] Ba\xFFd payload\n");
    bytes.extend_from_slice(b"2026-04-29T09:12:05+0000 [INFO] [Sync] User a@b.com synced\n");
    let path = write_temp("connect_bad_utf8.log", &bytes);

    let events = parse_connect_log_impl(&path).expect("parse");
    assert_eq!(events.len(), 3, "must not stop at the malformed line");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn connect_accepts_zulu_and_numeric_offsets() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"2026-04-29T09:12:03Z [INFO] [Login] User a@b.com (provider=Okta)\n");
    bytes.extend_from_slice(b"2026-04-29T09:12:03+0000 [INFO] [Sync] User a@b.com numeric\n");
    bytes.extend_from_slice(b"2026-04-29T09:12:03+00:00 [INFO] [Sync] User a@b.com colon\n");
    bytes.extend_from_slice(b"2026-04-29T02:12:03-0700 [INFO] [Sync] User a@b.com offset\n");
    let path = write_temp("connect_zulu.log", &bytes);

    let events = parse_connect_log_impl(&path).expect("parse");
    assert_eq!(events.len(), 4, "Z, +0000, +00:00 and -0700 must all parse");

    // All four describe the same instant.
    let first = events[0].timestamp;
    for e in &events {
        assert_eq!(e.timestamp, first, "offsets must normalize to one instant");
    }
    assert_eq!(events[0].idp.as_deref(), Some("Okta"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_file_with_no_newlines_does_not_grow_unbounded() {
    // A binary blob or wrong file picked by a glob has no delimiter at all.
    // read_until would pull the whole thing into one line; the cap keeps a
    // single record bounded while still consuming the file.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"Wed Apr 29 13:23:04 host jamf[1]: Executing Policy ");
    bytes.extend(std::iter::repeat_n(b'A', 512 * 1024));
    let path = write_temp("policy_no_newline.log", &bytes);

    let result = parse_policy_log_impl(&path).expect("parse");
    assert_eq!(result.total_lines, 1);
    for event in &result.events {
        assert!(
            event.raw_line.len() < 128 * 1024,
            "retained line should be capped, got {} bytes",
            event.raw_line.len()
        );
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_over_long_line_does_not_disturb_later_offsets() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"Wed Apr 29 13:23:04 host jamf[1]: Executing Policy Huge ");
    bytes.extend(std::iter::repeat_n(b'B', 128 * 1024));
    bytes.push(b'\n');
    bytes.extend_from_slice(b"Wed Apr 29 13:23:05 host jamf[1]: Executing Policy After\n");
    let path = write_temp("policy_long_then_short.log", &bytes);

    let result = parse_policy_log_impl(&path).expect("parse");
    assert_eq!(result.total_lines, 2);

    let last = result.events.last().expect("second event");
    assert_eq!(last.policy_name.as_deref(), Some("After"));

    // The short line following an over-long one must still be locatable.
    let raw = std::fs::read(&path).expect("read back");
    let start = last.raw_line_offset as usize;
    assert!(
        raw[start..].starts_with(b"Wed Apr 29 13:23:05"),
        "offset must survive a truncated predecessor"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn missing_files_are_not_errors_except_for_the_policy_log() {
    // Self Service / Connect may legitimately be absent; jamf.log going missing
    // is a condition worth surfacing.
    assert!(
        parse_self_service_log_impl(Path::new("/nonexistent/ss.log"))
            .expect("absent Self Service log is empty, not an error")
            .is_empty()
    );
    assert!(parse_connect_log_impl(Path::new("/nonexistent/jc.log"))
        .expect("absent Connect log is empty, not an error")
        .is_empty());
    assert!(parse_policy_log_impl(Path::new("/nonexistent/jamf.log")).is_err());
}
