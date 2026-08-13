//! Runs the .evtx file path against a real Windows event log.
//!
//! The unit tests in `event_log::parser` cover field extraction against hand-written XML. They
//! cannot cover the part that actually broke: what the `evtx` crate hands back per record, and
//! whether that survives the whole pipeline. The file path once fed a JSON projection to an XML
//! parser, which failed silently for every record and left the System block, every map, and the
//! XML export empty on an opened file. Nothing in the unit tests could see that.
//!
//! Captured logs carry real hostnames, account names and query traffic, so they live outside the
//! repo. Point `CMTRACE_EVTX_FIXTURE` at an .evtx file to run these; without it every test here
//! passes vacuously, so CI is unaffected.
//!
//!     CMTRACE_EVTX_FIXTURE=~/logs/dns-audit.evtx cargo test --features event-log --test event_log_real_evtx
//!
//! Assertions are floors and invariants rather than exact counts, so a different capture does not
//! break them.

#![cfg(feature = "event-log")]

use std::path::PathBuf;

use app_lib::event_log::export::{export_records, ExportFormat};
use app_lib::event_log::models::EvtxParseResult;
use app_lib::event_log::parser::parse_evtx_files;
use app_lib::event_log::provider_db::ProviderStore;
use cmtraceopen_parser::eventmap::MapRegistry;
use std::sync::RwLock;

fn fixture() -> Option<PathBuf> {
    let Some(raw) = std::env::var_os("CMTRACE_EVTX_FIXTURE") else {
        // Said out loud rather than passing silently. Seven tests reporting ok with nothing run is
        // the same failure this suite exists to catch: an empty result that reads as a verified
        // one. Visible with `cargo test -- --nocapture`, and in CI logs.
        eprintln!(
            "SKIP: CMTRACE_EVTX_FIXTURE is not set, so nothing in this file actually ran. \
             Point it at an .evtx file to exercise the real parse path."
        );
        return None;
    };
    let path = PathBuf::from(raw);
    assert!(
        path.is_file(),
        "CMTRACE_EVTX_FIXTURE is set but {} is not a file",
        path.display()
    );
    Some(path)
}

fn parsed() -> Option<EvtxParseResult> {
    let path = fixture()?;
    // Registries local to this call. The parse path takes them explicitly, so nothing here can be
    // perturbed by another test loading a different set on a parallel thread.
    let maps = RwLock::new(MapRegistry::new());
    let providers = RwLock::new(ProviderStore::default());
    let result = parse_evtx_files(&[path.to_string_lossy().into_owned()], &maps, &providers)
        .expect("the file parses");
    assert!(
        !result.records.is_empty(),
        "fixture produced no records at all"
    );
    Some(result)
}

#[test]
fn every_record_in_the_file_parses() {
    let Some(result) = parsed() else { return };
    // A record that cannot be read is counted, not dropped in silence. A real log from a healthy
    // machine should have none, so any error here means the reader is wrong rather than the file.
    assert_eq!(
        result.parse_errors,
        0,
        "{} of {} records failed to parse",
        result.parse_errors,
        result.records.len()
    );
}

#[test]
fn identity_is_populated_rather_than_defaulted() {
    let Some(result) = parsed() else { return };
    for record in &result.records {
        assert_ne!(
            record.provider, "Unknown",
            "record {} has no provider",
            record.event_record_id
        );
        assert_ne!(
            record.channel, "Unknown",
            "record {} has no channel",
            record.event_record_id
        );
        // Event ID 0 is legal and several in-box providers emit it, so it is not an invariant.
        assert_ne!(
            record.timestamp_epoch, 0,
            "record {} sorted to the epoch, so the timeline order is wrong",
            record.event_record_id
        );
    }
}

#[test]
fn the_system_block_survives_the_file_path() {
    let Some(result) = parsed() else { return };
    // These were empty on every opened file while the path re-parsed JSON as XML. Asserting that
    // some record carries each one, rather than all of them, because providers legitimately omit
    // any individual field.
    let has = |f: fn(&app_lib::event_log::models::EvtxRecord) -> bool| result.records.iter().any(f);
    assert!(has(|r| r.process_id.is_some()), "no record carries a PID");
    assert!(has(|r| r.thread_id.is_some()), "no record carries a TID");
    assert!(has(|r| r.keywords.is_some()), "no record carries keywords");
}

#[test]
fn records_carry_event_fields() {
    let Some(result) = parsed() else { return };
    assert!(
        result.records.iter().any(|r| !r.event_data.is_empty()),
        "no record has any fields, so EventData and UserData were both missed"
    );
    for record in &result.records {
        for field in &record.event_data {
            assert!(!field.name.is_empty(), "a field was extracted with no name");
        }
    }
}

#[test]
fn the_xml_export_emits_the_provider_representation() {
    let Some(result) = parsed() else { return };
    // The export used to contain pretty-printed JSON under an <Events> root, which no XML consumer
    // could read.
    let exported = export_records(&result.records[..1], ExportFormat::Xml).expect("exports");
    assert!(
        exported.contains("<Event"),
        "export carries no event element"
    );
    assert!(
        !exported.contains("\"Event\":"),
        "export carries a JSON projection rather than XML"
    );
}

#[test]
fn a_healthy_capture_reports_no_gaps() {
    let Some(result) = parsed() else { return };
    // A gap report on a clean file would train an operator to ignore it, which is how a real gap
    // goes unnoticed. Not an unconditional invariant, though: a capture larger than the reader's
    // per-file cap legitimately reports being truncated, and that message is correct rather than a
    // false alarm. Anything else on a healthy file is not.
    let unexpected: Vec<&String> = result
        .error_messages
        .iter()
        .filter(|message| !message.contains("stopped at"))
        .collect();
    assert!(
        unexpected.is_empty(),
        "clean capture reported gaps: {unexpected:?}"
    );
    assert_eq!(result.total_records, result.records.len() as u64);
}

#[test]
fn records_are_ordered_by_time() {
    let Some(result) = parsed() else { return };
    let ordered = result
        .records
        .windows(2)
        .all(|pair| pair[0].timestamp_epoch <= pair[1].timestamp_epoch);
    assert!(ordered, "records are not sorted by timestamp");
}
