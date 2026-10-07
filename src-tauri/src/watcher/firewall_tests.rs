use super::firewall::*;
use crate::parser::{firewall_source::*, parse_file_with_artifacts};
use std::{fs::OpenOptions, io::Write, path::Path};

const HEADER: &str = "#Software: Microsoft Windows Firewall\n#Time Format: UTC\n#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid future\n";
const ROW: &str = "2042-04-05 06:07:09 ALLOW TCP 192.0.2.11 203.0.113.21 54001 443 60 S - - - - - - SEND 8801 café";
fn owner(path: &Path) -> FirewallOwner {
    let a = parse_file_with_artifacts(path.to_str().unwrap()).unwrap();
    FirewallOwner::new(a.firewall.unwrap(), a.identity)
}
fn token(owner: &FirewallOwner, epoch: u64) -> FirewallControlToken {
    FirewallControlToken {
        source_session_id: owner.session_id.clone(),
        watch_epoch: epoch,
    }
}
fn append(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}
fn fixture() -> (tempfile::TempDir, std::path::PathBuf, FirewallOwner) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.log");
    std::fs::write(&path, HEADER).unwrap();
    let source = owner(&path);
    (dir, path, source)
}

#[test]
fn firewall_stale_start_cannot_stop_new_watch() {
    let (_dir, _path, mut source) = fixture();
    let newer = token(&source, 4);
    let older = token(&source, 3);
    assert_eq!(source.start(Some(&newer)), StartAdmission::Started);
    assert_eq!(source.start(Some(&newer)), StartAdmission::Current);
    assert_eq!(source.start(Some(&older)), StartAdmission::Rejected);
    assert_eq!(source.start(None), StartAdmission::Rejected);
    assert!(!source.stop(Some(&older)));
    assert!(source.request(&newer).is_some());
}
#[test]
fn firewall_stop_before_start_cancels_epoch() {
    let (_dir, _path, mut source) = fixture();
    let cancelled = token(&source, 8);
    assert!(source.stop(Some(&cancelled)));
    assert_eq!(source.start(Some(&cancelled)), StartAdmission::Rejected);
    let next = token(&source, 9);
    assert_eq!(source.start(Some(&next)), StartAdmission::Started);
}
#[test]
fn firewall_old_session_controls_are_noops() {
    let (_dir, path, first) = fixture();
    let old = token(&first, 999);
    let mut reopened = owner(&path);
    let current = token(&reopened, 1);
    reopened.start(Some(&current));
    assert_eq!(reopened.start(Some(&old)), StartAdmission::Rejected);
    assert!(!reopened.stop(Some(&old)));
    assert!(!reopened.set_paused(Some(&old), true));
    assert!(!reopened.set_paused(None, true));
    assert!(reopened.request(&current).is_some());
}
#[test]
fn firewall_candidate_commit_checks_current_owner() {
    let (_dir, path, mut first) = fixture();
    let old = token(&first, 1);
    first.start(Some(&old));
    append(&path, format!("{ROW}\n").as_bytes());
    let request = first.request(&old).unwrap();
    let outcome = read_candidate(&request, &path);
    let state = crate::state::app_state::AppState::new(vec![]);
    let mut reopened = owner(&path);
    let current = token(&reopened, 1);
    reopened.start(Some(&current));
    let before = reopened.checkpoint.decoder.raw_offset();
    state.open_files.lock().unwrap().insert(
        path.clone(),
        crate::state::app_state::OpenFile {
            path: path.clone(),
            parser_selection: crate::parser::ResolvedParser::windows_firewall(),
            initial_logical_record: None,
            byte_offset: before,
            file_identity: reopened.checkpoint.identity,
            firewall: Some(reopened),
        },
    );
    let mut published = Vec::new();
    assert!(
        !commit_current(&state, &path, &old, request.revision, outcome, |batch| {
            published.push(batch)
        })
        .unwrap()
    );
    assert!(published.is_empty());
    assert_eq!(
        state.open_files.lock().unwrap()[&path]
            .firewall
            .as_ref()
            .unwrap()
            .checkpoint
            .decoder
            .raw_offset(),
        before
    );

    let request = state.open_files.lock().unwrap()[&path]
        .firewall
        .as_ref()
        .unwrap()
        .request(&current)
        .unwrap();
    append(&path, format!("{ROW}\n").as_bytes());
    let outcome = read_candidate(&request, &path);
    assert!(
        commit_current(&state, &path, &current, request.revision, outcome, |_| {
            // Publication runs while the current-owner lock is held.
            assert!(state.open_files.try_lock().is_err());
        })
        .unwrap()
    );
}
#[test]
fn firewall_pause_stop_and_resume_retain_latest_checkpoint() {
    let (_dir, path, mut source) = fixture();
    let t = token(&source, 1);
    source.start(Some(&t));
    append(&path, ROW.as_bytes());
    let r = source.request(&t).unwrap();
    let outcome = read_candidate(&r, &path);
    assert!(source.commit(&t, r.revision, outcome, |_| {}));
    let offset = source.checkpoint.decoder.raw_offset();
    source.set_paused(Some(&t), true);
    assert!(source.request(&t).is_none());
    source.set_paused(Some(&t), false);
    source.stop(Some(&t));
    let t2 = token(&source, 2);
    source.start(Some(&t2));
    assert_eq!(source.checkpoint.decoder.raw_offset(), offset);
    append(&path, b"\n");
    let r = source.request(&t2).unwrap();
    let outcome = read_candidate(&r, &path);
    source.commit(&t2, r.revision, outcome, |batch| {
        assert_eq!(batch.entries.len(), 1);
        assert_eq!(batch.entries[0].firewall.as_ref().unwrap().raw_line, ROW);
        assert!(!batch.reset);
    });
}
#[test]
fn firewall_replacement_failure_keeps_reset_owed_and_empty_reset_clears_view() {
    let (dir, path, mut source) = fixture();
    let t = token(&source, 1);
    source.start(Some(&t));
    let old_offset = source.checkpoint.decoder.raw_offset();
    std::fs::rename(&path, dir.path().join("old.log")).unwrap();
    std::fs::write(&path, format!("{HEADER}{ROW}\n{ROW}\n")).unwrap();
    let request = source.request(&t).unwrap();
    let failed = read_candidate_with(&request, &path, |_, _, _| {
        Err(std::io::ErrorKind::Other.into())
    });
    source.commit(&t, request.revision, failed, |batch| {
        assert_eq!(batch.decoding.kind, FirewallDecodingKind::Gap)
    });
    assert_eq!(source.checkpoint.decoder.raw_offset(), old_offset);
    assert_eq!(source.pending, Some(FirewallTransition::Generation));
    let request = source.request(&t).unwrap();
    let outcome = read_candidate(&request, &path);
    source.commit(&t, request.revision, outcome, |batch| {
        assert!(batch.reset);
        assert_eq!(batch.entries.len(), 2);
    });
    let next_id = source.checkpoint.stream.next_id();
    std::fs::write(&path, b"").unwrap();
    let request = source.request(&t).unwrap();
    let outcome = read_candidate(&request, &path);
    source.commit(&t, request.revision, outcome, |batch| {
        assert!(batch.reset);
        assert!(batch.entries.is_empty());
    });
    assert_eq!(source.checkpoint.stream.next_id(), next_id);
    assert_eq!(source.checkpoint.stream.next_line(), 1);
    assert_eq!(
        source.checkpoint.decoder.encoding(),
        FirewallEncoding::Undetermined
    );
    append(&path, format!("{HEADER}{ROW}\n").as_bytes());
    let request = source.request(&t).unwrap();
    let outcome = read_candidate(&request, &path);
    source.commit(&t, request.revision, outcome, |batch| {
        assert_eq!(batch.entries[0].id, next_id);
        assert_eq!(batch.entries[0].line_number, 4);
    });
}
#[test]
fn firewall_late_invalid_utf8_resets_once_to_cp1252() {
    let (_dir, path, mut source) = fixture();
    let t = token(&source, 1);
    source.start(Some(&t));
    let (raw, _, _) = encoding_rs::WINDOWS_1252.encode(ROW);
    append(&path, &raw);
    append(&path, b"\n");
    let request = source.request(&t).unwrap();
    let mut calls = 0;
    let failed = read_candidate_with(&request, &path, |file, out, limit| {
        calls += 1;
        if calls == 2 {
            return Err(std::io::ErrorKind::Other.into());
        }
        read_bytes(file, out, limit)
    });
    source.commit(&t, request.revision, failed, |batch| {
        assert_eq!(batch.decoding.kind, FirewallDecodingKind::Gap)
    });
    assert_eq!(source.checkpoint.decoder.raw_offset(), HEADER.len() as u64);
    assert_eq!(source.pending, Some(FirewallTransition::Windows1252));
    let request = source.request(&t).unwrap();
    let outcome = read_candidate(&request, &path);
    source.commit(&t, request.revision, outcome, |batch| {
        assert!(batch.reset);
        assert_eq!(batch.entries[0].firewall.as_ref().unwrap().raw_line, ROW);
    });
    assert_eq!(
        source.checkpoint.decoder.encoding(),
        FirewallEncoding::Windows1252
    );
    append(&path, b"\n");
    let request = source.request(&t).unwrap();
    let outcome = read_candidate(&request, &path);
    source.commit(&t, request.revision, outcome, |batch| assert!(!batch.reset));
}
#[test]
fn firewall_windows1252_every_initial_eof_split_converges() {
    let text = format!("{HEADER}{ROW}\n");
    let (raw, _, _) = encoding_rs::WINDOWS_1252.encode(&text);
    let expected = snapshot_bytes(&raw, "synthetic", 0, false)
        .unwrap()
        .0
        .entries;
    for split in 0..=raw.len() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.log");
        std::fs::write(&path, &raw[..split]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let identity = crate::fs_identity::file_identity(&file, &file.metadata().unwrap());
        let (result, snapshot) =
            snapshot_bytes(&raw[..split], path.to_str().unwrap(), 0, false).unwrap();
        let mut rows = result.entries;
        let mut source = FirewallOwner::new(snapshot, identity);
        let t = token(&source, 1);
        source.start(Some(&t));
        append(&path, &raw[split..]);
        let request = source.request(&t).unwrap();
        let outcome = read_candidate(&request, &path);
        source.commit(&t, request.revision, outcome, |batch| {
            if batch.reset {
                rows.clear();
            }
            rows.extend(batch.entries);
            for r in batch.replacements {
                *rows
                    .iter_mut()
                    .find(|e| e.id == r.expected_id && e.line_number == r.expected_line_number)
                    .unwrap() = r.entry;
            }
        });
        assert_eq!(rows.len(), expected.len(), "split{split}");
        assert_eq!(rows[0].firewall, expected[0].firewall, "split{split}");
        assert_eq!(source.checkpoint.decoder.raw_offset(), raw.len() as u64);
        assert_eq!(
            source.checkpoint.decoder.encoding(),
            FirewallEncoding::Windows1252
        );
    }
}
#[test]
fn firewall_explicit_decode_gap_keeps_cursor() {
    let (_dir, path, _) = fixture();
    let mut bytes = vec![0xef, 0xbb, 0xbf];
    bytes.extend_from_slice(HEADER.as_bytes());
    std::fs::write(&path, &bytes).unwrap();
    let mut source = owner(&path);
    let t = token(&source, 1);
    source.start(Some(&t));
    append(&path, &[0xff]);
    for _ in 0..2 {
        let r = source.request(&t).unwrap();
        let outcome = read_candidate(&r, &path);
        source.commit(&t, r.revision, outcome, |batch| {
            assert_eq!(batch.decoding.kind, FirewallDecodingKind::Gap);
            assert!(!batch.reset);
        });
        assert_eq!(source.checkpoint.decoder.raw_offset(), bytes.len() as u64);
        assert_eq!(source.checkpoint.decoder.encoding(), FirewallEncoding::Utf8);
    }
}

#[test]
fn firewall_stop_start_preserves_utf16_surrogate_and_provisional_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.log");
    let text = format!("{HEADER}{ROW}😀");
    let mut raw = vec![0xff, 0xfe];
    for unit in text.encode_utf16() {
        raw.extend_from_slice(&unit.to_le_bytes());
    }
    let split = raw.len() - 2;
    std::fs::write(&path, &raw[..split]).unwrap();
    let a = parse_file_with_artifacts(path.to_str().unwrap()).unwrap();
    let initial_id = a.result.entries[0].id;
    let mut source = FirewallOwner::new(a.firewall.unwrap(), a.identity);
    assert_eq!(source.checkpoint.decoder.pending_bytes(), 2);
    let t = token(&source, 1);
    source.start(Some(&t));
    append(&path, &raw[split..split + 1]);
    let r = source.request(&t).unwrap();
    let outcome = read_candidate(&r, &path);
    source.commit(&t, r.revision, outcome, |_| {});
    assert_eq!(source.checkpoint.decoder.pending_bytes(), 3);
    source.set_paused(Some(&t), true);
    source.set_paused(Some(&t), false);
    source.stop(Some(&t));
    let next = token(&source, 2);
    source.start(Some(&next));
    append(&path, &raw[split + 1..]);
    append(&path, &[b'\n', 0]);
    let r = source.request(&next).unwrap();
    let outcome = read_candidate(&r, &path);
    source.commit(&next, r.revision, outcome, |batch| {
        assert!(batch.entries.is_empty());
        assert_eq!(batch.replacements.len(), 1);
        assert_eq!(batch.replacements[0].expected_id, initial_id);
        assert_eq!(
            batch.replacements[0]
                .entry
                .firewall
                .as_ref()
                .unwrap()
                .raw_line,
            format!("{ROW}😀")
        );
        assert_eq!(batch.decoding.kind, FirewallDecodingKind::Ready);
    });
}
#[test]
fn firewall_incremental_reads_and_padding_state_remain_bounded() {
    let (_dir, path, mut source) = fixture();
    let t = token(&source, 1);
    source.start(Some(&t));
    append(&path, &vec![0; 1024 * 1024]);
    append(&path, format!("{ROW}\n").as_bytes());
    let end = std::fs::metadata(&path).unwrap().len();
    let mut count = 0;
    while source.checkpoint.decoder.raw_offset() < end {
        let before = source.checkpoint.decoder.raw_offset();
        let r = source.request(&t).unwrap();
        let outcome = read_candidate_with(&r, &path, |file, out, limit| {
            assert_eq!(limit, Some(FIREWALL_READ_CHUNK_BYTES));
            read_bytes(file, out, limit)
        });
        source.commit(&t, r.revision, outcome, |batch| {
            count += batch.entries.len()
        });
        assert!(
            source.checkpoint.decoder.raw_offset() - before <= FIREWALL_READ_CHUNK_BYTES as u64
        );
        assert!(source.checkpoint.stream.retained_text_bytes() <= 65_536);
    }
    assert_eq!(count, 1);
    assert_eq!(
        source.checkpoint.stream.coverage().padding.count,
        1024 * 1024
    );
}
#[test]
fn firewall_unknown_identity_does_not_assert_replacement_or_allow_unverified_fallback() {
    let (_dir, path, mut source) = fixture();
    source.checkpoint.identity = None;
    let t = token(&source, 1);
    source.start(Some(&t));
    append(&path, b"ASCII\n");
    let r = source.request(&t).unwrap();
    let outcome = read_candidate(&r, &path);
    source.commit(&t, r.revision, outcome, |batch| assert!(!batch.reset));
    let before = source.checkpoint.decoder.raw_offset();
    append(&path, &[0xe9, b'\n']);
    let r = source.request(&t).unwrap();
    let outcome = read_candidate(&r, &path);
    source.commit(&t, r.revision, outcome, |batch| {
        assert_eq!(
            batch.decoding.reason,
            Some(FirewallGapReason::GenerationUnverifiable)
        );
    });
    assert_eq!(source.checkpoint.decoder.raw_offset(), before);
    assert_eq!(source.pending, Some(FirewallTransition::Windows1252));
}
