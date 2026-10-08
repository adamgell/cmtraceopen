use super::firewall::*;
use crate::parser::{parse_file_with_artifacts, NativeParseArtifacts};
use std::path::Path;

const HEADER: &str = "#Software: Microsoft Windows Firewall\n#Time Format: UTC\n#Fields: date time action protocol src-ip dst-ip src-port dst-port extra\n";
const ROW: &str = "2042-04-05 06:07:09 ALLOW TCP 192.0.2.11 203.0.113.21 41000 443 invented";
fn artifact(path: &Path, bytes: &[u8]) -> NativeParseArtifacts {
    std::fs::write(path, bytes).unwrap();
    parse_file_with_artifacts(path.to_str().unwrap()).unwrap()
}

#[test]
fn firewall_timeline_excludes_unplaced_before_counts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.log");
    let text = format!("{}{}\n", HEADER.replace("UTC", "Local"), ROW);
    let artifacts = artifact(&path, text.as_bytes());
    let indexed = index_firewall(&artifacts).unwrap();
    assert!(indexed.entries.is_empty());
    assert!(indexed.runtime.contexts.is_empty());
    assert_eq!(indexed.excluded, 1);
    let (timeline, _) = super::builder::build_timeline(
        &[super::builder::SourceRequest {
            path: path.to_string_lossy().into_owned(),
            display_name: None,
        }],
        0,
        vec![],
    )
    .unwrap();
    assert_eq!(timeline.bundle.total_entries, 0);
    assert_eq!(timeline.bundle.sources[0].firewall_excluded, Some(1));
    let mixed = format!(
        "{text}#Time Format: UTC\n{}\n{}\n#Time Format: unexpected\n{ROW}\n",
        ROW.replace("2042-04-05 06:07:09", "1970-01-01 00:00:00"),
        ROW.replace("2042-04-05", "2042-99-99")
    );
    let artifacts = artifact(&path, mixed.as_bytes());
    let indexed = index_firewall(&artifacts).unwrap();
    assert_eq!(indexed.entries.len(), 1);
    assert_eq!(indexed.entries[0].timestamp_ms, 0);
    assert_eq!(indexed.excluded, 3);
    let header_only = artifact(&path, HEADER.as_bytes());
    assert!(index_firewall(&header_only)
        .unwrap()
        .runtime
        .contexts
        .is_empty());
}

#[test]
fn firewall_timeline_retains_only_referenced_contexts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.log");
    let mut text = format!("{HEADER}{ROW}\n");
    for _ in 0..100 {
        text.push_str(&format!("#Time Format: Local\n{ROW}\n#Time Format: UTC\n"));
    }
    text.push_str(&format!("{ROW}\n#Fields: date time protocol action dst-ip src-ip dst-port src-port extra\n2042-04-05 06:07:10 UDP DROP 203.0.113.21 192.0.2.11 53 42000 reordered\n#Fields: date date\ninvalid\n#Software: Microsoft Windows Firewall\n{ROW}\n"));
    let artifacts = artifact(&path, text.as_bytes());
    let indexed = index_firewall(&artifacts).unwrap();
    assert_eq!(indexed.entries.len(), 3);
    assert_eq!(indexed.runtime.contexts.len(), 2);
    let mut session = FirewallReadSession::open(&path, &indexed.runtime).unwrap();
    for ei in &indexed.entries {
        let expected = artifacts
            .result
            .entries
            .iter()
            .find(|e| e.line_number == ei.line_number)
            .unwrap();
        let entry = materialize_firewall_entry(
            &mut session,
            indexed.runtime.context_at(ei.line_number).unwrap(),
            ei,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(entry).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
    }
}

#[test]
fn firewall_timeline_uses_snapshot_offsets_and_actual_encodings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.log");
    let text = format!(
        "{HEADER}\0\0{}\r\n",
        ROW.replace("invented", "invented-café")
    );
    let utf16 = |le: bool| {
        let mut bytes = if le {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        for u in text.encode_utf16() {
            bytes.extend(if le { u.to_le_bytes() } else { u.to_be_bytes() });
        }
        bytes
    };
    let cp = encoding_rs::WINDOWS_1252.encode(&text).0.into_owned();
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend(text.as_bytes());
    for bytes in [text.as_bytes().to_vec(), bom, utf16(true), utf16(false), cp] {
        let artifacts = artifact(&path, &bytes);
        let indexed = index_firewall(&artifacts).unwrap();
        assert_eq!(indexed.entries.len(), 1);
        let mut session = FirewallReadSession::open(&path, &indexed.runtime).unwrap();
        let ei = &indexed.entries[0];
        let entry = materialize_firewall_entry(
            &mut session,
            indexed.runtime.context_at(ei.line_number).unwrap(),
            ei,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(entry).unwrap(),
            serde_json::to_value(&artifacts.result.entries[0]).unwrap()
        );
    }
}

#[test]
fn firewall_timeline_reads_long_utf16_and_rejects_invalid_index_or_decode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.log");
    let text = format!("{HEADER}{}\n", ROW.replace("invented", &"x".repeat(40_000)));
    let mut bytes = vec![0xff, 0xfe];
    for u in text.encode_utf16() {
        bytes.extend(u.to_le_bytes());
    }
    let artifacts = artifact(&path, &bytes);
    let indexed = index_firewall(&artifacts).unwrap();
    let mut session = FirewallReadSession::open(&path, &indexed.runtime).unwrap();
    let ei = &indexed.entries[0];
    let ctx = indexed.runtime.context_at(ei.line_number).unwrap();
    let entry = materialize_firewall_entry(&mut session, ctx, ei).unwrap();
    assert_eq!(entry.firewall, artifacts.result.entries[0].firewall);
    let mut bad = ei.clone();
    bad.byte_offset += 1;
    assert!(matches!(
        materialize_firewall_entry(&mut session, ctx, &bad),
        Err(FirewallMaterializationError::InvalidIndexContext)
    ));
    assert!(matches!(
        materialize_firewall_entry(&mut session, &Default::default(), ei),
        Err(FirewallMaterializationError::InvalidIndexContext)
    ));
    // Same-identity in-place corruption is not claimed immutable; invalid decoding is still reported.
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(ei.byte_offset)).unwrap();
    file.write_all(&[0x00, 0xdc]).unwrap();
    assert!(matches!(
        materialize_firewall_entry(&mut session, ctx, ei),
        Err(FirewallMaterializationError::ReadDecodeFailure)
    ));
    let capped = artifact(
        &path,
        format!("{HEADER}{}\n", ROW.replace("invented", &"x".repeat(70_000))).as_bytes(),
    );
    let indexed = index_firewall(&capped).unwrap();
    assert!(indexed.entries.is_empty());
    assert_eq!(indexed.excluded, 1);
}

#[test]
fn firewall_timeline_validates_identity_once_per_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.log");
    let artifacts = artifact(&path, format!("{HEADER}{ROW}\n").as_bytes());
    let mut indexed = index_firewall(&artifacts).unwrap();
    let mut session = FirewallReadSession::open(&path, &indexed.runtime).unwrap();
    let replacement = dir.path().join("replacement.log");
    std::fs::write(
        &replacement,
        format!("{HEADER}{}\n", ROW.replace("ALLOW", "DROP")),
    )
    .unwrap();
    std::fs::rename(replacement, &path).unwrap();
    let ei = &indexed.entries[0];
    let entry = materialize_firewall_entry(
        &mut session,
        indexed.runtime.context_at(ei.line_number).unwrap(),
        ei,
    )
    .unwrap();
    assert_eq!(
        entry.firewall.as_ref().unwrap().field("action"),
        Some("ALLOW")
    );
    assert!(matches!(
        FirewallReadSession::open(&path, &indexed.runtime),
        Err(FirewallMaterializationError::SourceChanged)
    ));
    indexed.runtime.identity = None;
    assert!(matches!(
        FirewallReadSession::open(&path, &indexed.runtime),
        Err(FirewallMaterializationError::GenerationUnverifiable)
    ));
}

#[test]
fn firewall_query_and_detail_fail_instead_of_returning_partial_success() {
    use super::models::*;
    use super::query::{query_incident_details, query_timeline_entries, QueryContext};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.log");
    artifact(&path, format!("{HEADER}{ROW}\n{ROW}\n").as_bytes());
    let (mut timeline, runtimes) = super::builder::build_timeline(
        &[super::builder::SourceRequest {
            path: path.to_string_lossy().into_owned(),
            display_name: None,
        }],
        10,
        vec![],
    )
    .unwrap();
    let initial = query_timeline_entries(
        &QueryContext {
            timeline: &timeline,
            runtimes: &runtimes,
        },
        None,
        None,
        0,
        10,
    )
    .unwrap();
    assert_eq!(initial.len(), 2);
    // First row remains readable. The second index now fails after one success.
    timeline.indexes.get_mut(&0).unwrap()[1].byte_offset += 1;
    timeline.raw_signals = vec![0, 1]
        .into_iter()
        .map(|entry_ref| Signal {
            source_idx: 0,
            entry_ref,
            ts_ms: timeline.indexes[&0][0].timestamp_ms,
            kind: SignalKind::ErrorSeverity,
            correlation_id: None,
        })
        .collect();
    timeline.bundle.incidents = vec![Incident {
        id: 7,
        ts_start_ms: timeline.indexes[&0][0].timestamp_ms,
        ts_end_ms: timeline.indexes[&0][0].timestamp_ms,
        signal_count: 2,
        source_count: 1,
        confidence: 0.5,
        anchor_event_ref: None,
        anchor_guid: None,
        summary: "synthetic".into(),
    }];
    let ctx = QueryContext {
        timeline: &timeline,
        runtimes: &runtimes,
    };
    for failure in [
        query_timeline_entries(&ctx, None, None, 0, 10).unwrap_err(),
        query_incident_details(&ctx, 7).unwrap_err(),
    ] {
        assert!(matches!(
            failure,
            TimelineError::FirewallSource {
                reason: FirewallMaterializationError::InvalidIndexContext,
                ..
            }
        ));
    }
    // Correlation callbacks run only when a cluster has an IME GUID anchor.
    // Supply one so recomputation really reads row 0 before failing on row 1.
    let ts = timeline.indexes[&0][0].timestamp_ms;
    timeline.ime_events.insert(1, vec![serde_json::from_value(serde_json::json!({
        "id": 0, "eventType": "Win32App", "name": "Synthetic anchor", "guid": "11111111-2222-4333-8444-555555555555", "status": "Failed", "startTimeEpoch": ts,
        "detail": "Invented test event", "sourceFile": "/synthetic/ime.log", "lineNumber": 1
    })).unwrap()]);
    timeline.raw_signals.push(Signal {
        source_idx: 1,
        entry_ref: 0,
        ts_ms: ts,
        kind: SignalKind::ImeFailed,
        correlation_id: None,
    });
    let old = serde_json::to_value(&timeline.bundle).unwrap();
    let tunables = TimelineTunables {
        min_source_count: 1,
        ..Default::default()
    };
    assert!(super::query::recompute_tunables(&mut timeline, &runtimes, tunables).is_err());
    assert_eq!(serde_json::to_value(&timeline.bundle).unwrap(), old);
}

#[test]
fn firewall_legacy_callback_retains_first_error_and_sampling_aborts() {
    use super::query::MessageMaterializer;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.log");
    artifact(&path, format!("{HEADER}{ROW}\n{ROW}\n").as_bytes());
    let (mut timeline, runtimes) = super::builder::build_timeline(
        &[super::builder::SourceRequest {
            path: path.to_string_lossy().into_owned(),
            display_name: None,
        }],
        10,
        vec![],
    )
    .unwrap();
    timeline.indexes.get_mut(&0).unwrap()[1].byte_offset += 1;
    let adapter = MessageMaterializer::new(&runtimes, &timeline.indexes);
    assert!(adapter.message(0, 0).is_some());
    assert!(adapter.message(0, 1).is_none());
    assert!(adapter.finish().is_err());
    let adapter = MessageMaterializer::new(&runtimes, &timeline.indexes);
    assert!(super::builder::sample_source_messages(&timeline.indexes, 200, &adapter).is_err());
}
