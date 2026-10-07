//! Genuinely synthetic records: documentation address space and invented dates.
use super::firewall_source::*;
use super::*;
use cmtraceopen_parser::parser::firewall_stream::{apply_delta, FirewallStream};
use std::{
    fs::{File, OpenOptions},
    io::Write,
};

const SYNTHETIC: &str = "#Software: Microsoft Windows Firewall\r\n#Time Format: UTC\r\n#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid future\r\n\0\02042-04-05 06:07:09 ALLOW TCP 192.0.2.11 203.0.113.21 54001 443 60 S - - - - - - SEND 8801 café😀\r\n2042-04-05 06:07:10 DROP UDP 2001:db8::1 2001:db8::2 54002 53 72 - - - - - - - RECEIVE 8802 inventé";

fn encoded(text: &str, encoding: FirewallEncoding, bom: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    match encoding {
        FirewallEncoding::Utf8 => {
            if bom {
                bytes.extend_from_slice(&[0xef, 0xbb, 0xbf]);
            }
            bytes.extend_from_slice(text.as_bytes());
        }
        FirewallEncoding::Utf16Le | FirewallEncoding::Utf16Be => {
            let le = encoding == FirewallEncoding::Utf16Le;
            if bom {
                bytes.extend_from_slice(if le { &[0xff, 0xfe] } else { &[0xfe, 0xff] });
            }
            for unit in text.encode_utf16() {
                bytes.extend_from_slice(&if le {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
        }
        _ => unreachable!(),
    }
    bytes
}

fn parse_split(bytes: &[u8], split: usize) -> (String, Vec<RawLineSpan>, FirewallDecoder) {
    let mut decoder = FirewallDecoder::default();
    let mut stream = FirewallStream::new(0, 1);
    let mut rows = Vec::new();
    let mut spans = Vec::new();
    for (i, chunk) in [&bytes[..split], &bytes[split..]].iter().enumerate() {
        let decoded = decoder.push(chunk).unwrap();
        spans.extend(decoded.lines);
        apply_delta(&mut rows, stream.push_text(&decoded.text, "synthetic.log"));
        // Every split is a real initial EOF, not merely an internal chunk.
        apply_delta(&mut rows, stream.snapshot_eof("synthetic.log"));
        assert!(decoder.pending_bytes() <= 3, "split {split}, phase {i}");
        if decoder.encoding() == FirewallEncoding::Undetermined {
            assert!(decoder.pending_bytes() <= 2);
        }
    }
    if let Some(span) = decoder.pending_span() {
        spans.push(span);
    }
    (
        serde_json::to_string(&(rows, stream.coverage())).unwrap(),
        spans,
        decoder,
    )
}

#[test]
fn firewall_every_byte_split_snapshot_eof_preserves_rows_and_raw_spans() {
    for (encoding, bom) in [
        (FirewallEncoding::Utf8, false),
        (FirewallEncoding::Utf8, true),
        (FirewallEncoding::Utf16Le, true),
        (FirewallEncoding::Utf16Be, true),
    ] {
        let bytes = encoded(SYNTHETIC, encoding, bom);
        let expected = parse_split(&bytes, bytes.len());
        for split in 0..=bytes.len() {
            let actual = parse_split(&bytes, split);
            assert_eq!(actual.0, expected.0, "{encoding:?} split {split}");
            assert_eq!(actual.1, expected.1, "{encoding:?} raw split {split}");
            assert_eq!(actual.2.raw_offset(), bytes.len() as u64);
            assert_eq!(actual.2.encoding(), encoding);
        }
    }
}

#[test]
fn firewall_invalid_explicit_encoding_is_a_gap_and_does_not_commit() {
    for (prefix, invalid) in [
        (vec![0xef, 0xbb, 0xbf, b'A'], vec![0xff]),
        (vec![0xff, 0xfe, b'A', 0], vec![0x00, 0xdc]),
        (vec![0xfe, 0xff, 0, b'A'], vec![0xd8, 0, 0, b'B']),
    ] {
        let mut decoder = FirewallDecoder::default();
        decoder.push(&prefix).unwrap();
        let committed = decoder.clone();
        assert_eq!(
            decoder.push(&invalid).unwrap_err(),
            FirewallDecodeError::InvalidExplicitEncoding
        );
        assert_eq!(decoder, committed);
    }
    let mut decoder = FirewallDecoder::default();
    decoder.push(b"plain UTF-8 prefix").unwrap();
    let committed = decoder.clone();
    assert_eq!(
        decoder.push(&[0xff]).unwrap_err(),
        FirewallDecodeError::NeedsWindows1252
    );
    assert_eq!(decoder, committed);
}

#[test]
fn firewall_initial_windows1252_choice_and_pending_scalar_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("invented.log");
    let text = SYNTHETIC.replace('😀', "");
    let (bytes, _, errors) = encoding_rs::WINDOWS_1252.encode(&text);
    assert!(!errors);
    std::fs::write(&path, &bytes).unwrap();
    let artifacts = parse_file_with_artifacts(path.to_str().unwrap()).unwrap();
    let source = artifacts.firewall.unwrap();
    assert_eq!(source.decoder.encoding(), FirewallEncoding::Windows1252);
    assert_eq!(artifacts.result.byte_offset, bytes.len() as u64);
    assert!(artifacts.result.entries[0]
        .firewall
        .as_ref()
        .unwrap()
        .raw_line
        .contains("café"));

    for suffix in [vec![0xc3], vec![0xf0, 0x9f, 0x98]] {
        let mut raw = b"#Software: Microsoft Windows Firewall\n".to_vec();
        raw.extend(suffix.clone());
        std::fs::write(&path, &raw).unwrap();
        let artifacts = parse_file_with_artifacts(path.to_str().unwrap()).unwrap();
        let source = artifacts.firewall.unwrap();
        assert_eq!(source.decoder.encoding(), FirewallEncoding::Utf8);
        assert_eq!(source.decoder.pending_bytes(), suffix.len());
        assert_eq!(artifacts.result.byte_offset, raw.len() as u64);
        assert!(artifacts.result.entries.is_empty());
    }
}

#[test]
fn firewall_snapshot_uses_opened_handle_identity_and_consumed_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("invented.log");
    let prefix = "#Software: Microsoft Windows Firewall\n";
    std::fs::write(&path, prefix).unwrap();
    let file = File::open(&path).unwrap();
    let metadata = file.metadata().unwrap();
    let identity = crate::fs_identity::file_identity(&file, &metadata);
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(SYNTHETIC.as_bytes())
        .unwrap();
    std::fs::rename(&path, temp.path().join("old.log")).unwrap();
    std::fs::write(&path, "replacement unrelated content").unwrap();
    let artifacts =
        parse_opened_file_with_artifacts(file, metadata, path.to_str().unwrap()).unwrap();
    assert_eq!(artifacts.identity, identity);
    assert_eq!(
        artifacts.result.byte_offset,
        (prefix.len() + SYNTHETIC.len()) as u64
    );
    assert_eq!(artifacts.result.entries.len(), 2);
    assert!(artifacts.firewall.is_some());
}

#[test]
fn firewall_raw_utf16_span_can_exceed_decoded_line_cap() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("invented.log");
    let text = format!(
        "#Software: Microsoft Windows Firewall\n#Fields: future\n\0\0{}\n",
        "x".repeat(40_000)
    );
    let raw = encoded(&text, FirewallEncoding::Utf16Le, true);
    std::fs::write(&path, &raw).unwrap();
    let artifacts = parse_file_with_artifacts(path.to_str().unwrap()).unwrap();
    let source = artifacts.firewall.unwrap();
    let span = source
        .raw_spans
        .iter()
        .find(|s| s.line_number == 3)
        .unwrap();
    assert_eq!(span.end - span.start, 80_002);
    assert_eq!(
        &raw[span.start as usize..span.start as usize + 2],
        &[b'x', 0]
    );
    assert!(
        !artifacts.result.entries[0]
            .firewall
            .as_ref()
            .unwrap()
            .truncated
    );
    assert_eq!(artifacts.result.firewall_coverage.unwrap().padding.count, 2);
}
