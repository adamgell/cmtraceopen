// src-tauri/src/parser — thin shim over cmtraceopen_parser::parser.
//
// The pure parser lives in the cmtraceopen-parser crate (targets native + wasm32).
// This module adds the native-only concerns the desktop app needs:
//   - filesystem reads with BOM detection + Windows-1252 fallback
//   - EVTX / ETL binary-file special cases (dns_audit routes DNS audit EVTXs)
//
// Everything else (format detection, per-format parsing, encoding helpers, entry
// annotation) is re-exported from the crate so existing call sites that reference
// `crate::parser::*` or `app_lib::parser::*` keep resolving unchanged.

pub use cmtraceopen_parser::parser::*;
pub mod firewall_source;

#[cfg(feature = "event-log")]
pub mod dns_audit;

use crate::models::log_entry::ParseResult;
use std::path::Path;

/// Parse a log file from disk, auto-detecting its format.
///
/// Handles the native-only paths (ETL rejection, DNS EVTX routing under the
/// `event-log` feature), then reads the file, decodes it, and delegates text
/// parsing to `cmtraceopen_parser::parser::parse_content`.
pub fn parse_file(path: &str) -> Result<(ParseResult, ResolvedParser), String> {
    parse_file_identified(path).map(|(result, selection, _)| (result, selection))
}

/// Parse a file and report the identity of the file that was read.
///
/// Tail reading needs this: the identity of the generation whose bytes produced
/// `byte_offset` is the only thing that can tell a replacement from an append
/// when the replacement is larger than that offset. It is `None` where it cannot
/// come from the same read as the bytes (an EVTX goes through its own reader),
/// and callers must treat `None` as unknown rather than as a replacement.
pub fn parse_file_identified(
    path: &str,
) -> Result<
    (
        ParseResult,
        ResolvedParser,
        Option<crate::fs_identity::FileIdentity>,
    ),
    String,
> {
    parse_file_with_artifacts(path).map(|a| (a.result, a.selection, a.identity))
}

pub struct NativeParseArtifacts {
    pub result: ParseResult,
    pub selection: ResolvedParser,
    pub identity: Option<crate::fs_identity::FileIdentity>,
    pub firewall: Option<firewall_source::FirewallSourceSnapshot>,
}

/// Parse once from a single opened handle and retain firewall continuation/index artifacts.
pub fn parse_file_with_artifacts(path: &str) -> Result<NativeParseArtifacts, String> {
    let path_obj = Path::new(path);

    // Binary file detection by extension — intercept before text decoding
    if let Some(ext) = path_obj.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();

        if ext_lower == "etl" {
            #[cfg(target_os = "windows")]
            return Err(
                "ETL analytical logs are not yet supported. Convert to XML with: \
                 tracerpt \"<file>\" -of XML -o output.xml — then open the XML file."
                    .to_string(),
            );
            #[cfg(not(target_os = "windows"))]
            return Err(
                "ETL files contain binary Windows event traces that require the Windows \
                 tracerpt tool to convert. Export to XML on a Windows machine first, \
                 then open the XML file here."
                    .to_string(),
            );
        }

        if ext_lower == "evtx" {
            #[cfg(feature = "event-log")]
            {
                if dns_audit::is_dns_evtx(path_obj) {
                    let result = dns_audit::parse_evtx(path)?;
                    let selection = ResolvedParser::dns_audit();
                    // The EVTX reader opens its own handle, so no identity is claimed
                    // for it rather than one that might describe a later file.
                    return Ok(NativeParseArtifacts {
                        result,
                        selection,
                        identity: None,
                        firewall: None,
                    });
                }
                return Err("This EVTX file does not contain DNS audit events. \
                     Try opening it in the Sysmon workspace instead."
                    .to_string());
            }
            #[cfg(not(feature = "event-log"))]
            return Err("EVTX event log files require the 'event-log' feature. \
                 This build does not include EVTX support."
                .to_string());
        }
    }

    let file = std::fs::File::open(path).map_err(|e| format!("Failed to read file {path}: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to read file {path}: {e}"))?;
    parse_opened_file_with_artifacts(file, metadata, path)
}

fn parse_opened_file_with_artifacts(
    mut file: std::fs::File,
    metadata: std::fs::Metadata,
    path: &str,
) -> Result<NativeParseArtifacts, String> {
    use std::io::Read;
    let identity = crate::fs_identity::file_identity(&file, &metadata);
    let modified_unix_ms = crate::commands::file_ops::metadata_modified_unix_ms(&metadata);
    let mut bytes = Vec::with_capacity(metadata.len().min(8 * 1024 * 1024) as usize);
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Failed to read file {path}: {e}"))?;
    // The existing decoder is used only for format selection here. Firewall
    // publication uses the strict resumable decoder below; other formats retain
    // their existing decoding behavior, including CRLF normalization.
    let content = decode_bytes(&bytes, detect_encoding(&bytes))?;
    let selection = detect::detect_parser(path, &content);
    let (mut result, firewall) =
        if selection.parser == crate::models::log_entry::ParserKind::WindowsFirewall {
            drop(content);
            let (result, snapshot) = firewall_source::snapshot_bytes(&bytes, path, 0, false)
                .map_err(|e| e.to_string())?;
            (result, Some(snapshot))
        } else {
            (
                cmtraceopen_parser::parser::parse_content(&content, path, bytes.len() as u64).0,
                None,
            )
        };
    result.modified_unix_ms = modified_unix_ms;
    Ok(NativeParseArtifacts {
        result,
        selection,
        identity,
        firewall,
    })
}

/// Read file content, handling BOM and encoding fallback.
pub fn read_file_content(path: &str) -> Result<String, String> {
    read_file_content_identified(path).map(|(content, _, _, _)| content)
}

/// Read file content, identity, consumed byte count, and modification time
/// from one opened handle.
///
/// Tail reading needs the identity of the generation whose bytes produced
/// `byte_offset`. Taking it from a later `metadata(path)` call would describe
/// whatever the path points at by then, which is the replacement the identity
/// exists to notice.
pub fn read_file_content_identified(
    path: &str,
) -> Result<
    (
        String,
        Option<crate::fs_identity::FileIdentity>,
        u64,
        Option<u64>,
    ),
    String,
> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("Failed to read file {}: {}", path, e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to read file {}: {}", path, e))?;
    read_opened_file_content(file, metadata, path)
}

// The metadata must come from this handle, whose cursor is still at byte zero.
// Keeping the opened-file read separate lets tests interleave a writer after
// metadata capture without depending on thread scheduling.
fn read_opened_file_content(
    mut file: std::fs::File,
    metadata: std::fs::Metadata,
    path: &str,
) -> Result<
    (
        String,
        Option<crate::fs_identity::FileIdentity>,
        u64,
        Option<u64>,
    ),
    String,
> {
    use std::io::Read;

    let identity = crate::fs_identity::file_identity(&file, &metadata);
    let file_size = metadata.len();
    let modified_unix_ms = crate::commands::file_ops::metadata_modified_unix_ms(&metadata);

    let mut bytes = Vec::with_capacity(file_size.min(8 * 1024 * 1024) as usize);
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Failed to read file {}: {}", path, e))?;

    // The file can grow or shrink after metadata capture. Tail from the bytes
    // actually consumed, not the earlier size or the decoded string's length
    // (which excludes the BOM and changes with UTF-16/Windows-1252 decoding).
    let bytes_read = bytes.len() as u64;
    let encoding = detect_encoding(&bytes);
    Ok((
        decode_bytes(&bytes, encoding)?,
        identity,
        bytes_read,
        modified_unix_ms,
    ))
}

#[cfg(test)]
mod handoff_tests {
    use super::*;
    use crate::watcher::tail::TailReader;
    use std::fs::{File, OpenOptions};
    use std::io::Write;

    // Transform checked-in corpus records; do not invent a log grammar.
    const CORPUS: &str = include_str!("../../tests/corpus/simple/clean/basic.log");

    fn encoded(text: &str, encoding: FileEncoding, bom: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        match encoding {
            FileEncoding::Utf8 => {
                if bom {
                    bytes.extend_from_slice(&[0xef, 0xbb, 0xbf]);
                }
                bytes.extend_from_slice(text.as_bytes());
            }
            FileEncoding::Utf16Le | FileEncoding::Utf16Be => {
                let little_endian = matches!(encoding, FileEncoding::Utf16Le);
                if bom {
                    bytes.extend_from_slice(if little_endian {
                        &[0xff, 0xfe]
                    } else {
                        &[0xfe, 0xff]
                    });
                }
                for unit in text.replace('\n', "\r\n").encode_utf16() {
                    bytes.extend_from_slice(&if little_endian {
                        unit.to_le_bytes()
                    } else {
                        unit.to_be_bytes()
                    });
                }
            }
        }
        bytes
    }

    #[test]
    fn growth_after_metadata_does_not_replay_initial_records_at_tail_handoff() {
        for (encoding, bom) in [
            (FileEncoding::Utf8, false),
            (FileEncoding::Utf8, true),
            (FileEncoding::Utf16Le, true),
            (FileEncoding::Utf16Be, true),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("basic.log");
            let lines: Vec<_> = CORPUS.lines().map(|line| format!("{line}\n")).collect();
            let initial = encoded(&lines[0], encoding, bom);
            let during_read = encoded(&lines[1], encoding, false);
            std::fs::write(&path, &initial).unwrap();
            let file = File::open(&path).unwrap();
            let metadata = file.metadata().unwrap();
            let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
            writer.write_all(&during_read).unwrap();

            // Deterministic interleaving: metadata precedes the append; the
            // production read helper runs afterwards on the original handle.
            let (content, identity, consumed, _) =
                read_opened_file_content(file, metadata, path.to_str().unwrap()).unwrap();
            let (parsed, selection) = parse_content(&content, path.to_str().unwrap(), consumed);
            assert_eq!(parsed.entries.len(), 2);
            let mut tail = TailReader::new(
                path.clone(),
                parsed.byte_offset,
                selection,
                parsed.entries.len() as u64,
                parsed.total_lines + 1,
            );
            tail.seed_file_identity(identity);
            let batch = tail.read_new_entries().unwrap();
            assert!(!batch.reset);
            assert!(
                batch.entries.is_empty(),
                "initially parsed records must not replay"
            );
            assert_eq!(consumed, (initial.len() + during_read.len()) as u64);

            writer
                .write_all(&encoded(&lines[2], encoding, false))
                .unwrap();
            let batch = tail.read_new_entries().unwrap();
            assert!(!batch.reset);
            assert_eq!(batch.entries.len(), 1);
            assert_eq!(batch.entries[0].line_number, 3);
            assert_eq!(batch.entries[0].message, "Error: connection failed");
        }
    }

    #[test]
    fn modified_time_belongs_to_the_opened_file_after_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("basic.log");
        std::fs::write(&path, CORPUS).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_times(
            std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            ),
        )
        .unwrap();
        let metadata = file.metadata().unwrap();
        let expected_identity = crate::fs_identity::file_identity(&file, &metadata);
        std::fs::rename(&path, temp.path().join("old.log")).unwrap();
        std::fs::write(&path, CORPUS.repeat(2)).unwrap();
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000),
            ))
            .unwrap();

        let (content, identity, consumed, modified_unix_ms) =
            read_opened_file_content(file, metadata, path.to_str().unwrap()).unwrap();

        assert_eq!(content, CORPUS);
        assert_eq!(identity, expected_identity);
        assert_eq!(consumed, CORPUS.len() as u64);
        assert_eq!(modified_unix_ms, Some(1_700_000_000_000));
    }

    #[test]
    fn unchanged_public_read_preserves_raw_size_and_identity() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("basic.log");
        std::fs::write(&path, CORPUS).unwrap();
        let (parsed, _, identity) = parse_file_identified(path.to_str().unwrap()).unwrap();
        let file = File::open(&path).unwrap();
        let expected_identity = crate::fs_identity::file_identity(&file, &file.metadata().unwrap());
        assert_eq!(parsed.byte_offset, CORPUS.len() as u64);
        assert_eq!(parsed.file_size, CORPUS.len() as u64);
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(identity, expected_identity);
    }

    #[test]
    fn windows_1252_offset_counts_source_bytes_not_decoded_utf8() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("basic.log");
        // Add a non-ASCII character to the existing corpus message, then encode
        // it as Windows-1252 so decoding changes its byte count.
        let expected = CORPUS.replace("policy update", "policy update €");
        let (bytes, _, had_errors) = encoding_rs::WINDOWS_1252.encode(&expected);
        assert!(!had_errors);
        assert_ne!(bytes.len(), expected.len());
        std::fs::write(&path, &bytes).unwrap();
        let (content, _, consumed, _) =
            read_file_content_identified(path.to_str().unwrap()).unwrap();
        assert_eq!(content, expected);
        assert_eq!(consumed, bytes.len() as u64);
    }

    #[test]
    fn shrink_after_metadata_reports_only_consumed_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("basic.log");
        std::fs::write(&path, CORPUS).unwrap();
        let file = File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        let first = CORPUS.split_inclusive('\n').next().unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(first.len() as u64)
            .unwrap();
        let (content, _, consumed, _) =
            read_opened_file_content(file, metadata, path.to_str().unwrap()).unwrap();
        assert_eq!(content, first);
        assert_eq!(consumed, first.len() as u64);
    }
}

#[cfg(test)]
mod firewall_source_tests;
