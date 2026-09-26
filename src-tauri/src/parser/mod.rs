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
                    return Ok((result, selection, None));
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

    let (content, identity, file_size) = read_file_content_identified(path)?;
    let (result, selection) = cmtraceopen_parser::parser::parse_content(&content, path, file_size);
    Ok((result, selection, identity))
}

/// Read file content, handling BOM and encoding fallback.
pub fn read_file_content(path: &str) -> Result<String, String> {
    read_file_content_identified(path).map(|(content, _, _)| content)
}

/// Read file content together with the identity and length of the file that was
/// read, all three taken from one handle.
///
/// Tail reading needs the identity of the generation whose bytes produced
/// `byte_offset`. Taking it from a later `metadata(path)` call would describe
/// whatever the path points at by then, which is the replacement the identity
/// exists to notice.
pub fn read_file_content_identified(
    path: &str,
) -> Result<(String, Option<crate::fs_identity::FileIdentity>, u64), String> {
    use std::io::Read;

    let mut file =
        std::fs::File::open(path).map_err(|e| format!("Failed to read file {}: {}", path, e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to read file {}: {}", path, e))?;
    let identity = crate::fs_identity::file_identity(&file, &metadata);
    let file_size = metadata.len();

    let mut bytes = Vec::with_capacity(file_size.min(8 * 1024 * 1024) as usize);
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Failed to read file {}: {}", path, e))?;

    let encoding = detect_encoding(&bytes);
    Ok((decode_bytes(&bytes, encoding)?, identity, file_size))
}
