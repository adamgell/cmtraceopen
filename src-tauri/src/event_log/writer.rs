use std::borrow::Borrow;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::export::{self, ExportFormat};
use super::models::EvtxRecord;
use quick_xml::XmlVersion;

#[cfg(test)]
use super::models::EvtxLevel;
#[cfg(test)]
use std::io::Cursor;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(all(test, unix))]
use std::os::unix::fs::PermissionsExt;

#[cfg(not(target_os = "windows"))]
fn replace_destination(temporary: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temporary, destination)
}

#[cfg(target_os = "windows")]
fn replace_destination(temporary: &Path, destination: &Path) -> io::Result<()> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let temporary_wide: Vec<u16> = temporary.as_os_str().encode_wide().chain(once(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(once(0))
        .collect();
    unsafe {
        MoveFileExW(
            PCWSTR(temporary_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|error| io::Error::other(error.to_string()))
}

/// Counts bytes and records while forwarding writes to the selected sink.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportStats {
    pub bytes: u64,
    pub records: u64,
}

struct CountingWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    bytes: u64,
}

impl<W: Write + ?Sized> Write for CountingWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.bytes = self.bytes.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn create_staging_file(path: &Path) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}
struct StagedFile {
    path: PathBuf,
    file: Option<std::fs::File>,
    cleanup: bool,
}

impl StagedFile {
    fn file_mut(&mut self) -> &mut std::fs::File {
        self.file.as_mut().expect("staged file handle")
    }

    fn close(&mut self) {
        self.file.take();
    }

    fn disarm_cleanup(&mut self) {
        self.cleanup = false;
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_staged_file<F>(
    directory: &Path,
    candidate_name: F,
    create_error: &str,
    exhausted_error: &str,
) -> Result<StagedFile, String>
where
    F: Fn(u32) -> String,
{
    for attempt in 0..100u32 {
        let candidate = directory.join(candidate_name(attempt));
        match create_staging_file(&candidate) {
            Ok(handle) => {
                return Ok(StagedFile {
                    path: candidate,
                    file: Some(handle),
                    cleanup: true,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("{create_error}: {error}")),
        }
    }
    Err(exhausted_error.to_owned())
}

fn write_to_staged_destination<F>(path: &Path, write: F) -> Result<ExportStats, String>
where
    F: FnOnce(&mut std::fs::File) -> Result<ExportStats, String>,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("events");
    let mut staged = create_staged_file(
        parent,
        |attempt| format!(".{name}.tmp-{}-{attempt}", std::process::id()),
        "cannot create temporary output",
        "cannot allocate temporary output path",
    )?;
    let result = write(staged.file_mut());
    staged.close();
    match result {
        Ok(stats) => match replace_destination(&staged.path, path) {
            Ok(()) => {
                staged.disarm_cleanup();
                Ok(stats)
            }
            Err(error) => Err(format!("cannot replace {}: {error}", path.display())),
        },
        Err(error) => Err(error),
    }
}

fn io_other(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn write_delimited_row<W: Write>(
    writer: &mut W,
    cells: impl Iterator<Item = String>,
    delimiter: char,
) -> io::Result<()> {
    let mut first = true;
    for cell in cells {
        if !first {
            writer.write_all(&[delimiter as u8])?;
        }
        first = false;
        writer.write_all(export::escape_delimited(&cell, delimiter).as_bytes())?;
    }
    writer.write_all(b"\n")
}

fn write_html_row<W: Write>(
    writer: &mut W,
    cells: impl Iterator<Item = String>,
    header: bool,
) -> io::Result<()> {
    writer.write_all(b"<tr>")?;
    for cell in cells {
        let (open, close) = if header {
            (b"<th>" as &[u8], b"</th>" as &[u8])
        } else {
            (b"<td>" as &[u8], b"</td>" as &[u8])
        };
        writer.write_all(open)?;
        writer.write_all(html_escape(&cell).as_bytes())?;
        writer.write_all(close)?;
    }
    writer.write_all(b"</tr>\n")
}

fn invalid_raw_xml(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_comment(comment: quick_xml::events::BytesText<'_>) -> bool {
    let bytes = comment.into_inner();
    bytes.windows(2).any(|pair| pair == b"--")
        || bytes.last() == Some(&b'-')
        || has_invalid_xml_code_point(&bytes)
}

fn has_invalid_xml_code_point(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .map(|value| {
            value
                .chars()
                .any(|character| !valid_xml_code_point(character as u32))
        })
        .unwrap_or(true)
}

fn valid_xml_code_point(value: u32) -> bool {
    value <= 0x10_FFFF
        && !(0xD800..=0xDFFF).contains(&value)
        && !(0xFFFE..=0xFFFF).contains(&value)
        && !matches!(value, 0x00..=0x08 | 0x0B..=0x0C | 0x0E..=0x1F)
}

fn valid_xml_name(name: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    valid_xml_name_start(first) && characters.all(valid_xml_name_char)
}

fn valid_xml_name_start(character: char) -> bool {
    matches!(
        character as u32,
        0x3A
            | 0x41..=0x5A
            | 0x5F
            | 0x61..=0x7A
            | 0xC0..=0xD6
            | 0xD8..=0xF6
            | 0xF8..=0x2FF
            | 0x370..=0x37D
            | 0x37F..=0x1FFF
            | 0x200C..=0x200D
            | 0x2070..=0x218F
            | 0x2C00..=0x2FEF
            | 0x3001..=0xD7FF
            | 0xF900..=0xFDCF
            | 0xFDF0..=0xFFFD
            | 0x10000..=0xEFFFF
    )
}

fn valid_xml_name_char(character: char) -> bool {
    valid_xml_name_start(character)
        || matches!(
            character as u32,
            0x2D | 0x2E | 0x30..=0x39 | 0xB7 | 0x300..=0x36F | 0x203F..=0x2040
        )
}

fn trim_xml_whitespace(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'))
}

fn validate_element(
    element: &quick_xml::events::BytesStart<'_>,
    decoder: quick_xml::Decoder,
) -> io::Result<()> {
    if !valid_xml_name(element.name().as_ref()) {
        return Err(invalid_raw_xml(
            "raw XML has an invalid element or attribute name",
        ));
    }
    for attribute in element.attributes().with_checks(true) {
        let attribute =
            attribute.map_err(|error| invalid_raw_xml(format!("raw XML is malformed: {error}")))?;
        if !valid_xml_name(attribute.key.as_ref()) {
            return Err(invalid_raw_xml(
                "raw XML has an invalid element or attribute name",
            ));
        }
        let value = attribute
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
            .map_err(|error| invalid_raw_xml(format!("raw XML attribute is malformed: {error}")))?;
        if has_invalid_xml_code_point(value.as_bytes()) {
            return Err(invalid_raw_xml("raw XML has an invalid Unicode code point"));
        }
    }
    Ok(())
}

fn validate_xml_declaration(declaration: &quick_xml::events::BytesDecl<'_>) -> io::Result<()> {
    let bytes: &[u8] = declaration;
    if has_invalid_xml_code_point(bytes) {
        return Err(invalid_raw_xml(
            "raw XML declaration has an invalid Unicode code point",
        ));
    }
    let content = std::str::from_utf8(bytes)
        .map_err(|_| invalid_raw_xml("raw XML declaration is not valid UTF-8"))?;
    if !content.starts_with("xml") || content.len() < 3 {
        return Err(invalid_raw_xml("raw XML declaration is malformed"));
    }
    let start = quick_xml::events::BytesStart::from_content(content, 3);
    let mut version_seen = false;
    let mut encoding_seen = false;
    let mut standalone_seen = false;
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| {
            invalid_raw_xml(format!("raw XML declaration is malformed: {error}"))
        })?;
        let name = attribute.key.as_ref();
        if !valid_xml_name(name) {
            return Err(invalid_raw_xml(
                "raw XML declaration has an invalid attribute name",
            ));
        }
        let value = attribute.value.as_ref();
        match name {
            b"version" => {
                if version_seen || encoding_seen || standalone_seen {
                    return Err(invalid_raw_xml(
                        "raw XML declaration attributes are out of order or duplicated",
                    ));
                }
                if !matches!(value, b"1.0" | b"1.1") {
                    return Err(invalid_raw_xml(
                        "raw XML declaration has an invalid version",
                    ));
                }
                version_seen = true;
            }
            b"encoding" => {
                if !version_seen || encoding_seen || standalone_seen {
                    return Err(invalid_raw_xml(
                        "raw XML declaration attributes are out of order or duplicated",
                    ));
                }
                if !value.eq_ignore_ascii_case(b"UTF-8") {
                    return Err(invalid_raw_xml(
                        "raw XML encoding must agree with UTF-8 output",
                    ));
                }
                encoding_seen = true;
            }
            b"standalone" => {
                if !version_seen || standalone_seen || !matches!(value, b"yes" | b"no") {
                    return Err(invalid_raw_xml(
                        "raw XML declaration has an invalid standalone attribute",
                    ));
                }
                standalone_seen = true;
            }
            _ => {
                return Err(invalid_raw_xml(
                    "raw XML declaration has an unsupported attribute",
                ));
            }
        }
    }
    if !version_seen {
        return Err(invalid_raw_xml(
            "raw XML declaration is missing its version",
        ));
    }
    Ok(())
}

fn valid_general_ref(name: &[u8]) -> bool {
    let valid_named = matches!(name, b"amp" | b"lt" | b"gt" | b"apos" | b"quot");
    let valid_numeric = name
        .strip_prefix(b"#x")
        .filter(|value| !value.is_empty() && value.iter().all(u8::is_ascii_hexdigit))
        .and_then(|value| u32::from_str_radix(std::str::from_utf8(value).ok()?, 16).ok())
        .or_else(|| {
            name.strip_prefix(b"#")
                .filter(|value| !value.is_empty() && value.iter().all(u8::is_ascii_digit))
                .and_then(|value| std::str::from_utf8(value).ok()?.parse::<u32>().ok())
        })
        .is_some_and(valid_xml_code_point);
    valid_named || valid_numeric
}

pub(super) const MAX_RAW_XML_BYTES: usize = 256 * 1024;
pub(super) const OVERSIZED_RAW_XML_MARKER: &str =
    "<Event><Redaction>[redacted: oversized text omitted]</Redaction></Event>";

fn required_raw_xml(record: &EvtxRecord) -> io::Result<&str> {
    // Redaction applies the same cap and emits the bounded marker. Do not feed an
    // attacker-controlled oversized payload through the XML validator first.
    if record.raw_xml.len() > MAX_RAW_XML_BYTES {
        return Ok(OVERSIZED_RAW_XML_MARKER);
    }
    let raw_xml = trim_xml_whitespace(&record.raw_xml);
    if raw_xml.is_empty() {
        return Err(invalid_raw_xml("record is missing raw XML"));
    }
    let mut reader = quick_xml::Reader::from_str(raw_xml);
    reader.config_mut().check_end_names = true;
    let mut depth = 0usize;
    let mut root_seen = false;
    let mut declaration_seen = false;
    let mut preamble_content_seen = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| invalid_raw_xml(format!("raw XML is malformed: {error}")))?;
        match event {
            quick_xml::events::Event::Eof => break,
            quick_xml::events::Event::Decl(declaration) => {
                if declaration_seen || root_seen || preamble_content_seen {
                    return Err(invalid_raw_xml("raw XML declaration is outside the prolog"));
                }
                validate_xml_declaration(&declaration)?;
                declaration_seen = true;
            }
            quick_xml::events::Event::Start(element) => {
                if depth == 0 && root_seen {
                    return Err(invalid_raw_xml("raw XML has multiple roots"));
                }
                validate_element(&element, reader.decoder())?;
                if depth == 0 {
                    root_seen = true;
                }
                depth += 1;
            }
            quick_xml::events::Event::Empty(element) => {
                if depth == 0 && root_seen {
                    return Err(invalid_raw_xml("raw XML has multiple roots"));
                }
                validate_element(&element, reader.decoder())?;
                if depth == 0 {
                    root_seen = true;
                }
            }
            quick_xml::events::Event::End(element) => {
                if depth == 0 {
                    return Err(invalid_raw_xml("raw XML has an unexpected closing tag"));
                }
                if !valid_xml_name(element.name().as_ref()) {
                    return Err(invalid_raw_xml(
                        "raw XML has an invalid element or attribute name",
                    ));
                }
                depth -= 1;
            }
            quick_xml::events::Event::Text(text) => {
                let bytes = text.into_inner();
                let top_level = depth == 0;
                if has_invalid_xml_code_point(&bytes)
                    || (top_level && !bytes.iter().all(u8::is_ascii_whitespace))
                {
                    return Err(invalid_raw_xml("raw XML has invalid text"));
                }
            }
            quick_xml::events::Event::CData(data) => {
                if depth == 0 {
                    return Err(invalid_raw_xml("raw XML has top-level CDATA"));
                }
                let bytes = data.into_inner();
                if has_invalid_xml_code_point(&bytes) {
                    return Err(invalid_raw_xml("raw XML has an invalid Unicode code point"));
                }
            }
            quick_xml::events::Event::GeneralRef(reference) => {
                if depth == 0 {
                    return Err(invalid_raw_xml("raw XML has a top-level entity reference"));
                }
                if !valid_general_ref(reference.into_inner().as_ref()) {
                    return Err(invalid_raw_xml(
                        "raw XML contains an unknown or invalid entity reference",
                    ));
                }
            }
            quick_xml::events::Event::DocType(_) => {
                return Err(invalid_raw_xml("raw XML doctype is not allowed"));
            }
            quick_xml::events::Event::PI(instruction) => {
                let target = instruction.target();
                if !valid_xml_name(target) || target.eq_ignore_ascii_case(b"xml") {
                    return Err(invalid_raw_xml(
                        "raw XML processing instruction has an invalid target",
                    ));
                }
                if has_invalid_xml_code_point(instruction.into_inner().as_ref()) {
                    return Err(invalid_raw_xml(
                        "raw XML processing instruction has an invalid Unicode code point",
                    ));
                }
                if depth == 0 {
                    preamble_content_seen = true;
                }
            }
            quick_xml::events::Event::Comment(comment) => {
                if depth == 0 {
                    preamble_content_seen = true;
                }
                if invalid_comment(comment) {
                    return Err(invalid_raw_xml("raw XML has an invalid comment"));
                }
            }
        }
    }
    if depth != 0 || !root_seen {
        return Err(invalid_raw_xml("raw XML is incomplete"));
    }
    Ok(raw_xml)
}
fn validate_optional_raw_xml(record: &EvtxRecord) -> io::Result<()> {
    if trim_xml_whitespace(&record.raw_xml).is_empty() {
        Ok(())
    } else {
        required_raw_xml(record).map(|_| ())
    }
}

fn validate_raw_xml_record(record: &EvtxRecord, format: ExportFormat) -> io::Result<()> {
    match format {
        ExportFormat::Json => validate_optional_raw_xml(record),
        ExportFormat::Xml | ExportFormat::RawXml => required_raw_xml(record).map(|_| ()),
        ExportFormat::Csv | ExportFormat::Tsv | ExportFormat::Html => Ok(()),
    }
}

/// Streams records without per-record raw-XML validation.
///
/// Before calling this helper, callers must validate the complete input with
/// [`validate_raw_xml`] or [`validate_raw_xml_iter`] using the same `format`;
/// `records` must then yield exactly that validated input. Unlike
/// [`write_record_stream`], this helper intentionally skips validation.
pub(super) fn write_record_stream_unchecked<W, I, R>(
    writer: &mut W,
    format: ExportFormat,
    records: I,
    mapped_columns: &[String],
) -> io::Result<ExportStats>
where
    W: Write + ?Sized,
    I: IntoIterator<Item = R>,
    R: Borrow<EvtxRecord>,
{
    write_record_stream_inner(writer, format, records, mapped_columns, |_, _| Ok(()))
}

/// Streams records directly to `writer`, applying the export redaction projection
/// one record at a time.
///
/// `mapped_columns` is supplied by the caller because a delimited header must be
/// emitted before the first record. It contains names only, never records,
/// so a large export still has bounded writer state.
pub fn write_record_stream<W, I, R>(
    writer: &mut W,
    format: ExportFormat,
    records: I,
    mapped_columns: &[String],
) -> io::Result<ExportStats>
where
    W: Write + ?Sized,
    I: IntoIterator<Item = R>,
    R: Borrow<EvtxRecord>,
{
    write_record_stream_inner(
        writer,
        format,
        records,
        mapped_columns,
        validate_raw_xml_record,
    )
}

fn write_record_stream_inner<W, I, R, V>(
    writer: &mut W,
    format: ExportFormat,
    records: I,
    mapped_columns: &[String],
    mut validate: V,
) -> io::Result<ExportStats>
where
    W: Write + ?Sized,
    I: IntoIterator<Item = R>,
    R: Borrow<EvtxRecord>,
    V: FnMut(&EvtxRecord, ExportFormat) -> io::Result<()>,
{
    let mut writer = CountingWriter {
        inner: writer,
        bytes: 0,
    };
    let mut count = 0u64;

    match format {
        ExportFormat::Csv | ExportFormat::Tsv => {
            let delimiter = format.delimiter();
            write_delimited_row(
                &mut writer,
                super::export::COLUMNS
                    .iter()
                    .map(|column| (*column).to_owned())
                    .chain(mapped_columns.iter().cloned()),
                delimiter,
            )?;
            for item in records {
                let redacted = export::redact_record(item.borrow());
                write_delimited_row(
                    &mut writer,
                    export::row_of(&redacted, mapped_columns).into_iter(),
                    delimiter,
                )?;
                count = count.saturating_add(1);
            }
        }
        ExportFormat::Json => {
            writer.write_all(b"[")?;
            let mut first = true;
            for item in records {
                validate(item.borrow(), format)?;
                if !first {
                    writer.write_all(b",")?;
                }
                first = false;
                serde_json::to_writer(&mut writer, &export::redact_record(item.borrow()))
                    .map_err(io_other)?;
                count = count.saturating_add(1);
            }
            writer.write_all(b"]")?;
        }
        ExportFormat::Xml => {
            writer.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Events>\n")?;
            for item in records {
                validate(item.borrow(), format)?;
                let redacted = export::redact_record(item.borrow());
                writer
                    .write_all(export::strip_xml_declaration(redacted.raw_xml.trim()).as_bytes())?;
                writer.write_all(b"\n")?;
                count = count.saturating_add(1);
            }
            writer.write_all(b"</Events>\n")?;
        }
        ExportFormat::RawXml => {
            for item in records {
                validate(item.borrow(), format)?;
                let redacted = export::redact_record(item.borrow());
                writer.write_all(redacted.raw_xml.trim().as_bytes())?;
                writer.write_all(b"\n")?;
                count = count.saturating_add(1);
            }
        }
        ExportFormat::Html => {
            writer.write_all(
                b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Event export</title></head><body><table><thead>",
            )?;
            write_html_row(
                &mut writer,
                super::export::COLUMNS
                    .iter()
                    .map(|column| (*column).to_owned())
                    .chain(mapped_columns.iter().cloned()),
                true,
            )?;
            writer.write_all(b"</thead><tbody>\n")?;
            for item in records {
                let redacted = export::redact_record(item.borrow());
                write_html_row(
                    &mut writer,
                    export::row_of(&redacted, mapped_columns).into_iter(),
                    false,
                )?;
                count = count.saturating_add(1);
            }
            writer.write_all(b"</tbody></table></body></html>\n")?;
        }
    }

    writer.flush()?;
    Ok(ExportStats {
        bytes: writer.bytes,
        records: count,
    })
}
pub fn validate_raw_xml_iter<I, R>(records: I, format: ExportFormat) -> io::Result<()>
where
    I: IntoIterator<Item = R>,
    R: Borrow<EvtxRecord>,
{
    for record in records {
        validate_raw_xml_record(record.borrow(), format)?;
    }
    Ok(())
}

pub fn validate_raw_xml(records: &[EvtxRecord], format: ExportFormat) -> io::Result<()> {
    validate_raw_xml_iter(records.iter(), format)
}

/// Rejects a destination that resolves to one of the opened inputs.
///
/// A missing destination is normalized against the current directory so a relative
/// save path is compared with the same identity as an existing source. `-` remains
/// the stdout sentinel used by the CLI and is intentionally never treated as a file.
pub fn reject_source_destination(
    sources: &[String],
    destination: Option<&Path>,
) -> Result<(), String> {
    let Some(destination) = destination.filter(|path| *path != Path::new("-")) else {
        return Ok(());
    };
    let normalize = |path: &Path| {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(path)
        };
        let normalized = fs::canonicalize(&absolute).unwrap_or_else(|_| {
            let parent = absolute.parent().unwrap_or_else(|| Path::new("."));
            let parent = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
            absolute
                .file_name()
                .map(|name| parent.join(name))
                .unwrap_or(parent)
        });
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            // Windows and the default macOS filesystems compare paths without
            // case, including when the destination has not been created yet.
            // Fold the fallback identity too so a case-only alias cannot race
            // past the source collision check.
            std::path::PathBuf::from(normalized.to_string_lossy().to_lowercase())
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            normalized
        }
    };
    let destination = normalize(destination);
    if sources
        .iter()
        .map(Path::new)
        .map(normalize)
        .any(|source| source == destination)
    {
        return Err("output path cannot overwrite an opened source or manifest".to_owned());
    }
    Ok(())
}

/// Writes records to an already-open sink.
pub fn write_records<W: Write + ?Sized>(
    writer: &mut W,
    format: ExportFormat,
    records: &[EvtxRecord],
) -> io::Result<ExportStats> {
    validate_raw_xml(records, format)?;
    let mapped = super::export::mapped_columns(records).map_err(io::Error::other)?;
    write_record_stream_unchecked(writer, format, records.iter(), &mapped)
}

/// Writes to a path, or to stdout when `destination` is `None` or `-`.
pub fn write_records_to_destination(
    records: &[EvtxRecord],
    format: ExportFormat,
    destination: Option<&Path>,
) -> Result<ExportStats, String> {
    if destination.is_some_and(|path| path.as_os_str() == "-") || destination.is_none() {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        return write_records(&mut stdout, format, records).map_err(|error| error.to_string());
    }

    let path = destination.expect("destination checked above");
    write_to_staged_destination(path, |file| {
        write_records(file, format, records)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))
    })
}
pub fn write_record_stream_to_writer<W, I, R>(
    output: &mut W,
    records: I,
    format: ExportFormat,
    mapped_columns: &[String],
) -> Result<ExportStats, String>
where
    W: Write + ?Sized,
    I: IntoIterator<Item = R>,
    R: Borrow<EvtxRecord>,
{
    write_record_stream(output, format, records, mapped_columns).map_err(|error| error.to_string())
}

/// Streams an iterator directly to stdout, or atomically replaces a file destination.
pub fn write_record_stream_to_destination<I, R>(
    records: I,
    format: ExportFormat,
    destination: Option<&Path>,
    mapped_columns: &[String],
) -> Result<ExportStats, String>
where
    I: IntoIterator<Item = R>,
    R: Borrow<EvtxRecord>,
{
    if destination.is_some_and(|path| path.as_os_str() == "-") || destination.is_none() {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        return write_record_stream_to_writer(&mut stdout, records, format, mapped_columns);
    }

    let path = destination.expect("destination checked above");
    write_to_staged_destination(path, |file| {
        write_record_stream(file, format, records, mapped_columns)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))
    })
}
#[cfg(test)]
fn record(message: &str) -> EvtxRecord {
    EvtxRecord {
        id: 7,
        event_record_id: 42,
        event_record_id_text: Some("42".into()),
        timestamp: "2026-08-09T12:00:00Z".into(),
        timestamp_epoch: 0,
        provider: "Provider".into(),
        channel: "Application".into(),
        event_id: 326,
        level: EvtxLevel::Error,
        computer: "HOST".into(),
        message: message.into(),
        event_data: vec![],
        raw_xml: "<?xml version=\"1.0\"?><Event><Data>message</Data></Event>".into(),
        source_label: "source.evtx".into(),
        origin_kind: super::models::EvtxOriginKind::Event,
        task: None,
        opcode: None,
        process_id: None,
        activity_id: None,
        related_activity_id: None,
        session_id: None,
        device_id: None,
        user_id: None,
        process_start_time: None,
        thread_id: None,
        user_sid: None,
        keywords: None,
        mapped: vec![],
    }
}

#[test]
fn streaming_writer_handles_each_record_without_collecting_the_iterator() {
    let records = (0..10_000).map(|index| record(&format!("event-{index}")));
    let mut output = Cursor::new(Vec::new());
    let stats = super::writer::write_record_stream(&mut output, ExportFormat::Json, records, &[])
        .expect("stream succeeds");

    assert_eq!(stats.records, 10_000);
    let value: serde_json::Value = serde_json::from_slice(output.get_ref()).expect("valid JSON");
    assert_eq!(value.as_array().expect("array").len(), 10_000);
}

#[test]
fn streaming_writer_forwards_output_before_the_iterator_finishes() {
    #[derive(Clone)]
    struct SharedWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("output lock").extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = std::sync::Arc::clone(&output);
    let mut index = 0;
    let records = std::iter::from_fn(move || {
        if index == 1 {
            assert!(
                !observed.lock().expect("observed output lock").is_empty(),
                "the supplied writer must receive the first record before the next is requested"
            );
        }
        if index >= 2 {
            return None;
        }
        let current = index;
        index += 1;
        Some(record(&format!("event-{current}")))
    });
    let mut writer = SharedWriter(std::sync::Arc::clone(&output));

    let stats = super::writer::write_record_stream_to_writer(
        &mut writer,
        records,
        ExportFormat::Json,
        &[],
    )
    .expect("stream succeeds");

    assert_eq!(stats.records, 2);
}

#[test]
fn writer_supports_html_and_raw_xml_without_reusing_xml_container() {
    let mut event = record("<danger>&");
    event.raw_xml = "<?xml version=\"1.0\"?><Event><Data>message</Data><Message>PASSWORD=raw-secret</Message></Event>".into();
    event.event_data = vec![super::models::EvtxField {
        name: "Password".into(),
        value: "event-secret".into(),
    }];
    let mut html = Cursor::new(Vec::new());
    super::writer::write_record_stream(&mut html, ExportFormat::Html, [&event], &[])
        .expect("HTML succeeds");
    let html = String::from_utf8(html.into_inner()).expect("UTF-8");
    assert!(html.contains("<table"));
    assert!(html.contains("&lt;danger&gt;&amp;"));

    assert!(!html.contains("raw-secret"));
    assert!(!html.contains("event-secret"));
    let mut raw = Cursor::new(Vec::new());
    super::writer::write_record_stream(&mut raw, ExportFormat::RawXml, [&event], &[])
        .expect("raw XML succeeds");
    let raw = String::from_utf8(raw.into_inner()).expect("UTF-8");
    assert!(raw.starts_with("<?xml version=\"1.0\"?>"));
    assert!(raw.contains("<Event><Data>message</Data>"));
    assert!(!raw.contains("<Events>"));
}

#[test]
fn empty_stream_has_a_valid_shape_for_every_format() {
    for format in [
        ExportFormat::Csv,
        ExportFormat::Tsv,
        ExportFormat::Json,
        ExportFormat::Xml,
        ExportFormat::Html,
        ExportFormat::RawXml,
    ] {
        let mut output = Cursor::new(Vec::new());
        let stats = super::writer::write_record_stream(
            &mut output,
            format,
            std::iter::empty::<EvtxRecord>(),
            &[],
        )
        .expect("empty export succeeds");
        assert_eq!(stats.records, 0);
        let output = String::from_utf8(output.into_inner()).expect("UTF-8");
        match format {
            ExportFormat::Csv => assert!(output.starts_with("Event Time,")),
            ExportFormat::Tsv => assert!(output.starts_with("Event Time\t")),
            ExportFormat::Json => assert_eq!(output, "[]"),
            ExportFormat::Xml => assert!(output.contains("<Events>")),
            ExportFormat::Html => assert!(output.contains("<table")),
            ExportFormat::RawXml => assert!(output.is_empty()),
        }
    }
}

#[test]
fn delimited_writer_neutralizes_formula_values_while_streaming() {
    let mut output = Cursor::new(Vec::new());

    super::writer::write_record_stream(&mut output, ExportFormat::Csv, [record("=cmd|calc")], &[])
        .expect("CSV succeeds");
    let output = String::from_utf8(output.into_inner()).expect("UTF-8");
    assert!(output.contains("'=cmd|calc"));
}
#[test]
fn writes_directly_to_a_file_and_reports_bytes() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("events.csv");
    let stats = super::writer::write_records_to_destination(
        &[record("file output")],
        ExportFormat::Csv,
        Some(&path),
    )
    .expect("file output succeeds");
    let bytes = std::fs::read(&path).expect("output exists");
    assert_eq!(stats.bytes, bytes.len() as u64);
    assert_eq!(stats.records, 1);
    assert!(String::from_utf8_lossy(&bytes).contains("file output"));
}

#[cfg(unix)]
#[test]
fn staged_destination_exports_are_owner_only() {
    let directory = tempfile::tempdir().expect("temp directory");
    let direct_path = directory.path().join("direct.csv");
    write_records_to_destination(&[record("direct")], ExportFormat::Csv, Some(&direct_path))
        .expect("direct destination export");

    let streamed_path = directory.path().join("streamed.csv");
    write_record_stream_to_destination(
        [record("streamed")],
        ExportFormat::Csv,
        Some(&streamed_path),
        &[],
    )
    .expect("streamed destination export");

    for path in [direct_path, streamed_path] {
        let mode = std::fs::metadata(path)
            .expect("destination metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "staged export must not be group/world-readable"
        );
    }
}

#[test]
fn failed_file_validation_preserves_existing_destination() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("events.xml");
    std::fs::write(&path, "sentinel").expect("seed destination");
    let mut invalid = record("invalid");
    invalid.raw_xml = "<Event>".into();
    let error =
        super::writer::write_records_to_destination(&[invalid], ExportFormat::Xml, Some(&path))
            .expect_err("malformed XML fails");
    assert!(error.contains("malformed") || error.contains("incomplete"));
    assert_eq!(
        std::fs::read_to_string(path).expect("destination"),
        "sentinel"
    );
}

#[test]
fn strict_xml_validation_rejects_duplicate_attributes_and_invalid_comments() {
    for raw_xml in [
        r#"<Event id="1" id="2"/>"#,
        r#"<Event><!-- invalid--comment --></Event>"#,
        r#"<Event><!DOCTYPE Event [ <!ENTITY x "y"> ] /></Event>"#,
        r#"<Event attr="&#x1;"/>"#,
        r#"<Event attr="&#xB;"/>"#,
        r#"<![CDATA[top-level]]><Event/>"#,
        r#"&amp;<Event/>"#,
        r#"<Event><1bad/></Event>"#,
        r#"<Event 1bad="x"/>"#,
        r#"<Event><Child bad name="x"/></Event>"#,
        r#"<Event /><?xml version="1.0"?>"#,
        r#"<?provider?><?xml version="1.0"?><Event/>"#,
        r#"<?xml foo?><Event/>"#,
        r#"<?1bad?><Event/>"#,
        r#"<?xml version="2.0"?><Event/>"#,
        r#"<?xml encoding="UTF-8" version="1.0"?><Event/>"#,
        r#"<?xml version="1.0" standalone="yes" encoding="UTF-8"?><Event/>"#,
        r#"<?xml version="1.0" encoding="UTF-8" encoding="UTF-8"?><Event/>"#,
        r#"<?xml version="1.0" foo="bar"?><Event/>"#,
        r#"<?xml version="1.0" encoding="UTF-16"?><Event/>"#,
        "<Event>bad\u{0001}</Event>",
    ] {
        let mut event = record("invalid");
        event.raw_xml = raw_xml.into();
        let error = super::writer::write_records(
            &mut Cursor::new(Vec::new()),
            ExportFormat::Json,
            &[event],
        )
        .expect_err("strict XML must reject malformed content");
        assert!(
            error.to_string().contains("malformed")
                || error.to_string().contains("invalid")
                || error.to_string().contains("prolog")
                || error.to_string().contains("control")
                || error.to_string().contains("doctype")
                || error.to_string().contains("CDATA")
                || error.to_string().contains("encoding")
                || error.to_string().contains("duplicated")
                || error.to_string().contains("order")
                || error.to_string().contains("top-level")
                || error.to_string().contains("unsupported"),
            "unexpected strict XML error: {error}"
        );
    }
}

#[test]
fn leading_whitespace_before_utf8_declaration_is_accepted() {
    let mut event = record("safe");
    event.raw_xml = " \n\t<?xml version=\"1.0\" encoding=\"UTF-8\"?><Event/>".into();

    write_records(&mut Cursor::new(Vec::new()), ExportFormat::Json, &[event])
        .expect("leading XML whitespace is allowed");
}

#[test]
fn strict_xml_validation_accepts_prolog_and_nested_pi_newlines() {
    let mut event = record("safe");
    event.raw_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <?provider line one\n\
        line two?>\n\
        <Event><?nested\n\
        value?></Event>\n"
        .into();

    write_records(&mut Cursor::new(Vec::new()), ExportFormat::Json, &[event])
        .expect("XML whitespace and processing instructions are valid");
}

#[test]
fn oversized_raw_xml_skips_validation_and_uses_bounded_marker() {
    let mut event = record("oversized");
    event.raw_xml = "not XML ".repeat((MAX_RAW_XML_BYTES / 8) + 1);

    let mut output = Cursor::new(Vec::new());
    write_records(&mut output, ExportFormat::Json, &[event])
        .expect("oversized XML is replaced before validation");
    let output = String::from_utf8(output.into_inner()).expect("UTF-8");
    assert!(output.contains("[redacted: oversized text omitted]"));
    assert!(!output.contains("not XML"));
}

#[test]
fn strict_xml_validation_rejects_non_xml_unicode_code_points_across_event_kinds() {
    for raw_xml in [
        "<Event>bad\u{FFFE}</Event>",
        "<Event>&#xFFFE;</Event>",
        "<Event><![CDATA[bad\u{FFFE}]]></Event>",
        "<Event><!--bad\u{FFFE}--></Event>",
        "<Event><?target bad\u{FFFE}?></Event>",
        "<Event attr=\"bad\u{FFFE}\"/>",
        "<Event attr=\"&#xFFFE;\"/>",
    ] {
        let mut event = record("invalid");
        event.raw_xml = raw_xml.into();
        let error = super::writer::write_records(
            &mut Cursor::new(Vec::new()),
            ExportFormat::Json,
            &[event],
        )
        .expect_err("invalid XML code points must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
#[test]
fn xml_redaction_preserves_markup_and_masks_named_event_data() {
    let event = record("safe");
    let event = EvtxRecord {
        raw_xml: "<Event><EventData><Data Name=\"TargetUserName\">CONTOSO\\John Doe</Data><Data Name=\"DeviceHardwareData\">AA-BB-CC</Data></EventData></Event>".into(),
        ..event
    };
    let mut output = Cursor::new(Vec::new());
    write_record_stream(&mut output, ExportFormat::RawXml, [&event], &[])
        .expect("raw XML succeeds");
    let output = String::from_utf8(output.into_inner()).expect("UTF-8");
    assert!(!output.contains("John Doe"));
    assert!(!output.contains("AA-BB-CC"));
    let mut reader = quick_xml::Reader::from_str(&output);
    let mut buffer = Vec::new();
    while reader
        .read_event_into(&mut buffer)
        .expect("well-formed XML")
        .into_owned()
        != quick_xml::events::Event::Eof
    {
        buffer.clear();
    }
}
#[test]
fn xml_redaction_preserves_literal_markup_inside_cdata() {
    let event = EvtxRecord {
        raw_xml: "<Event><Message><![CDATA[<safe>& PASSWORD=hunter2]]></Message></Event>".into(),
        ..record("safe")
    };
    let mut output = Cursor::new(Vec::new());
    write_record_stream(&mut output, ExportFormat::RawXml, [&event], &[])
        .expect("raw XML succeeds");
    let output = String::from_utf8(output.into_inner()).expect("UTF-8");

    assert!(output.contains("<![CDATA[<safe>& "));
    assert!(!output.contains("&lt;safe&gt;"));
    assert!(!output.contains("hunter2"));
}

#[test]
fn log_records_without_raw_xml_export_as_json_but_not_xml() {
    let mut log = EvtxRecord {
        raw_xml: String::new(),
        source_label: "archive.txt".into(),
        origin_kind: super::models::EvtxOriginKind::Log,
        ..record(r#"RunAsUser=CONTOSO\Jane Doe PASSWORD=hunter2"#)
    };
    log.computer = "DESKTOP-JOHN".into();
    log.event_data = vec![super::models::EvtxField {
        name: "Password".into(),
        value: "hunter2".into(),
    }];

    let mut output = Cursor::new(Vec::new());
    write_record_stream(&mut output, ExportFormat::Json, [&log], &[])
        .expect("JSON accepts normalized log records without raw XML");
    let value: serde_json::Value =
        serde_json::from_slice(output.get_ref()).expect("JSON output is valid");
    let serialized = &value[0];
    assert_eq!(serialized["originKind"], "log");
    assert_eq!(serialized["rawXml"], "");
    assert!(!serialized.to_string().contains("Jane Doe"));
    assert!(!serialized.to_string().contains("hunter2"));
    assert!(!serialized.to_string().contains("DESKTOP-JOHN"));

    for format in [ExportFormat::Xml, ExportFormat::RawXml] {
        let mut output = Cursor::new(Vec::new());
        let error = write_record_stream(&mut output, format, [&log], &[])
            .expect_err("XML-bearing exports require raw XML");
        assert!(error.to_string().contains("raw XML"));
    }
}

#[test]
fn raw_xml_computer_and_subject_fields_are_redacted_without_consuming_tags() {
    let event = EvtxRecord {
        raw_xml: "<Event><System><Computer>DESKTOP-JOHN</Computer><ns:Computer>DESKTOP-NS</ns:Computer><SubjectUserName>CONTOSO\\Jane Doe</SubjectUserName><ns:SubjectUserName>CONTOSO\\Ns User</ns:SubjectUserName><SubjectDomainName>CONTOSO</SubjectDomainName></System><ns:RemoteHost>REMOTE-HOST-2</ns:RemoteHost><RemoteHost>REMOTE-HOST-3</RemoteHost><ns:Data Name=\"SubjectUserName\">\n <![CDATA[\n CONTOSO\\Bob Doe\n ]]>\n</ns:Data><ns:Data Name=\"TargetUserName\">CONTOSO\\Target User</ns:Data><ns:Data Name=\"RemoteHost\"><![CDATA[REMOTE-HOST]]></ns:Data><Data><![CDATA[TenantId=99999999-8888-4777-8666-555555555555]]></Data><Message><![CDATA[PASSWORD=hunter2]]></Message><!-- SubjectUserName=CONTOSO\\Comment User --><Next /></Event>".into(),
        ..record("safe")
    };
    let mut output = Cursor::new(Vec::new());
    write_record_stream(&mut output, ExportFormat::RawXml, [&event], &[])
        .expect("raw XML succeeds");
    let output = String::from_utf8(output.into_inner()).expect("UTF-8");
    assert!(!output.contains("DESKTOP-JOHN"));
    assert!(!output.contains("DESKTOP-NS"));
    assert!(!output.contains("Ns User"));
    assert!(!output.contains("Target User"));
    assert!(!output.contains("Jane Doe"));
    assert!(!output.contains("Bob Doe"));
    assert!(!output.contains("REMOTE-HOST"));
    assert!(!output.contains("REMOTE-HOST-2"));
    assert!(!output.contains("REMOTE-HOST-3"));
    assert!(!output.contains("99999999-8888"));
    assert!(!output.contains("hunter2"));
    assert!(!output.contains("Comment User"));
    assert!(output.contains("<Message><![CDATA["));
    assert!(output.contains("</Message><!--"));
    assert!(output.contains("--><Next />"));
    assert!(!output.contains(">CONTOSO<"));
    let mut reader = quick_xml::Reader::from_str(&output);
    let mut buffer = Vec::new();
    while reader
        .read_event_into(&mut buffer)
        .expect("well-formed XML")
        .into_owned()
        != quick_xml::events::Event::Eof
    {
        buffer.clear();
    }
}

#[test]
fn replacement_helper_overwrites_existing_destination_atomically() {
    let directory = tempfile::tempdir().expect("temp directory");
    let temporary = directory.path().join("staged.tmp");
    let destination = directory.path().join("events.csv");
    std::fs::write(&temporary, "new").expect("staged output");
    std::fs::write(&destination, "old").expect("existing output");

    replace_destination(&temporary, &destination).expect("replacement succeeds");

    assert_eq!(
        std::fs::read_to_string(&destination).expect("destination"),
        "new"
    );
    assert!(!temporary.exists());
}

#[cfg(target_os = "windows")]
#[test]
fn source_destination_collision_rejects_case_aliases_on_windows() {
    let directory = tempfile::tempdir().expect("temp directory");
    let source = directory.path().join("Events.evtx");
    std::fs::write(&source, "evidence").expect("source");
    let alias = directory.path().join("events.EVTX");

    let error = reject_source_destination(&[source.to_string_lossy().into_owned()], Some(&alias))
        .expect_err("case alias must be rejected");
    assert!(error.contains("overwrite"));
}

#[test]
fn source_destination_collision_rejects_the_exact_source_path() {
    let directory = tempfile::tempdir().expect("temp directory");
    let source = directory.path().join("Events.evtx");
    std::fs::write(&source, "evidence").expect("source");

    let error = reject_source_destination(&[source.to_string_lossy().into_owned()], Some(&source))
        .expect_err("the exact source path must be rejected");
    assert!(error.contains("overwrite"));
}
#[cfg(target_os = "macos")]
#[test]
fn source_destination_collision_rejects_case_aliases_on_macos() {
    let directory = tempfile::tempdir().expect("temp directory");
    let source = directory.path().join("Events.evtx");
    std::fs::write(&source, "evidence").expect("source");
    let alias = directory.path().join("events.EVTX");

    let error = reject_source_destination(&[source.to_string_lossy().into_owned()], Some(&alias))
        .expect_err("case alias must be rejected on macOS");
    assert!(error.contains("overwrite"));
}
