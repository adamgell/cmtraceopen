use std::borrow::Borrow;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use super::export::{self, ExportFormat};
use super::models::EvtxRecord;

#[cfg(test)]
use std::io::Cursor;
#[cfg(test)]
use super::models::EvtxLevel;

fn replace_destination(temporary: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "atomic replacement of an existing destination is unavailable on Windows",
        ));
    }
    fs::rename(temporary, destination)
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

fn invalid_comment(comment: quick_xml::events::BytesText<'_>) -> bool {
    let bytes = comment.into_inner();
    bytes.windows(2).any(|pair| pair == b"--") || bytes.last() == Some(&b'-')
}

fn has_illegal_xml_control(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| matches!(*byte, 0x00..=0x08 | 0x0B..=0x0C | 0x0E..=0x1F))
}

fn required_raw_xml(record: &EvtxRecord) -> io::Result<&str> {
    let raw_xml = record.raw_xml.trim();
    if raw_xml.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "record is missing raw XML",
        ));
    }
    let mut reader = quick_xml::Reader::from_str(raw_xml);
    let mut depth = 0usize;
    let mut root_seen = false;
    let mut declaration_seen = false;
    loop {
        let event = reader.read_event().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("raw XML is malformed: {error}"),
            )
        })?;
        match event {
            quick_xml::events::Event::Eof => break,
            quick_xml::events::Event::Decl(_) => {
                if declaration_seen || root_seen {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML declaration is outside the prolog"));
                }
                declaration_seen = true;
            }
            quick_xml::events::Event::Start(element) => {
                if depth == 0 && root_seen {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML has multiple roots"));
                }
                for attribute in element.attributes().with_checks(true) {
                    let attribute = attribute.map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("raw XML is malformed: {error}"))
                    })?;
                    let value = attribute.unescape_value().map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("raw XML attribute is malformed: {error}"))
                    })?;
                    if has_illegal_xml_control(value.as_bytes()) {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML has an illegal control character"));
                    }
                }
                if depth == 0 {
                    root_seen = true;
                }
                depth += 1;
            }
            quick_xml::events::Event::Empty(element) => {
                if depth == 0 && root_seen {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML has multiple roots"));
                }
                for attribute in element.attributes().with_checks(true) {
                    let attribute = attribute.map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("raw XML is malformed: {error}"))
                    })?;
                    let value = attribute.unescape_value().map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("raw XML attribute is malformed: {error}"))
                    })?;
                    if has_illegal_xml_control(value.as_bytes()) {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML has an illegal control character"));
                    }
                }
                if depth == 0 {
                    root_seen = true;
                }
            }
            quick_xml::events::Event::End(_) => {
                if depth == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML has an unexpected closing tag"));
                }
                depth -= 1;
            }
            quick_xml::events::Event::Text(text) => {
                let bytes = text.into_inner();
                if has_illegal_xml_control(&bytes)
                    || (depth == 0 && !bytes.iter().all(u8::is_ascii_whitespace))
                {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML has invalid text"));
                }
            }
            quick_xml::events::Event::CData(data) => {
                let bytes = data.into_inner();
                if has_illegal_xml_control(&bytes) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML has an illegal control character"));
                }
            }
            quick_xml::events::Event::GeneralRef(reference) => {
                let name = reference.into_inner();
                let valid_named = matches!(name.as_ref(), b"amp" | b"lt" | b"gt" | b"apos" | b"quot");
                let valid_numeric = name
                    .strip_prefix(b"#x")
                    .and_then(|value| u32::from_str_radix(std::str::from_utf8(value).ok()?, 16).ok())
                    .or_else(|| {
                        name.strip_prefix(b"#")
                            .and_then(|value| std::str::from_utf8(value).ok()?.parse::<u32>().ok())
                    })
                    .map(|value| value <= 0x10FFFF && !(0xD800..=0xDFFF).contains(&value))
                    .unwrap_or(false);
                if !valid_named && !valid_numeric {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML contains an unknown entity reference"));
                }
            }
            quick_xml::events::Event::DocType(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "raw XML doctype is not allowed",
                ));
            }
            quick_xml::events::Event::Comment(comment) => {
                if invalid_comment(comment) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML has an invalid comment"));
                }
            }
            _ => {}
        }
    }
    if depth != 0 || !root_seen {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "raw XML is incomplete"));
    }
    Ok(raw_xml)
}

/// Streams records directly to `writer`, applying the export redaction projection
/// one record at a time.
///
/// `mapped_columns` is supplied by the caller because a delimited header must
/// be emitted before the first record. It contains names only, never records,
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
                required_raw_xml(item.borrow())?;
                let redacted = export::redact_record(item.borrow());
                writer.write_all(export::strip_xml_declaration(redacted.raw_xml.trim()).as_bytes())?;
                writer.write_all(b"\n")?;
                count = count.saturating_add(1);
            }
            writer.write_all(b"</Events>\n")?;
        }
        ExportFormat::RawXml => {
            for item in records {
                required_raw_xml(item.borrow())?;
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

pub(crate) fn validate_raw_xml(records: &[EvtxRecord], format: ExportFormat) -> io::Result<()> {
    if matches!(format, ExportFormat::Json | ExportFormat::Xml | ExportFormat::RawXml) {
        for record in records {
            required_raw_xml(record)?;
        }
    }
    Ok(())
}

pub fn write_records<W: Write + ?Sized>(
    writer: &mut W,
    format: ExportFormat,
    records: &[EvtxRecord],
) -> io::Result<ExportStats> {
    validate_raw_xml(records, format)?;
    let mapped = super::export::mapped_columns(records);
    write_record_stream(writer, format, records.iter(), &mapped)
}


/// Writes to a path, or to stdout when `destination` is `None` or `-`.
pub fn write_records_to_destination(
    records: &[EvtxRecord],
    format: ExportFormat,
    destination: Option<&Path>,
) -> Result<ExportStats, String> {
    validate_raw_xml(records, format).map_err(|error| error.to_string())?;
    if destination.is_some_and(|path| path.as_os_str() == "-") || destination.is_none() {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        return write_records(&mut stdout, format, records).map_err(|error| error.to_string());
    }

    let path = destination.expect("destination checked above");
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("events");
    let mut temporary = None;
    let mut file = None;
    for attempt in 0..100u32 {
        let candidate = parent.join(format!(".{name}.tmp-{}-{attempt}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&candidate) {
            Ok(handle) => {
                temporary = Some(candidate);
                file = Some(handle);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("cannot create temporary output: {error}")),
        }
    }
    let temporary = temporary.ok_or_else(|| "cannot allocate temporary output path".to_owned())?;
    let mut file = file.expect("temporary file handle");
    let result = write_records(&mut file, format, records)
        .map_err(|error| format!("cannot write {}: {error}", path.display()));
    drop(file);
    match result {
        Ok(stats) => match replace_destination(&temporary, path) {
            Ok(()) => Ok(stats),
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                Err(format!("cannot replace {}: {error}", path.display()))
            }
        },
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error)
        }
    }
}
#[cfg(test)]
fn record(message: &str) -> EvtxRecord {
    EvtxRecord {
        id: 7,
        event_record_id: 42,
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
        task: None,
        opcode: None,
        process_id: None,
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
    let stats = super::writer::write_record_stream(
        &mut output,
        ExportFormat::Json,
        records,
        &[],
    )
    .expect("stream succeeds");

    assert_eq!(stats.records, 10_000);
    let value: serde_json::Value = serde_json::from_slice(output.get_ref()).expect("valid JSON");
    assert_eq!(value.as_array().expect("array").len(), 10_000);
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

#[test]
fn failed_file_validation_preserves_existing_destination() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("events.xml");
    std::fs::write(&path, "sentinel").expect("seed destination");
    let mut invalid = record("invalid");
    invalid.raw_xml = "<Event>".into();
    let error = super::writer::write_records_to_destination(
        &[invalid],
        ExportFormat::Xml,
        Some(&path),
    )
    .expect_err("malformed XML fails");
    assert!(error.contains("malformed") || error.contains("incomplete"));
    assert_eq!(std::fs::read_to_string(path).expect("destination"), "sentinel");
}

#[test]
fn strict_xml_validation_rejects_duplicate_attributes_and_invalid_comments() {
    for raw_xml in [
        r#"<Event id="1" id="2"/>"#,
        r#"<Event><!-- invalid--comment --></Event>"#,
        r#"<Event><!DOCTYPE Event [ <!ENTITY x "y"> ] /></Event>"#,
        r#"<Event attr="&#x1;"/>"#,
        r#"<Event /><?xml version="1.0"?>"#,
        "<Event>bad\u{0001}</Event>",
    ] {
        let mut event = record("invalid");
        event.raw_xml = raw_xml.into();
        let error = super::writer::write_records(&mut Cursor::new(Vec::new()), ExportFormat::Json, &[event])
            .expect_err("strict XML must reject malformed content");
        assert!(
            error.to_string().contains("malformed")
                || error.to_string().contains("invalid")
                || error.to_string().contains("prolog")
                || error.to_string().contains("control")
                || error.to_string().contains("doctype")
        );
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
fn xml_formats_reject_records_without_raw_xml() {
    let event = EvtxRecord {
        raw_xml: String::new(),
        ..record("missing")
    };
    for format in [ExportFormat::Xml, ExportFormat::RawXml] {
        let mut output = Cursor::new(Vec::new());
        let error = write_record_stream(&mut output, format, [&event], &[])
            .expect_err("missing raw XML must not count as exported");
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
