//! WIM XML data decoding: UTF-16LE + BOM strip, then extraction of `<IMAGE>`
//! entries. Hand-rolled scanning — the WIM XML schema is fixed and tiny, so a
//! full XML dependency is not warranted.

use super::{WimError, WimImage};

/// Decodes the XML resource bytes (UTF-16LE, optional BOM) into a `String`.
pub fn decode_xml(bytes: &[u8]) -> Result<String, WimError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(WimError::InvalidUtf16);
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let body = match units.first() {
        Some(&0xFEFF) => &units[1..],
        _ => &units[..],
    };
    String::from_utf16(body).map_err(|_| WimError::InvalidUtf16)
}

/// Extracts image metadata from decoded WIM XML.
pub fn parse_images(xml: &str) -> Result<Vec<WimImage>, WimError> {
    let mut images = Vec::new();
    let mut cursor = 0usize;
    while let Some(tag_start) = xml[cursor..].find("<IMAGE") {
        let tag_start = cursor + tag_start;
        let Some(tag_end_rel) = xml[tag_start..].find('>') else {
            return Err(WimError::MalformedXml {
                reason: "image_tag",
            });
        };
        let tag_end = tag_start + tag_end_rel;
        let open_tag = &xml[tag_start..tag_end];
        let Some(body_end_rel) = xml[tag_end..].find("</IMAGE>") else {
            return Err(WimError::MalformedXml {
                reason: "image_tag",
            });
        };
        let body = &xml[tag_end + 1..tag_end + body_end_rel];
        cursor = tag_end + body_end_rel + "</IMAGE>".len();

        let index = extract_attr(open_tag, "INDEX")
            .ok_or(WimError::MalformedXml { reason: "index" })?
            .parse::<u32>()
            .map_err(|_| WimError::MalformedXml { reason: "index" })?;
        let name = extract_element(body, "NAME")
            .ok_or(WimError::MalformedXml { reason: "name" })?
            .to_owned();
        let dir_count = parse_element(body, "DIRCOUNT")?;
        let file_count = parse_element(body, "FILECOUNT")?;
        let total_bytes = parse_element(body, "TOTALBYTES")?;

        images.push(WimImage {
            index,
            name,
            dir_count,
            file_count,
            total_bytes,
        });
    }
    Ok(images)
}

fn extract_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let start = tag.find(&needle)? + needle.len();
    tag[start..].split('"').next()
}

fn extract_element<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(&body[start..end])
}

fn parse_element(body: &str, tag: &str) -> Result<u64, WimError> {
    extract_element(body, tag)
        .ok_or(WimError::MalformedXml {
            reason: "image_field",
        })?
        .trim()
        .parse::<u64>()
        .map_err(|_| WimError::MalformedXml {
            reason: "image_field",
        })
}
