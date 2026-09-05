//! WIM XML data decoding: UTF-16LE + BOM strip, then extraction of `<IMAGE>`
//! entries. Hand-rolled scanning — the WIM XML schema is fixed and tiny, so a
//! full XML dependency is not warranted. The scanner validates the document
//! root (`<WIM>`) and decodes the five predefined XML entities in element
//! text and attribute values.

use super::{WimError, WimImage};

/// Decodes the XML resource bytes (UTF-16LE, optional BOM) into a `String`.
pub fn decode_xml(bytes: &[u8]) -> Result<String, WimError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(WimError::InvalidUtf16);
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        units.push(u16::from_le_bytes([bytes[i], bytes[i + 1]]));
    }
    let body = match units.first() {
        Some(&0xFEFF) => &units[1..],
        _ => &units[..],
    };
    String::from_utf16(body).map_err(|_| WimError::InvalidUtf16)
}

/// Decodes the five predefined XML entities in `text`. Numeric character
/// references are not decoded — real WIM XML data uses named entities.
fn decode_entities(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let (entity, remainder) = match after.find(';') {
            Some(end) => (&after[..end], &after[end + 1..]),
            None => {
                // A bare '&' with no ';' is kept verbatim.
                out.push('&');
                ("", after)
            }
        };
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            // The entity is unterminated (`None` branch above) — already kept.
            "" => {}
            _ => out.push_str(&format!("&{entity};")),
        }
        rest = remainder;
    }
    out.push_str(rest);
    out
}

/// Extracts image metadata from decoded WIM XML.
///
/// Expects the decoded XML text of a WIM's XML data resource. The document
/// root must be a `<WIM>` element; only its body is scanned for `<IMAGE>`
/// entries. Returns [`WimError::MalformedXml`] when the root is missing,
/// an image tag is unclosed, or a required image field is absent/invalid.
pub fn parse_images(xml: &str) -> Result<Vec<WimImage>, WimError> {
    let trimmed = xml.trim_start_matches('\u{feff}');
    // The document root must be <WIM>. Allow an optional XML prolog
    // (<?xml ...?>) and whitespace, but no other text or element before it.
    let Some(root_start) = trimmed.find("<WIM>") else {
        return Err(WimError::MalformedXml { reason: "root" });
    };
    let before_root = &trimmed[..root_start];
    if !before_root.trim_start().is_empty() && !before_root.trim_start().starts_with("<?xml") {
        return Err(WimError::MalformedXml { reason: "root" });
    }
    // Search for the root close only after the root open — an input like
    // "</WIM><WIM>" must not produce an inverted (panicking) range.
    let Some(root_end) = trimmed[root_start..].find("</WIM>") else {
        return Err(WimError::MalformedXml { reason: "root" });
    };
    let root_end = root_start + root_end;
    // Only the root element's body is scanned — anything after </WIM> is
    // trailing junk and must never contribute image metadata.
    let root = &trimmed[root_start..root_end];
    let mut images = Vec::new();
    let mut cursor = 0usize;
    while let Some(tag_start) = root[cursor..].find("<IMAGE") {
        let tag_start = cursor + tag_start;
        let Some(tag_end_rel) = root[tag_start..].find('>') else {
            return Err(WimError::MalformedXml {
                reason: "image_tag",
            });
        };
        let tag_end = tag_start + tag_end_rel;
        let open_tag = &root[tag_start..tag_end];
        let Some(body_end_rel) = root[tag_end..].find("</IMAGE>") else {
            return Err(WimError::MalformedXml {
                reason: "image_tag",
            });
        };
        let body = &root[tag_end + 1..tag_end + body_end_rel];
        cursor = tag_end + body_end_rel + "</IMAGE>".len();

        let index = extract_attr(open_tag, "INDEX")
            .ok_or(WimError::MalformedXml { reason: "index" })?
            .parse::<u32>()
            .map_err(|_| WimError::MalformedXml { reason: "index" })?;
        let name = decode_entities(
            extract_element(body, "NAME").ok_or(WimError::MalformedXml { reason: "name" })?,
        );
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
