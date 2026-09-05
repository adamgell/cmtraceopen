//! WIM (Windows Imaging Format) reader tests — Layer 1: header + resource
//! entries + XML metadata.
//!
//! Fixtures are real captures from wimlib 1.14.5 (see tests/fixtures/wim/manifest.json).
//! Ground truth cross-checked with `wimlib-imagex info --header` and `--xml`.

use cmtraceopen_parser::wim::{parse_wim, WimCompression, WimError, WIM_HEADER_SIZE, WIM_MAGIC};

const UNCOMPRESSED: &[u8] = include_bytes!("fixtures/wim/sample-uncompressed.wim");
const XPRESS: &[u8] = include_bytes!("fixtures/wim/sample-xpress.wim");

// ---- happy path: uncompressed fixture ----

#[test]
fn magic_and_header_size_constants_match_spec() {
    assert_eq!(WIM_MAGIC, *b"MSWIM\x00\x00\x00");
    assert_eq!(WIM_HEADER_SIZE, 208);
}

#[test]
fn parses_uncompressed_header() {
    let info = parse_wim(UNCOMPRESSED).expect("uncompressed fixture must parse");
    assert_eq!(info.version, 0x10D00);
    assert_eq!(info.flags, 0x80); // WIM_HDR_FLAG_RP_FIX only; no compression bits
    assert_eq!(info.compression, WimCompression::None);
    assert_eq!(info.chunk_size, 0);
    assert_eq!(info.image_count, 1);
    assert_eq!(info.boot_index, 0);
    assert_eq!(
        info.guid,
        [
            0x74, 0x04, 0x71, 0x64, 0xa9, 0x9e, 0xe1, 0x36, 0x35, 0x5f, 0x18, 0x2f, 0xe4, 0x4d,
            0xb1, 0x39
        ]
    );
}

#[test]
fn parses_uncompressed_images_from_xml() {
    let info = parse_wim(UNCOMPRESSED).expect("uncompressed fixture must parse");
    assert_eq!(info.images.len(), 1);
    let image = &info.images[0];
    assert_eq!(image.index, 1);
    assert_eq!(image.name, "sample_dir");
    assert_eq!(image.dir_count, 2);
    assert_eq!(image.file_count, 3);
    assert_eq!(image.total_bytes, 39);
}

#[test]
fn xml_field_holds_decoded_xml() {
    let info = parse_wim(UNCOMPRESSED).expect("uncompressed fixture must parse");
    assert!(info.xml.contains("<WIM>"));
    assert!(info.xml.contains("<NAME>sample_dir</NAME>"));
    assert!(info.xml.contains("<FILECOUNT>3</FILECOUNT>"));
}

// ---- happy path: xpress fixture (XML resource itself is uncompressed) ----

#[test]
fn parses_xpress_header_and_images() {
    let info = parse_wim(XPRESS).expect("xpress fixture must parse");
    assert_eq!(info.version, 0x10D00);
    assert_eq!(info.flags, 0x2_0082); // RP_FIX | COMPRESSION | XPRESS
    assert_eq!(info.compression, WimCompression::Xpress);
    assert_eq!(info.chunk_size, 32768);
    assert_eq!(info.image_count, 1);
    assert_eq!(info.images.len(), 1);
    assert_eq!(info.images[0].name, "sample_dir");
    assert_eq!(info.images[0].file_count, 3);
}

// ---- coverage states: conservative, never a fabricated success ----

#[test]
fn empty_input_is_too_small() {
    assert_eq!(parse_wim(&[]), Err(WimError::TooSmall));
    assert_eq!(parse_wim(&[0u8; 100]), Err(WimError::TooSmall));
}

#[test]
fn bad_magic_is_rejected() {
    let mut bytes = UNCOMPRESSED.to_vec();
    bytes[0] = b'X';
    assert_eq!(parse_wim(&bytes), Err(WimError::BadMagic));
}

#[test]
fn compressed_xml_resource_is_unsupported_not_success() {
    // Transform of a real exemplar (rule: transform, never fabricate):
    // flip the XML resource entry's flags byte 0x02 -> 0x06 (set compressed bit).
    // XML entry sits at header offset 72; flags byte is at 72 + 7.
    let mut bytes = UNCOMPRESSED.to_vec();
    bytes[72 + 7] |= 0x04;
    assert_eq!(parse_wim(&bytes), Err(WimError::UnsupportedCompression));

    // A genuinely compressed resource — stored size < original size — must also
    // name the coverage gap, not misroute to BadHeader.
    let mut bytes = UNCOMPRESSED.to_vec();
    bytes[72 + 7] |= 0x04; // compressed flag
    let packed = 200u64 | (0x06u64 << 56); // stored 200 < original 776
    bytes[72..80].copy_from_slice(&packed.to_le_bytes());
    assert_eq!(parse_wim(&bytes), Err(WimError::UnsupportedCompression));
}

#[test]
fn xml_resource_past_end_of_file_is_out_of_bounds() {
    let mut bytes = UNCOMPRESSED.to_vec();
    // XML entry offset field at 72 + 8; set a huge offset.
    bytes[72 + 8..72 + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(parse_wim(&bytes), Err(WimError::ResourceOutOfBounds));
}

#[test]
fn odd_utf16_xml_length_is_invalid_utf16() {
    let mut bytes = UNCOMPRESSED.to_vec();
    // XML entry packed size at 72..79; set BOTH sizes to an odd value (775)
    // within file bounds so the resource itself is consistent, just not valid UTF-16.
    let packed = 775u64 | (0x02u64 << 56);
    bytes[72..80].copy_from_slice(&packed.to_le_bytes());
    bytes[88..96].copy_from_slice(&775u64.to_le_bytes());
    assert_eq!(parse_wim(&bytes), Err(WimError::InvalidUtf16));
}

#[test]
fn spanned_wim_is_reported_unsupported() {
    let mut bytes = UNCOMPRESSED.to_vec();
    // Set FLAG_HEADER_SPANNED (0x08) and total parts > 1.
    bytes[16..20].copy_from_slice(&0x88u32.to_le_bytes()); // flags |= 0x08
    bytes[42..44].copy_from_slice(&2u16.to_le_bytes()); // total parts = 2
    assert_eq!(parse_wim(&bytes), Err(WimError::SpannedUnsupported));
}

#[test]
fn spanned_part_number_without_flag_is_reported_unsupported() {
    // Regression: a header claiming part_number 2 without the spanned flag
    // must still be named SpannedUnsupported, not silently parsed.
    let mut bytes = UNCOMPRESSED.to_vec();
    bytes[40..42].copy_from_slice(&2u16.to_le_bytes()); // part number = 2
    assert_eq!(parse_wim(&bytes), Err(WimError::SpannedUnsupported));
}

#[test]
fn declared_header_size_mismatch_is_bad_header() {
    let mut bytes = UNCOMPRESSED.to_vec();
    // cbSize at bytes 8..12; declare a size the decoder does not anchor to.
    bytes[8..12].copy_from_slice(&104u32.to_le_bytes());
    assert_eq!(parse_wim(&bytes), Err(WimError::BadHeader));
}

#[test]
fn unsupported_wim_version_is_a_coverage_state() {
    let mut bytes = UNCOMPRESSED.to_vec();
    // Version at bytes 12..16; claim an unknown version.
    bytes[12..16].copy_from_slice(&0x20E00u32.to_le_bytes());
    assert_eq!(parse_wim(&bytes), Err(WimError::UnsupportedVersion));
}

#[test]
fn image_count_mismatch_between_header_and_xml_is_malformed() {
    let mut bytes = UNCOMPRESSED.to_vec();
    // Header claims 2 images; XML contains 1.
    bytes[44..48].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(parse_wim(&bytes), Err(WimError::ImageCountMismatch));
}

#[test]
fn missing_xml_resource_is_malformed_xml() {
    let mut bytes = UNCOMPRESSED.to_vec();
    // Zero out the XML resource entry (offset + size): no XML to decode.
    bytes[72..96].fill(0);
    assert_eq!(
        parse_wim(&bytes),
        Err(WimError::MalformedXml { reason: "missing" })
    );
}
