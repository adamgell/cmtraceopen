//! WIM (Windows Imaging Format) reader — Layer 1: header, resource entries,
//! and XML metadata (image list).
//!
//! Pure byte-slice parsing. No I/O, no decompression. Compressed resources
//! are reported as [`WimError::UnsupportedCompression`] — a coverage state,
//! never a fabricated success.
//!
//! Format reference: libyal "Windows Imaging (WIM) file format" working doc,
//! cross-checked against wimlib 1.14.5 captures (see
//! `tests/fixtures/wim/manifest.json`).

mod header;
mod resource;
mod xml;

pub use header::{
    WimHeader, WIM_HDR_FLAG_COMPRESSED, WIM_HDR_FLAG_COMPRESS_LZMS, WIM_HDR_FLAG_COMPRESS_LZX,
    WIM_HDR_FLAG_COMPRESS_XPRESS, WIM_HDR_FLAG_SPANNED,
};
pub use resource::{ResourceEntry, RESHDR_FLAG_COMPRESSED};

/// WIM signature: `MSWIM\x00\x00\x00`.
pub const WIM_MAGIC: [u8; 8] = *b"MSWIM\x00\x00\x00";
/// Size of the WIM file header in bytes.
pub const WIM_HEADER_SIZE: usize = 208;
/// The WIM format version (`0x10D00`, "e") this reader is verified against.
pub const SUPPORTED_WIM_VERSION: u32 = 0x10D00;

/// Compression algorithm declared by the WIM header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WimCompression {
    /// No compression; resources are stored verbatim.
    None,
    /// XPRESS (LZ77+Huffman) compression.
    Xpress,
    /// LZX compression.
    Lzx,
    /// LZMS compression (solid, used by WIMBoot/EsdD).
    Lzms,
    /// Compression bits set but the combination is not recognized.
    Unknown,
}

/// One image entry parsed from the WIM XML data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimImage {
    /// 1-based image index as declared in the XML `INDEX` attribute.
    pub index: u32,
    /// Human-readable image name (`<NAME>` element).
    pub name: String,
    /// Number of directories in the image (`<DIRCOUNT>`).
    pub dir_count: u64,
    /// Number of files in the image (`<FILECOUNT>`).
    pub file_count: u64,
    /// Uncompressed total payload size in bytes (`<TOTALBYTES>`).
    pub total_bytes: u64,
}

/// Everything Layer 1 can state about a WIM file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimInfo {
    /// Format version from the header (verified: `0x10D00`).
    pub version: u32,
    /// Raw header flags, preserved verbatim.
    pub flags: u32,
    /// Compression algorithm the header declares for its resources.
    pub compression: WimCompression,
    /// Compressed chunk size in bytes (0 when uncompressed).
    pub chunk_size: u32,
    /// WIM GUID, byte-for-byte as stored.
    pub guid: [u8; 16],
    /// Segment number within a spanned set (always 1 here).
    pub part_number: u16,
    /// Total segments in a spanned set (always 1 here).
    pub total_parts: u16,
    /// Image count declared by the header; cross-checked against the XML.
    pub image_count: u32,
    /// 1-based index of the bootable image, 0 if none.
    pub boot_index: u32,
    /// Decoded XML data (UTF-16LE resource), kept raw.
    pub xml: String,
    /// Image entries extracted from the XML data.
    pub images: Vec<WimImage>,
}

/// Conservative parse failures. A missing or unsupported capability is a
/// distinct variant — never folded into a generic error, never a success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WimError {
    /// Input is shorter than a WIM header.
    TooSmall,
    /// Signature is not `MSWIM\x00\x00\x00`.
    BadMagic,
    /// Header fields are internally inconsistent or malformed.
    BadHeader,
    /// A resource entry extends past the end of the input.
    ResourceOutOfBounds,
    /// A resource required for Layer 1 is compressed; decompression is Layer 2.
    UnsupportedCompression,
    /// Resource data is not valid UTF-16LE.
    InvalidUtf16,
    /// XML data is present but malformed. `reason` names the failed step.
    MalformedXml { reason: &'static str },
    /// Header image count does not match the number of `<IMAGE>` elements.
    ImageCountMismatch,
    /// Spanned (`.swm`) sets are not supported.
    SpannedUnsupported,
    /// Header declares a format version this reader does not support.
    UnsupportedVersion,
}

fn compression_from_flags(flags: u32) -> WimCompression {
    if flags & WIM_HDR_FLAG_COMPRESSED == 0 {
        return WimCompression::None;
    }
    match flags
        & (WIM_HDR_FLAG_COMPRESS_XPRESS | WIM_HDR_FLAG_COMPRESS_LZX | WIM_HDR_FLAG_COMPRESS_LZMS)
    {
        WIM_HDR_FLAG_COMPRESS_XPRESS => WimCompression::Xpress,
        WIM_HDR_FLAG_COMPRESS_LZX => WimCompression::Lzx,
        WIM_HDR_FLAG_COMPRESS_LZMS => WimCompression::Lzms,
        _ => WimCompression::Unknown,
    }
}

/// Parses a complete WIM byte slice into [`WimInfo`].
pub fn parse_wim(bytes: &[u8]) -> Result<WimInfo, WimError> {
    if bytes.len() < WIM_HEADER_SIZE {
        return Err(WimError::TooSmall);
    }
    if bytes[..8] != WIM_MAGIC {
        return Err(WimError::BadMagic);
    }

    let Some(hdr) = WimHeader::read(bytes) else {
        return Err(WimError::TooSmall);
    };
    // The header declares its own size (bytes 8..12). Anything else means the
    // layout this decoder anchors to does not apply.
    let declared_size = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if declared_size as usize != WIM_HEADER_SIZE {
        return Err(WimError::BadHeader);
    }
    // Layer 1 supports the "e" (0x10D00) version family this parser was
    // verified against. Unknown versions are a coverage gap, not a failure.
    if hdr.version != SUPPORTED_WIM_VERSION {
        return Err(WimError::UnsupportedVersion);
    }

    if hdr.part_number != 1 || hdr.total_parts != 1 || hdr.flags & WIM_HDR_FLAG_SPANNED != 0 {
        return Err(WimError::SpannedUnsupported);
    }
    // Compression must be named before the size-consistency check: a genuinely
    // compressed XML resource (stored size < original) is an unsupported-capability
    // gap, not a malformed header.
    if hdr.xml_data.flags & RESHDR_FLAG_COMPRESSED != 0 {
        return Err(WimError::UnsupportedCompression);
    }
    if hdr.xml_data.size != hdr.xml_data.original_size {
        return Err(WimError::BadHeader);
    }
    if hdr.xml_data.size == 0 && hdr.image_count > 0 {
        return Err(WimError::MalformedXml { reason: "missing" });
    }

    // Slice the XML resource, checking bounds explicitly.
    let xml_start =
        usize::try_from(hdr.xml_data.offset).map_err(|_| WimError::ResourceOutOfBounds)?;
    let xml_end = xml_start
        .checked_add(usize::try_from(hdr.xml_data.size).map_err(|_| WimError::ResourceOutOfBounds)?)
        .ok_or(WimError::ResourceOutOfBounds)?;
    let xml_bytes = bytes
        .get(xml_start..xml_end)
        .ok_or(WimError::ResourceOutOfBounds)?;

    let xml_text = xml::decode_xml(xml_bytes)?;
    let images = xml::parse_images(&xml_text)?;

    if images.len() as u32 != hdr.image_count {
        return Err(WimError::ImageCountMismatch);
    }

    Ok(WimInfo {
        version: hdr.version,
        flags: hdr.flags,
        compression: compression_from_flags(hdr.flags),
        chunk_size: hdr.chunk_size,
        guid: hdr.guid,
        part_number: hdr.part_number,
        total_parts: hdr.total_parts,
        image_count: hdr.image_count,
        boot_index: hdr.boot_index,
        xml: xml_text,
        images,
    })
}
