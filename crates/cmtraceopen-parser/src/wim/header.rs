//! WIM file header (`WIMHEADER_V1_PACKED`, 208 bytes), little-endian.
//!
//! Layout verified against `wimlib-imagex info --header` ground truth:
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0  | 8  | magic `MSWIM\x00\x00\x00` |
//! | 8  | 4  | header size |
//! | 12 | 4  | version |
//! | 16 | 4  | flags |
//! | 20 | 4  | chunk size |
//! | 24 | 16 | GUID |
//! | 40 | 2  | part number |
//! | 42 | 2  | total parts |
//! | 44 | 4  | image count |
//! | 48 | 24 | offset (blob) table resource entry |
//! | 72 | 24 | XML data resource entry |
//! | 96 | 24 | boot metadata resource entry |
//! | 120 | 4 | boot index |
//! | 124 | 24 | integrity table resource entry |

use super::resource::ResourceEntry;

/// Header flag: resources in this WIM are compressed.
pub const WIM_HDR_FLAG_COMPRESSED: u32 = 0x02;
/// Header flag: contents span multiple WIM segments (`.swm`).
pub const WIM_HDR_FLAG_SPANNED: u32 = 0x08;
/// Header flag: resources use XPRESS compression (with `COMPRESSED`).
pub const WIM_HDR_FLAG_COMPRESS_XPRESS: u32 = 0x2_0000;
/// Header flag: resources use LZX compression (with `COMPRESSED`).
pub const WIM_HDR_FLAG_COMPRESS_LZX: u32 = 0x4_0000;
/// Header flag: resources use LZMS compression (with `COMPRESSED`).
pub const WIM_HDR_FLAG_COMPRESS_LZMS: u32 = 0x8_0000;

/// The decoded fixed part of a WIM header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WimHeader {
    pub version: u32,
    pub flags: u32,
    pub chunk_size: u32,
    pub guid: [u8; 16],
    pub part_number: u16,
    pub total_parts: u16,
    pub image_count: u32,
    pub boot_index: u32,
    pub offset_table: ResourceEntry,
    pub xml_data: ResourceEntry,
    pub boot_metadata: ResourceEntry,
    pub integrity: ResourceEntry,
}

impl WimHeader {
    /// Reads the 208-byte header. `None` if the buffer is too small.
    pub fn read(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < super::WIM_HEADER_SIZE {
            return None;
        }
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let u16_at = |at: usize| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        Some(Self {
            version: u32_at(12),
            flags: u32_at(16),
            chunk_size: u32_at(20),
            guid: bytes[24..40].try_into().unwrap(),
            part_number: u16_at(40),
            total_parts: u16_at(42),
            image_count: u32_at(44),
            offset_table: ResourceEntry::read(bytes, 48)?,
            xml_data: ResourceEntry::read(bytes, 72)?,
            boot_metadata: ResourceEntry::read(bytes, 96)?,
            boot_index: u32_at(120),
            integrity: ResourceEntry::read(bytes, 124)?,
        })
    }
}
