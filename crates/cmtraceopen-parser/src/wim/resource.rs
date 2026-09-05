//! On-disk resource entry (`RESHDR_DISK_SHORT`, 24 bytes).
//!
//! Layout (little-endian):
//! - `0..8`:   packed u64 — stored size in the low 56 bits, flags in the high byte
//! - `8..16`:  absolute offset from the start of the WIM file
//! - `16..24`: original (uncompressed) size

/// Set on a resource entry when the resource data is compressed.
pub const RESHDR_FLAG_COMPRESSED: u8 = 0x04;

/// Size of a resource entry on disk, in bytes.
pub const RESOURCE_ENTRY_SIZE: usize = 24;

/// A decoded WIM resource entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceEntry {
    /// Stored (possibly compressed) size — low 56 bits of the packed field.
    pub size: u64,
    /// Entry flags — high byte of the packed field.
    pub flags: u8,
    /// Absolute offset from the start of the WIM file.
    pub offset: u64,
    /// Original (uncompressed) size.
    pub original_size: u64,
}

impl ResourceEntry {
    /// Reads a resource entry at byte offset `at`. `None` if it does not fit
    /// (including offsets near `usize::MAX`, which cannot overflow here).
    pub fn read(bytes: &[u8], at: usize) -> Option<Self> {
        let end = at.checked_add(RESOURCE_ENTRY_SIZE)?;
        let window = bytes.get(at..end)?;
        let packed = u64::from_le_bytes(window[0..8].try_into().ok()?);
        let offset = u64::from_le_bytes(window[8..16].try_into().ok()?);
        let original_size = u64::from_le_bytes(window[16..24].try_into().ok()?);
        Some(Self {
            size: packed & 0x00ff_ffff_ffff_ffff,
            flags: (packed >> 56) as u8,
            offset,
            original_size,
        })
    }
}
