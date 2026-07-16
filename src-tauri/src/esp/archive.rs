//! Bounded, read-only extraction of captured ESP evidence archives.
//!
//! Archive paths and declared sizes are validated before any member is written.
//! A unique temporary directory owns every extracted file and removes it on drop.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cmtraceopen_parser::parser::registry::{parse_registry_content, RegistryParseResult};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use thiserror::Error;

pub const MAX_ARCHIVE_ENTRIES: usize = 512;
pub const MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_ARCHIVE_FILE_BYTES: u64 = 256 * 1024 * 1024;

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const ZIP_EOCD_MIN_BYTES: usize = 22;
const ZIP_EOCD_MAX_SEARCH_BYTES: usize = ZIP_EOCD_MIN_BYTES + u16::MAX as usize;
const ZIP_EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const ZIP64_EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
const ZIP64_LOCATOR_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
const CAB_SIGNATURE: [u8; 4] = *b"MSCF";
const CAB_FLAG_PREV_CABINET: u16 = 0x0001;
const CAB_FLAG_NEXT_CABINET: u16 = 0x0002;
const CAB_FLAG_RESERVE_PRESENT: u16 = 0x0004;
const CAB_CONTINUED_FROM_PREVIOUS: u16 = 0xfffd;
const CAB_CONTINUED_TO_NEXT: u16 = 0xfffe;
const CAB_CONTINUED_PREVIOUS_AND_NEXT: u16 = 0xffff;
const MAX_CAB_STRING_BYTES: usize = 255;
const MAX_CAB_FOLDER_COUNT: usize = MAX_ARCHIVE_ENTRIES;
const MAX_CAB_TOTAL_DATA_BLOCKS: usize = 65_536;
const MAX_CAB_ENTRY_PRESEEK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CAB_CUMULATIVE_DECODE_WORK_BYTES: u64 = MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES;
const ALLOWED_EVIDENCE_EXTENSIONS: &[&str] = &[
    "csv", "etl", "evtx", "htm", "html", "json", "log", "reg", "txt", "xml",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ArchiveFormat {
    Zip,
    Cab,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ArchiveEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveEntryMetadata {
    pub path: String,
    pub uncompressed_size: u64,
    pub kind: ArchiveEntryKind,
}

impl ArchiveEntryMetadata {
    pub fn file(path: impl Into<String>, uncompressed_size: u64) -> Self {
        Self {
            path: path.into(),
            uncompressed_size,
            kind: ArchiveEntryKind::File,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedEvidenceFile {
    pub relative_path: PathBuf,
    pub path: PathBuf,
    pub uncompressed_size: u64,
}

#[derive(Debug)]
pub struct ExtractedArchive {
    format: ArchiveFormat,
    temp_dir: TempDir,
    files: Vec<ExtractedEvidenceFile>,
}

impl ExtractedArchive {
    pub fn format(&self) -> ArchiveFormat {
        self.format
    }

    pub fn root(&self) -> &Path {
        self.temp_dir.path()
    }

    pub fn files(&self) -> &[ExtractedEvidenceFile] {
        &self.files
    }

    /// Parse captured `.reg` exports as text. This never imports or opens a live hive.
    pub fn parse_registry_exports(&self) -> Result<Vec<RegistryParseResult>, ArchiveError> {
        self.files
            .iter()
            .filter(|entry| has_extension(&entry.relative_path, "reg"))
            .map(|entry| {
                let bytes = fs::read(&entry.path).map_err(|error| ArchiveError::Io {
                    operation: "read extracted registry evidence",
                    detail: error.to_string(),
                })?;
                let content = decode_registry_text(&bytes)?;
                Ok(parse_registry_content(
                    &content,
                    &portable_path(&entry.relative_path),
                    entry.uncompressed_size,
                ))
            })
            .collect()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    #[error("unsupported captured archive type: {extension}")]
    UnsupportedArchiveType { extension: String },
    #[error("invalid {format:?} archive: {detail}")]
    InvalidArchive {
        format: ArchiveFormat,
        detail: String,
    },
    #[error("unsafe archive entry path: {path}")]
    UnsafeEntryPath { path: String },
    #[error("unsupported archive entry type {kind:?}: {path}")]
    UnsupportedEntryType {
        path: String,
        kind: ArchiveEntryKind,
    },
    #[error("archive contains {count} entries; maximum is {maximum}")]
    EntryCountExceeded { count: usize, maximum: usize },
    #[error("archive entry {path} is {size} bytes; maximum is {maximum}")]
    EntryTooLarge {
        path: String,
        size: u64,
        maximum: u64,
    },
    #[error("archive expands to {size} bytes; maximum is {maximum}")]
    TotalSizeExceeded { size: u64, maximum: u64 },
    #[error("archive contains a duplicate entry path: {path}")]
    DuplicateEntry { path: String },
    #[error("captured archive extraction was cancelled")]
    Cancelled,
    #[error("invalid captured evidence: {detail}")]
    InvalidEvidence { detail: String },
    #[error("{operation} failed: {detail}")]
    Io {
        operation: &'static str,
        detail: String,
    },
}

#[derive(Debug)]
struct ValidatedEntry {
    source_index: usize,
    relative_path: PathBuf,
    should_extract: bool,
}

#[derive(Debug)]
struct CabPreflightEntry {
    metadata: ArchiveEntryMetadata,
    uncompressed_offset: u64,
    folder_index: usize,
}

#[derive(Debug)]
struct CabPreflight {
    entries: Vec<CabPreflightEntry>,
    folder_uncompressed_sizes: Vec<u64>,
}

pub fn extract_captured_archive(path: &Path) -> Result<ExtractedArchive, ArchiveError> {
    extract_captured_archive_inner(path, None, &|| false)
}

/// Testable cancellation seam used by the live-session service in a later phase.
pub fn extract_captured_archive_with_cancel_in(
    path: &Path,
    temp_parent: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<ExtractedArchive, ArchiveError> {
    extract_captured_archive_inner(path, Some(temp_parent), cancelled)
}

pub fn validate_archive_manifest(entries: &[ArchiveEntryMetadata]) -> Result<(), ArchiveError> {
    validate_entries(entries).map(|_| ())
}

fn extract_captured_archive_inner(
    path: &Path,
    temp_parent: Option<&Path>,
    cancelled: &dyn Fn() -> bool,
) -> Result<ExtractedArchive, ArchiveError> {
    let format = archive_format(path)?;
    let temp_dir = create_temp_dir(temp_parent)?;
    check_cancelled(cancelled)?;

    let files = match format {
        ArchiveFormat::Zip => extract_zip(path, temp_dir.path(), cancelled)?,
        ArchiveFormat::Cab => extract_cab(path, temp_dir.path(), cancelled)?,
    };

    Ok(ExtractedArchive {
        format,
        temp_dir,
        files,
    })
}

fn archive_format(path: &Path) -> Result<ArchiveFormat, ArchiveError> {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("zip") => Ok(ArchiveFormat::Zip),
        Some("cab") => Ok(ArchiveFormat::Cab),
        extension => Err(ArchiveError::UnsupportedArchiveType {
            extension: extension.unwrap_or("<none>").to_string(),
        }),
    }
}

fn create_temp_dir(parent: Option<&Path>) -> Result<TempDir, ArchiveError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("cmtrace-open-esp-archive-");
    match parent {
        Some(parent) => builder.tempdir_in(parent),
        None => builder.tempdir(),
    }
    .map_err(|error| ArchiveError::Io {
        operation: "create unique archive extraction directory",
        detail: error.to_string(),
    })
}

fn extract_zip(
    archive_path: &Path,
    root: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ExtractedEvidenceFile>, ArchiveError> {
    let mut file = File::open(archive_path).map_err(|error| ArchiveError::Io {
        operation: "open ZIP archive",
        detail: error.to_string(),
    })?;
    preflight_zip_entry_count(&mut file)?;
    rewind_archive(&mut file, ArchiveFormat::Zip)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|error| ArchiveError::InvalidArchive {
        format: ArchiveFormat::Zip,
        detail: error.to_string(),
    })?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ArchiveError::EntryCountExceeded {
            count: archive.len(),
            maximum: MAX_ARCHIVE_ENTRIES,
        });
    }

    let mut metadata = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        check_cancelled(cancelled)?;
        let entry = archive
            .by_index(index)
            .map_err(|error| ArchiveError::InvalidArchive {
                format: ArchiveFormat::Zip,
                detail: error.to_string(),
            })?;
        metadata.push(ArchiveEntryMetadata {
            path: entry.name().to_string(),
            uncompressed_size: entry.size(),
            kind: zip_entry_kind(&entry),
        });
    }

    let mut validated = validate_entries(&metadata)?;
    validated.retain(|entry| entry.should_extract);
    validated.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    let mut extracted = Vec::with_capacity(validated.len());
    for entry in validated {
        check_cancelled(cancelled)?;
        let mut reader =
            archive
                .by_index(entry.source_index)
                .map_err(|error| ArchiveError::InvalidArchive {
                    format: ArchiveFormat::Zip,
                    detail: error.to_string(),
                })?;
        let expected_size = metadata[entry.source_index].uncompressed_size;
        let output_path = write_bounded_entry(
            &mut reader,
            root,
            &entry.relative_path,
            expected_size,
            cancelled,
        )?;
        extracted.push(ExtractedEvidenceFile {
            relative_path: entry.relative_path,
            path: output_path,
            uncompressed_size: expected_size,
        });
    }
    Ok(extracted)
}

fn extract_cab(
    archive_path: &Path,
    root: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ExtractedEvidenceFile>, ArchiveError> {
    let mut file = File::open(archive_path).map_err(|error| ArchiveError::Io {
        operation: "open CAB archive",
        detail: error.to_string(),
    })?;
    let preflight = preflight_cab(&mut file, cancelled)?;
    let metadata = preflight
        .entries
        .iter()
        .map(|entry| entry.metadata.clone())
        .collect::<Vec<_>>();
    let mut validated = validate_entries(&metadata)?;
    validate_cab_decode_work(&preflight, &validated)?;
    validated.retain(|entry| entry.should_extract);
    validated.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    rewind_archive(&mut file, ArchiveFormat::Cab)?;
    let mut cabinet = cab::Cabinet::new(file).map_err(|error| ArchiveError::InvalidArchive {
        format: ArchiveFormat::Cab,
        detail: error.to_string(),
    })?;

    let mut extracted = Vec::with_capacity(validated.len());
    for entry in validated {
        check_cancelled(cancelled)?;
        let source_name = &metadata[entry.source_index].path;
        let expected_size = metadata[entry.source_index].uncompressed_size;
        let mut reader =
            cabinet
                .read_file(source_name)
                .map_err(|error| ArchiveError::InvalidArchive {
                    format: ArchiveFormat::Cab,
                    detail: error.to_string(),
                })?;
        let output_path = write_bounded_entry(
            &mut reader,
            root,
            &entry.relative_path,
            expected_size,
            cancelled,
        )?;
        extracted.push(ExtractedEvidenceFile {
            relative_path: entry.relative_path,
            path: output_path,
            uncompressed_size: expected_size,
        });
    }
    Ok(extracted)
}

fn preflight_zip_entry_count(reader: &mut File) -> Result<(), ArchiveError> {
    let file_len = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| invalid_archive(ArchiveFormat::Zip, error))?;
    let search_len = usize::try_from(file_len.min(ZIP_EOCD_MAX_SEARCH_BYTES as u64))
        .expect("ZIP EOCD search length is bounded");
    if search_len < ZIP_EOCD_MIN_BYTES {
        return Err(invalid_archive_detail(
            ArchiveFormat::Zip,
            "missing end-of-central-directory record",
        ));
    }
    reader
        .seek(SeekFrom::End(-(search_len as i64)))
        .map_err(|error| invalid_archive(ArchiveFormat::Zip, error))?;
    let mut tail = vec![0_u8; search_len];
    reader
        .read_exact(&mut tail)
        .map_err(|error| invalid_archive(ArchiveFormat::Zip, error))?;

    let Some(relative_eocd) = (0..=tail.len() - ZIP_EOCD_MIN_BYTES).rev().find(|offset| {
        tail[*offset..].starts_with(&ZIP_EOCD_SIGNATURE)
            && read_u16_le(&tail, *offset + 20).is_some_and(|comment_len| {
                *offset + ZIP_EOCD_MIN_BYTES + comment_len as usize == tail.len()
            })
    }) else {
        return Err(invalid_archive_detail(
            ArchiveFormat::Zip,
            "missing end-of-central-directory record",
        ));
    };
    let absolute_eocd = file_len - search_len as u64 + relative_eocd as u64;
    let disk_number = read_u16_le(&tail, relative_eocd + 4).expect("validated EOCD");
    let central_directory_disk = read_u16_le(&tail, relative_eocd + 6).expect("validated EOCD");
    let entries_on_disk = read_u16_le(&tail, relative_eocd + 8).expect("validated EOCD");
    let total_entries = read_u16_le(&tail, relative_eocd + 10).expect("validated EOCD");
    let central_directory_size = read_u32_le(&tail, relative_eocd + 12).expect("validated EOCD");
    let central_directory_offset = read_u32_le(&tail, relative_eocd + 16).expect("validated EOCD");
    let uses_zip64_sentinel = disk_number == u16::MAX
        || central_directory_disk == u16::MAX
        || entries_on_disk == u16::MAX
        || total_entries == u16::MAX
        || central_directory_size == u32::MAX
        || central_directory_offset == u32::MAX;
    let count = if uses_zip64_sentinel {
        preflight_zip64_entry_count(reader, absolute_eocd)?
    } else {
        usize::from(total_entries.max(entries_on_disk))
    };
    enforce_entry_count(count)
}

fn preflight_zip64_entry_count(reader: &mut File, eocd_offset: u64) -> Result<usize, ArchiveError> {
    let locator_offset = eocd_offset
        .checked_sub(20)
        .ok_or_else(|| invalid_archive_detail(ArchiveFormat::Zip, "missing ZIP64 locator"))?;
    let mut locator = [0_u8; 20];
    read_exact_at(reader, locator_offset, &mut locator, ArchiveFormat::Zip)?;
    if !locator.starts_with(&ZIP64_LOCATOR_SIGNATURE) {
        return Err(invalid_archive_detail(
            ArchiveFormat::Zip,
            "missing ZIP64 locator",
        ));
    }
    let zip64_offset = read_u64_le(&locator, 8).expect("fixed ZIP64 locator");
    let mut zip64_eocd = [0_u8; 56];
    read_exact_at(reader, zip64_offset, &mut zip64_eocd, ArchiveFormat::Zip)?;
    if !zip64_eocd.starts_with(&ZIP64_EOCD_SIGNATURE) {
        return Err(invalid_archive_detail(
            ArchiveFormat::Zip,
            "invalid ZIP64 end-of-central-directory record",
        ));
    }
    let entries_on_disk = read_u64_le(&zip64_eocd, 24).expect("fixed ZIP64 EOCD");
    let total_entries = read_u64_le(&zip64_eocd, 32).expect("fixed ZIP64 EOCD");
    Ok(usize::try_from(total_entries.max(entries_on_disk)).unwrap_or(usize::MAX))
}

fn preflight_cab(
    reader: &mut File,
    cancelled: &dyn Fn() -> bool,
) -> Result<CabPreflight, ArchiveError> {
    let file_len = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| invalid_archive(ArchiveFormat::Cab, error))?;
    let mut header = [0_u8; 36];
    read_exact_at(reader, 0, &mut header, ArchiveFormat::Cab)?;
    if !header.starts_with(&CAB_SIGNATURE) {
        return Err(invalid_archive_detail(
            ArchiveFormat::Cab,
            "invalid cabinet signature",
        ));
    }
    let folder_count = usize::from(read_u16_le(&header, 26).expect("fixed CAB header"));
    let file_count = usize::from(read_u16_le(&header, 28).expect("fixed CAB header"));
    enforce_entry_count(file_count)?;
    if folder_count > MAX_CAB_FOLDER_COUNT {
        return Err(ArchiveError::EntryCountExceeded {
            count: folder_count,
            maximum: MAX_CAB_FOLDER_COUNT,
        });
    }

    let first_file_offset = u64::from(read_u32_le(&header, 16).expect("fixed CAB header"));
    let flags = read_u16_le(&header, 30).expect("fixed CAB header");
    let mut cursor = 36_u64;
    let (folder_reserve_bytes, data_reserve_bytes) = if flags & CAB_FLAG_RESERVE_PRESENT != 0 {
        let mut reserve_sizes = [0_u8; 4];
        read_exact_at(reader, cursor, &mut reserve_sizes, ArchiveFormat::Cab)?;
        cursor += reserve_sizes.len() as u64;
        let header_reserve_bytes =
            u64::from(read_u16_le(&reserve_sizes, 0).expect("fixed CAB reserve header"));
        cursor = cursor.checked_add(header_reserve_bytes).ok_or_else(|| {
            invalid_archive_detail(ArchiveFormat::Cab, "CAB header reserve overflows")
        })?;
        (usize::from(reserve_sizes[2]), usize::from(reserve_sizes[3]))
    } else {
        (0, 0)
    };
    if flags & CAB_FLAG_PREV_CABINET != 0 {
        skip_cab_string(reader, &mut cursor, cancelled)?;
        skip_cab_string(reader, &mut cursor, cancelled)?;
    }
    if flags & CAB_FLAG_NEXT_CABINET != 0 {
        skip_cab_string(reader, &mut cursor, cancelled)?;
        skip_cab_string(reader, &mut cursor, cancelled)?;
    }

    let mut folders = Vec::with_capacity(folder_count);
    let mut total_blocks = 0_usize;
    for _ in 0..folder_count {
        check_cancelled(cancelled)?;
        let mut folder = [0_u8; 8];
        read_exact_at(reader, cursor, &mut folder, ArchiveFormat::Cab)?;
        cursor = cursor
            .checked_add(folder.len() as u64 + folder_reserve_bytes as u64)
            .ok_or_else(|| {
                invalid_archive_detail(ArchiveFormat::Cab, "CAB folder table overflows")
            })?;
        let first_data_offset = u64::from(read_u32_le(&folder, 0).expect("fixed CFFOLDER"));
        let block_count = usize::from(read_u16_le(&folder, 4).expect("fixed CFFOLDER"));
        total_blocks = total_blocks.checked_add(block_count).ok_or_else(|| {
            invalid_archive_detail(ArchiveFormat::Cab, "CAB data-block count overflows")
        })?;
        if total_blocks > MAX_CAB_TOTAL_DATA_BLOCKS {
            return Err(ArchiveError::InvalidEvidence {
                detail: format!(
                    "CAB contains {total_blocks} data blocks; maximum is {MAX_CAB_TOTAL_DATA_BLOCKS}"
                ),
            });
        }
        folders.push(cab_folder_uncompressed_size(
            reader,
            file_len,
            first_data_offset,
            block_count,
            data_reserve_bytes,
            cancelled,
        )?);
    }

    cursor = first_file_offset;
    let mut entries = Vec::with_capacity(file_count);
    for _ in 0..file_count {
        check_cancelled(cancelled)?;
        let mut fixed = [0_u8; 16];
        read_exact_at(reader, cursor, &mut fixed, ArchiveFormat::Cab)?;
        cursor += fixed.len() as u64;
        let uncompressed_size = u64::from(read_u32_le(&fixed, 0).expect("fixed CFFILE"));
        let uncompressed_offset = u64::from(read_u32_le(&fixed, 4).expect("fixed CFFILE"));
        let raw_folder_index = read_u16_le(&fixed, 8).expect("fixed CFFILE");
        let name = read_cab_string(reader, &mut cursor, cancelled)?;
        if matches!(
            raw_folder_index,
            CAB_CONTINUED_FROM_PREVIOUS | CAB_CONTINUED_TO_NEXT | CAB_CONTINUED_PREVIOUS_AND_NEXT
        ) {
            return Err(ArchiveError::UnsupportedEntryType {
                path: name,
                kind: ArchiveEntryKind::Other,
            });
        }
        let folder_index = usize::from(raw_folder_index);
        if folder_index >= folders.len() {
            return Err(invalid_archive_detail(
                ArchiveFormat::Cab,
                format!("CAB entry {name} references missing folder {folder_index}"),
            ));
        }
        entries.push(CabPreflightEntry {
            metadata: ArchiveEntryMetadata::file(name, uncompressed_size),
            uncompressed_offset,
            folder_index,
        });
    }

    Ok(CabPreflight {
        entries,
        folder_uncompressed_sizes: folders,
    })
}

fn cab_folder_uncompressed_size(
    reader: &mut File,
    file_len: u64,
    mut cursor: u64,
    block_count: usize,
    data_reserve_bytes: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<u64, ArchiveError> {
    let mut total = 0_u64;
    for _ in 0..block_count {
        check_cancelled(cancelled)?;
        let mut block = [0_u8; 8];
        read_exact_at(reader, cursor, &mut block, ArchiveFormat::Cab)?;
        let compressed_size = u64::from(read_u16_le(&block, 4).expect("fixed CFDATA"));
        let uncompressed_size = u64::from(read_u16_le(&block, 6).expect("fixed CFDATA"));
        total = total.checked_add(uncompressed_size).ok_or_else(|| {
            invalid_archive_detail(ArchiveFormat::Cab, "CAB folder size overflows")
        })?;
        cursor = cursor
            .checked_add(8 + data_reserve_bytes as u64)
            .and_then(|value| value.checked_add(compressed_size))
            .ok_or_else(|| {
                invalid_archive_detail(ArchiveFormat::Cab, "CAB data-block offset overflows")
            })?;
        if cursor > file_len {
            return Err(invalid_archive_detail(
                ArchiveFormat::Cab,
                "CAB data block extends beyond the container",
            ));
        }
    }
    Ok(total)
}

fn read_cab_string(
    reader: &mut File,
    cursor: &mut u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, ArchiveError> {
    let mut bytes = Vec::with_capacity(MAX_CAB_STRING_BYTES);
    loop {
        check_cancelled(cancelled)?;
        let mut byte = [0_u8; 1];
        read_exact_at(reader, *cursor, &mut byte, ArchiveFormat::Cab)?;
        *cursor += 1;
        if byte[0] == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        if bytes.len() == MAX_CAB_STRING_BYTES {
            return Err(invalid_archive_detail(
                ArchiveFormat::Cab,
                format!("CAB string exceeds {MAX_CAB_STRING_BYTES} bytes"),
            ));
        }
        bytes.push(byte[0]);
    }
}

fn skip_cab_string(
    reader: &mut File,
    cursor: &mut u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), ArchiveError> {
    read_cab_string(reader, cursor, cancelled).map(|_| ())
}

fn validate_cab_decode_work(
    preflight: &CabPreflight,
    validated: &[ValidatedEntry],
) -> Result<(), ArchiveError> {
    let mut cumulative_work = 0_u64;
    for entry in validated.iter().filter(|entry| entry.should_extract) {
        let cab_entry = &preflight.entries[entry.source_index];
        if cab_entry.uncompressed_offset > MAX_CAB_ENTRY_PRESEEK_BYTES {
            return Err(ArchiveError::InvalidEvidence {
                detail: format!(
                    "CAB pre-seek work exceeds {MAX_CAB_ENTRY_PRESEEK_BYTES} bytes for {}",
                    cab_entry.metadata.path
                ),
            });
        }
        let entry_work = cab_entry
            .uncompressed_offset
            .checked_add(cab_entry.metadata.uncompressed_size)
            .ok_or_else(|| ArchiveError::InvalidEvidence {
                detail: format!("CAB decode work overflows for {}", cab_entry.metadata.path),
            })?;
        cumulative_work = cumulative_work.checked_add(entry_work).ok_or_else(|| {
            ArchiveError::InvalidEvidence {
                detail: "CAB cumulative decode work overflows".to_string(),
            }
        })?;
        if cumulative_work > MAX_CAB_CUMULATIVE_DECODE_WORK_BYTES {
            return Err(ArchiveError::InvalidEvidence {
                detail: format!(
                    "CAB cumulative decode work exceeds {MAX_CAB_CUMULATIVE_DECODE_WORK_BYTES} bytes"
                ),
            });
        }
    }

    for entry in validated.iter().filter(|entry| entry.should_extract) {
        let cab_entry = &preflight.entries[entry.source_index];
        let entry_work = cab_entry
            .uncompressed_offset
            .checked_add(cab_entry.metadata.uncompressed_size)
            .ok_or_else(|| ArchiveError::InvalidEvidence {
                detail: format!("CAB decode work overflows for {}", cab_entry.metadata.path),
            })?;
        let folder_size = preflight.folder_uncompressed_sizes[cab_entry.folder_index];
        if entry_work > folder_size {
            return Err(ArchiveError::InvalidEvidence {
                detail: format!(
                    "CAB entry {} declares range {}..{} beyond folder size {folder_size}",
                    cab_entry.metadata.path, cab_entry.uncompressed_offset, entry_work
                ),
            });
        }
    }
    Ok(())
}

fn enforce_entry_count(count: usize) -> Result<(), ArchiveError> {
    if count > MAX_ARCHIVE_ENTRIES {
        Err(ArchiveError::EntryCountExceeded {
            count,
            maximum: MAX_ARCHIVE_ENTRIES,
        })
    } else {
        Ok(())
    }
}

fn read_exact_at(
    reader: &mut File,
    offset: u64,
    buffer: &mut [u8],
    format: ArchiveFormat,
) -> Result<(), ArchiveError> {
    reader
        .seek(SeekFrom::Start(offset))
        .and_then(|_| reader.read_exact(buffer))
        .map_err(|error| invalid_archive(format, error))
}

fn rewind_archive(reader: &mut File, format: ArchiveFormat) -> Result<(), ArchiveError> {
    reader
        .seek(SeekFrom::Start(0))
        .map(|_| ())
        .map_err(|error| invalid_archive(format, error))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn invalid_archive(format: ArchiveFormat, error: impl std::fmt::Display) -> ArchiveError {
    invalid_archive_detail(format, error.to_string())
}

fn invalid_archive_detail(format: ArchiveFormat, detail: impl Into<String>) -> ArchiveError {
    ArchiveError::InvalidArchive {
        format,
        detail: detail.into(),
    }
}

fn validate_entries(entries: &[ArchiveEntryMetadata]) -> Result<Vec<ValidatedEntry>, ArchiveError> {
    if entries.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ArchiveError::EntryCountExceeded {
            count: entries.len(),
            maximum: MAX_ARCHIVE_ENTRIES,
        });
    }

    let mut total_size = 0_u64;
    let mut seen = BTreeSet::new();
    let mut validated = Vec::with_capacity(entries.len());
    for (source_index, entry) in entries.iter().enumerate() {
        let relative_path = safe_relative_path(&entry.path)?;
        match entry.kind {
            ArchiveEntryKind::Symlink | ArchiveEntryKind::Other => {
                return Err(ArchiveError::UnsupportedEntryType {
                    path: entry.path.clone(),
                    kind: entry.kind,
                });
            }
            ArchiveEntryKind::File => {
                if entry.uncompressed_size > MAX_ARCHIVE_FILE_BYTES {
                    return Err(ArchiveError::EntryTooLarge {
                        path: entry.path.clone(),
                        size: entry.uncompressed_size,
                        maximum: MAX_ARCHIVE_FILE_BYTES,
                    });
                }
                total_size = total_size.saturating_add(entry.uncompressed_size);
                if total_size > MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES {
                    return Err(ArchiveError::TotalSizeExceeded {
                        size: total_size,
                        maximum: MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES,
                    });
                }
            }
            ArchiveEntryKind::Directory => {}
        }

        let identity = portable_path(&relative_path).to_lowercase();
        if !seen.insert(identity) {
            return Err(ArchiveError::DuplicateEntry {
                path: entry.path.clone(),
            });
        }
        validated.push(ValidatedEntry {
            source_index,
            should_extract: entry.kind == ArchiveEntryKind::File
                && is_allowlisted_evidence(&relative_path),
            relative_path,
        });
    }
    Ok(validated)
}

fn safe_relative_path(raw: &str) -> Result<PathBuf, ArchiveError> {
    let reject = || ArchiveError::UnsafeEntryPath {
        path: raw.to_string(),
    };
    if raw.is_empty() || raw.chars().any(|character| character.is_control()) {
        return Err(reject());
    }
    let normalized = raw.replace('\\', "/");
    let normalized = normalized.trim_end_matches('/');
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.starts_with("//")
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
    {
        return Err(reject());
    }

    let mut path = PathBuf::new();
    for component in normalized.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.ends_with([' ', '.'])
            || component
                .chars()
                .any(|character| "<>:\"|?*".contains(character))
            || is_reserved_windows_component(component)
        {
            return Err(reject());
        }
        path.push(component);
    }
    Ok(path)
}

fn is_reserved_windows_component(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
}

fn zip_entry_kind(entry: &zip::read::ZipFile<'_>) -> ArchiveEntryKind {
    if entry.is_dir() {
        return ArchiveEntryKind::Directory;
    }
    match entry.unix_mode().map(|mode| mode & 0o170000) {
        Some(0o120000) => ArchiveEntryKind::Symlink,
        Some(0) | Some(0o100000) | None => ArchiveEntryKind::File,
        _ => ArchiveEntryKind::Other,
    }
}

fn is_allowlisted_evidence(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|extension| ALLOWED_EVIDENCE_EXTENSIONS.contains(&extension.as_str()))
}

fn write_bounded_entry(
    reader: &mut impl Read,
    root: &Path,
    relative_path: &Path,
    expected_size: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<PathBuf, ArchiveError> {
    let output_path = root.join(relative_path);
    let parent = output_path
        .parent()
        .ok_or_else(|| ArchiveError::UnsafeEntryPath {
            path: portable_path(relative_path),
        })?;
    fs::create_dir_all(parent).map_err(|error| ArchiveError::Io {
        operation: "create archive entry directory",
        detail: error.to_string(),
    })?;
    ensure_contained_directory(root, parent, relative_path)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .map_err(|error| ArchiveError::Io {
            operation: "create extracted evidence file",
            detail: error.to_string(),
        })?;

    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut written = 0_u64;
    loop {
        check_cancelled(cancelled)?;
        let read = reader.read(&mut buffer).map_err(|error| ArchiveError::Io {
            operation: "read compressed evidence entry",
            detail: error.to_string(),
        })?;
        if read == 0 {
            break;
        }
        written = written.saturating_add(read as u64);
        if written > expected_size || written > MAX_ARCHIVE_FILE_BYTES {
            return Err(ArchiveError::EntryTooLarge {
                path: portable_path(relative_path),
                size: written,
                maximum: expected_size.min(MAX_ARCHIVE_FILE_BYTES),
            });
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| ArchiveError::Io {
                operation: "write extracted evidence entry",
                detail: error.to_string(),
            })?;
    }
    if written != expected_size {
        return Err(ArchiveError::InvalidEvidence {
            detail: format!(
                "entry {} declared {expected_size} bytes but produced {written}",
                portable_path(relative_path)
            ),
        });
    }
    Ok(output_path)
}

fn ensure_contained_directory(
    root: &Path,
    directory: &Path,
    relative_path: &Path,
) -> Result<(), ArchiveError> {
    let canonical_root = root.canonicalize().map_err(|error| ArchiveError::Io {
        operation: "resolve archive extraction root",
        detail: error.to_string(),
    })?;
    let canonical_directory = directory.canonicalize().map_err(|error| ArchiveError::Io {
        operation: "resolve archive entry directory",
        detail: error.to_string(),
    })?;
    if !canonical_directory.starts_with(&canonical_root) {
        return Err(ArchiveError::UnsafeEntryPath {
            path: portable_path(relative_path),
        });
    }
    Ok(())
}

fn check_cancelled(cancelled: &dyn Fn() -> bool) -> Result<(), ArchiveError> {
    if cancelled() {
        Err(ArchiveError::Cancelled)
    } else {
        Ok(())
    }
}

fn decode_registry_text(bytes: &[u8]) -> Result<String, ArchiveError> {
    if let Some(payload) = bytes.strip_prefix(&[0xff, 0xfe]) {
        return decode_utf16(payload, true);
    }
    if let Some(payload) = bytes.strip_prefix(&[0xfe, 0xff]) {
        return decode_utf16(payload, false);
    }
    let payload = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    match String::from_utf8(payload.to_vec()) {
        Ok(content) => Ok(content),
        Err(_) => {
            let (content, _, _) = encoding_rs::WINDOWS_1252.decode(payload);
            Ok(content.into_owned())
        }
    }
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> Result<String, ArchiveError> {
    if bytes.len() % 2 != 0 {
        return Err(ArchiveError::InvalidEvidence {
            detail: "registry export contains an odd number of UTF-16 bytes".to_string(),
        });
    }
    let code_units = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect::<Vec<_>>();
    String::from_utf16(&code_units).map_err(|error| ArchiveError::InvalidEvidence {
        detail: format!("registry export is not valid UTF-16: {error}"),
    })
}

fn has_extension(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
}

fn portable_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
