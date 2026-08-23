use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::RwLock;

use cmtraceopen_parser::eventmap::MapRegistry;
use cmtraceopen_parser::models::log_entry::{LogEntry, Severity};
use cmtraceopen_parser::parser::{decode_bytes, detect_encoding, parse_content};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use super::models::{
    EvtxArchiveMember, EvtxArchiveMemberKind, EvtxArchiveMemberOutcome, EvtxCoverageGap,
    EvtxCoverageGapKind, EvtxField, EvtxLevel, EvtxRecord,
};
use super::parser::{parse_evtx_buffer, ParsedFile};
use super::provider_db::ProviderStore;

pub const MAX_ARCHIVE_MEMBERS: usize = 512;
pub const MAX_ARCHIVE_MEMBER_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_ARCHIVE_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_COMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_COVERAGE: usize = MAX_ARCHIVE_MEMBERS + 32;
fn bounded_member_indices(member_count: usize) -> std::ops::Range<usize> {
    0..member_count.min(MAX_ARCHIVE_MEMBERS)
}
fn archive_budget_allows(total: u64, next: u64, limit: u64) -> bool {
    limit
        .checked_sub(total)
        .is_some_and(|remaining| remaining > 0 && next <= remaining)
}
fn account_archive_bytes(total: u64, consumed: u64) -> u64 {
    total.saturating_add(consumed).min(MAX_ARCHIVE_TOTAL_BYTES)
}

fn archive_record_budget_allows(total: usize, max_records: usize) -> bool {
    total < max_records
}
const MAX_ARCHIVE_TEXT_PARSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_TEXT_RECORDS: usize = 25_000;

fn archive_text_parser_admission_allows(
    declared_bytes: u64,
    total_records: usize,
    max_records: usize,
) -> bool {
    declared_bytes <= MAX_ARCHIVE_TEXT_PARSE_BYTES
        && archive_record_budget_allows(total_records, max_records)
}

fn text_parse_error_is_limit(error: &str) -> bool {
    error.starts_with("text member exceeds parser budget")
}

#[derive(Debug, Clone, Copy)]
struct ArchiveDirectoryInfo {
    member_count: u64,
    directory_size: u64,
    directory_offset: u64,
}

fn archive_directory_info(file: &mut File) -> std::io::Result<Option<ArchiveDirectoryInfo>> {
    const END_OF_CENTRAL_DIRECTORY: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
    const ZIP64_END_OF_CENTRAL_DIRECTORY: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    const END_OF_CENTRAL_DIRECTORY_BYTES: usize = 22;
    const MAX_ZIP_COMMENT_BYTES: usize = u16::MAX as usize;

    let file_len = file.seek(SeekFrom::End(0))?;
    let probe_len = usize::try_from(
        file_len.min((END_OF_CENTRAL_DIRECTORY_BYTES + MAX_ZIP_COMMENT_BYTES) as u64),
    )
    .expect("ZIP trailer probe is bounded by the u16 comment limit");
    file.seek(SeekFrom::Start(file_len - probe_len as u64))?;
    let mut probe = vec![0u8; probe_len];
    file.read_exact(&mut probe)?;
    let probe_start = file_len - probe_len as u64;
    if probe_len < END_OF_CENTRAL_DIRECTORY_BYTES {
        return Ok(None);
    }
    let mut saw_zip64_sentinel = false;
    for index in (0..=probe_len - END_OF_CENTRAL_DIRECTORY_BYTES).rev() {
        if probe.get(index..index + 4) != Some(&END_OF_CENTRAL_DIRECTORY) {
            continue;
        }
        let comment_len = u16::from_le_bytes([probe[index + 20], probe[index + 21]]) as usize;
        if index + END_OF_CENTRAL_DIRECTORY_BYTES + comment_len > probe_len {
            continue;
        }
        let member_count = u16::from_le_bytes([probe[index + 10], probe[index + 11]]) as u64;
        let directory_size = u32::from_le_bytes(
            probe[index + 12..index + 16]
                .try_into()
                .expect("fixed ZIP field"),
        ) as u64;
        let directory_offset = u32::from_le_bytes(
            probe[index + 16..index + 20]
                .try_into()
                .expect("fixed ZIP field"),
        ) as u64;
        if member_count != u16::MAX as u64 {
            return Ok(Some(ArchiveDirectoryInfo {
                member_count,
                directory_size,
                directory_offset,
            }));
        }
        saw_zip64_sentinel = true;

        let eocd_offset = probe_start + index as u64;
        if eocd_offset < 20 {
            continue;
        }
        file.seek(SeekFrom::Start(eocd_offset - 20))?;
        let mut locator = [0u8; 20];
        file.read_exact(&mut locator)?;
        if locator[0..4] != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR {
            continue;
        }
        let zip64_offset =
            u64::from_le_bytes(locator[8..16].try_into().expect("fixed ZIP64 field"));
        if zip64_offset > file_len.saturating_sub(56) {
            continue;
        }
        file.seek(SeekFrom::Start(zip64_offset))?;
        let mut zip64_end = [0u8; 56];
        file.read_exact(&mut zip64_end)?;
        if zip64_end[0..4] == ZIP64_END_OF_CENTRAL_DIRECTORY {
            let member_count =
                u64::from_le_bytes(zip64_end[32..40].try_into().expect("fixed ZIP64 field"));
            let directory_size =
                u64::from_le_bytes(zip64_end[40..48].try_into().expect("fixed ZIP64 field"));
            let directory_offset =
                u64::from_le_bytes(zip64_end[48..56].try_into().expect("fixed ZIP64 field"));
            return Ok(Some(ArchiveDirectoryInfo {
                member_count,
                directory_size,
                directory_offset,
            }));
        }
    }
    if saw_zip64_sentinel {
        Ok(Some(ArchiveDirectoryInfo {
            member_count: u64::MAX,
            directory_size: u64::MAX,
            directory_offset: u64::MAX,
        }))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
fn archive_member_count(file: &mut File) -> std::io::Result<Option<u64>> {
    Ok(archive_directory_info(file)?.map(|info| info.member_count))
}

#[derive(Debug)]
pub(crate) struct ArchiveMember {
    pub(crate) source_label: String,
    pub(crate) parsed: ParsedFile,
}

#[derive(Debug, Default)]
pub(crate) struct ArchiveParseResult {
    pub(crate) metadata: Vec<EvtxArchiveMember>,
    pub(crate) coverage: Vec<EvtxCoverageGap>,
    pub(crate) parse_errors: u32,
    pub(crate) messages: Vec<String>,
    omitted_coverage: usize,
}

/// Parse EVTX members directly from a bounded ZIP stream. No extracted path escapes this call.
pub(crate) fn parse_archive_batches<F>(
    path: &Path,
    maps: &RwLock<MapRegistry>,
    providers: &RwLock<ProviderStore>,
    max_records: usize,
    mut emit: F,
) -> Result<ArchiveParseResult, EvtxCoverageGap>
where
    F: FnMut(ArchiveMember) -> bool,
{
    let source = path.to_string_lossy().into_owned();
    let mut file = File::open(path).map_err(|error| {
        EvtxCoverageGap::new(
            source.clone(),
            EvtxCoverageGapKind::File,
            format!("failed to open archive: {error}"),
        )
    })?;
    let directory_info = archive_directory_info(&mut file).map_err(|error| {
        EvtxCoverageGap::new(
            source.clone(),
            EvtxCoverageGapKind::File,
            format!("archive directory could not be inspected: {error}"),
        )
    })?;
    if let Some(info) = directory_info {
        if info.member_count > MAX_ARCHIVE_MEMBERS as u64 {
            return Err(EvtxCoverageGap::new(
                source.clone(),
                EvtxCoverageGapKind::Limit,
                format!(
                    "archive member count {} exceeds limit of {MAX_ARCHIVE_MEMBERS}; \
                     archive was not opened",
                    info.member_count
                ),
            ));
        }
        let file_len = file
            .metadata()
            .map_err(|error| {
                EvtxCoverageGap::new(
                    source.clone(),
                    EvtxCoverageGapKind::File,
                    format!("archive metadata could not be inspected: {error}"),
                )
            })?
            .len();
        let directory_end = info.directory_offset.checked_add(info.directory_size);
        if info.directory_size > MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES
            || directory_end.is_none_or(|end| end > file_len)
        {
            return Err(EvtxCoverageGap::new(
                source.clone(),
                EvtxCoverageGapKind::Limit,
                format!(
                    "archive central directory exceeds {MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES} byte \
                     limit or lies outside the archive"
                ),
            ));
        }
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        EvtxCoverageGap::new(
            source.clone(),
            EvtxCoverageGapKind::File,
            format!("archive could not be rewound: {error}"),
        )
    })?;
    let mut archive = ZipArchive::new(file).map_err(|error| {
        EvtxCoverageGap::new(
            source.clone(),
            EvtxCoverageGapKind::File,
            format!("archive is corrupt or not a ZIP: {error}"),
        )
    })?;

    let mut result = ArchiveParseResult::default();
    let mut seen_paths = HashSet::new();
    let mut total_bytes = 0u64;
    let mut total_compressed_bytes = 0u64;
    let mut total_records = 0usize;
    let mut emitted_members = 0usize;
    let member_count = archive.len();

    'members: for index in bounded_member_indices(member_count) {
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(error) => {
                push_metadata(
                    &mut result,
                    format!("{source}::member-{index}"),
                    EvtxArchiveMemberKind::Binary,
                    None,
                    EvtxArchiveMemberOutcome::Malformed,
                );
                push_gap(
                    &mut result,
                    &source,
                    EvtxCoverageGapKind::File,
                    format!("member {index} could not be opened: {error}"),
                );
                continue;
            }
        };
        let raw_name = entry.name().to_string();
        let member_label = if raw_name.chars().any(is_unsafe_member_character) {
            format!("{source}::member-{index}")
        } else {
            format!("{source}::{raw_name}")
        };

        let Some(member_name) = validate_member_name(&raw_name) else {
            push_metadata(
                &mut result,
                member_label.clone(),
                archive_member_kind(&raw_name),
                None,
                EvtxArchiveMemberOutcome::Unsupported,
            );
            push_gap(
                &mut result,
                &member_label,
                EvtxCoverageGapKind::Unsupported,
                "member path is not a safe relative path",
            );
            continue;
        };
        let normalized_label = format!("{source}::{member_name}");

        if entry
            .unix_mode()
            .is_some_and(|mode| (mode & 0o170000) == 0o120000)
        {
            push_metadata(
                &mut result,
                normalized_label.clone(),
                archive_member_kind(&member_name),
                None,
                EvtxArchiveMemberOutcome::Unsupported,
            );
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Unsupported,
                "symbolic-link archive members are not followed",
            );
            continue;
        }
        if !seen_paths.insert(member_name.to_ascii_lowercase()) {
            push_metadata(
                &mut result,
                normalized_label.clone(),
                archive_member_kind(&member_name),
                None,
                EvtxArchiveMemberOutcome::Duplicate,
            );
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Unsupported,
                "duplicate archive member path (case-insensitive)",
            );
            continue;
        }
        if entry.is_dir() {
            push_metadata(
                &mut result,
                normalized_label.clone(),
                archive_member_kind(&member_name),
                None,
                EvtxArchiveMemberOutcome::Unsupported,
            );
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Unsupported,
                "directory archive member was skipped",
            );
            continue;
        }
        let compressed_size = entry.compressed_size();
        let declared_size = entry.size();
        if is_evtx_name(&member_name) && !archive_record_budget_allows(total_records, max_records) {
            push_metadata(
                &mut result,
                normalized_label.clone(),
                archive_member_kind(&member_name),
                None,
                EvtxArchiveMemberOutcome::Limit,
            );
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                format!("archive record budget of {max_records} records was exhausted"),
            );
            continue;
        }
        if compressed_size > MAX_ARCHIVE_MEMBER_BYTES {
            push_metadata(
                &mut result,
                normalized_label.clone(),
                archive_member_kind(&member_name),
                None,
                EvtxArchiveMemberOutcome::Limit,
            );
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                format!("compressed member exceeds {MAX_ARCHIVE_MEMBER_BYTES} byte limit"),
            );
            continue;
        }
        if declared_size > MAX_ARCHIVE_MEMBER_BYTES {
            push_metadata(
                &mut result,
                normalized_label.clone(),
                archive_member_kind(&member_name),
                None,
                EvtxArchiveMemberOutcome::Limit,
            );
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                format!("member exceeds {MAX_ARCHIVE_MEMBER_BYTES} byte limit"),
            );
            continue;
        }
        if is_text_name(&member_name)
            && !archive_text_parser_admission_allows(declared_size, total_records, max_records)
        {
            push_metadata(
                &mut result,
                normalized_label.clone(),
                EvtxArchiveMemberKind::Text,
                None,
                EvtxArchiveMemberOutcome::Limit,
            );
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                format!(
                    "text member exceeds parser budget of {MAX_ARCHIVE_TEXT_PARSE_BYTES} bytes \
                     or archive record budget of {max_records} records"
                ),
            );
            continue;
        }
        if !archive_budget_allows(
            total_compressed_bytes,
            compressed_size,
            MAX_ARCHIVE_TOTAL_COMPRESSED_BYTES,
        ) {
            push_metadata(
                &mut result,
                normalized_label.clone(),
                archive_member_kind(&member_name),
                None,
                EvtxArchiveMemberOutcome::Limit,
            );
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                format!(
                    "archive aggregate compressed bytes exceed \
                     {MAX_ARCHIVE_TOTAL_COMPRESSED_BYTES} byte limit"
                ),
            );
            continue;
        }
        total_compressed_bytes = total_compressed_bytes.saturating_add(compressed_size);
        let Some(remaining_bytes) = MAX_ARCHIVE_TOTAL_BYTES.checked_sub(total_bytes) else {
            push_metadata(
                &mut result,
                normalized_label.clone(),
                archive_member_kind(&member_name),
                None,
                EvtxArchiveMemberOutcome::Limit,
            );
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                "archive aggregate byte accounting overflowed",
            );
            continue;
        };
        if declared_size > remaining_bytes || remaining_bytes == 0 {
            push_metadata(
                &mut result,
                normalized_label.clone(),
                archive_member_kind(&member_name),
                None,
                EvtxArchiveMemberOutcome::Limit,
            );
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                format!("archive aggregate exceeds {MAX_ARCHIVE_TOTAL_BYTES} byte limit"),
            );
            continue;
        }
        let member_limit = MAX_ARCHIVE_MEMBER_BYTES.min(remaining_bytes);
        if !is_evtx_name(&member_name) {
            let category = inventory_category(&member_name);
            if is_text_name(&member_name) {
                match read_member_bytes(&mut entry, member_limit.min(MAX_ARCHIVE_TEXT_PARSE_BYTES))
                {
                    Ok(bytes) => {
                        total_bytes = account_archive_bytes(total_bytes, bytes.len() as u64);
                        let digest = sha256_hex(&bytes);
                        match parse_text_member(
                            bytes,
                            &normalized_label,
                            max_records.saturating_sub(total_records),
                        ) {
                            Ok(mut parsed) => {
                                bound_archive_records(
                                    &mut parsed,
                                    max_records.saturating_sub(total_records),
                                    &normalized_label,
                                    max_records,
                                );
                                total_records = total_records.saturating_add(parsed.records.len());
                                let outcome = parsed_member_outcome(&parsed);
                                push_metadata(
                                    &mut result,
                                    normalized_label.clone(),
                                    EvtxArchiveMemberKind::Text,
                                    Some(digest),
                                    outcome,
                                );
                                emitted_members = emitted_members.saturating_add(1);
                                if !emit(ArchiveMember {
                                    source_label: normalized_label,
                                    parsed,
                                }) {
                                    break 'members;
                                }
                            }
                            Err(error) => {
                                let limited = text_parse_error_is_limit(&error);
                                push_metadata(
                                    &mut result,
                                    normalized_label.clone(),
                                    EvtxArchiveMemberKind::Text,
                                    Some(digest),
                                    if limited {
                                        EvtxArchiveMemberOutcome::Limit
                                    } else {
                                        EvtxArchiveMemberOutcome::Malformed
                                    },
                                );
                                push_gap(
                                    &mut result,
                                    &normalized_label,
                                    if limited {
                                        EvtxCoverageGapKind::Limit
                                    } else {
                                        EvtxCoverageGapKind::File
                                    },
                                    format!("text member could not be parsed: {error}"),
                                );
                            }
                        }
                    }
                    Err(error) => {
                        let limited = error.is_limit();
                        total_bytes = account_archive_bytes(total_bytes, error.bytes_read());
                        push_metadata(
                            &mut result,
                            normalized_label.clone(),
                            EvtxArchiveMemberKind::Text,
                            None,
                            if limited {
                                EvtxArchiveMemberOutcome::Limit
                            } else {
                                EvtxArchiveMemberOutcome::Malformed
                            },
                        );
                        push_gap(
                            &mut result,
                            &normalized_label,
                            if limited {
                                EvtxCoverageGapKind::Limit
                            } else {
                                EvtxCoverageGapKind::File
                            },
                            format!("text member could not be read: {error}"),
                        );
                    }
                }
            } else {
                match read_member_digest(&mut entry, member_limit) {
                    Ok((digest, read_bytes)) => {
                        total_bytes = account_archive_bytes(total_bytes, read_bytes);
                        push_metadata(
                            &mut result,
                            normalized_label.clone(),
                            archive_member_kind(&member_name),
                            Some(digest.clone()),
                            EvtxArchiveMemberOutcome::Unsupported,
                        );
                        push_gap(
                            &mut result,
                            &normalized_label,
                            EvtxCoverageGapKind::Unsupported,
                            format!(
                                "unsupported {category} member retained as inventory (sha256:{digest})"
                            ),
                        );
                    }
                    Err(error) => {
                        let limited = error.is_limit();
                        total_bytes = account_archive_bytes(total_bytes, error.bytes_read());
                        push_metadata(
                            &mut result,
                            normalized_label.clone(),
                            archive_member_kind(&member_name),
                            None,
                            if limited {
                                EvtxArchiveMemberOutcome::Limit
                            } else {
                                EvtxArchiveMemberOutcome::Malformed
                            },
                        );
                        push_gap(
                            &mut result,
                            &normalized_label,
                            if limited {
                                EvtxCoverageGapKind::Limit
                            } else {
                                EvtxCoverageGapKind::File
                            },
                            format!("{category} member could not be read: {error}"),
                        );
                    }
                }
            }
            continue;
        }

        let bytes = match read_member_bytes(&mut entry, member_limit) {
            Ok(bytes) => {
                total_bytes = account_archive_bytes(total_bytes, bytes.len() as u64);
                bytes
            }
            Err(error) => {
                let limited = error.is_limit();
                total_bytes = account_archive_bytes(total_bytes, error.bytes_read());
                push_metadata(
                    &mut result,
                    normalized_label.clone(),
                    EvtxArchiveMemberKind::Evtx,
                    None,
                    if limited {
                        EvtxArchiveMemberOutcome::Limit
                    } else {
                        EvtxArchiveMemberOutcome::Malformed
                    },
                );
                push_gap(
                    &mut result,
                    &normalized_label,
                    if limited {
                        EvtxCoverageGapKind::Limit
                    } else {
                        EvtxCoverageGapKind::File
                    },
                    format!("EVTX member could not be read: {error}"),
                );
                continue;
            }
        };
        let digest = sha256_hex(&bytes);
        match parse_evtx_buffer(bytes, &normalized_label, maps, providers) {
            Ok(mut parsed) => {
                bound_archive_records(
                    &mut parsed,
                    max_records.saturating_sub(total_records),
                    &normalized_label,
                    max_records,
                );
                total_records = total_records.saturating_add(parsed.records.len());
                push_metadata(
                    &mut result,
                    normalized_label.clone(),
                    EvtxArchiveMemberKind::Evtx,
                    Some(digest.clone()),
                    parsed_member_outcome(&parsed),
                );
                emitted_members = emitted_members.saturating_add(1);
                if !emit(ArchiveMember {
                    source_label: normalized_label,
                    parsed,
                }) {
                    break 'members;
                }
            }
            Err(mut gap) => {
                push_metadata(
                    &mut result,
                    normalized_label.clone(),
                    EvtxArchiveMemberKind::Evtx,
                    Some(digest.clone()),
                    EvtxArchiveMemberOutcome::Malformed,
                );
                gap.reason = format!("{} (sha256:{digest})", gap.reason);
                result.parse_errors = result.parse_errors.saturating_add(1);
                push_existing_gap(&mut result, gap);
            }
        }
    }
    if member_count > MAX_ARCHIVE_MEMBERS {
        push_metadata(
            &mut result,
            format!("{source}::[members {MAX_ARCHIVE_MEMBERS}..{member_count})"),
            EvtxArchiveMemberKind::Binary,
            None,
            EvtxArchiveMemberOutcome::Limit,
        );
        push_gap(
            &mut result,
            &source,
            EvtxCoverageGapKind::Limit,
            format!(
                "archive member count {member_count} exceeds limit of {MAX_ARCHIVE_MEMBERS}; \
                 later members were not inspected"
            ),
        );
    }

    if emitted_members == 0 && result.coverage.is_empty() {
        push_gap(
            &mut result,
            &source,
            EvtxCoverageGapKind::Empty,
            "archive contains no supported EVTX or inventory members",
        );
    }
    if emitted_members == 0 {
        result.messages.push(format!(
            "{source}: no readable EVTX members were found; archive coverage is reported below"
        ));
    }
    Ok(result)
}

fn is_evtx_name(name: &str) -> bool {
    name.rsplit('/').next().is_some_and(|file| {
        let lower = file.to_ascii_lowercase();
        if lower.ends_with(".evtx") {
            return true;
        }
        let Some((stem, rotation)) = lower.rsplit_once(".evtx.") else {
            return false;
        };
        !stem.is_empty()
            && !rotation.is_empty()
            && rotation.bytes().all(|byte| byte.is_ascii_digit())
    })
}
fn is_text_name(name: &str) -> bool {
    inventory_category(name) == "text"
}

fn bounded_text_content(content: &str, max_lines: usize) -> (&str, bool) {
    if content.is_empty() {
        return (content, false);
    }
    if max_lines == 0 {
        return ("", true);
    }

    let mut end = 0;
    for (index, line) in content.split_inclusive('\n').enumerate() {
        if index >= max_lines {
            return (&content[..end], true);
        }
        end += line.len();
    }
    (content, false)
}

fn parse_text_member(
    bytes: Vec<u8>,
    source_label: &str,
    max_records: usize,
) -> Result<ParsedFile, String> {
    if bytes.len() as u64 > MAX_ARCHIVE_TEXT_PARSE_BYTES {
        return Err(format!(
            "text member exceeds parser budget of {MAX_ARCHIVE_TEXT_PARSE_BYTES} bytes"
        ));
    }
    let encoding = detect_encoding(&bytes);
    let content = decode_bytes(&bytes, encoding)?;
    let line_limit = max_records.min(MAX_ARCHIVE_TEXT_RECORDS);
    let (bounded_content, truncated) = bounded_text_content(&content, line_limit);
    let (parsed, _) = parse_content(bounded_content, source_label, bytes.len() as u64);
    let mut coverage_gaps = Vec::new();
    let messages = Vec::new();

    if parsed.parse_errors > 0 {
        let gap = EvtxCoverageGap::new(
            source_label,
            EvtxCoverageGapKind::Record,
            format!("{} text records could not be parsed", parsed.parse_errors),
        );
        coverage_gaps.push(gap);
    } else if parsed.entries.is_empty() {
        let gap = EvtxCoverageGap::new(
            source_label,
            EvtxCoverageGapKind::Empty,
            "text member is empty",
        );
        coverage_gaps.push(gap);
    }
    if truncated {
        coverage_gaps.push(EvtxCoverageGap::new(
            source_label,
            EvtxCoverageGapKind::Limit,
            format!(
                "text member parsing stopped after {line_limit} lines; \
                 later records were not parsed"
            ),
        ));
    }

    let records = parsed
        .entries
        .into_iter()
        .map(|entry| text_entry_to_record(entry, source_label))
        .collect();
    Ok(ParsedFile {
        records,
        parse_errors: parsed.parse_errors,
        messages,
        coverage_gaps,
    })
}

fn text_entry_to_record(entry: LogEntry, source_label: &str) -> EvtxRecord {
    let event_record_id = u64::from(entry.line_number);
    let provider = entry
        .component
        .filter(|component| !component.trim().is_empty())
        .unwrap_or_default();
    let channel = source_label.to_string();
    EvtxRecord {
        id: 0,
        event_record_id,
        event_record_id_text: Some(event_record_id.to_string()),
        timestamp: entry.timestamp_display.unwrap_or_default(),
        timestamp_epoch: entry.timestamp.unwrap_or_default(),
        provider,
        channel,
        event_id: 0,
        level: text_level(entry.severity),
        computer: String::new(),
        message: entry.message,
        event_data: vec![EvtxField {
            name: "Line".to_string(),
            value: entry.line_number.to_string(),
        }],
        raw_xml: String::new(),
        source_label: source_label.to_string(),
        origin_kind: super::models::EvtxOriginKind::Log,
        task: None,
        opcode: None,
        process_id: None,
        activity_id: None,
        related_activity_id: None,
        session_id: None,
        device_id: None,
        user_id: None,
        process_start_time: None,
        thread_id: entry.thread,
        user_sid: None,
        keywords: None,
        mapped: Vec::new(),
    }
}

fn text_level(severity: Severity) -> EvtxLevel {
    match severity {
        Severity::Error => EvtxLevel::Error,
        Severity::Warning => EvtxLevel::Warning,
        Severity::Success | Severity::Info => EvtxLevel::Information,
    }
}
fn parsed_member_outcome(parsed: &ParsedFile) -> EvtxArchiveMemberOutcome {
    if parsed.parse_errors > 0 {
        EvtxArchiveMemberOutcome::Malformed
    } else if parsed
        .coverage_gaps
        .iter()
        .any(|gap| gap.kind == EvtxCoverageGapKind::Limit)
    {
        EvtxArchiveMemberOutcome::Limit
    } else {
        EvtxArchiveMemberOutcome::Parsed
    }
}
fn bound_archive_records(
    parsed: &mut ParsedFile,
    remaining: usize,
    source: &str,
    max_records: usize,
) {
    if parsed.records.len() <= remaining {
        return;
    }
    let omitted = parsed.records.len() - remaining;
    parsed.records.truncate(remaining);
    let gap = EvtxCoverageGap::new(
        source,
        EvtxCoverageGapKind::Limit,
        format!("archive record budget of {max_records} records omitted {omitted} parsed records"),
    );
    parsed.coverage_gaps.push(gap);
}

fn inventory_category(name: &str) -> &'static str {
    match name
        .rsplit('/')
        .next()
        .and_then(|file| file.rsplit_once('.'))
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("txt" | "log" | "xml" | "json" | "csv") => "text",
        Some("reg") => "registry",
        _ => "binary",
    }
}
fn archive_member_kind(name: &str) -> EvtxArchiveMemberKind {
    if is_evtx_name(name) {
        EvtxArchiveMemberKind::Evtx
    } else {
        match inventory_category(name) {
            "text" => EvtxArchiveMemberKind::Text,
            "registry" => EvtxArchiveMemberKind::Registry,
            _ => EvtxArchiveMemberKind::Binary,
        }
    }
}

fn push_metadata(
    result: &mut ArchiveParseResult,
    path: impl Into<String>,
    kind: EvtxArchiveMemberKind,
    sha256: Option<String>,
    outcome: EvtxArchiveMemberOutcome,
) {
    result.metadata.push(EvtxArchiveMember {
        path: path.into(),
        kind,
        sha256,
        outcome,
    });
}

/// ZIP member names become coverage labels and CLI-visible reasons. Reject Unicode controls and
/// noncharacters before either output path can include them.
fn is_unsafe_member_character(character: char) -> bool {
    let code_point = character as u32;
    character.is_control()
        || (0xFDD0..=0xFDEF).contains(&code_point)
        || (code_point & 0xFFFF) >= 0xFFFE
}

fn validate_member_name(raw: &str) -> Option<String> {
    if raw.chars().any(is_unsafe_member_character) {
        return None;
    }
    let normalized = raw.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.starts_with("//")
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|byte| *byte == b':')
    {
        return None;
    }
    let mut parts = Vec::new();
    for part in normalized.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains('\0') {
            return None;
        }
        parts.push(part);
    }
    Some(parts.join("/"))
}
#[derive(Debug)]
enum MemberReadError {
    Limit {
        bytes_read: u64,
    },
    Io {
        source: std::io::Error,
        bytes_read: u64,
    },
}

impl MemberReadError {
    fn bytes_read(&self) -> u64 {
        match self {
            Self::Limit { bytes_read } | Self::Io { bytes_read, .. } => *bytes_read,
        }
    }

    fn is_limit(&self) -> bool {
        matches!(self, Self::Limit { .. })
    }
}

impl std::fmt::Display for MemberReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limit { .. } => formatter.write_str("member expanded beyond archive limit"),
            Self::Io { source, .. } => source.fmt(formatter),
        }
    }
}

impl std::error::Error for MemberReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Limit { .. } => None,
            Self::Io { source, .. } => Some(source),
        }
    }
}

fn read_member_bytes<R: Read>(
    entry: &mut zip::read::ZipFile<'_, R>,
    max_bytes: u64,
) -> Result<Vec<u8>, MemberReadError> {
    let mut bytes = Vec::new();
    let mut reader = entry.take(max_bytes.saturating_add(1));
    if let Err(source) = reader.read_to_end(&mut bytes) {
        return Err(MemberReadError::Io {
            source,
            bytes_read: bytes.len() as u64,
        });
    }
    if bytes.len() as u64 > max_bytes {
        return Err(MemberReadError::Limit {
            bytes_read: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

fn read_member_digest<R: Read>(
    entry: &mut zip::read::ZipFile<'_, R>,
    max_bytes: u64,
) -> Result<(String, u64), MemberReadError> {
    let mut hasher = Sha256::new();
    let mut reader = entry.take(max_bytes.saturating_add(1));
    let mut buffer = [0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(source) => {
                return Err(MemberReadError::Io {
                    source,
                    bytes_read: total,
                });
            }
        };
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(MemberReadError::Limit { bytes_read: total });
        }
        hasher.update(&buffer[..read]);
    }
    Ok((
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        total,
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn push_existing_gap(result: &mut ArchiveParseResult, gap: EvtxCoverageGap) {
    if result.coverage.len() < MAX_ARCHIVE_COVERAGE - 1 {
        result
            .messages
            .push(format!("{}: {}", gap.source, gap.reason));
        result.coverage.push(gap);
        return;
    }

    if result.omitted_coverage == 0 {
        result.omitted_coverage = 1;
        let summary = EvtxCoverageGap::new(
            "<archive coverage>",
            EvtxCoverageGapKind::Limit,
            "additional archive member diagnostics were coalesced",
        );
        result
            .messages
            .push(format!("{}: {}", summary.source, summary.reason));
        result.coverage.push(summary);
        return;
    }

    result.omitted_coverage = result.omitted_coverage.saturating_add(1);
    let omitted = result.omitted_coverage;
    if let Some(summary) = result.coverage.last_mut() {
        summary.reason = format!("{omitted} additional archive member diagnostics were coalesced");
        if let Some(message) = result.messages.last_mut() {
            *message = format!("{}: {}", summary.source, summary.reason);
        }
    }
}

fn push_gap(
    result: &mut ArchiveParseResult,
    source: &str,
    kind: EvtxCoverageGapKind,
    reason: impl Into<String>,
) {
    let gap = EvtxCoverageGap::new(source, kind, reason);
    result.parse_errors = result.parse_errors.saturating_add(1);
    push_existing_gap(result, gap);
}

#[cfg(test)]
mod tests {
    use super::super::models::{
        ChannelSourceType, EvtxArchiveMember, EvtxArchiveMemberKind, EvtxArchiveMemberOutcome,
        EvtxCoverageGap, EvtxCoverageGapKind,
    };
    use super::super::parser::{
        parse_evtx_manifest, EventLogSource, EventLogSourceKind, EventLogSourceManifest,
    };
    use super::{
        account_archive_bytes, archive_budget_allows, archive_member_count, archive_member_kind,
        archive_record_budget_allows, archive_text_parser_admission_allows, bounded_member_indices,
        is_evtx_name, parse_archive_batches, parse_text_member, push_existing_gap,
        text_parse_error_is_limit, validate_member_name, ArchiveMember, ArchiveParseResult,
        MemberReadError, MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES, MAX_ARCHIVE_COVERAGE,
        MAX_ARCHIVE_MEMBERS, MAX_ARCHIVE_TEXT_PARSE_BYTES, MAX_ARCHIVE_TEXT_RECORDS,
        MAX_ARCHIVE_TOTAL_BYTES,
    };
    use cmtraceopen_parser::eventmap::MapRegistry;
    use std::fs::{self, File};
    use std::io::Write;
    use std::sync::RwLock;

    fn collect_archive(
        path: &std::path::Path,
        maps: &RwLock<MapRegistry>,
        providers: &RwLock<super::super::provider_db::ProviderStore>,
        max_records: usize,
    ) -> Result<(ArchiveParseResult, Vec<ArchiveMember>), EvtxCoverageGap> {
        let mut members = Vec::new();
        let parsed = parse_archive_batches(path, maps, providers, max_records, |member| {
            members.push(member);
            true
        })?;
        Ok((parsed, members))
    }

    #[test]
    fn evtx_member_names_require_a_real_extension_or_numeric_rotation() {
        for name in [
            "logs/Application.evtx",
            "logs/Application.EVTX",
            "logs/Application.evtx.1",
            "logs/Application.evtx.001",
        ] {
            assert!(is_evtx_name(name), "{name} should be an EVTX member");
            assert_eq!(
                archive_member_kind(name),
                EvtxArchiveMemberKind::Evtx,
                "{name} should be classified as EVTX"
            );
        }

        for name in [
            "logs/Application.evtx.gz",
            "logs/Application.evtx.txt",
            "logs/Application.evtx.zip",
            "logs/Application.evtx~",
            "logs/Application.evtx.1~",
        ] {
            assert!(!is_evtx_name(name), "{name} should not be an EVTX member");
        }

        assert_eq!(
            archive_member_kind("logs/Application.evtx.txt"),
            EvtxArchiveMemberKind::Text
        );
        assert_eq!(
            archive_member_kind("logs/Application.evtx.zip"),
            EvtxArchiveMemberKind::Binary
        );
    }

    #[test]
    fn componentless_archive_text_members_use_source_qualified_channels() {
        let path = std::env::temp_dir().join(format!(
            "cmtraceopen-event-archive-componentless-text-{}.zip",
            std::process::id()
        ));
        let file = File::create(&path).expect("create archive fixture");
        let mut writer = zip::ZipWriter::new(file);
        for (name, content) in [
            ("logs/first.log", b"first archive text member" as &[u8]),
            ("logs/second.log", b"second archive text member"),
        ] {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .expect("create text member");
            writer.write_all(content).expect("write text member");
        }
        writer.finish().expect("finish archive fixture");

        let maps = RwLock::new(MapRegistry::new());
        let providers = RwLock::new(super::super::provider_db::ProviderStore::default());
        let archive_path = path.to_string_lossy().into_owned();
        let parsed = parse_evtx_manifest(
            &EventLogSourceManifest {
                entries: vec![EventLogSource {
                    source_id: archive_path.clone(),
                    path: archive_path.clone(),
                    kind: EventLogSourceKind::Archive,
                }],
                coverage: Vec::new(),
            },
            &maps,
            &providers,
        )
        .expect("archive should parse");

        let first_source = format!("{archive_path}::logs/first.log");
        let second_source = format!("{archive_path}::logs/second.log");
        assert_eq!(parsed.records.len(), 2);
        assert!(parsed
            .records
            .iter()
            .all(|record| record.provider.is_empty()));
        assert_eq!(
            parsed
                .records
                .iter()
                .map(|record| record.channel.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            2,
            "component-less archive records must not collide in channel identity"
        );
        assert!(parsed
            .records
            .iter()
            .all(|record| !record.channel.is_empty()));
        assert!(parsed
            .records
            .iter()
            .all(|record| record.channel == record.source_label));
        assert_eq!(
            parsed
                .records
                .iter()
                .map(|record| record.channel.as_str())
                .collect::<std::collections::HashSet<_>>(),
            [first_source.as_str(), second_source.as_str()]
                .into_iter()
                .collect()
        );

        assert_eq!(parsed.channels.len(), 2);
        assert!(parsed
            .channels
            .iter()
            .all(|channel| !channel.name.is_empty()));
        assert_eq!(
            parsed
                .channels
                .iter()
                .map(|channel| channel.name.as_str())
                .collect::<std::collections::HashSet<_>>(),
            [first_source.as_str(), second_source.as_str()]
                .into_iter()
                .collect()
        );
        assert!(parsed.channels.iter().all(|channel| {
            matches!(
                &channel.source_type,
                ChannelSourceType::File { path } if path == &channel.name
            )
        }));
        assert!(parsed
            .channels
            .iter()
            .all(|channel| channel.event_count == 1));

        fs::remove_file(path).expect("remove archive fixture");
    }

    #[test]
    fn rejects_traversal_and_absolute_member_paths() {
        assert!(validate_member_name("../outside.evtx").is_none());
        assert!(validate_member_name("/absolute.evtx").is_none());
        assert!(validate_member_name("C:/absolute.evtx").is_none());
    }

    #[test]
    fn rejects_terminal_controls_and_unicode_noncharacters() {
        for name in [
            "logs/line\rbreak.evtx",
            "logs/line\nbreak.evtx",
            "logs/\u{1b}[31m.evtx",
            "logs/\u{7f}.evtx",
            "logs/\u{85}.evtx",
            "logs/\u{fdd0}.evtx",
            "logs/\u{fffe}.evtx",
            "logs/\u{1ffff}.evtx",
        ] {
            assert!(
                validate_member_name(name).is_none(),
                "unsafe archive member should be rejected: {name:?}"
            );
        }
    }

    #[test]
    fn normalizes_backslashes_without_following_them() {
        assert_eq!(
            validate_member_name("logs\\Application.evtx"),
            Some("logs/Application.evtx".into())
        );
    }
    #[test]
    fn archive_member_limit_bounds_indices_before_zip_entry_access() {
        assert_eq!(
            bounded_member_indices(MAX_ARCHIVE_MEMBERS + 1),
            0..MAX_ARCHIVE_MEMBERS
        );
    }
    #[test]
    fn archive_gap_overflow_retains_real_gaps_and_coalesces_repeated_omissions() {
        let mut result = ArchiveParseResult {
            parse_errors: 11,
            ..ArchiveParseResult::default()
        };

        for index in 0..MAX_ARCHIVE_COVERAGE - 1 {
            push_existing_gap(
                &mut result,
                EvtxCoverageGap::new(
                    format!("member-{index}"),
                    EvtxCoverageGapKind::File,
                    "diagnostic",
                ),
            );
        }

        push_existing_gap(
            &mut result,
            EvtxCoverageGap::new("member-omitted-1", EvtxCoverageGapKind::File, "diagnostic"),
        );
        assert_eq!(result.coverage.len(), MAX_ARCHIVE_COVERAGE);
        assert_eq!(result.messages.len(), MAX_ARCHIVE_COVERAGE);
        assert_eq!(result.omitted_coverage, 1);
        assert_eq!(result.parse_errors, 11);
        for index in 0..MAX_ARCHIVE_COVERAGE - 1 {
            assert_eq!(result.coverage[index].source, format!("member-{index}"));
            assert_eq!(
                result.messages[index],
                format!("member-{index}: diagnostic")
            );
        }
        assert_eq!(result.coverage.last().unwrap().source, "<archive coverage>");
        assert_eq!(
            result.messages.last().unwrap(),
            "<archive coverage>: additional archive member diagnostics were coalesced"
        );

        for index in 2..=3 {
            push_existing_gap(
                &mut result,
                EvtxCoverageGap::new(
                    format!("member-omitted-{index}"),
                    EvtxCoverageGapKind::File,
                    "diagnostic",
                ),
            );
        }
        assert_eq!(result.coverage.len(), MAX_ARCHIVE_COVERAGE);
        assert_eq!(result.messages.len(), MAX_ARCHIVE_COVERAGE);
        assert_eq!(result.omitted_coverage, 3);
        assert_eq!(
            result.coverage.last().unwrap().reason,
            "3 additional archive member diagnostics were coalesced"
        );
        assert_eq!(
            result.messages.last().unwrap(),
            "<archive coverage>: 3 additional archive member diagnostics were coalesced"
        );
    }

    #[test]
    fn compressed_archive_budget_rejects_later_members() {
        assert!(archive_budget_allows(0, 4, 5));
        assert!(!archive_budget_allows(4, 2, 5));
        assert!(!archive_budget_allows(5, 0, 5));
        assert!(!archive_budget_allows(u64::MAX, 1, u64::MAX));
        assert!(!archive_record_budget_allows(0, 0));
        assert!(archive_record_budget_allows(0, 1));
    }

    #[test]
    fn text_parser_admission_rejects_oversized_or_exhausted_inputs() {
        assert!(!archive_text_parser_admission_allows(
            MAX_ARCHIVE_TEXT_PARSE_BYTES + 1,
            0,
            1
        ));
        assert!(!archive_text_parser_admission_allows(1, 1, 1));
        assert!(archive_text_parser_admission_allows(1, 0, 1));
        assert!(text_parse_error_is_limit(
            "text member exceeds parser budget of 16777216 bytes"
        ));
        assert!(!text_parse_error_is_limit(
            "text member could not be parsed: checksum failed"
        ));
    }

    #[test]
    fn archive_batch_consumer_can_stop_before_later_members_are_retained() {
        let temporary = tempfile::tempdir().expect("temp directory");
        let path = temporary.path().join("events.zip");
        let file = File::create(&path).expect("create archive fixture");
        let mut writer = zip::ZipWriter::new(file);
        for (name, content) in [
            ("logs/first.log", b"first archive record" as &[u8]),
            ("logs/second.log", b"second archive record" as &[u8]),
        ] {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .expect("create archive member");
            writer.write_all(content).expect("write archive member");
        }
        writer.finish().expect("finish archive fixture");
        let maps = RwLock::new(MapRegistry::new());
        let providers = RwLock::new(super::super::provider_db::ProviderStore::default());
        let mut emitted = Vec::new();

        let parsed = parse_archive_batches(&path, &maps, &providers, usize::MAX, |member| {
            emitted.push(member.source_label);
            false
        })
        .expect("first archive batch parses");

        assert_eq!(emitted.len(), 1);
        assert!(emitted[0].ends_with("logs/first.log"));
        assert_eq!(parsed.metadata.len(), 1);
        assert!(!parsed
            .messages
            .iter()
            .any(|message| message.contains("no readable EVTX members")));
        assert!(!parsed
            .coverage
            .iter()
            .any(|gap| gap.kind == EvtxCoverageGapKind::Empty));
    }

    #[test]
    fn archive_record_budget_skips_later_text_members_before_admission() {
        let path = std::env::temp_dir().join(format!(
            "cmtraceopen-event-archive-record-limit-{}.zip",
            std::process::id()
        ));
        let content = br#"<![LOG[Archive text record]LOG]!><time="08:00:00.000+000" date="01-01-2024" component="ArchiveText" context="" type="1" thread="100" file="">"#;
        let file = File::create(&path).expect("create archive fixture");
        let mut writer = zip::ZipWriter::new(file);
        for name in ["logs/first.log", "logs/second.log"] {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .expect("create text member");
            writer.write_all(content).expect("write text member");
        }
        writer.finish().expect("finish archive fixture");

        let maps = RwLock::new(MapRegistry::new());
        let providers = RwLock::new(super::super::provider_db::ProviderStore::default());
        let (parsed, members) =
            collect_archive(&path, &maps, &providers, 1).expect("archive should parse");

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].parsed.records.len(), 1);
        assert_eq!(parsed.metadata.len(), 2);
        assert_eq!(parsed.metadata[1].outcome, EvtxArchiveMemberOutcome::Limit);
        assert!(parsed.coverage.iter().any(|gap| {
            gap.kind == super::super::models::EvtxCoverageGapKind::Limit
                && gap.source.ends_with("logs/second.log")
        }));
        fs::remove_file(path).expect("remove archive fixture");
    }

    #[test]
    fn malformed_crc_is_reported_as_malformed_not_limit() {
        let path = std::env::temp_dir().join(format!(
            "cmtraceopen-event-archive-crc-{}.zip",
            std::process::id()
        ));
        let content = b"CRC-protected archive text";
        let file = File::create(&path).expect("create archive fixture");
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file(
                "logs/app.log",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .expect("create text member");
        writer.write_all(content).expect("write text member");
        writer.finish().expect("finish archive fixture");
        let mut bytes = fs::read(&path).expect("read archive fixture");
        let offset = bytes
            .windows(content.len())
            .position(|window| window == content)
            .expect("find stored member bytes");
        bytes[offset] ^= 1;
        fs::write(&path, bytes).expect("corrupt archive CRC payload");

        let maps = RwLock::new(MapRegistry::new());
        let providers = RwLock::new(super::super::provider_db::ProviderStore::default());
        let parsed = parse_archive_batches(&path, &maps, &providers, usize::MAX, |_| true)
            .expect("malformed member should remain covered");

        assert_eq!(parsed.metadata.len(), 1);
        assert_eq!(
            parsed.metadata[0].outcome,
            EvtxArchiveMemberOutcome::Malformed
        );
        assert!(parsed.coverage.iter().any(|gap| {
            gap.kind == super::super::models::EvtxCoverageGapKind::File
                && gap.source.ends_with("logs/app.log")
        }));
        assert!(!parsed
            .coverage
            .iter()
            .any(|gap| { gap.kind == super::super::models::EvtxCoverageGapKind::Limit }));
        fs::remove_file(path).expect("remove archive fixture");
    }

    #[test]
    fn non_limit_read_errors_preserve_consumed_bytes_for_aggregate_accounting() {
        let error = MemberReadError::Io {
            source: std::io::Error::other("reader failed"),
            bytes_read: 17,
        };

        assert!(!error.is_limit());
        assert_eq!(error.bytes_read(), 17);
        assert_eq!(
            account_archive_bytes(MAX_ARCHIVE_TOTAL_BYTES - 2, error.bytes_read()),
            MAX_ARCHIVE_TOTAL_BYTES
        );
    }

    #[test]
    fn forged_large_member_count_is_rejected_before_archive_open() {
        let path = std::env::temp_dir().join(format!(
            "cmtraceopen-event-archive-member-limit-{}.zip",
            std::process::id()
        ));
        let file = File::create(&path).expect("create archive fixture");
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("logs/app.log", zip::write::SimpleFileOptions::default())
            .expect("create archive member");
        writer
            .write_all(b"Archive member")
            .expect("write archive member");
        writer.finish().expect("finish archive fixture");

        let mut bytes = fs::read(&path).expect("read archive fixture");
        let eocd = bytes
            .windows(4)
            .rposition(|signature| signature == [0x50, 0x4b, 0x05, 0x06])
            .expect("find end of central directory");
        bytes[eocd + 8..eocd + 10].copy_from_slice(&(MAX_ARCHIVE_MEMBERS as u16 + 1).to_le_bytes());
        bytes[eocd + 10..eocd + 12]
            .copy_from_slice(&(MAX_ARCHIVE_MEMBERS as u16 + 1).to_le_bytes());
        fs::write(&path, bytes).expect("forge archive member count");

        let mut file = File::open(&path).expect("open archive fixture");
        assert_eq!(
            archive_member_count(&mut file).expect("inspect archive member count"),
            Some((MAX_ARCHIVE_MEMBERS + 1) as u64)
        );
        let maps = RwLock::new(MapRegistry::new());
        let providers = RwLock::new(super::super::provider_db::ProviderStore::default());
        let error = parse_archive_batches(&path, &maps, &providers, usize::MAX, |_| true)
            .expect_err("forged large member count should be rejected");

        assert_eq!(error.kind, EvtxCoverageGapKind::Limit);
        assert_eq!(error.source, path.to_string_lossy());
        assert!(error.reason.contains("archive was not opened"));
        fs::remove_file(path).expect("remove archive fixture");
    }
    #[test]
    fn forged_large_central_directory_is_rejected_before_archive_open() {
        let path = std::env::temp_dir().join(format!(
            "cmtraceopen-event-archive-central-limit-{}.zip",
            std::process::id()
        ));
        let file = File::create(&path).expect("create archive fixture");
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("logs/app.log", zip::write::SimpleFileOptions::default())
            .expect("create archive member");
        writer
            .write_all(b"Archive member")
            .expect("write archive member");
        writer.finish().expect("finish archive fixture");

        let mut bytes = fs::read(&path).expect("read archive fixture");
        let eocd = bytes
            .windows(4)
            .rposition(|signature| signature == [0x50, 0x4b, 0x05, 0x06])
            .expect("find end of central directory");
        bytes[eocd + 12..eocd + 16]
            .copy_from_slice(&(MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES as u32 + 1).to_le_bytes());
        fs::write(&path, bytes).expect("forge archive central directory size");

        let maps = RwLock::new(MapRegistry::new());
        let providers = RwLock::new(super::super::provider_db::ProviderStore::default());
        let error = parse_archive_batches(&path, &maps, &providers, usize::MAX, |_| true)
            .expect_err("forged central directory size should be rejected");

        assert_eq!(error.kind, EvtxCoverageGapKind::Limit);
        assert!(error.reason.contains("central directory"));
        fs::remove_file(path).expect("remove archive fixture");
    }
    #[test]
    fn archive_member_metadata_preserves_type_digest_and_outcome() {
        let metadata = EvtxArchiveMember {
            path: "logs/app.log".into(),
            kind: EvtxArchiveMemberKind::Text,
            sha256: Some("abc123".into()),
            outcome: EvtxArchiveMemberOutcome::Unsupported,
        };

        assert_eq!(metadata.path, "logs/app.log");
        assert_eq!(metadata.kind, EvtxArchiveMemberKind::Text);
        assert_eq!(metadata.sha256.as_deref(), Some("abc123"));
        assert_eq!(metadata.outcome, EvtxArchiveMemberOutcome::Unsupported);
    }
    #[test]
    fn text_archive_members_use_existing_parser_and_preserve_source() {
        let content = br#"<![LOG[Archive text record]LOG]!><time="08:00:00.000+000" date="01-01-2024" component="ArchiveText" context="" type="1" thread="100" file="">"#;
        let parsed = parse_text_member(content.to_vec(), "bundle.zip::logs/app.log", usize::MAX)
            .expect("text archive member should parse");

        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].message, "Archive text record");
        assert_eq!(parsed.records[0].source_label, "bundle.zip::logs/app.log");
        assert_eq!(
            parsed.records[0].origin_kind,
            super::super::models::EvtxOriginKind::Log
        );
        assert_eq!(parsed.records[0].provider, "ArchiveText");
        assert_eq!(parsed.records[0].channel, "bundle.zip::logs/app.log");
        assert_eq!(parsed.records[0].event_id, 0);
        assert!(parsed.records[0].computer.is_empty());
        let timeline = super::super::timeline::build(&[], &parsed.records);
        assert!(matches!(
            timeline.items[0].origin,
            cmtraceopen_parser::unified_timeline::TimelineOrigin::Log { .. }
        ));
        assert_eq!(parsed.parse_errors, 0);
    }

    #[test]
    fn text_archive_members_with_blank_components_use_source_channel() {
        for (index, component) in ["", " \t"].into_iter().enumerate() {
            let content = format!(
                r#"<![LOG[Archive text record]LOG]!><time="08:00:00.000+000" date="01-01-2024" component="{component}" context="" type="1" thread="100" file="">"#
            );
            let source = format!("bundle.zip::logs/blank-{index}.log");
            let parsed = parse_text_member(content.into_bytes(), &source, usize::MAX)
                .expect("blank component should parse");

            assert_eq!(parsed.records.len(), 1);
            assert!(parsed.records[0].provider.is_empty());
            assert_eq!(parsed.records[0].channel, source);
        }
    }
    #[test]
    fn text_archive_parser_bounds_line_materialization() {
        let line = r#"<![LOG[Archive text record]LOG]!><time="08:00:00.000+000" date="01-01-2024" component="ArchiveText" context="" type="1" thread="100" file="">"#;
        let mut content = String::new();
        for _ in 0..=MAX_ARCHIVE_TEXT_RECORDS {
            content.push_str(line);
            content.push('\n');
        }

        let parsed = parse_text_member(
            content.into_bytes(),
            "bundle.zip::logs/large.log",
            usize::MAX,
        )
        .expect("bounded text member should parse");

        assert_eq!(parsed.records.len(), MAX_ARCHIVE_TEXT_RECORDS);
        assert!(parsed.coverage_gaps.iter().any(|gap| {
            gap.kind == EvtxCoverageGapKind::Limit
                && gap.reason.contains("later records were not parsed")
        }));
    }
    #[test]
    fn archive_routes_text_members_into_the_timeline_with_provenance() {
        let path = std::env::temp_dir().join(format!(
            "cmtraceopen-event-archive-text-{}.zip",
            std::process::id()
        ));
        let file = File::create(&path).expect("create archive fixture");
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("logs/app.log", zip::write::SimpleFileOptions::default())
            .expect("create text member");
        writer
            .write_all(
                br#"<![LOG[Archive text record]LOG]!><time="08:00:00.000+000" date="01-01-2024" component="ArchiveText" context="" type="1" thread="100" file="">"#,
            )
            .expect("write text member");
        writer.finish().expect("finish archive fixture");

        let maps = RwLock::new(MapRegistry::new());
        let providers = RwLock::new(super::super::provider_db::ProviderStore::default());
        let (parsed, members) =
            collect_archive(&path, &maps, &providers, usize::MAX).expect("archive should parse");
        let expected_path = format!("{}::logs/app.log", path.to_string_lossy());

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].parsed.records.len(), 1);
        assert_eq!(members[0].source_label, expected_path);
        assert_eq!(parsed.metadata.len(), 1);
        assert_eq!(parsed.metadata[0].path, expected_path);
        assert_eq!(parsed.metadata[0].kind, EvtxArchiveMemberKind::Text);
        assert!(parsed.metadata[0]
            .sha256
            .as_deref()
            .is_some_and(|digest| digest.len() == 64));
        assert_eq!(parsed.metadata[0].outcome, EvtxArchiveMemberOutcome::Parsed);
        fs::remove_file(path).expect("remove archive fixture");
    }
}
