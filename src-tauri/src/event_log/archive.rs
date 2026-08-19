use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::RwLock;

use cmtraceopen_parser::eventmap::MapRegistry;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use super::models::{EvtxCoverageGap, EvtxCoverageGapKind};
use super::parser::{parse_evtx_buffer, ParsedFile};
use super::provider_db::ProviderStore;

pub const MAX_ARCHIVE_MEMBERS: usize = 512;
pub const MAX_ARCHIVE_MEMBER_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_ARCHIVE_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_COVERAGE: usize = MAX_ARCHIVE_MEMBERS + 32;

#[derive(Debug)]
pub(crate) struct ArchiveMember {
    pub(crate) source_label: String,
    pub(crate) parsed: ParsedFile,
}

#[derive(Debug, Default)]
pub(crate) struct ArchiveParseResult {
    pub(crate) members: Vec<ArchiveMember>,
    pub(crate) coverage: Vec<EvtxCoverageGap>,
    pub(crate) parse_errors: u32,
    pub(crate) messages: Vec<String>,
    omitted_coverage: usize,
}

/// Parse EVTX members directly from a bounded ZIP stream. No extracted path escapes this call.
pub(crate) fn parse_archive(
    path: &Path,
    maps: &RwLock<MapRegistry>,
    providers: &RwLock<ProviderStore>,
) -> Result<ArchiveParseResult, EvtxCoverageGap> {
    let source = path.to_string_lossy().into_owned();
    let file = File::open(path).map_err(|error| {
        EvtxCoverageGap::new(
            source.clone(),
            EvtxCoverageGapKind::File,
            format!("failed to open archive: {error}"),
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
    let member_count = archive.len();

    for index in 0..member_count {
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(error) => {
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
        let member_label = format!("{source}::{raw_name}");

        if index >= MAX_ARCHIVE_MEMBERS {
            push_gap(
                &mut result,
                &member_label,
                EvtxCoverageGapKind::Limit,
                format!("archive member count exceeds limit of {MAX_ARCHIVE_MEMBERS}"),
            );
            continue;
        }
        let Some(member_name) = validate_member_name(&raw_name) else {
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
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Unsupported,
                "symbolic-link archive members are not followed",
            );
            continue;
        }
        if !seen_paths.insert(member_name.to_ascii_lowercase()) {
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Unsupported,
                "duplicate archive member path (case-insensitive)",
            );
            continue;
        }
        if entry.is_dir() {
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Unsupported,
                "directory archive member was skipped",
            );
            continue;
        }

        let declared_size = entry.size();
        if declared_size > MAX_ARCHIVE_MEMBER_BYTES {
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                format!("member exceeds {MAX_ARCHIVE_MEMBER_BYTES} byte limit"),
            );
            continue;
        }
        let Some(new_total) = total_bytes.checked_add(declared_size) else {
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                "archive member size overflowed the aggregate budget",
            );
            continue;
        };
        if new_total > MAX_ARCHIVE_TOTAL_BYTES {
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                format!("archive aggregate exceeds {MAX_ARCHIVE_TOTAL_BYTES} byte limit"),
            );
            continue;
        }
        total_bytes = new_total;

        if !is_evtx_name(&member_name) {
            let category = inventory_category(&member_name);
            let digest = read_member_digest(&mut entry).unwrap_or_else(|_| "unavailable".to_string());
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Unsupported,
                format!("unsupported {category} member retained as inventory (sha256:{digest})"),
            );
            continue;
        }

        let mut bytes = Vec::new();
        let mut bounded_entry = (&mut entry).take(MAX_ARCHIVE_MEMBER_BYTES.saturating_add(1));
        if let Err(error) = bounded_entry.read_to_end(&mut bytes) {
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::File,
                format!("EVTX member could not be read: {error}"),
            );
            continue;
        }
        if bytes.len() as u64 > MAX_ARCHIVE_MEMBER_BYTES {
            push_gap(
                &mut result,
                &normalized_label,
                EvtxCoverageGapKind::Limit,
                format!("member expanded beyond {MAX_ARCHIVE_MEMBER_BYTES} byte limit"),
            );
            continue;
        }
        let digest = sha256_hex(&bytes);
        match parse_evtx_buffer(bytes, &normalized_label, maps, providers) {
            Ok(parsed) => result.members.push(ArchiveMember {
                source_label: normalized_label,
                parsed,
            }),
            Err(mut gap) => {
                gap.reason = format!("{} (sha256:{digest})", gap.reason);
                result.parse_errors = result.parse_errors.saturating_add(1);
                push_existing_gap(&mut result, gap);
            }
        }
    }

    if result.members.is_empty() && result.coverage.is_empty() {
        push_gap(
            &mut result,
            &source,
            EvtxCoverageGapKind::Empty,
            "archive contains no supported EVTX or inventory members",
        );
    }
    if result.members.is_empty() {
        result.messages.push(format!(
            "{source}: no readable EVTX members were found; archive coverage is reported below"
        ));
    }
    Ok(result)
}

fn is_evtx_name(name: &str) -> bool {
    name.rsplit('/').next().is_some_and(|file| {
        let lower = file.to_ascii_lowercase();
        lower.ends_with(".evtx") || lower.contains(".evtx.") || lower.ends_with(".evtx~")
    })
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

fn validate_member_name(raw: &str) -> Option<String> {
    let normalized = raw.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.starts_with("//")
        || normalized.as_bytes().get(1).is_some_and(|byte| *byte == b':')
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
fn read_member_digest<R: Read>(
    entry: &mut zip::read::ZipFile<'_, R>,
) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut reader = entry.take(MAX_ARCHIVE_MEMBER_BYTES.saturating_add(1));
    let mut buffer = [0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_ARCHIVE_MEMBER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "member expanded beyond archive limit",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn push_existing_gap(result: &mut ArchiveParseResult, gap: EvtxCoverageGap) {
    if result.coverage.len() < MAX_ARCHIVE_COVERAGE {
        result.messages.push(format!("{}: {}", gap.source, gap.reason));
        result.coverage.push(gap);
        return;
    }

    result.omitted_coverage = result.omitted_coverage.saturating_add(1);
    let omitted = result.omitted_coverage;
    if omitted == 1 {
        result.coverage.pop();
        let summary = EvtxCoverageGap::new(
            "<archive coverage>",
            EvtxCoverageGapKind::Limit,
            "additional archive member diagnostics were coalesced",
        );
        result.messages.push(format!("{}: {}", summary.source, summary.reason));
        result.coverage.push(summary);
    } else if let Some(summary) = result.coverage.last_mut() {
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
    use super::validate_member_name;

    #[test]
    fn rejects_traversal_and_absolute_member_paths() {
        assert!(validate_member_name("../outside.evtx").is_none());
        assert!(validate_member_name("/absolute.evtx").is_none());
        assert!(validate_member_name("C:/absolute.evtx").is_none());
    }

    #[test]
    fn normalizes_backslashes_without_following_them() {
        assert_eq!(
            validate_member_name("logs\\Application.evtx"),
            Some("logs/Application.evtx".into())
        );
    }
}
