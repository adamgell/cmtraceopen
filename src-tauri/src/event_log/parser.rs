use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use cmtraceopen_parser::eventmap::MapRegistry;
use evtx::EvtxParser;
use serde::{Deserialize, Serialize};

// `extract_event_data` sits in `event_node` alongside `extract_system_fields`: both read a parsed
// tree, and both are needed by the live path as well as this one. Keeping the data extractor here
// while the live path scanned raw XML for itself is what let the two drift apart.
use super::event_node::{extract_event_data, EventFields};
use super::provider_db::ProviderStore;

use super::models::{
    ChannelSourceType, EvtxChannelInfo, EvtxField, EvtxLevel, EvtxParseResult, EvtxRecord,
};
use super::{parse_timestamp_to_epoch_ms, sanitize_control_chars};

/// Maximum entries to parse from a single .evtx file to prevent memory issues.

/// Maximum number of files a source selection may hand to the EVTX parser.
///
/// This is deliberately applied before parsing. A folder or wildcard is user input and must not
/// turn into an unbounded parser workload.
pub const MAX_SOURCE_MANIFEST_ENTRIES: usize = 4_096;
const MAX_SOURCE_MANIFEST_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EventLogSourceKind {
    File,
    Folder,
    Wildcard,
    Archive,
    Vss,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogSource {
    pub source_id: String,
    pub path: String,
    pub kind: EventLogSourceKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum SourceCoverage {
    Unsupported { path: String, reason: String },
    AccessDenied { path: String, reason: String },
    Missing { path: String, reason: String },
    LimitReached { path: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogSourceManifest {
    pub entries: Vec<EventLogSource>,
    pub coverage: Vec<SourceCoverage>,
}

/// Expand files, folders, and wildcard selections into one bounded, deterministic manifest.
///
/// Expansion uses the existing bounded folder-listing command rather than walking arbitrary
/// directories directly. Source IDs are lexical, separator-normalized, and case-folded so the
/// same member selected through two paths is represented once.
pub fn build_source_manifest(sources: &[String]) -> Result<EventLogSourceManifest, String> {
    let mut manifest = EventLogSourceManifest {
        entries: Vec::new(),
        coverage: Vec::new(),
    };

    for source in sources {
        let is_wildcard = !is_vss_path(source) && (source.contains('*') || source.contains('?'));
        let paths = if is_wildcard {
            expand_wildcard(source, &mut manifest.coverage)
        } else {
            vec![PathBuf::from(source)]
        };

        if is_wildcard && paths.is_empty() {
            manifest.coverage.push(SourceCoverage::Missing {
                path: source.clone(),
                reason: "wildcard did not match any filesystem path".to_string(),
            });
        }

        for path in paths {
            expand_path(
                &path,
                if is_wildcard {
                    EventLogSourceKind::Wildcard
                } else {
                    EventLogSourceKind::File
                },
                0,
                &mut manifest,
            )?;
        }
    }

    manifest.entries.sort_by(|left, right| {
        left.source_id
            .cmp(&right.source_id)
            .then_with(|| left.path.cmp(&right.path))
    });
    manifest.coverage.sort_by(|left, right| coverage_path(left).cmp(coverage_path(right)));
    Ok(manifest)
}

fn expand_wildcard(pattern: &str, coverage: &mut Vec<SourceCoverage>) -> Vec<PathBuf> {
    let options = glob::MatchOptions {
        case_sensitive: false,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };
    match glob::glob_with(pattern, options) {
        Ok(matches) => matches
            .filter_map(|result| match result {
                Ok(path) => Some(path),
                Err(error) => {
                    coverage.push(SourceCoverage::Missing {
                        path: pattern.to_string(),
                        reason: format!("wildcard entry could not be read: {error}"),
                    });
                    None
                }
            })
            .collect(),
        Err(error) => {
            coverage.push(SourceCoverage::Missing {
                path: pattern.to_string(),
                reason: format!("invalid wildcard: {error}"),
            });
            Vec::new()
        }
    }
}

fn expand_path(
    path: &Path,
    requested_kind: EventLogSourceKind,
    depth: usize,
    manifest: &mut EventLogSourceManifest,
) -> Result<(), String> {
    if manifest.entries.len() >= MAX_SOURCE_MANIFEST_ENTRIES {
        manifest.coverage.push(SourceCoverage::LimitReached {
            path: path.to_string_lossy().to_string(),
            reason: format!(
                "source selection exceeds the {} file manifest limit",
                MAX_SOURCE_MANIFEST_ENTRIES
            ),
        });
        return Ok(());
    }

    let path_string = path.to_string_lossy().to_string();
    let kind = classify_source_kind(&path_string, requested_kind);
    if let Some(gap) = gated_source(&path_string, kind) {
        manifest.coverage.push(gap);
        return Ok(());
    }

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            manifest.coverage.push(SourceCoverage::Missing {
                path: path_string,
                reason: "source path does not exist".to_string(),
            });
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            manifest.coverage.push(SourceCoverage::AccessDenied {
                path: path_string,
                reason: "source metadata access was denied".to_string(),
            });
            return Ok(());
        }
        Err(error) => return Err(format!("cannot inspect source {path_string}: {error}")),
    };

    if metadata.is_dir() {
        if depth >= MAX_SOURCE_MANIFEST_DEPTH {
            manifest.coverage.push(SourceCoverage::LimitReached {
                path: path_string,
                reason: format!("folder nesting exceeds {MAX_SOURCE_MANIFEST_DEPTH} levels"),
            });
            return Ok(());
        }
        let listing = match crate::commands::file_ops::list_log_folder(path_string.clone()) {
            Ok(listing) => listing,
            Err(crate::error::AppError::AccessDenied { .. }) => {
                manifest.coverage.push(SourceCoverage::AccessDenied {
                    path: path_string,
                    reason: "folder listing access was denied".to_string(),
                });
                return Ok(());
            }
            Err(error) => {
                manifest.coverage.push(SourceCoverage::Missing {
                    path: path_string,
                    reason: error.to_string(),
                });
                return Ok(());
            }
        };
        for entry in listing.entries {
            expand_path(
                Path::new(&entry.path),
                EventLogSourceKind::Folder,
                depth + 1,
                manifest,
            )?;
        }
        return Ok(());
    }

    if !is_evtx_candidate(path) {
        return Ok(());
    }

    let normalized_path = normalize_source_path(path);
    let source_id = normalized_path.to_lowercase();
    if manifest.entries.iter().any(|entry| entry.source_id == source_id) {
        return Ok(());
    }
    manifest.entries.push(EventLogSource {
        source_id,
        path: normalized_path,
        kind,
    });
    Ok(())
}

fn classify_source_kind(path: &str, requested_kind: EventLogSourceKind) -> EventLogSourceKind {
    if is_vss_path(path) {
        EventLogSourceKind::Vss
    } else if Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase().starts_with("archive-"))
        .unwrap_or(false)
    {
        EventLogSourceKind::Archive
    } else {
        requested_kind
    }
}

fn gated_source(path: &str, kind: EventLogSourceKind) -> Option<SourceCoverage> {
    if !matches!(kind, EventLogSourceKind::Archive | EventLogSourceKind::Vss) {
        return None;
    }

    #[cfg(not(target_os = "windows"))]
    {
        return Some(SourceCoverage::Unsupported {
            path: path.to_string(),
            reason: "archived and VSS event-log sources are only available on Windows".to_string(),
        });
    }

    #[cfg(target_os = "windows")]
    if !crate::elevation::current_elevation_state().is_elevated {
        return Some(SourceCoverage::AccessDenied {
            path: path.to_string(),
            reason: "archived and VSS event-log sources require an elevated process".to_string(),
        });
    }

    None
}

fn is_vss_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_lowercase();
    normalized.contains("globalroot\\device\\harddiskvolumeshadowcopy")
}

fn is_evtx_candidate(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_lowercase();
    lower.ends_with(".evtx")
        || lower.contains(".evtx.")
        || lower.ends_with(".evtx~")
}

fn normalize_source_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn coverage_path(coverage: &SourceCoverage) -> &str {
    match coverage {
        SourceCoverage::Unsupported { path, .. }
        | SourceCoverage::AccessDenied { path, .. }
        | SourceCoverage::Missing { path, .. }
        | SourceCoverage::LimitReached { path, .. } => path,
    }
}
const MAX_ENTRIES_PER_FILE: usize = 100_000;

/// Parse source selections after bounded expansion into a deterministic manifest.
pub fn parse_evtx_files(
    paths: &[String],
    maps: &RwLock<MapRegistry>,
    providers: &RwLock<ProviderStore>,
) -> Result<EvtxParseResult, String> {
    let manifest = build_source_manifest(paths)?;
    parse_evtx_manifest(&manifest, maps, providers)
}

pub fn parse_evtx_manifest(
    manifest: &EventLogSourceManifest,
    maps: &RwLock<MapRegistry>,
    providers: &RwLock<ProviderStore>,
) -> Result<EvtxParseResult, String> {
    let mut all_records = Vec::new();
    let mut channels = Vec::new();
    let mut parse_errors = manifest.coverage.len() as u32;
    let mut error_messages: Vec<String> = manifest
        .coverage
        .iter()
        .map(|coverage| match coverage {
            SourceCoverage::Unsupported { path, reason }
            | SourceCoverage::AccessDenied { path, reason }
            | SourceCoverage::Missing { path, reason }
            | SourceCoverage::LimitReached { path, reason } => format!("{path}: {reason}"),
        })
        .collect();

    for source in &manifest.entries {
        let path = Path::new(&source.path);
        match parse_single_file(path, maps, providers) {
            Ok(file) => {
                let records = file.records;
                parse_errors += file.parse_errors;
                error_messages.extend(file.messages);
                let source_label = path
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| source.path.clone());

                let mut channel_counts: std::collections::HashMap<String, u64> =
                    std::collections::HashMap::new();
                for record in &records {
                    *channel_counts.entry(record.channel.clone()).or_insert(0) += 1;
                }

                if channel_counts.is_empty() {
                    channels.push(EvtxChannelInfo {
                        name: source_label,
                        event_count: 0,
                        source_type: ChannelSourceType::File {
                            path: source.path.clone(),
                        },
                    });
                } else {
                    for (channel_name, count) in channel_counts {
                        channels.push(EvtxChannelInfo {
                            name: channel_name,
                            event_count: count,
                            source_type: ChannelSourceType::File {
                                path: source.path.clone(),
                            },
                        });
                    }
                }
                all_records.extend(records);
            }
            Err(error) => {
                log::warn!(
                    "event=evtx_parse_error file=\"{}\" error=\"{}\"",
                    source.path,
                    error
                );
                parse_errors += 1;
                error_messages.push(format!("{}: {error}", source.path));
            }
        }
    }

    all_records.sort_by_key(|record| record.timestamp_epoch);
    for (index, record) in all_records.iter_mut().enumerate() {
        record.id = index as u64;
    }

    Ok(EvtxParseResult {
        total_records: all_records.len() as u64,
        records: all_records,
        channels,
        parse_errors,
        error_messages,
    })
}

/// What one file yielded, including why anything was missing from it.
struct ParsedFile {
    records: Vec<EvtxRecord>,
    /// Records that could not be read. Kept as a count because a damaged file can produce
    /// thousands, and thousands of near-identical strings are not worth carrying.
    parse_errors: u32,
    /// Operator-facing explanations, already summarised.
    messages: Vec<String>,
}

/// Parse a single .evtx file.
///
/// Anything missing from the result is explained rather than merely counted. A damaged file, a
/// record whose XML will not parse, and a file so large it was truncated are all cases where the
/// view is incomplete, and a view that is silently incomplete is worse than one that is empty:
/// the absent events look like evidence that the thing being investigated did not happen.
fn parse_single_file(
    path: &Path,
    maps: &RwLock<MapRegistry>,
    providers: &RwLock<ProviderStore>,
) -> Result<ParsedFile, String> {
    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open EVTX file {}: {}", path.display(), e))?;

    let source_label = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut records = Vec::new();
    let mut parse_errors = 0u32;
    let mut messages = Vec::new();
    let mut truncated = false;

    // Locked once for the whole file rather than per record. A hundred thousand lock round trips
    // would cost more than the parsing does.
    let maps = maps
        .read()
        .map_err(|_| "map registry lock was poisoned".to_string())?;
    // A read guard: looking a provider up caches internally, so it needs no exclusive access.
    // Taking the write lock here blocked every other reader for the length of the file.
    let providers = providers
        .read()
        .map_err(|_| "provider store lock was poisoned".to_string())?;

    // XML rather than JSON. The JSON projection cannot be re-parsed into an event tree, which is
    // what the map engine, the System block, and the XML export all consume; reading XML here is
    // what makes those work on an opened file at all.
    for record_result in parser.records() {
        if records.len() >= MAX_ENTRIES_PER_FILE {
            log::warn!(
                "event=evtx_entry_cap_reached file=\"{}\" cap={}",
                path.display(),
                MAX_ENTRIES_PER_FILE
            );
            truncated = true;
            break;
        }

        let record = match record_result {
            Ok(r) => r,
            Err(e) => {
                log::warn!(
                    "event=evtx_record_skip file=\"{}\" error=\"{}\"",
                    path.display(),
                    e
                );
                parse_errors += 1;
                continue;
            }
        };

        let raw_xml = record.data;
        let event_record_id = record.event_record_id;

        // Parsed once and used for identity, the System block, the decoded payload, and any
        // registered map, so none of them costs an extra parse. A record whose XML will not parse
        // is counted as an error rather than pushed with every field defaulted, which would show a
        // row claiming provider "Unknown" at the epoch.
        let parsed = match super::event_node::parse_event_xml(&raw_xml) {
            Ok(root) => root,
            Err(error) => {
                log::warn!(
                    "event=evtx_record_unparsable file=\"{}\" error=\"{}\"",
                    path.display(),
                    error
                );
                parse_errors += 1;
                continue;
            }
        };

        let system = super::event_node::extract_system_fields(&parsed);
        let provider = system.provider.clone().unwrap_or_else(|| "Unknown".into());
        let channel = system.channel.clone().unwrap_or_else(|| "Unknown".into());
        let event_id = system.event_id.unwrap_or(0);
        let evtx_level = EvtxLevel::from_level_value(system.level.unwrap_or(0));
        let computer = system.computer.clone().unwrap_or_else(|| "Unknown".into());
        let timestamp_str = system.time_created.clone().unwrap_or_default();
        let timestamp_epoch = parse_timestamp_to_epoch_ms(&timestamp_str);

        let EventFields {
            mut fields,
            insertions,
        } = extract_event_data(&parsed);

        // Same treatment as the live path: a trace-backed event carries its message as hex, and
        // without decoding it the row is a wall of digits.
        let payload = cmtraceopen_parser::event_payload::decode_payload_in(&parsed)
            .map(|decoded| sanitize_control_chars(&decoded.text));
        if let Some(text) = &payload {
            // Appended after every real field, so it cannot disturb the positional insertions.
            fields.push(EvtxField {
                name: "EventPayload".to_string(),
                value: text.clone(),
            });
        }

        // A provider database, when one is loaded, turns raw field values into the sentence the
        // provider intended. Without it the file path can only summarise EventData, which is what
        // every other cross-platform reader shows and why they are hard to read.
        let message = describe_event(&providers, &provider, event_id, &insertions)
            .or(payload)
            .unwrap_or_else(|| super::rendered::build_event_data_summary(&fields));

        let mapped = super::maps::apply_registered(&maps, &channel, &provider, event_id, &parsed);
        records.push(EvtxRecord {
            id: 0, // Will be reassigned after sorting
            event_record_id,
            timestamp: timestamp_str,
            timestamp_epoch,
            provider,
            channel,
            event_id,
            level: evtx_level,
            computer,
            message,
            event_data: fields,
            raw_xml,
            source_label: source_label.clone(),
            task: system.task,
            opcode: system.opcode,
            process_id: system.process_id,
            thread_id: system.thread_id,
            user_sid: system.user_sid,
            keywords: system.keywords,
            mapped,
        });
    }

    if truncated {
        // Previously only logged. An operator saw exactly the cap as the event count with nothing
        // saying the file held more, which reads as a complete picture of a file that was cut off.
        messages.push(format!(
            "{}: stopped at {} events, the most this reader loads from one file. The file holds more.",
            source_label, MAX_ENTRIES_PER_FILE
        ));
    }
    if parse_errors > 0 {
        messages.push(format!(
            "{source_label}: {parse_errors} of {} records could not be read and are missing from the view.",
            parse_errors as usize + records.len()
        ));
    }

    Ok(ParsedFile {
        records,
        parse_errors,
        messages,
    })
}

/// Renders the provider's own description for this event, when metadata for it is loaded.
///
/// Returns `None` when no database is loaded, the provider is absent from it, or the provider does
/// not define this event. Falling back to a field summary is right in all three cases: an absent
/// description is a coverage gap, not a reason to show nothing.
///
/// A partially rendered description is rejected rather than shown. If the template references
/// insertions the event did not supply, the metadata and the event disagree, and a sentence with
/// `%4` embedded in it is less honest than the field summary it would replace.
fn describe_event(
    store: &ProviderStore,
    provider: &str,
    event_id: u32,
    insertions: &[String],
) -> Option<String> {
    let metadata = store.provider(provider)?;
    let event = metadata.event(event_id, None)?;
    let template = event.description.as_deref()?;

    let rendered = cmtraceopen_parser::provider::render_description(template, insertions);
    if rendered.is_complete() {
        Some(super::sanitize_control_chars(&rendered.text))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evtx_level_from_level_value() {
        assert_eq!(EvtxLevel::from_level_value(1), EvtxLevel::Critical);
        assert_eq!(EvtxLevel::from_level_value(2), EvtxLevel::Error);
        assert_eq!(EvtxLevel::from_level_value(3), EvtxLevel::Warning);
        assert_eq!(EvtxLevel::from_level_value(4), EvtxLevel::Information);
        assert_eq!(EvtxLevel::from_level_value(5), EvtxLevel::Verbose);
        assert_eq!(EvtxLevel::from_level_value(0), EvtxLevel::Information);
        assert_eq!(EvtxLevel::from_level_value(255), EvtxLevel::Information);
    }

    /// Empty registries, for tests that only care about parsing.
    ///
    /// Each test gets its own, so nothing here can be perturbed by another test on a parallel
    /// thread loading a different set.
    fn empty_state() -> (RwLock<MapRegistry>, RwLock<ProviderStore>) {
        (
            RwLock::new(MapRegistry::new()),
            RwLock::new(ProviderStore::default()),
        )
    }

    fn parse(xml: &str) -> cmtraceopen_parser::eventmap::EventNode {
        super::super::event_node::parse_event_xml(xml).expect("well formed")
    }

    fn fields_of(xml: &str) -> Vec<EvtxField> {
        extract_event_data(&parse(xml)).fields
    }

    fn insertions_of(xml: &str) -> Vec<String> {
        extract_event_data(&parse(xml)).insertions
    }

    #[test]
    fn a_file_that_cannot_be_opened_is_named_in_the_result() {
        // A count with no file name and no reason leaves an operator with a number and no next
        // step. The message is what makes a missing log actionable.
        let (maps, providers) = empty_state();
        let result = parse_evtx_files(&["/no/such/file.evtx".to_string()], &maps, &providers)
            .expect("returns");
        assert_eq!(result.parse_errors, 1);
        assert_eq!(result.error_messages.len(), 1);
        assert!(
            result.error_messages[0].contains("/no/such/file.evtx"),
            "{:?}",
            result.error_messages
        );
        assert!(result.records.is_empty());
    }

    #[test]
    fn a_clean_parse_reports_nothing() {
        // The messages are a gap report, so an empty run must not manufacture one.
        let (maps, providers) = empty_state();
        let result = parse_evtx_files(&[], &maps, &providers).expect("returns");
        assert_eq!(result.parse_errors, 0);
        assert!(result.error_messages.is_empty());
        assert_eq!(result.total_records, 0);
    }
    #[test]
    fn source_manifest_recurses_matches_rotated_files_and_deduplicates_case_insensitively() {
        let root = std::env::temp_dir().join(format!(
            "cmtrace-event-source-manifest-{}",
            std::process::id()
        ));
        let nested = root.join("Nested");
        std::fs::create_dir_all(&nested).expect("create source tree");
        std::fs::write(root.join("Application.EVTX"), b"not an evtx fixture").expect("write evtx");
        std::fs::write(root.join("Application.evtx.1"), b"rotated").expect("write rotated");
        std::fs::write(nested.join("System.evtx"), b"nested").expect("write nested");

        let manifest = build_source_manifest(&[root.to_string_lossy().to_string()])
            .expect("build manifest");
        let paths: Vec<String> = manifest
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        assert_eq!(paths.len(), 3);
        assert!(paths.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(paths.iter().any(|path| path.ends_with("Application.evtx.1")));
        assert!(manifest.coverage.is_empty());

        let duplicate = build_source_manifest(&[
            root.join("application.evtx").to_string_lossy().to_string(),
            root.join("Application.EVTX").to_string_lossy().to_string(),
        ])
        .expect("build duplicate manifest");
        assert_eq!(duplicate.entries.len(), 1);
        assert_eq!(duplicate.entries[0].source_id, duplicate.entries[0].path.to_lowercase());

        std::fs::remove_dir_all(root).expect("remove source tree");
    }

    #[test]
    fn source_manifest_wildcards_are_case_insensitive_and_deterministic() {
        let root = std::env::temp_dir().join(format!(
            "cmtrace-event-source-wildcard-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create source tree");
        std::fs::write(root.join("Archive-Application.EVTX"), b"archive").expect("write archive");
        std::fs::write(root.join("Application.evtx"), b"application").expect("write app");
        std::fs::write(root.join("readme.txt"), b"ignored").expect("write text");

        let pattern = root.join("*.evtx").to_string_lossy().to_string();
        let manifest = build_source_manifest(&[pattern]).expect("build wildcard manifest");
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(manifest.entries.len(), 1);
            assert_eq!(manifest.entries[0].kind, EventLogSourceKind::Wildcard);
            assert!(matches!(
                manifest.coverage.as_slice(),
                [SourceCoverage::Unsupported { .. }]
            ));
        }
        #[cfg(target_os = "windows")]
        assert_eq!(manifest.entries.len(), 2);

        std::fs::remove_dir_all(root).expect("remove source tree");
    }

    #[test]
    fn source_manifest_reports_vss_as_unsupported_on_non_windows() {
        let manifest = build_source_manifest(&[
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\winevt\Logs\Application.evtx"
                .to_string(),
        ])
        .expect("build vss manifest");

        #[cfg(not(target_os = "windows"))]
        {
            assert!(manifest.entries.is_empty());
            assert_eq!(manifest.coverage.len(), 1);
            assert!(matches!(
                manifest.coverage[0],
                SourceCoverage::Unsupported { .. }
            ));
        }
    }

    #[test]
    fn named_event_data_becomes_named_fields() {
        let fields = fields_of(
            r#"<Event><EventData>
                 <Data Name="SubjectUserName">SYSTEM</Data>
                 <Data Name="TargetLogonId">0x3e7</Data>
               </EventData></Event>"#,
        );
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "SubjectUserName");
        assert_eq!(fields[0].value, "SYSTEM");
        assert_eq!(fields[1].name, "TargetLogonId");
    }

    #[test]
    fn an_empty_data_element_is_dropped_rather_than_shown_blank() {
        let fields = fields_of(
            r#"<Event><EventData>
                 <Data Name="Present">yes</Data>
                 <Data Name="Absent"></Data>
               </EventData></Event>"#,
        );
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "Present");
    }

    #[test]
    fn unnamed_data_is_numbered_from_one_to_match_insertion_order() {
        // Classic providers emit positional Data. Numbering from one lines the fields up with the
        // %1 style references in the provider's message template.
        let fields = fields_of(
            r#"<Event><EventData>
                 <Data>first</Data>
                 <Data>second</Data>
               </EventData></Event>"#,
        );
        assert_eq!(fields[0].name, "Data1");
        assert_eq!(fields[0].value, "first");
        assert_eq!(fields[1].name, "Data2");
        assert_eq!(fields[1].value, "second");
    }

    #[test]
    fn user_data_fields_are_read_through_the_provider_wrapper() {
        // Skipping UserData would leave every classic and trace-backed event with no fields at all.
        let fields = fields_of(
            r#"<Event><UserData>
                 <RuleAndFileData xmlns="http://example">
                   <PolicyName>Enforce</PolicyName>
                   <FilePath>C:\app.exe</FilePath>
                 </RuleAndFileData>
               </UserData></Event>"#,
        );
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "PolicyName");
        assert_eq!(fields[1].value, "C:\\app.exe");
    }

    #[test]
    fn an_empty_field_still_holds_its_insertion_position() {
        // The provider's template addresses fields by position. Dropping the empty one would make
        // %3 resolve to what %4 said, and the rendered description would state it as fact.
        let xml = r#"<Event><EventData>
                 <Data Name="First">alpha</Data>
                 <Data Name="Second"></Data>
                 <Data Name="Third">gamma</Data>
               </EventData></Event>"#;

        assert_eq!(insertions_of(xml), vec!["alpha", "", "gamma"]);
        // The display list still omits the blank, because a column of blanks is noise.
        assert_eq!(
            fields_of(xml)
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            vec!["First", "Third"]
        );
    }

    #[test]
    fn a_leading_empty_field_does_not_shift_the_rest() {
        let xml = "<Event><EventData><Data></Data><Data>second</Data></EventData></Event>";
        assert_eq!(insertions_of(xml), vec!["", "second"]);
    }

    #[test]
    fn a_positional_label_matches_the_slot_the_template_addresses() {
        // The label is how an operator matches a field against the provider's template. Skipping
        // the count for a blank slot labelled the survivor Data1 while the template calls it %2.
        let xml = "<Event><EventData><Data></Data><Data>second</Data></EventData></Event>";
        let fields = fields_of(xml);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "Data2");
        assert_eq!(fields[0].value, "second");
    }

    #[test]
    fn insertions_cover_user_data_too() {
        let xml = r#"<Event><UserData><Wrapper>
                 <A>one</A><B></B><C>three</C>
               </Wrapper></UserData></Event>"#;
        assert_eq!(insertions_of(xml), vec!["one", "", "three"]);
    }

    #[test]
    fn a_binary_only_event_keeps_its_value() {
        // Classic providers emit <Binary> with no <Data> at all. Treating a container without
        // <Data> as a set of wrappers descends into <Binary>, finds no children, and drops the
        // only value the event carried.
        let fields = fields_of("<Event><EventData><Binary>DEADBEEF</Binary></EventData></Event>");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "Binary");
        assert_eq!(fields[0].value, "DEADBEEF");
    }

    #[test]
    fn data_and_binary_together_both_survive() {
        let fields = fields_of(
            r#"<Event><EventData>
                 <Data Name="Reason">timeout</Data>
                 <Binary>00FF</Binary>
               </EventData></Event>"#,
        );
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "Reason");
        assert_eq!(fields[1].name, "Binary");
    }

    #[test]
    fn a_wrapper_and_a_direct_field_can_coexist() {
        // Decided per child rather than per container, so one shape does not suppress the other.
        let fields = fields_of(
            r#"<Event><UserData>
                 <Direct>here</Direct>
                 <Wrapper><Nested>there</Nested></Wrapper>
               </UserData></Event>"#,
        );
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "Direct");
        assert_eq!(fields[1].name, "Nested");
    }

    #[test]
    fn positional_numbering_continues_across_containers() {
        // The %1 style references in a message template are numbered over the whole event, not
        // restarted per container.
        let fields = fields_of(
            r#"<Event>
                 <EventData><Data>one</Data></EventData>
                 <UserData><Data>two</Data></UserData>
               </Event>"#,
        );
        assert_eq!(fields[0].name, "Data1");
        assert_eq!(fields[1].name, "Data2");
    }

    #[test]
    fn control_characters_in_a_value_are_stripped() {
        let fields = fields_of(
            "<Event><EventData><Data Name=\"Path\">C:\\app.exe\r</Data></EventData></Event>",
        );
        assert_eq!(fields[0].value, "C:\\app.exe");
    }

    #[test]
    fn system_identity_comes_off_the_parsed_tree() {
        // The file path used to re-parse a JSON projection as XML, which always failed, leaving
        // every System-derived column empty on an opened file.
        let system = super::super::event_node::extract_system_fields(&parse(
            r#"<Event><System>
                 <Provider Name="Microsoft-Windows-Kernel-General" />
                 <EventID Qualifiers="49152">12</EventID>
                 <Level>2</Level>
                 <TimeCreated SystemTime="2026-08-09T12:00:00.000Z" />
                 <Channel>System</Channel>
                 <Computer>TESTHOST-01</Computer>
                 <Execution ProcessID="4" ThreadID="8" />
               </System></Event>"#,
        ));
        assert_eq!(
            system.provider.as_deref(),
            Some("Microsoft-Windows-Kernel-General")
        );
        // The qualifier is a separate value; the id is still the element text.
        assert_eq!(system.event_id, Some(12));
        assert_eq!(system.level, Some(2));
        assert_eq!(system.channel.as_deref(), Some("System"));
        assert_eq!(system.computer.as_deref(), Some("TESTHOST-01"));
        assert_eq!(system.process_id, Some(4));
        assert_eq!(
            parse_timestamp_to_epoch_ms(system.time_created.as_deref().unwrap_or_default()),
            1_786_276_800_000
        );
    }
}

#[cfg(test)]
mod description_tests {
    use super::*;

    /// Positional insertions, which is what a description template consumes.
    ///
    /// Names are kept in the call sites for readability but are not what the template addresses;
    /// it refers to fields by position, which is why the insertion list carries empties.
    fn insertions(values: &[(&str, &str)]) -> Vec<String> {
        values
            .iter()
            .map(|(_name, value)| value.to_string())
            .collect()
    }

    /// A store with nothing registered, which is the state until an operator loads a database.
    fn empty_store() -> ProviderStore {
        ProviderStore::default()
    }

    /// A store with the databases beside `CMTRACEOPEN_PROVIDER_DB` registered.
    ///
    /// Built per test. A shared one would let these interfere with each other, since registering a
    /// directory replaces whatever was there.
    fn loaded_store() -> ProviderStore {
        let path = std::env::var("CMTRACEOPEN_PROVIDER_DB").expect("database path");
        let directory = std::path::Path::new(&path)
            .parent()
            .expect("database has a parent directory");
        let mut store = ProviderStore::default();
        store.load_directory(directory).expect("databases load");
        store
    }

    #[test]
    fn with_no_database_loaded_it_falls_back_to_the_field_summary() {
        // The common case until an operator loads metadata. Must not fail or blank the message.
        let data = insertions(&[("HRESULT", "0x80180005")]);
        assert!(describe_event(&empty_store(), "Nobody-Has-This-Provider", 1, &data).is_none());
    }

    #[test]
    #[ignore = "requires a real provider database via CMTRACEOPEN_PROVIDER_DB"]
    fn an_unknown_event_id_falls_back_rather_than_inventing_a_description() {
        // Needs a store that actually holds the provider. Against an empty one the lookup returns
        // None on the provider itself and the event-id branch is never reached, so this only
        // repeated the no-database case while claiming to cover something else.
        let store = loaded_store();
        let data = insertions(&[("X", "1")]);
        assert!(
            describe_event(
                &store,
                "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
                999_999,
                &data
            )
            .is_none(),
            "a provider that is loaded but does not define this id must fall back"
        );
    }

    #[test]
    #[ignore = "requires a real provider database via CMTRACEOPEN_PROVIDER_DB"]
    fn a_loaded_database_renders_a_real_provider_description() {
        // The whole chain: SQLite on disk, gzip payload, provider metadata, insertion rendering.
        let store = loaded_store();

        let data = insertions(&[("HRESULT", "0x80180005")]);
        let described = describe_event(
            &store,
            "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
            2,
            &data,
        )
        .expect("the MDM provider defines event 2");

        println!("rendered: {described}");
        assert!(described.contains("0x80180005"), "{described}");
        assert!(!described.contains("%1"), "{described}");
        assert!(
            described.len() > "0x80180005".len(),
            "a description should be a sentence, not just the value: {described}"
        );
    }

    #[test]
    #[ignore = "requires a real provider database via CMTRACEOPEN_PROVIDER_DB"]
    fn an_event_the_database_does_not_cover_still_falls_back() {
        let store = loaded_store();

        // A provider that genuinely is not in a Windows capture.
        assert!(describe_event(
            &store,
            "Definitely-Not-A-Real-Provider",
            1,
            &insertions(&[("a", "b")])
        )
        .is_none());
    }
}
