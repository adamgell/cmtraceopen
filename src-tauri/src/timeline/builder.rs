use std::path::{Path, PathBuf};

/// Result of scanning a folder for timeline-eligible sources. Used by the
/// frontend ingestion layer (and future command wrappers) to decide which
/// paths to pass into `build_timeline` as log files vs. IME folders.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassifiedSource {
    LogFile(PathBuf),
    ImeLogsFolder(PathBuf),
}

/// Walk the given root (one level deep) and classify what we find.
/// Produces log files for every recognized log path plus at most one
/// IME-events source per IME folder detected.
#[allow(dead_code)]
pub fn classify_folder(root: &Path) -> Vec<ClassifiedSource> {
    let mut out: Vec<ClassifiedSource> = Vec::new();
    if !root.is_dir() {
        return out;
    }

    let ime_hint_files = ["AgentExecutor.log", "IntuneManagementExtension.log"];
    let mut contains_ime_logs = false;

    if let Ok(rd) = std::fs::read_dir(root) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if ime_hint_files.contains(&name) {
                    contains_ime_logs = true;
                }
                if is_log_file(name) {
                    out.push(ClassifiedSource::LogFile(path));
                }
            }
        }
    }
    if contains_ime_logs {
        out.push(ClassifiedSource::ImeLogsFolder(root.to_path_buf()));
    }
    out
}

fn is_log_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".log")
        || lower.ends_with(".cmtlog")
        || lower.ends_with(".txt")
        || lower == "setupact.log"
        || lower == "setupapi.app.log"
        || lower == "setupapi.dev.log"
}

#[cfg(test)]
mod tests_classify {
    use super::*;

    #[test]
    fn classifies_plain_log_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.log"), b"hello\n").unwrap();
        std::fs::write(dir.path().join("bar.txt"), b"bye\n").unwrap();
        std::fs::write(dir.path().join("ignore.bin"), b"x").unwrap();
        let mut out = classify_folder(dir.path());
        out.sort_by_key(|c| format!("{:?}", c));
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], ClassifiedSource::LogFile(_)));
        assert!(matches!(out[1], ClassifiedSource::LogFile(_)));
    }

    #[test]
    fn detects_ime_folder_when_agentexecutor_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("AgentExecutor.log"), b"hello\n").unwrap();
        std::fs::write(dir.path().join("IntuneManagementExtension.log"), b"hi\n").unwrap();
        let out = classify_folder(dir.path());
        assert!(out.iter().any(|c| matches!(c, ClassifiedSource::ImeLogsFolder(_))));
        assert_eq!(
            out.iter()
                .filter(|c| matches!(c, ClassifiedSource::LogFile(_)))
                .count(),
            2
        );
    }
}

use std::collections::{HashMap, HashSet};

use crate::timeline::models::*;
use crate::timeline::query::SourceRuntime;
use crate::timeline::store::Timeline;

pub const DEFAULT_ENTRY_LIMIT: u64 = 5_000_000;

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceRequest {
    pub path: String,
    pub display_name: Option<String>,
}

/// Build a timeline from a set of source requests. Each request is either
/// a log file path or a folder (containing IME logs).
pub fn build_timeline(
    requests: &[SourceRequest],
    limit: u64,
    denied_seed: Vec<String>,
) -> Result<(Timeline, HashMap<u16, SourceRuntime>), TimelineError> {
    if requests.is_empty() {
        return Err(TimelineError::NoSources);
    }

    const PALETTE: [&str; 8] = [
        "#2563eb", "#a855f7", "#16a34a", "#dc2626", "#f59e0b", "#0891b2", "#ea580c", "#65a30d",
    ];
    let mut sources: Vec<TimelineSourceMeta> = Vec::new();
    let mut indexes: HashMap<u16, Vec<EntryIndex>> = HashMap::new();
    let mut ime_events: HashMap<u16, Vec<crate::intune::models::IntuneEvent>> = HashMap::new();
    let mut runtimes: HashMap<u16, SourceRuntime> = HashMap::new();
    let mut errors: Vec<SourceError> = Vec::new();
    let mut total_entries: u64 = 0;
    let mut time_min = i64::MAX;
    let mut time_max = i64::MIN;

    for (i, req) in requests.iter().enumerate() {
        let idx = i as u16;
        let color = PALETTE[i % PALETTE.len()].to_string();
        let path = std::path::PathBuf::from(&req.path);
        let display_name = req.display_name.clone().unwrap_or_else(|| {
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("source")
                .to_string()
        });

        if path.is_dir() {
            match extract_ime_events(&path) {
                Ok(events) => {
                    for ev in &events {
                        if let Some(ts) = ev.start_time_epoch_ms() {
                            time_min = time_min.min(ts);
                            time_max = time_max.max(ts);
                        }
                    }
                    total_entries += events.len() as u64;
                    if total_entries > limit {
                        return Err(TimelineError::TooLarge {
                            estimated: total_entries,
                            limit,
                        });
                    }
                    sources.push(TimelineSourceMeta {
                        idx,
                        color,
                        display_name,
                        kind: TimelineSourceKind::IntuneEvents,
                        path: req.path.clone(),
                        entry_count: events.len() as u32,
                    });
                    ime_events.insert(idx, events);
                }
                Err(e) => errors.push(SourceError {
                    path: req.path.clone(),
                    message: e.to_string(),
                }),
            }
            continue;
        }

        match parse_to_index(&path) {
            Ok((parser_kind, idx_vec, parser, entry_count)) => {
                for ei in &idx_vec {
                    time_min = time_min.min(ei.timestamp_ms);
                    time_max = time_max.max(ei.timestamp_ms);
                }
                total_entries += entry_count as u64;
                if total_entries > limit {
                    return Err(TimelineError::TooLarge {
                        estimated: total_entries,
                        limit,
                    });
                }
                sources.push(TimelineSourceMeta {
                    idx,
                    color,
                    display_name,
                    kind: TimelineSourceKind::LogFile { parser_kind },
                    path: req.path.clone(),
                    entry_count,
                });
                indexes.insert(idx, idx_vec);
                runtimes.insert(idx, SourceRuntime { path, parser });
            }
            Err(e) => errors.push(SourceError {
                path: req.path.clone(),
                message: e.to_string(),
            }),
        }
    }

    if time_min == i64::MAX {
        time_min = 0;
        time_max = 0;
    }

    let mut denied: HashSet<String> = denied_seed
        .into_iter()
        .filter_map(|g| crate::timeline::correlation::normalize_guid(&g))
        .collect();
    let samples = sample_source_messages(&runtimes, &indexes, 200);
    let samples_as_refs: HashMap<u16, Vec<&str>> = samples
        .iter()
        .map(|(k, v)| (*k, v.iter().map(|s| s.as_str()).collect()))
        .collect();
    let hf = crate::timeline::correlation::high_frequency_guids(&samples_as_refs, 0.35, 2);
    denied.extend(hf);

    let tunables = TimelineTunables::default();
    let materialize = |src: u16, eref: u32| -> Option<String> {
        let ei = indexes.get(&src).and_then(|v| v.get(eref as usize))?;
        let rt = runtimes.get(&src)?;
        crate::timeline::query::materialize_msg(&rt.path, &rt.parser, ei)
    };
    let (raw_signals, incidents) = crate::timeline::incidents::detect_incidents(
        &indexes,
        &ime_events,
        &tunables,
        &denied,
        &materialize,
    );

    let bundle = TimelineBundle {
        id: uuid::Uuid::new_v4().to_string(),
        sources,
        time_range_ms: (time_min, time_max),
        total_entries,
        incidents,
        denied_guids: denied.into_iter().collect(),
        errors,
        tunables,
    };
    Ok((
        Timeline {
            bundle,
            indexes,
            ime_events,
            raw_signals,
        },
        runtimes,
    ))
}

/// Parse one log file. Returns parser kind, index vec, resolved parser,
/// and entry count.
fn parse_to_index(
    path: &std::path::Path,
) -> Result<
    (
        crate::models::log_entry::ParserKind,
        Vec<EntryIndex>,
        crate::parser::ResolvedParser,
        u32,
    ),
    anyhow::Error,
> {
    let path_str = path.to_string_lossy().to_string();
    let (parse_result, parser) = crate::parser::parse_file(&path_str)
        .map_err(|e| anyhow::anyhow!("parse_file: {}", e))?;

    // Re-read the raw bytes so we can compute per-line byte offsets.
    // The byte offset for line N (1-based) is offsets[N - 1]. offsets[0] is 0.
    let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("read: {}", e))?;
    let mut offsets: Vec<u64> = Vec::with_capacity(bytes.len() / 40 + 1);
    offsets.push(0);
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            offsets.push((i + 1) as u64);
        }
    }

    let parser_kind = parser.parser;
    let mut idx_vec: Vec<EntryIndex> = Vec::with_capacity(parse_result.entries.len());
    for entry in &parse_result.entries {
        let timestamp_ms = entry.timestamp.unwrap_or(0);
        let byte_offset = if entry.line_number == 0 {
            0
        } else {
            offsets
                .get((entry.line_number - 1) as usize)
                .copied()
                .unwrap_or(0)
        };
        let mut flags: u8 = 0;
        if !entry.error_code_spans.is_empty() {
            flags |= SIGNAL_FLAG_HAS_ERROR_CODE;
        }
        idx_vec.push(EntryIndex {
            timestamp_ms,
            severity: entry.severity,
            source_idx: 0, // filled in by caller (we set via per-source insertion anyway, but keep zero placeholder)
            byte_offset,
            line_number: entry.line_number,
            signal_flags: flags,
        });
    }
    let entry_count = idx_vec.len() as u32;
    Ok((parser_kind, idx_vec, parser, entry_count))
}

/// Walk an IME-logs folder and extract Intune events by running the same
/// pipeline the `analyze_intune_logs` command uses: ime_parser → GuidRegistry
/// ingest → event_tracker::extract_events → timeline::build_timeline.
#[cfg(feature = "intune-diagnostics")]
fn extract_ime_events(
    folder: &std::path::Path,
) -> Result<Vec<crate::intune::models::IntuneEvent>, anyhow::Error> {
    let rd = std::fs::read_dir(folder)
        .map_err(|e| anyhow::anyhow!("read_dir {}: {}", folder.display(), e))?;

    // Collect IME-relevant log files in the folder. Match on the pattern table
    // used by the intune command (case-insensitive substring on file name).
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let name_lower = p
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if !name_lower.ends_with(".log") {
            continue;
        }
        if IME_LOG_HINTS.iter().any(|h| name_lower.contains(h)) {
            files.push(p);
        }
    }

    // Parse each file, build a global GUID registry, then extract events.
    let mut per_file: Vec<(String, Vec<crate::intune::ime_parser::ImeLine>)> = Vec::new();
    let mut registry = crate::intune::guid_registry::GuidRegistry::new();
    for p in &files {
        let content = std::fs::read_to_string(p)
            .map_err(|e| anyhow::anyhow!("read_to_string {}: {}", p.display(), e))?;
        let lines = crate::intune::ime_parser::parse_ime_content(&content);
        registry.ingest_lines(&lines);
        per_file.push((p.to_string_lossy().to_string(), lines));
    }

    let mut all_events: Vec<crate::intune::models::IntuneEvent> = Vec::new();
    for (source_file, lines) in &per_file {
        let events = crate::intune::event_tracker::extract_events(lines, source_file, &registry);
        all_events.extend(events);
    }

    // Run the same timeline build (dedupe + sort + epoch_ms population) used
    // by the intune command path.
    Ok(crate::intune::timeline::build_timeline(all_events))
}

/// When built without the `intune-diagnostics` feature, IME event extraction
/// is unavailable. The timeline builder surfaces the per-source failure as a
/// `SourceError`, matching the pattern used for individual file read errors.
#[cfg(not(feature = "intune-diagnostics"))]
fn extract_ime_events(
    _folder: &std::path::Path,
) -> Result<Vec<crate::intune::models::IntuneEvent>, anyhow::Error> {
    Err(anyhow::anyhow!(
        "IME event extraction requires the `intune-diagnostics` feature"
    ))
}

#[cfg(feature = "intune-diagnostics")]
const IME_LOG_HINTS: &[&str] = &[
    "intunemanagementextension",
    "appworkload",
    "appactionprocessor",
    "agentexecutor",
    "healthscripts",
    "clienthealth",
    "clientcertcheck",
    "devicehealthmonitoring",
    "sensor",
    "win32appinventory",
    "imeui",
];

fn sample_source_messages(
    runtimes: &HashMap<u16, SourceRuntime>,
    indexes: &HashMap<u16, Vec<EntryIndex>>,
    per_source_cap: usize,
) -> HashMap<u16, Vec<String>> {
    let mut out: HashMap<u16, Vec<String>> = HashMap::new();
    for (src, idx_vec) in indexes {
        let rt = match runtimes.get(src) {
            Some(r) => r,
            None => continue,
        };
        let step = (idx_vec.len() / per_source_cap).max(1);
        let mut msgs: Vec<String> = Vec::with_capacity(per_source_cap);
        for ei in idx_vec.iter().step_by(step).take(per_source_cap) {
            if let Some(m) = crate::timeline::query::materialize_msg(&rt.path, &rt.parser, ei) {
                msgs.push(m);
            }
        }
        out.insert(*src, msgs);
    }
    out
}
