use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use serde::Serialize;
use serde_json::Value;
use tauri::{async_runtime, AppHandle, Emitter};

use crate::error_db::lookup::lookup_error_code;
use crate::intune::download_stats;
use crate::intune::event_tracker;
use crate::intune::evtx_parser;
use crate::intune::guid_registry::GuidRegistry;
use crate::intune::ime_parser;
use crate::intune::models::{
    DownloadStat, EventLogAnalysis, EvidenceBundleArtifactCounts, EvidenceBundleMetadata,
    IntuneAnalysisResult, IntuneDiagnosticCategory, IntuneDiagnosticInsight,
    IntuneDiagnosticSeverity, IntuneDiagnosticsConfidence, IntuneDiagnosticsConfidenceLevel,
    IntuneDiagnosticsCoverage, IntuneDiagnosticsFileCoverage, IntuneDominantSource, IntuneEvent,
    IntuneEventType, IntuneRemediationPriority, IntuneRepeatedFailureGroup, IntuneStatus,
    IntuneSummary, IntuneTimestampBounds,
};
use crate::intune::timeline;

const IME_LOG_PATTERNS: &[&str] = &[
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

const DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS: &[&str] = &[
    "evidence/logs",
    "evidence/registry",
    "evidence/event-logs",
    "evidence/exports",
    "evidence/screenshots",
    "evidence/command-output",
];

const INTUNE_ANALYSIS_PROGRESS_EVENT: &str = "intune-analysis-progress";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IntuneAnalysisProgressPayload {
    request_id: String,
    stage: &'static str,
    message: String,
    detail: Option<String>,
    current_file: Option<String>,
    completed_files: usize,
    total_files: Option<usize>,
}

/// Analyze Intune Management Extension logs and return structured results.
///
/// Supports either:
/// - A single IME log file path
/// - A directory containing IME logs (aggregated)
#[tauri::command]
pub async fn analyze_intune_logs(
    path: String,
    request_id: String,
    include_live_event_logs: bool,
    app: AppHandle,
) -> Result<IntuneAnalysisResult, String> {
    async_runtime::spawn_blocking(move || {
        analyze_intune_logs_blocking(path, request_id, include_live_event_logs, app)
    })
    .await
    .map_err(|error| format!("Intune analysis task failed: {}", error))?
}

fn analyze_intune_logs_blocking(
    path: String,
    request_id: String,
    include_live_event_logs: bool,
    app: AppHandle,
) -> Result<IntuneAnalysisResult, String> {
    let analysis_started = Instant::now();
    eprintln!("event=intune_analysis_start path=\"{}\"", path);
    emit_analysis_progress(
        &app,
        &request_id,
        "resolving",
        "Resolving Intune source...".to_string(),
        Some(path.clone()),
        None,
        0,
        None,
    );

    let input_path = Path::new(&path);
    let resolved_input = resolve_intune_input(input_path)?;
    let source_paths = resolved_input.source_paths;
    let evidence_bundle = resolved_input.evidence_bundle;
    eprintln!(
        "event=intune_analysis_sources_resolved path=\"{}\" source_count={}",
        path,
        source_paths.len()
    );
    let total_files = source_paths.len();
    emit_analysis_progress(
        &app,
        &request_id,
        "enumerating",
        if total_files == 1 {
            "Found 1 IME log file".to_string()
        } else {
            format!("Found {} IME log files", total_files)
        },
        Some(path.clone()),
        None,
        0,
        Some(total_files),
    );

    let source_files: Vec<String> = source_paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let completed_files = AtomicUsize::new(0);
    let mut processed_files: Vec<ProcessedIntuneFile> = source_paths
        .par_iter()
        .enumerate()
        .map(|(index, source_path)| {
            analyze_intune_source_file(
                source_path,
                index,
                total_files,
                &request_id,
                &app,
                &completed_files,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    processed_files.sort_by_key(|file| file.index);

    let completed_files = completed_files.load(Ordering::Relaxed);

    // Build global GUID→name registry from all files
    let mut guid_registry = GuidRegistry::new();
    for processed_file in &processed_files {
        guid_registry.merge(&processed_file.guid_registry);
    }
    let guid_registry_map = guid_registry.to_serializable();

    let mut all_events = Vec::new();
    let mut all_downloads = Vec::new();
    let mut coverage = Vec::new();

    for processed_file in processed_files {
        all_events.extend(processed_file.events);
        all_downloads.extend(processed_file.downloads);
        coverage.push(processed_file.coverage);
    }

    // Enrich event and download names using the global GUID registry
    let mut diag_buffer = String::new();
    let mut enriched_events = 0u32;
    let mut enriched_downloads = 0u32;
    let mut missed_events = 0u32;
    let mut missed_downloads = 0u32;
    if !guid_registry.is_empty() {
        let _ = writeln!(diag_buffer, "event=guid_registry_global entries={}", guid_registry.len());
        for (guid, entry) in guid_registry.iter() {
            let _ = writeln!(diag_buffer, "  guid={} name=\"{}\" source={:?}", guid, entry.name, entry.source);
        }

        for event in &mut all_events {
            if let Some(guid) = &event.guid {
                if let Some(enriched) = guid_registry.enrich_event_name(&event.name, guid) {
                    let _ = writeln!(diag_buffer, "event=guid_enriched_event old=\"{}\" new=\"{}\" guid={}", event.name, enriched, guid);
                    event.name = enriched;
                    enriched_events += 1;
                } else if event.name.ends_with(')') && event.name.contains('(') {
                    let _ = writeln!(diag_buffer, "event=guid_enrich_miss name=\"{}\" guid={} registry_has={}", event.name, guid, guid_registry.resolve(guid).unwrap_or("NOT_FOUND"));
                    missed_events += 1;
                }
            } else if event.name.ends_with(')') && event.name.contains('(') {
                let _ = writeln!(diag_buffer, "event=guid_enrich_skip_no_guid name=\"{}\"", event.name);
                missed_events += 1;
            }
        }
        for dl in &mut all_downloads {
            if let Some(resolved) = guid_registry.resolve_fallback_name(&dl.name, &dl.content_id)
            {
                let _ = writeln!(diag_buffer, "event=guid_enriched_download old=\"{}\" new=\"{}\" guid={}", dl.name, resolved, dl.content_id);
                dl.name = resolved;
                enriched_downloads += 1;
            } else if dl.name.starts_with("Download (") || dl.name.starts_with("Download:") {
                let _ = writeln!(diag_buffer, "event=guid_enrich_miss_download name=\"{}\" guid={} registry_has={}", dl.name, dl.content_id, guid_registry.resolve(&dl.content_id).unwrap_or("NOT_FOUND"));
                missed_downloads += 1;
            }
        }
    }

    // Append pipeline summary and write diag file (verbose detail to file only, summary to stderr)
    {
        let _ = writeln!(diag_buffer, "event=pipeline_summary event_count={} download_count={} guid_registry_entries={}", all_events.len(), all_downloads.len(), guid_registry.len());
        for (i, dl) in all_downloads.iter().enumerate() {
            let _ = writeln!(diag_buffer, "  download[{}] content_id={} name=\"{}\" success={} size={}", i, dl.content_id, dl.name, dl.success, dl.size_bytes);
        }
        eprintln!(
            "event=guid_enrichment_summary registry={} enriched_events={} missed_events={} enriched_downloads={} missed_downloads={} total_downloads={}",
            guid_registry.len(), enriched_events, missed_events, enriched_downloads, missed_downloads, all_downloads.len()
        );
        let diag_path = std::env::temp_dir().join("cmtrace-guid-diag.log");
        if let Ok(mut f) = fs::File::create(&diag_path) {
            let _ = f.write_all(diag_buffer.as_bytes());
            eprintln!("event=guid_diag_written path=\"{}\"", diag_path.display());
        }
    }

    // Fallback: synthesize DownloadStat records from ContentDownload events
    // when the regex-based download_stats extractor found nothing.
    if all_downloads.is_empty() {
        all_downloads = synthesize_downloads_from_events(&all_events);
        if !all_downloads.is_empty() {
            eprintln!(
                "event=download_synthesized_from_events count={}",
                all_downloads.len()
            );
        }
    }

    emit_analysis_progress(
        &app,
        &request_id,
        "finalizing",
        "Building Intune diagnostics view...".to_string(),
        Some(if total_files == 0 {
            path.clone()
        } else {
            format!("{} file(s) scanned", total_files)
        }),
        None,
        completed_files,
        Some(total_files),
    );

    if all_events.is_empty() {
        // Parse event logs even when no IME events were found
        let mut event_log_analysis = load_event_log_analysis(
            Path::new(&path),
            &evidence_bundle,
            include_live_event_logs,
            &app,
            &request_id,
            completed_files,
            total_files,
        );

        let download_summary = summarize_download_signals(&[], &all_downloads);
        let summary = IntuneSummary {
            total_events: 0,
            win32_apps: 0,
            winget_apps: 0,
            scripts: 0,
            remediations: 0,
            succeeded: 0,
            failed: 0,
            in_progress: 0,
            pending: 0,
            timed_out: 0,
            total_downloads: download_summary.total_downloads,
            successful_downloads: download_summary.successful_downloads,
            failed_downloads: download_summary.failed_downloads,
            failed_scripts: 0,
            log_time_span: None,
        };
        let mut diagnostics = build_diagnostics(&[], &all_downloads, &summary);
        let diagnostics_coverage = finalize_coverage(coverage, &[], &all_downloads);
        let repeated_failures = build_repeated_failures(&[]);

        // Run correlation (no IME events, but diagnostics may have error codes)
        if let Some(ref mut ela) = event_log_analysis {
            ela.correlation_links =
                evtx_parser::build_event_log_correlations(&[], &ela.entries, &diagnostics);

            // Enrich diagnostics with event log corroboration evidence
            for diag in &mut diagnostics {
                let corroboration = evtx_parser::build_corroboration_evidence(
                    &ela.entries,
                    &ela.correlation_links,
                    &diag.id,
                );
                diag.evidence.extend(corroboration);
            }
        }

        let diagnostics_confidence = build_diagnostics_confidence(
            &summary,
            &diagnostics_coverage,
            &repeated_failures,
            &[],
            &event_log_analysis,
        );

        eprintln!(
            "event=intune_analysis_complete path=\"{}\" source_count={} event_count=0 download_count={} diagnostics_count={} evtx_entries={} elapsed_ms={}",
            path,
            source_files.len(),
            all_downloads.len(),
            diagnostics.len(),
            event_log_analysis.as_ref().map_or(0, |e| e.total_entry_count),
            analysis_started.elapsed().as_millis()
        );

        return Ok(IntuneAnalysisResult {
            events: Vec::new(),
            downloads: all_downloads,
            summary,
            diagnostics,
            source_file: path,
            source_files,
            diagnostics_coverage,
            diagnostics_confidence,
            repeated_failures,
            evidence_bundle,
            event_log_analysis,
            guid_registry: guid_registry_map,
        });
    }

    // Parse Windows Event Logs from evidence bundle (if present)
    let mut event_log_analysis = load_event_log_analysis(
        Path::new(&path),
        &evidence_bundle,
        include_live_event_logs,
        &app,
        &request_id,
        completed_files,
        total_files,
    );

    let events = timeline::build_timeline(all_events);
    let summary = build_summary(&events, &all_downloads);
    let mut diagnostics = build_diagnostics(&events, &all_downloads, &summary);
    let diagnostics_coverage = finalize_coverage(coverage, &events, &all_downloads);
    let repeated_failures = build_repeated_failures(&events);

    // Run event log correlation after diagnostics are built
    if let Some(ref mut ela) = event_log_analysis {
        ela.correlation_links =
            evtx_parser::build_event_log_correlations(&events, &ela.entries, &diagnostics);

        // Enrich diagnostics with event log corroboration evidence
        for diag in &mut diagnostics {
            let corroboration = evtx_parser::build_corroboration_evidence(
                &ela.entries,
                &ela.correlation_links,
                &diag.id,
            );
            diag.evidence.extend(corroboration);
        }
    }

    let diagnostics_confidence = build_diagnostics_confidence(
        &summary,
        &diagnostics_coverage,
        &repeated_failures,
        &events,
        &event_log_analysis,
    );

    let payload_chars: usize = events
        .iter()
        .map(|event| {
            event.name.len()
                + event.detail.len()
                + event.source_file.len()
                + event.error_code.as_ref().map_or(0, |value| value.len())
        })
        .sum();

    eprintln!(
        "event=intune_analysis_complete path=\"{}\" source_count={} event_count={} download_count={} diagnostics_count={} evtx_entries={} payload_chars={} elapsed_ms={}",
        path,
        source_files.len(),
        events.len(),
        all_downloads.len(),
        diagnostics.len(),
        event_log_analysis.as_ref().map_or(0, |e| e.total_entry_count),
        payload_chars,
        analysis_started.elapsed().as_millis()
    );

    Ok(IntuneAnalysisResult {
        events,
        downloads: all_downloads,
        summary,
        diagnostics,
        source_file: path,
        source_files,
        diagnostics_coverage,
        diagnostics_confidence,
        repeated_failures,
        evidence_bundle,
        event_log_analysis,
        guid_registry: guid_registry_map,
    })
}

fn load_event_log_analysis(
    input_path: &Path,
    evidence_bundle: &Option<EvidenceBundleMetadata>,
    include_live_event_logs: bool,
    app: &AppHandle,
    request_id: &str,
    completed_files: usize,
    total_files: usize,
) -> Option<EventLogAnalysis> {
    if evidence_bundle.is_some() {
        emit_analysis_progress(
            app,
            request_id,
            "parsing-event-logs",
            "Parsing Windows Event Logs...".to_string(),
            None,
            None,
            completed_files,
            Some(total_files),
        );
        return evtx_parser::parse_bundle_event_logs(input_path, evidence_bundle);
    }

    if include_live_event_logs {
        emit_analysis_progress(
            app,
            request_id,
            "parsing-event-logs",
            "Querying live Windows Event Logs...".to_string(),
            None,
            None,
            completed_files,
            Some(total_files),
        );
        return evtx_parser::parse_live_event_logs();
    }

    None
}

#[expect(clippy::too_many_arguments, reason = "progress event keeps all fields explicit")]
fn emit_analysis_progress(
    app: &AppHandle,
    request_id: &str,
    stage: &'static str,
    message: String,
    detail: Option<String>,
    current_file: Option<String>,
    completed_files: usize,
    total_files: Option<usize>,
) {
    let payload = IntuneAnalysisProgressPayload {
        request_id: request_id.to_string(),
        stage,
        message,
        detail,
        current_file,
        completed_files,
        total_files,
    };

    if let Err(error) = app.emit(INTUNE_ANALYSIS_PROGRESS_EVENT, payload) {
        log::warn!("Failed to emit Intune analysis progress: {}", error);
    }
}

fn format_progress_detail(completed_files: usize, total_files: usize, source_file: &str) -> String {
    format!(
        "{} of {} complete | {}",
        completed_files, total_files, source_file
    )
}

fn display_file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_string())
        .unwrap_or_else(|| path.to_string())
}

#[derive(Debug, Clone)]
struct ResolvedIntuneInput {
    source_paths: Vec<PathBuf>,
    evidence_bundle: Option<EvidenceBundleMetadata>,
}

#[derive(Debug, Clone)]
struct CoverageAccumulator {
    coverage: IntuneDiagnosticsFileCoverage,
    rotation_candidate: Option<String>,
    is_explicit_rotated_segment: bool,
}

#[derive(Debug, Clone)]
struct RotationMetadata {
    is_rotated_segment: bool,
    rotation_group: Option<String>,
}

#[derive(Debug)]
struct ProcessedIntuneFile {
    index: usize,
    events: Vec<IntuneEvent>,
    downloads: Vec<DownloadStat>,
    coverage: CoverageAccumulator,
    guid_registry: GuidRegistry,
}

#[derive(Debug, Clone)]
struct TimestampCandidate {
    parsed: chrono::NaiveDateTime,
    raw: String,
}

#[derive(Debug, Clone)]
struct FailureReason {
    key: String,
    display: String,
}

#[derive(Debug, Clone)]
struct RepeatedFailureAccumulator {
    name: String,
    event_type: IntuneEventType,
    error_code: Option<String>,
    occurrences: u32,
    source_files: HashSet<String>,
    sample_event_ids: Vec<u64>,
    earliest: Option<TimestampCandidate>,
    latest: Option<TimestampCandidate>,
    reason_display: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadSignalState {
    InProgress,
    Success,
    Failed,
}

#[derive(Debug, Clone)]
struct DownloadSignalAccumulator {
    state: DownloadSignalState,
    timestamp: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DownloadSignalSummary {
    total_downloads: u32,
    successful_downloads: u32,
    failed_downloads: u32,
}

fn finalize_coverage(
    mut coverage: Vec<CoverageAccumulator>,
    events: &[IntuneEvent],
    downloads: &[DownloadStat],
) -> IntuneDiagnosticsCoverage {
    let mut rotation_counts: HashMap<String, usize> = HashMap::new();
    for file in &coverage {
        if let Some(group) = &file.rotation_candidate {
            *rotation_counts.entry(group.clone()).or_insert(0) += 1;
        }
    }

    let event_counts = count_events_by_source(events);
    for file in &mut coverage {
        if let Some(event_count) = event_counts.get(&file.coverage.file_path) {
            file.coverage.event_count = *event_count;
        }

        if let Some(group) = &file.rotation_candidate {
            if rotation_counts.get(group).copied().unwrap_or(0) > 1 {
                file.coverage.rotation_group = Some(group.clone());
                file.coverage.is_rotated_segment = file.is_explicit_rotated_segment;
            }
        }
    }

    let files: Vec<IntuneDiagnosticsFileCoverage> =
        coverage.into_iter().map(|file| file.coverage).collect();
    let timestamp_bounds = merge_timestamp_bounds(
        files
            .iter()
            .filter_map(|file| file.timestamp_bounds.as_ref()),
    );
    let has_rotated_logs = files.iter().any(|file| file.rotation_group.is_some());
    let dominant_source = build_dominant_source(&files, events, downloads);

    IntuneDiagnosticsCoverage {
        files,
        timestamp_bounds,
        has_rotated_logs,
        dominant_source,
    }
}

fn analyze_intune_source_file(
    source_path: &Path,
    index: usize,
    total_files: usize,
    request_id: &str,
    app: &AppHandle,
    completed_files: &AtomicUsize,
) -> Result<ProcessedIntuneFile, String> {
    let file_started = Instant::now();
    let source_file = source_path.to_string_lossy().to_string();
    eprintln!("event=intune_analysis_file_start file=\"{}\"", source_file);
    emit_analysis_progress(
        app,
        request_id,
        "reading-file",
        format!(
            "Reading {} ({}/{})",
            display_file_name(&source_file),
            index + 1,
            total_files
        ),
        Some(format_progress_detail(index, total_files, &source_file)),
        Some(source_file.clone()),
        completed_files.load(Ordering::Relaxed),
        Some(total_files),
    );

    let content = fs::read_to_string(source_path)
        .map_err(|error| format!("Failed to read file '{}': {}", source_file, error))?;

    let lines = ime_parser::parse_ime_content(&content);
    let rotation = detect_rotation_metadata(source_path);

    let mut file_guid_registry = GuidRegistry::new();

    let (file_events, file_downloads, file_timestamp_bounds, line_count): (
        Vec<IntuneEvent>,
        Vec<DownloadStat>,
        Option<IntuneTimestampBounds>,
        usize,
    ) = if lines.is_empty() {
        (Vec::new(), Vec::new(), None, 0usize)
    } else {
        file_guid_registry.ingest_lines(&lines);
        eprintln!(
            "event=guid_registry_file file=\"{}\" entries={}",
            source_file,
            file_guid_registry.len()
        );
        for (guid, entry) in file_guid_registry.iter() {
            eprintln!("  guid={} name=\"{}\" source={:?}", guid, entry.name, entry.source);
        }
        let file_events = event_tracker::extract_events(&lines, &source_file, &file_guid_registry);
        let file_downloads = download_stats::extract_downloads(&lines, &source_file, &file_guid_registry);
        let file_timestamp_bounds = build_timestamp_bounds(&file_events, &file_downloads);

        (
            file_events,
            file_downloads,
            file_timestamp_bounds,
            lines.len(),
        )
    };

    let coverage = CoverageAccumulator {
        coverage: IntuneDiagnosticsFileCoverage {
            file_path: source_file.clone(),
            event_count: file_events.len() as u32,
            download_count: file_downloads.len() as u32,
            timestamp_bounds: file_timestamp_bounds,
            is_rotated_segment: false,
            rotation_group: None,
        },
        rotation_candidate: rotation.rotation_group,
        is_explicit_rotated_segment: rotation.is_rotated_segment,
    };

    eprintln!(
        "event=intune_analysis_file_complete file=\"{}\" line_count={} event_count={} download_count={} elapsed_ms={}",
        source_file,
        line_count,
        file_events.len(),
        file_downloads.len(),
        file_started.elapsed().as_millis()
    );

    let completed = completed_files.fetch_add(1, Ordering::Relaxed) + 1;
    emit_analysis_progress(
        app,
        request_id,
        "completed-file",
        format!(
            "Indexed {} ({}/{})",
            display_file_name(&source_file),
            completed,
            total_files
        ),
        Some(format_progress_detail(completed, total_files, &source_file)),
        Some(source_file.clone()),
        completed,
        Some(total_files),
    );

    Ok(ProcessedIntuneFile {
        index,
        events: file_events,
        downloads: file_downloads,
        coverage,
        guid_registry: file_guid_registry,
    })
}

fn count_events_by_source(events: &[IntuneEvent]) -> HashMap<String, u32> {
    let mut counts = HashMap::new();

    for event in events {
        *counts.entry(event.source_file.clone()).or_insert(0) += 1;
    }

    counts
}

fn build_dominant_source(
    files: &[IntuneDiagnosticsFileCoverage],
    events: &[IntuneEvent],
    _downloads: &[DownloadStat],
) -> Option<IntuneDominantSource> {
    let total_events = events.len() as f64;
    let mut scores: HashMap<&str, u32> = HashMap::new();

    for event in events {
        *scores.entry(event.source_file.as_str()).or_insert(0) += event_signal_score(event);
    }

    for file in files {
        if file.download_count > 0 {
            *scores.entry(file.file_path.as_str()).or_insert(0) += file.download_count * 2;
        }
    }

    let best = files
        .iter()
        .filter_map(|file| {
            let score = scores.get(file.file_path.as_str()).copied().unwrap_or(0);
            if score == 0 {
                None
            } else {
                Some((file, score))
            }
        })
        .max_by(|(left_file, left_score), (right_file, right_score)| {
            left_score
                .cmp(right_score)
                .then_with(|| left_file.event_count.cmp(&right_file.event_count))
                .then_with(|| left_file.download_count.cmp(&right_file.download_count))
                .then_with(|| right_file.file_path.cmp(&left_file.file_path))
        })?;

    Some(IntuneDominantSource {
        file_path: best.0.file_path.clone(),
        event_count: best.0.event_count,
        event_share: if total_events > 0.0 {
            Some(((best.0.event_count as f64 / total_events) * 1000.0).round() / 1000.0)
        } else {
            None
        },
    })
}

fn event_signal_score(event: &IntuneEvent) -> u32 {
    let status_weight = match event.status {
        IntuneStatus::Failed | IntuneStatus::Timeout => 5,
        IntuneStatus::Success => 2,
        IntuneStatus::InProgress | IntuneStatus::Pending => 1,
        IntuneStatus::Unknown => 1,
    };
    let type_weight = match event.event_type {
        IntuneEventType::ContentDownload => 4,
        IntuneEventType::Win32App | IntuneEventType::WinGetApp => 4,
        IntuneEventType::PowerShellScript | IntuneEventType::Remediation => 4,
        IntuneEventType::PolicyEvaluation => 3,
        IntuneEventType::Esp | IntuneEventType::SyncSession => 1,
        IntuneEventType::Other => 1,
    };
    let error_weight = if event.error_code.is_some() { 1 } else { 0 };

    status_weight + type_weight + error_weight
}

fn build_timestamp_bounds(
    events: &[IntuneEvent],
    downloads: &[DownloadStat],
) -> Option<IntuneTimestampBounds> {
    let mut earliest: Option<TimestampCandidate> = None;
    let mut latest: Option<TimestampCandidate> = None;

    for event in events {
        if let Some(timestamp) = event.start_time.as_deref() {
            update_timestamp_candidate(&mut earliest, &mut latest, timestamp);
        }

        if let Some(timestamp) = event.end_time.as_deref() {
            update_timestamp_candidate(&mut earliest, &mut latest, timestamp);
        }
    }

    for download in downloads {
        if let Some(timestamp) = download.timestamp.as_deref() {
            update_timestamp_candidate(&mut earliest, &mut latest, timestamp);
        }
    }

    match (earliest, latest) {
        (Some(first), Some(last)) => Some(IntuneTimestampBounds {
            first_timestamp: Some(first.raw),
            last_timestamp: Some(last.raw),
        }),
        _ => None,
    }
}

fn merge_timestamp_bounds<'a>(
    bounds: impl Iterator<Item = &'a IntuneTimestampBounds>,
) -> Option<IntuneTimestampBounds> {
    let mut earliest: Option<TimestampCandidate> = None;
    let mut latest: Option<TimestampCandidate> = None;

    for bound in bounds {
        if let Some(timestamp) = bound.first_timestamp.as_deref() {
            update_timestamp_candidate(&mut earliest, &mut latest, timestamp);
        }

        if let Some(timestamp) = bound.last_timestamp.as_deref() {
            update_timestamp_candidate(&mut earliest, &mut latest, timestamp);
        }
    }

    match (earliest, latest) {
        (Some(first), Some(last)) => Some(IntuneTimestampBounds {
            first_timestamp: Some(first.raw),
            last_timestamp: Some(last.raw),
        }),
        _ => None,
    }
}

fn update_timestamp_candidate(
    earliest: &mut Option<TimestampCandidate>,
    latest: &mut Option<TimestampCandidate>,
    value: &str,
) {
    let Some(parsed) = timeline::parse_timestamp(value) else {
        return;
    };

    let candidate = TimestampCandidate {
        parsed,
        raw: value.to_string(),
    };

    match earliest {
        Some(current)
            if candidate.parsed > current.parsed
                || (candidate.parsed == current.parsed && candidate.raw >= current.raw) => {}
        _ => *earliest = Some(candidate.clone()),
    }

    match latest {
        Some(current)
            if candidate.parsed < current.parsed
                || (candidate.parsed == current.parsed && candidate.raw <= current.raw) => {}
        _ => *latest = Some(candidate),
    }
}

fn detect_rotation_metadata(path: &Path) -> RotationMetadata {
    let stem = path
        .file_stem()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();

    let segments = [".", "-", "_"];
    for separator in segments {
        if let Some((base, suffix)) = stem.rsplit_once(separator) {
            if is_rotation_suffix(suffix) {
                return RotationMetadata {
                    is_rotated_segment: true,
                    rotation_group: Some(base.to_ascii_lowercase()),
                };
            }
        }
    }

    RotationMetadata {
        is_rotated_segment: false,
        rotation_group: Some(stem.to_ascii_lowercase()),
    }
}

fn is_rotation_suffix(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    if normalized.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }

    if normalized.starts_with("lo_") || normalized == "bak" || normalized == "old" {
        return true;
    }

    normalized.len() == 8 && normalized.chars().all(|ch| ch.is_ascii_digit())
}

fn build_repeated_failures(events: &[IntuneEvent]) -> Vec<IntuneRepeatedFailureGroup> {
    let mut groups: HashMap<String, RepeatedFailureAccumulator> = HashMap::new();

    for event in events
        .iter()
        .filter(|event| matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout))
    {
        let reason = normalize_failure_reason(event);
        let subject_key = event
            .guid
            .clone()
            .unwrap_or_else(|| normalize_group_label(&event.name));
        let key = format!("{:?}|{}|{}", event.event_type, subject_key, reason.key);

        let entry = groups
            .entry(key)
            .or_insert_with(|| RepeatedFailureAccumulator {
                name: event.name.clone(),
                event_type: event.event_type,
                error_code: event.error_code.clone(),
                occurrences: 0,
                source_files: HashSet::new(),
                sample_event_ids: Vec::new(),
                earliest: None,
                latest: None,
                reason_display: reason.display.clone(),
            });

        entry.occurrences += 1;
        entry.source_files.insert(event.source_file.clone());
        if entry.sample_event_ids.len() < 5 {
            entry.sample_event_ids.push(event.id);
        }
        if event.name.len() < entry.name.len() {
            entry.name = event.name.clone();
        }
        if entry.error_code.is_none() {
            entry.error_code = event.error_code.clone();
        }
        if let Some(timestamp) = event.start_time.as_deref().or(event.end_time.as_deref()) {
            update_timestamp_candidate(&mut entry.earliest, &mut entry.latest, timestamp);
        }
    }

    let mut repeated: Vec<IntuneRepeatedFailureGroup> = groups
        .into_iter()
        .filter_map(|(key, group)| {
            if group.occurrences < 2 {
                return None;
            }

            let mut source_files: Vec<String> = group.source_files.into_iter().collect();
            source_files.sort();

            let timestamp_bounds = match (group.earliest, group.latest) {
                (Some(first), Some(last)) => Some(IntuneTimestampBounds {
                    first_timestamp: Some(first.raw),
                    last_timestamp: Some(last.raw),
                }),
                _ => None,
            };

            Some(IntuneRepeatedFailureGroup {
                id: format!("repeated-{}", sanitize_identifier(&key)),
                name: format!("{}: {}", group.name, group.reason_display),
                event_type: group.event_type,
                error_code: group.error_code,
                occurrences: group.occurrences,
                timestamp_bounds,
                source_files,
                sample_event_ids: group.sample_event_ids,
            })
        })
        .collect();

    repeated.sort_by(|left, right| {
        right
            .occurrences
            .cmp(&left.occurrences)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.id.cmp(&right.id))
    });
    repeated
}

fn normalize_failure_reason(event: &IntuneEvent) -> FailureReason {
    if let Some(error_code) = &event.error_code {
        let lookup = lookup_error_code(error_code);
        let display = if lookup.found {
            format!("{} ({})", lookup.code_hex, lookup.description)
        } else {
            error_code.clone()
        };

        return FailureReason {
            key: format!("code:{}", sanitize_identifier(error_code)),
            display,
        };
    }

    let detail = event.detail.to_ascii_lowercase();
    let patterns = [
        ("access is denied", "access is denied"),
        ("permission denied", "permission denied"),
        ("unauthorized", "unauthorized"),
        ("not applicable", "not applicable"),
        ("will not be enforced", "will not be enforced"),
        ("requirement rule", "requirement rule blocked enforcement"),
        ("detection rule", "detection rule blocked enforcement"),
        ("hash validation failed", "hash validation failed"),
        ("hash mismatch", "hash mismatch"),
        ("cannot find path", "path not found"),
        ("path not found", "path not found"),
        ("file not found", "file not found"),
        ("execution policy", "execution policy blocked execution"),
        ("digitally signed", "script signing blocked execution"),
        (
            "running scripts is disabled",
            "script execution is disabled",
        ),
        ("timed out", "timed out"),
        ("timeout", "timed out"),
        ("stalled", "stalled"),
        ("retry exhausted", "retry exhausted"),
        ("installer execution failed", "installer execution failed"),
        ("failed to download", "download failed"),
    ];

    for (needle, label) in patterns {
        if detail.contains(needle) {
            return FailureReason {
                key: sanitize_identifier(label),
                display: label.to_string(),
            };
        }
    }

    let normalized = normalize_detail_snippet(&detail);
    FailureReason {
        key: sanitize_identifier(&normalized),
        display: normalized,
    }
}

fn normalize_detail_snippet(value: &str) -> String {
    let mut words = Vec::new();

    for token in value.split_whitespace() {
        let cleaned: String = token
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();

        if cleaned.is_empty() || cleaned.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }

        words.push(cleaned);
        if words.len() >= 8 {
            break;
        }
    }

    if words.is_empty() {
        "unspecified failure".to_string()
    } else {
        words.join(" ")
    }
}

fn sanitize_identifier(value: &str) -> String {
    let mut result = String::new();
    let mut last_was_dash = false;

    for ch in value.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };

        if mapped == '-' {
            if !last_was_dash {
                result.push(mapped);
            }
            last_was_dash = true;
        } else {
            result.push(mapped);
            last_was_dash = false;
        }
    }

    result.trim_matches('-').to_string()
}

fn build_diagnostics_confidence(
    summary: &IntuneSummary,
    coverage: &IntuneDiagnosticsCoverage,
    repeated_failures: &[IntuneRepeatedFailureGroup],
    events: &[IntuneEvent],
    event_log_analysis: &Option<EventLogAnalysis>,
) -> IntuneDiagnosticsConfidence {
    if summary.total_events == 0 && summary.total_downloads == 0 {
        return IntuneDiagnosticsConfidence {
            level: IntuneDiagnosticsConfidenceLevel::Unknown,
            score: None,
            reasons: vec!["No Intune events or download evidence were available.".to_string()],
        };
    }

    let mut score: f64 = 0.15;
    let mut reasons = Vec::new();
    let failed_events = events
        .iter()
        .filter(|event| matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout))
        .count();
    let distinct_source_kinds = distinct_source_kinds(&coverage.files);
    let contributing_files = coverage
        .files
        .iter()
        .filter(|file| file.event_count > 0 || file.download_count > 0)
        .count();

    if summary.total_events >= 20 {
        score += 0.25;
        reasons.push(format!(
            "{} events were extracted across the selected logs.",
            summary.total_events
        ));
    } else if summary.total_events >= 8 {
        score += 0.15;
        reasons.push(format!(
            "{} events were extracted across the selected logs.",
            summary.total_events
        ));
    } else if summary.total_events > 0 {
        score += 0.05;
        reasons.push(format!(
            "Only {} event(s) were extracted, so the evidence set is narrow.",
            summary.total_events
        ));
    }

    if failed_events >= 4 {
        score += 0.2;
        reasons.push(format!(
            "{} failed or timed-out event(s) were available for review.",
            failed_events
        ));
    } else if failed_events > 0 {
        score += 0.1;
        reasons.push(format!(
            "{} failed or timed-out event(s) were available for review.",
            failed_events
        ));
    }

    if distinct_source_kinds >= 3 {
        score += 0.2;
        reasons.push(format!(
            "Evidence spans {} distinct Intune log families.",
            distinct_source_kinds
        ));
    } else if distinct_source_kinds == 2 {
        score += 0.1;
        reasons.push("Evidence spans two distinct Intune log families.".to_string());
    }

    if coverage.timestamp_bounds.is_some() {
        score += 0.1;
        reasons.push(
            "Parsed timestamps were available for the overall diagnostics window.".to_string(),
        );
    }

    if !repeated_failures.is_empty() {
        score += 0.15;
        reasons.push(format!(
            "{} repeated failure group(s) were identified deterministically.",
            repeated_failures.len()
        ));
    }

    if coverage.has_rotated_logs {
        score += 0.05;
        reasons.push(
            "Rotated log segments were available, which improves continuity across retries."
                .to_string(),
        );
    }

    if contributing_files <= 1 {
        score -= 0.15;
        reasons.push("Evidence comes from a single contributing source file.".to_string());
    }

    if coverage.files.iter().any(|file| {
        (file.event_count > 0 || file.download_count > 0) && file.timestamp_bounds.is_none()
    }) {
        score -= 0.1;
        reasons.push("Some contributing files had no parseable timestamps, which weakens ordering confidence.".to_string());
    }

    if summary.total_events == 0 && summary.total_downloads > 0 {
        score -= 0.2;
        reasons.push(
            "Only download statistics were available; no correlated Intune events were extracted."
                .to_string(),
        );
    }

    if summary.in_progress + summary.pending > summary.failed + summary.succeeded
        && summary.total_events > 0
    {
        score -= 0.1;
        reasons.push("Most observed work is still pending or in progress, so the failure picture may be incomplete.".to_string());
    }

    if has_app_or_download_failures(events) && !has_source_kind(&coverage.files, "appworkload") {
        score -= 0.15;
        reasons.push(
            "AppWorkload evidence was not available for app or download failures.".to_string(),
        );
    }

    if has_policy_failures(events) && !has_source_kind(&coverage.files, "appactionprocessor") {
        score -= 0.15;
        reasons.push(
            "AppActionProcessor evidence was not available for applicability or policy failures."
                .to_string(),
        );
    }

    if has_script_failures(events)
        && !has_source_kind(&coverage.files, "agentexecutor")
        && !has_source_kind(&coverage.files, "healthscripts")
    {
        score -= 0.15;
        reasons.push("AgentExecutor or HealthScripts evidence was not available for script-related failures.".to_string());
    }

    // Event log evidence boosts
    if let Some(ref ela) = event_log_analysis {
        if ela.error_entry_count + ela.warning_entry_count > 0 {
            score += 0.15;
            reasons.push(format!(
                "Windows Event Log evidence available with {} error/warning entries across {} channel(s).",
                ela.error_entry_count + ela.warning_entry_count,
                ela.channel_summaries.len()
            ));
        }
        if !ela.correlation_links.is_empty() {
            let linked_ime_count = ela
                .correlation_links
                .iter()
                .filter(|l| l.linked_intune_event_id.is_some())
                .count();
            if linked_ime_count > 0 {
                score += 0.10;
                reasons.push(format!(
                    "Event log entries correlated with {} IME event(s).",
                    linked_ime_count
                ));
            }
        }
    }

    score = score.clamp(0.0, 1.0);
    let level = if score >= 0.75 {
        IntuneDiagnosticsConfidenceLevel::High
    } else if score >= 0.45 {
        IntuneDiagnosticsConfidenceLevel::Medium
    } else {
        IntuneDiagnosticsConfidenceLevel::Low
    };

    IntuneDiagnosticsConfidence {
        level,
        score: Some((score * 1000.0).round() / 1000.0),
        reasons,
    }
}

fn distinct_source_kinds(files: &[IntuneDiagnosticsFileCoverage]) -> usize {
    let mut kinds = HashSet::new();

    for file in files {
        if file.event_count == 0 && file.download_count == 0 {
            continue;
        }

        kinds.insert(source_kind_key(&file.file_path));
    }

    kinds.len()
}

fn has_source_kind(files: &[IntuneDiagnosticsFileCoverage], kind: &str) -> bool {
    files.iter().any(|file| {
        (file.event_count > 0 || file.download_count > 0)
            && source_kind_key(&file.file_path) == kind
    })
}

fn source_kind_key(file_path: &str) -> &'static str {
    let normalized = Path::new(file_path)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| file_path.to_ascii_lowercase());

    if normalized.contains("appworkload") {
        "appworkload"
    } else if normalized.contains("appactionprocessor") {
        "appactionprocessor"
    } else if normalized.contains("agentexecutor") {
        "agentexecutor"
    } else if normalized.contains("healthscripts") {
        "healthscripts"
    } else if normalized.contains("intunemanagementextension") {
        "intunemanagementextension"
    } else {
        "other"
    }
}

fn has_app_or_download_failures(events: &[IntuneEvent]) -> bool {
    events.iter().any(|event| {
        matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout)
            && matches!(
                event.event_type,
                IntuneEventType::Win32App
                    | IntuneEventType::WinGetApp
                    | IntuneEventType::ContentDownload
            )
    })
}

fn has_policy_failures(events: &[IntuneEvent]) -> bool {
    events.iter().any(|event| {
        event.event_type == IntuneEventType::PolicyEvaluation
            && matches!(
                event.status,
                IntuneStatus::Failed | IntuneStatus::Timeout | IntuneStatus::Pending
            )
    })
}

fn has_script_failures(events: &[IntuneEvent]) -> bool {
    events.iter().any(|event| {
        matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout)
            && matches!(
                event.event_type,
                IntuneEventType::PowerShellScript | IntuneEventType::Remediation
            )
    })
}

fn describe_path_access_error(path: &Path, error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => {
            format!(
                "The selected Intune source was not found: '{}'",
                path.display()
            )
        }
        std::io::ErrorKind::PermissionDenied => format!(
            "The selected Intune source could not be accessed because permission was denied: '{}'",
            path.display()
        ),
        _ => format!(
            "The selected Intune source could not be accessed: '{}' ({})",
            path.display(),
            error
        ),
    }
}

fn describe_directory_read_error(path: &Path, error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => format!(
            "The selected Intune folder could not be read because permission was denied: '{}'",
            path.display()
        ),
        _ => format!(
            "The selected Intune folder could not be read: '{}' ({})",
            path.display(),
            error
        ),
    }
}

fn resolve_intune_input(path: &Path) -> Result<ResolvedIntuneInput, String> {
    let metadata = fs::metadata(path).map_err(|error| describe_path_access_error(path, &error))?;

    if metadata.is_file() {
        return Ok(ResolvedIntuneInput {
            source_paths: vec![path.to_path_buf()],
            evidence_bundle: None,
        });
    }

    if !metadata.is_dir() {
        return Err(format!(
            "The selected Intune source is neither a file nor a folder: '{}'",
            path.display()
        ));
    }

    if let Some(bundle_input) = resolve_evidence_bundle_input(path)? {
        return Ok(bundle_input);
    }

    Ok(ResolvedIntuneInput {
        source_paths: collect_directory_log_paths(path)?,
        evidence_bundle: None,
    })
}

/// Resolve a single file or a directory of Intune logs into a deterministic file list.
#[cfg(test)]
fn collect_input_paths(path: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(resolve_intune_input(path)?.source_paths)
}

fn collect_directory_log_paths(path: &Path) -> Result<Vec<PathBuf>, String> {
    let entries =
        fs::read_dir(path).map_err(|error| describe_directory_read_error(path, &error))?;

    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|entry_path| entry_path.is_file())
        .collect();

    files.sort_by_key(|p| {
        p.file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default()
    });

    let mut ime_files: Vec<PathBuf> = files
        .iter()
        .filter(|p| is_ime_related_log_file(p))
        .cloned()
        .collect();

    if ime_files.is_empty() {
        ime_files = files.iter().filter(|p| is_log_file(p)).cloned().collect();
    }

    if ime_files.is_empty() {
        return Err(format!(
            "The selected folder does not contain any .log files to analyze: '{}'",
            path.display()
        ));
    }

    Ok(ime_files)
}

fn resolve_evidence_bundle_input(path: &Path) -> Result<Option<ResolvedIntuneInput>, String> {
    let manifest_path = path.join("manifest.json");
    if !manifest_path.is_file() {
        return Ok(None);
    }

    let manifest = match fs::read_to_string(&manifest_path) {
        Ok(content) => match serde_json::from_str::<Value>(&content) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "event=intune_bundle_manifest_parse_failed path=\"{}\" error=\"{}\"",
                    manifest_path.display(),
                    error
                );
                return Ok(None);
            }
        },
        Err(error) => {
            eprintln!(
                "event=intune_bundle_manifest_read_failed path=\"{}\" error=\"{}\"",
                manifest_path.display(),
                error
            );
            return Ok(None);
        }
    };

    let evidence_bundle = build_evidence_bundle_metadata(path, &manifest);
    let source_paths = collect_bundle_log_paths(path, &manifest, &evidence_bundle)?;

    eprintln!(
        "event=intune_bundle_resolved bundle_id=\"{}\" path=\"{}\" source_count={} available_primary_entry_points={}",
        evidence_bundle.bundle_id.as_deref().unwrap_or("unknown"),
        path.display(),
        source_paths.len(),
        evidence_bundle.available_primary_entry_points.len()
    );

    Ok(Some(ResolvedIntuneInput {
        source_paths,
        evidence_bundle: Some(evidence_bundle),
    }))
}

fn build_evidence_bundle_metadata(bundle_root: &Path, manifest: &Value) -> EvidenceBundleMetadata {
    let manifest_path = bundle_root.join("manifest.json");
    let notes_path = resolve_bundle_hint_path(
        bundle_root,
        json_string_at(manifest, &["intakeHints", "notesPath"]).as_deref(),
    )
    .or_else(|| {
        let default_path = bundle_root.join("notes.md");
        default_path.is_file().then_some(default_path)
    });
    let evidence_root = resolve_bundle_hint_path(
        bundle_root,
        json_string_at(manifest, &["intakeHints", "evidenceRoot"]).as_deref(),
    )
    .or_else(|| {
        let default_path = bundle_root.join("evidence");
        default_path.is_dir().then_some(default_path)
    });

    let mut primary_entry_points = resolve_bundle_primary_entry_points(bundle_root, manifest);
    if primary_entry_points.is_empty() {
        primary_entry_points = DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS
            .iter()
            .map(|relative| bundle_root.join(relative))
            .collect();
    }

    let available_primary_entry_points = primary_entry_points
        .iter()
        .filter(|entry| entry.exists())
        .map(|entry| entry.to_string_lossy().to_string())
        .collect();

    EvidenceBundleMetadata {
        manifest_path: manifest_path.to_string_lossy().to_string(),
        notes_path: notes_path.map(|value| value.to_string_lossy().to_string()),
        evidence_root: evidence_root.map(|value| value.to_string_lossy().to_string()),
        primary_entry_points: primary_entry_points
            .iter()
            .map(|entry| entry.to_string_lossy().to_string())
            .collect(),
        available_primary_entry_points,
        bundle_id: json_string_at(manifest, &["bundle", "bundleId"]),
        bundle_label: json_string_at(manifest, &["bundle", "bundleLabel"]),
        created_utc: json_string_at(manifest, &["bundle", "createdUtc"]),
        case_reference: json_string_at(manifest, &["bundle", "caseReference"]),
        summary: json_string_at(manifest, &["bundle", "summary"]),
        collector_profile: json_string_at(manifest, &["collection", "collectorProfile"]),
        collector_version: json_string_at(manifest, &["collection", "collectorVersion"]),
        collected_utc: json_string_at(manifest, &["collection", "collectedUtc"]),
        device_name: json_string_at(manifest, &["bundle", "device", "deviceName"]),
        primary_user: json_string_at(manifest, &["bundle", "device", "primaryUser"]),
        platform: json_string_at(manifest, &["bundle", "device", "platform"]),
        os_version: json_string_at(manifest, &["bundle", "device", "osVersion"]),
        tenant: json_string_at(manifest, &["bundle", "device", "tenant"]),
        artifact_counts: build_bundle_artifact_counts(manifest),
    }
}

fn build_bundle_artifact_counts(manifest: &Value) -> Option<EvidenceBundleArtifactCounts> {
    Some(EvidenceBundleArtifactCounts {
        collected: json_u64_at(
            manifest,
            &["collection", "results", "artifactCounts", "collected"],
        )?,
        missing: json_u64_at(
            manifest,
            &["collection", "results", "artifactCounts", "missing"],
        )?,
        failed: json_u64_at(
            manifest,
            &["collection", "results", "artifactCounts", "failed"],
        )?,
        skipped: json_u64_at(
            manifest,
            &["collection", "results", "artifactCounts", "skipped"],
        )?,
    })
}

fn collect_bundle_log_paths(
    bundle_root: &Path,
    manifest: &Value,
    evidence_bundle: &EvidenceBundleMetadata,
) -> Result<Vec<PathBuf>, String> {
    let primary_entry_points: Vec<PathBuf> = evidence_bundle
        .primary_entry_points
        .iter()
        .map(PathBuf::from)
        .collect();
    let mut seen = HashSet::new();
    let mut manifest_candidates = Vec::new();

    if let Some(artifacts) = manifest.get("artifacts").and_then(Value::as_array) {
        for artifact in artifacts {
            let Some(relative_path) = artifact.get("relativePath").and_then(Value::as_str) else {
                continue;
            };

            let candidate_path = bundle_root.join(relative_path);
            if !candidate_path.is_file() || !is_log_file(&candidate_path) {
                continue;
            }

            if !primary_entry_points.is_empty()
                && !primary_entry_points
                    .iter()
                    .any(|entry_point| candidate_path.starts_with(entry_point))
            {
                continue;
            }

            let key = candidate_path.to_string_lossy().to_string();
            if seen.insert(key) {
                manifest_candidates.push(candidate_path);
            }
        }
    }

    let mut selected = prioritize_ime_log_paths(manifest_candidates);
    if !selected.is_empty() {
        return Ok(selected);
    }

    let mut scanned_candidates = Vec::new();
    for entry_point in primary_entry_points {
        if !entry_point.is_dir() {
            continue;
        }

        let read_dir = fs::read_dir(&entry_point)
            .map_err(|error| describe_directory_read_error(&entry_point, &error))?;

        let mut entries: Vec<PathBuf> = read_dir
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && is_log_file(path))
            .collect();

        entries.sort_by_key(|candidate| {
            candidate
                .file_name()
                .map(|value| value.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default()
        });

        for candidate in entries {
            let key = candidate.to_string_lossy().to_string();
            if seen.insert(key) {
                scanned_candidates.push(candidate);
            }
        }
    }

    selected = prioritize_ime_log_paths(scanned_candidates);
    Ok(selected)
}

fn prioritize_ime_log_paths(candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    let ime_files: Vec<PathBuf> = candidates
        .iter()
        .filter(|path| is_ime_related_log_file(path))
        .cloned()
        .collect();

    if !ime_files.is_empty() {
        return ime_files;
    }

    candidates
}

fn resolve_bundle_primary_entry_points(bundle_root: &Path, manifest: &Value) -> Vec<PathBuf> {
    let manifest_entry_points =
        json_string_array_at(manifest, &["intakeHints", "primaryEntryPoints"]);
    let entry_points = if manifest_entry_points.is_empty() {
        DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    } else {
        manifest_entry_points
    };

    entry_points
        .iter()
        .filter_map(|entry| resolve_bundle_hint_path(bundle_root, Some(entry.as_str())))
        .collect()
}

fn resolve_bundle_hint_path(bundle_root: &Path, raw_path: Option<&str>) -> Option<PathBuf> {
    let raw_path = raw_path?.trim();
    if raw_path.is_empty() {
        return None;
    }

    let path = PathBuf::from(raw_path);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(bundle_root.join(path))
    }
}

fn json_value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn json_string_at(value: &Value, path: &[&str]) -> Option<String> {
    json_value_at(value, path)
        .and_then(Value::as_str)
        .map(|value| value.to_string())
}

fn json_u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    json_value_at(value, path).and_then(Value::as_u64)
}

fn json_string_array_at(value: &Value, path: &[&str]) -> Vec<String> {
    json_value_at(value, path)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|value| value.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn is_log_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_string_lossy().eq_ignore_ascii_case("log"))
        .unwrap_or(false)
}

fn is_ime_related_log_file(path: &Path) -> bool {
    if !is_log_file(path) {
        return false;
    }

    path.file_name()
        .map(|name| {
            let name = name.to_string_lossy().to_ascii_lowercase();
            IME_LOG_PATTERNS
                .iter()
                .any(|pattern| name.contains(pattern))
        })
        .unwrap_or(false)
}

/// Build summary statistics from events and downloads.
fn build_summary(events: &[IntuneEvent], downloads: &[DownloadStat]) -> IntuneSummary {
    let summary_events: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| is_summary_signal_event(event))
        .collect();
    let mut win32_apps = 0u32;
    let mut winget_apps = 0u32;
    let mut scripts = 0u32;
    let mut remediations = 0u32;
    let mut succeeded = 0u32;
    let mut failed = 0u32;
    let mut in_progress = 0u32;
    let mut pending = 0u32;
    let mut timed_out = 0u32;
    let mut failed_scripts = 0u32;

    for event in &summary_events {
        match event.event_type {
            IntuneEventType::Win32App => win32_apps += 1,
            IntuneEventType::WinGetApp => winget_apps += 1,
            IntuneEventType::PowerShellScript => scripts += 1,
            IntuneEventType::Remediation => remediations += 1,
            _ => {}
        }

        match event.status {
            IntuneStatus::Success => succeeded += 1,
            IntuneStatus::Failed => {
                failed += 1;
                if event.event_type == IntuneEventType::PowerShellScript {
                    failed_scripts += 1;
                }
            }
            IntuneStatus::InProgress => in_progress += 1,
            IntuneStatus::Pending => pending += 1,
            IntuneStatus::Timeout => {
                timed_out += 1;
                failed += 1;
                if event.event_type == IntuneEventType::PowerShellScript {
                    failed_scripts += 1;
                }
            }
            _ => {}
        }
    }

    let download_summary = summarize_download_signals(events, downloads);
    let log_time_span = timeline::calculate_time_span(events);

    IntuneSummary {
        total_events: summary_events.len() as u32,
        win32_apps,
        winget_apps,
        scripts,
        remediations,
        succeeded,
        failed,
        in_progress,
        pending,
        timed_out,
        total_downloads: download_summary.total_downloads,
        successful_downloads: download_summary.successful_downloads,
        failed_downloads: download_summary.failed_downloads,
        failed_scripts,
        log_time_span,
    }
}

fn is_summary_signal_event(event: &IntuneEvent) -> bool {
    match event.event_type {
        IntuneEventType::Win32App
        | IntuneEventType::WinGetApp
        | IntuneEventType::PowerShellScript
        | IntuneEventType::Remediation
        | IntuneEventType::PolicyEvaluation
        | IntuneEventType::ContentDownload
        | IntuneEventType::Esp
        | IntuneEventType::SyncSession => true,
        IntuneEventType::Other => matches!(
            event.status,
            IntuneStatus::Failed
                | IntuneStatus::Timeout
                | IntuneStatus::Pending
                | IntuneStatus::InProgress
        ),
    }
}

/// Synthesize `DownloadStat` records from ContentDownload events when
/// the regex-based `download_stats` extractor found nothing (i.e. the log
/// format didn't match `DOWNLOAD_RE`). Groups events by GUID and picks the
/// latest status per GUID as the outcome.
fn synthesize_downloads_from_events(events: &[IntuneEvent]) -> Vec<DownloadStat> {
    let mut by_guid: HashMap<String, Vec<&IntuneEvent>> = HashMap::new();
    for event in events {
        if event.event_type != IntuneEventType::ContentDownload {
            continue;
        }
        let key = event
            .guid
            .clone()
            .unwrap_or_else(|| event.name.clone());
        by_guid.entry(key).or_default().push(event);
    }

    let mut downloads = Vec::new();
    for (content_id, group) in &by_guid {
        // Use the last event's status as the outcome
        let last = group.iter().max_by_key(|e| e.id).unwrap();
        let success = last.status == IntuneStatus::Success;
        let name = last.name.clone();
        let timestamp = last
            .start_time
            .clone()
            .or_else(|| last.end_time.clone());

        downloads.push(DownloadStat {
            content_id: content_id.clone(),
            name,
            size_bytes: 0,
            speed_bps: 0.0,
            do_percentage: 0.0,
            duration_secs: last.duration_secs.unwrap_or(0.0),
            success,
            timestamp,
        });
    }

    downloads.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    downloads
}

fn summarize_download_signals(
    events: &[IntuneEvent],
    downloads: &[DownloadStat],
) -> DownloadSignalSummary {
    let mut signals: HashMap<String, DownloadSignalAccumulator> = HashMap::new();

    for event in events {
        let Some(key) = download_signal_key_for_event(event) else {
            continue;
        };
        let Some(state) = download_signal_state_for_event(event) else {
            continue;
        };

        upsert_download_signal(
            &mut signals,
            key,
            state,
            event.start_time.as_deref().or(event.end_time.as_deref()),
        );
    }

    for download in downloads {
        let state = if download.success {
            DownloadSignalState::Success
        } else {
            DownloadSignalState::Failed
        };
        upsert_download_signal(
            &mut signals,
            download_signal_key_for_stat(download),
            state,
            download.timestamp.as_deref(),
        );
    }

    DownloadSignalSummary {
        total_downloads: signals.len() as u32,
        successful_downloads: signals
            .values()
            .filter(|signal| signal.state == DownloadSignalState::Success)
            .count() as u32,
        failed_downloads: signals
            .values()
            .filter(|signal| signal.state == DownloadSignalState::Failed)
            .count() as u32,
    }
}

fn download_signal_key_for_event(event: &IntuneEvent) -> Option<String> {
    if event.event_type != IntuneEventType::ContentDownload {
        return None;
    }

    if let Some(guid) = &event.guid {
        return Some(format!("guid:{}", guid.to_ascii_lowercase()));
    }

    let normalized_name = normalize_group_label(&event.name);
    if !normalized_name.is_empty() {
        return Some(format!(
            "name:{}|family:{}",
            normalized_name,
            timeline::normalized_source_identity(&event.source_file)
        ));
    }

    let normalized_detail = normalize_group_label(&event.detail);
    if !normalized_detail.is_empty() {
        return Some(format!(
            "detail:{}|family:{}",
            normalized_detail,
            timeline::normalized_source_identity(&event.source_file)
        ));
    }

    None
}

fn download_signal_key_for_stat(download: &DownloadStat) -> String {
    if !download.content_id.trim().is_empty()
        && !download.content_id.eq_ignore_ascii_case("unknown")
    {
        return format!("guid:{}", download.content_id.to_ascii_lowercase());
    }

    let normalized_name = normalize_group_label(&download.name);
    if !normalized_name.is_empty() {
        return format!("name:{}", normalized_name);
    }

    format!(
        "timestamp:{}|result:{}",
        download.timestamp.as_deref().unwrap_or("unknown"),
        if download.success {
            "success"
        } else {
            "failed"
        }
    )
}

fn download_signal_state_for_event(event: &IntuneEvent) -> Option<DownloadSignalState> {
    match event.status {
        IntuneStatus::Failed | IntuneStatus::Timeout => Some(DownloadSignalState::Failed),
        IntuneStatus::Success => Some(DownloadSignalState::Success),
        IntuneStatus::InProgress | IntuneStatus::Pending => Some(DownloadSignalState::InProgress),
        IntuneStatus::Unknown => None,
    }
}

fn upsert_download_signal(
    signals: &mut HashMap<String, DownloadSignalAccumulator>,
    key: String,
    state: DownloadSignalState,
    timestamp: Option<&str>,
) {
    let candidate_timestamp = timestamp.map(|value| value.to_string());
    let should_replace = match signals.get(&key) {
        Some(existing) => {
            should_replace_download_signal(existing, state, candidate_timestamp.as_deref())
        }
        None => true,
    };

    if should_replace {
        signals.insert(
            key,
            DownloadSignalAccumulator {
                state,
                timestamp: candidate_timestamp,
            },
        );
    }
}

fn should_replace_download_signal(
    existing: &DownloadSignalAccumulator,
    candidate_state: DownloadSignalState,
    candidate_timestamp: Option<&str>,
) -> bool {
    match compare_optional_timestamps(candidate_timestamp, existing.timestamp.as_deref()) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            download_signal_rank(candidate_state) >= download_signal_rank(existing.state)
        }
    }
}

fn compare_optional_timestamps(left: Option<&str>, right: Option<&str>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => match (
            timeline::parse_timestamp(left),
            timeline::parse_timestamp(right),
        ) {
            (Some(left_time), Some(right_time)) => {
                left_time.cmp(&right_time).then_with(|| left.cmp(right))
            }
            _ => left.cmp(right),
        },
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn download_signal_rank(state: DownloadSignalState) -> u8 {
    match state {
        DownloadSignalState::InProgress => 1,
        DownloadSignalState::Success => 2,
        DownloadSignalState::Failed => 3,
    }
}

fn build_diagnostics(
    events: &[IntuneEvent],
    downloads: &[DownloadStat],
    summary: &IntuneSummary,
) -> Vec<IntuneDiagnosticInsight> {
    let mut insights = Vec::new();

    let failed_download_events: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| {
            event.event_type == IntuneEventType::ContentDownload
                && matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout)
        })
        .collect();
    let install_failures: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| {
            matches!(
                event.event_type,
                IntuneEventType::Win32App | IntuneEventType::WinGetApp
            ) && matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout)
                && contains_any(
                    &event.detail,
                    &[
                        "install",
                        "installer",
                        "execution",
                        "enforcement",
                        "launching install",
                    ],
                )
        })
        .collect();
    let timed_out_events: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| event.status == IntuneStatus::Timeout)
        .collect();
    let script_failures: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| {
            matches!(
                event.event_type,
                IntuneEventType::PowerShellScript | IntuneEventType::Remediation
            ) && matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout)
        })
        .collect();
    let policy_events: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| {
            event.event_type == IntuneEventType::PolicyEvaluation
                && event.status != IntuneStatus::Success
        })
        .collect();

    if summary.failed_downloads > 0 {
        let download_case = classify_download_failure_case(&failed_download_events, downloads);
        let mut evidence = vec![format!(
            "{} download attempt(s) ended in failure, stall, or retry exhaustion.",
            summary.failed_downloads
        )];
        evidence.extend(top_failed_download_labels(downloads, 2));
        evidence.extend(top_event_detail_matches(&failed_download_events, 2));
        if let Some(retries) = repeated_retry_evidence(&failed_download_events) {
            evidence.push(retries);
        }
        if let Some(stall) = stalled_download_evidence(&failed_download_events) {
            evidence.push(stall);
        }
        evidence.extend(repeated_group_evidence(
            &failed_download_events,
            2,
            "Repeated failed download pattern",
        ));

        insights.push(IntuneDiagnosticInsight {
            id: "download-failures".to_string(),
            severity: IntuneDiagnosticSeverity::Error,
            category: IntuneDiagnosticCategory::Download,
            remediation_priority: IntuneRemediationPriority::Immediate,
            title: download_case.title.to_string(),
            summary: download_case.summary.to_string(),
            likely_cause: Some(download_case.likely_cause.to_string()),
            evidence,
            next_checks: vec![
                "Review AppWorkload download, staging, and hash-validation lines for the affected content IDs.".to_string(),
                "Check whether the last download state is progressing, stalling, or immediately retrying for the same content.".to_string(),
                "Verify Delivery Optimization, proxy, VPN, or content-source reachability on the device.".to_string(),
            ],
            suggested_fixes: download_case
                .suggested_fixes
                .into_iter()
                .map(|item| item.to_string())
                .collect(),
            focus_areas: vec![
                "AppWorkload download and staging transitions".to_string(),
                "Delivery Optimization, proxy, and content reachability".to_string(),
                "IME cache health and package revision consistency".to_string(),
            ],
            affected_source_files: related_source_files(&failed_download_events, 4),
            related_error_codes: related_error_codes(&failed_download_events, 3),
        });
    }

    if !install_failures.is_empty() {
        let install_hint = best_error_hint(&install_failures);
        let mut evidence = vec![format!(
            "{} app install or enforcement event(s) failed after download or staging work began.",
            install_failures.len()
        )];
        evidence.extend(top_event_labels(&install_failures, 3));
        evidence.extend(top_event_detail_matches(&install_failures, 2));
        if let Some(error_hint) = &install_hint {
            evidence.push(format!(
                "Most specific error observed: {} ({})",
                error_hint.code, error_hint.description
            ));
        }

        insights.push(IntuneDiagnosticInsight {
            id: "install-enforcement-failures".to_string(),
            severity: IntuneDiagnosticSeverity::Error,
            category: IntuneDiagnosticCategory::Install,
            remediation_priority: IntuneRemediationPriority::High,
            title: "App install or enforcement failures detected".to_string(),
            summary: "The workload progressed past content acquisition but failed during installer launch, enforcement, or completion tracking.".to_string(),
            likely_cause: Some(
                install_hint
                    .as_ref()
                    .map(|hint| format!("Installer enforcement is failing with {} ({}).", hint.code, hint.description))
                    .unwrap_or_else(|| "Installer launch, execution, or detection handoff is failing after content acquisition completed.".to_string()),
            ),
            evidence,
            next_checks: vec![
                "Inspect AppWorkload install and enforcement rows near the failure for the last successful phase before the installer returned control.".to_string(),
                "Compare the installer command, return-code mapping, and detection rule behavior for the affected app.".to_string(),
                "Correlate the failure with AgentExecutor or remediation activity if the deployment depends on prerequisite scripts.".to_string(),
            ],
            suggested_fixes: install_failure_suggested_fixes(install_hint),
            focus_areas: vec![
                "Installer command line and return-code mapping".to_string(),
                "Detection-rule accuracy after install".to_string(),
                "Prerequisite scripts and execution context".to_string(),
            ],
            affected_source_files: related_source_files(&install_failures, 4),
            related_error_codes: related_error_codes(&install_failures, 3),
        });
    }

    if !timed_out_events.is_empty() {
        let timeout_loops = repeated_failure_groups(&timed_out_events, 2);
        let mut evidence = vec![format!(
            "{} event(s) timed out before reporting a clean success or failure.",
            timed_out_events.len()
        )];
        evidence.extend(top_event_labels(&timed_out_events, 2));
        evidence.extend(repeated_group_evidence(
            &timed_out_events,
            2,
            "Timeout loop",
        ));

        let (title, summary) = if timeout_loops.is_empty() {
            (
                "Timed-out operations detected",
                "One or more app or script operations stalled long enough to be treated as failures.",
            )
        } else {
            (
                "Repeated timeout loop detected",
                "The same app or script path is timing out across multiple attempts, which suggests the retry cycle is repeating without a state change.",
            )
        };

        let mut suggested_fixes = vec![
            "Shorten or optimize long-running installers or scripts that routinely exceed the IME execution window.".to_string(),
            "Remove dependencies on user interaction, mapped drives, or transient network resources during enforcement.".to_string(),
        ];
        if !timeout_loops.is_empty() {
            suggested_fixes.push(
                "Break the retry loop by fixing the underlying block before forcing another sync; repeated retries with the same timeout rarely self-heal.".to_string(),
            );
        } else {
            suggested_fixes.push(
                "If the timeout is expected during first install, validate whether the assignment deadline or retry cadence needs adjustment.".to_string(),
            );
        }

        insights.push(IntuneDiagnosticInsight {
            id: "operation-timeouts".to_string(),
            severity: IntuneDiagnosticSeverity::Error,
            category: IntuneDiagnosticCategory::Timeout,
            remediation_priority: if timeout_loops.is_empty() {
                IntuneRemediationPriority::High
            } else {
                IntuneRemediationPriority::Immediate
            },
            title: title.to_string(),
            summary: summary.to_string(),
            likely_cause: Some(if timeout_loops.is_empty() {
                "The operation is running long enough to hit IME timeout thresholds without a definitive completion signal.".to_string()
            } else {
                "The same timeout path is repeating across retries, which means the blocking condition is persisting between attempts.".to_string()
            }),
            evidence,
            next_checks: vec![
                "Inspect the matching event rows around the timeout for the last successful phase before the stall.".to_string(),
                "Check whether install commands, detection scripts, or remediation scripts are waiting on external resources or device state.".to_string(),
                "Look for repeated retries or follow-on failure codes in AppWorkload, AgentExecutor, or HealthScripts logs.".to_string(),
            ],
            suggested_fixes,
            focus_areas: vec![
                "Last successful phase before the stall".to_string(),
                "Installer or script wait conditions".to_string(),
                "External dependencies that never become ready".to_string(),
            ],
            affected_source_files: related_source_files(&timed_out_events, 4),
            related_error_codes: related_error_codes(&timed_out_events, 3),
        });
    }

    if !script_failures.is_empty() {
        let script_hint = best_error_hint(&script_failures);
        let script_case = classify_script_failure_case(&script_failures);
        let mut evidence = vec![format!(
            "{} script or remediation event(s) failed or timed out.",
            script_failures.len()
        )];
        evidence.extend(top_event_labels(&script_failures, 3));
        evidence.extend(top_event_detail_matches(&script_failures, 2));
        evidence.extend(repeated_group_evidence(
            &script_failures,
            2,
            "Recurring script failure",
        ));
        evidence.extend(script_scope_evidence(&script_failures));
        if let Some(error_hint) = &script_hint {
            evidence.push(format!(
                "Most specific script error observed: {} ({})",
                error_hint.code, error_hint.description
            ));
        }

        insights.push(IntuneDiagnosticInsight {
            id: "script-failures".to_string(),
            severity: IntuneDiagnosticSeverity::Error,
            category: IntuneDiagnosticCategory::Script,
            remediation_priority: IntuneRemediationPriority::High,
            title: script_case.title.to_string(),
            summary: script_case.summary.to_string(),
            likely_cause: Some(script_case.likely_cause.to_string()),
            evidence,
            next_checks: vec![
                "Review AgentExecutor and HealthScripts entries for stdout, stderr, and explicit exit-code lines around the affected script.".to_string(),
                "Separate detection-script failures from remediation-script failures before deciding whether the issue is logic, environment, or permissions.".to_string(),
                "Validate script prerequisites such as execution context, file paths, network access, and required modules or commands.".to_string(),
            ],
            suggested_fixes: script_failure_suggested_fixes(&script_failures, script_hint),
            focus_areas: vec![
                "AgentExecutor and HealthScripts output around failure".to_string(),
                "Execution context, paths, and dependency availability".to_string(),
                "Detection vs remediation script separation".to_string(),
            ],
            affected_source_files: related_source_files(&script_failures, 4),
            related_error_codes: related_error_codes(&script_failures, 3),
        });
    }

    if !policy_events.is_empty() {
        let policy_case = classify_policy_failure_case(&policy_events);
        let mut evidence = vec![format!(
            "{} policy or applicability event(s) did not end in success.",
            policy_events.len()
        )];
        evidence.extend(top_event_labels(&policy_events, 2));
        evidence.extend(top_event_detail_matches(&policy_events, 2));
        evidence.extend(repeated_group_evidence(
            &policy_events,
            2,
            "Repeated policy block",
        ));
        if let Some(reason) = applicability_reason_evidence(&policy_events) {
            evidence.push(reason);
        }

        insights.push(IntuneDiagnosticInsight {
            id: "policy-applicability".to_string(),
            severity: IntuneDiagnosticSeverity::Warning,
            category: IntuneDiagnosticCategory::Policy,
            remediation_priority: IntuneRemediationPriority::Medium,
            title: policy_case.title.to_string(),
            summary: policy_case.summary.to_string(),
            likely_cause: Some(policy_case.likely_cause.to_string()),
            evidence,
            next_checks: vec![
                "Review AppActionProcessor requirement-rule, detection-rule, and applicability lines for the affected app GUIDs.".to_string(),
                "Confirm the assignment intent, targeting, and any deadline or GRS behavior for the device or user.".to_string(),
                "Correlate policy-evaluation events with the later AppWorkload or AgentExecutor phases to see where enforcement stopped.".to_string(),
            ],
            suggested_fixes: policy_case
                .suggested_fixes
                .into_iter()
                .map(|item| item.to_string())
                .collect(),
            focus_areas: vec![
                "AppActionProcessor applicability and requirement evaluation".to_string(),
                "Assignment targeting and deployment intent".to_string(),
                "Detection-rule and applicability-rule truthfulness".to_string(),
            ],
            affected_source_files: related_source_files(&policy_events, 4),
            related_error_codes: related_error_codes(&policy_events, 3),
        });
    }

    if insights.is_empty() {
        if summary.in_progress > 0 || summary.pending > 0 {
            insights.push(IntuneDiagnosticInsight {
                id: "work-in-progress".to_string(),
                severity: IntuneDiagnosticSeverity::Info,
                category: IntuneDiagnosticCategory::State,
                remediation_priority: IntuneRemediationPriority::Monitor,
                title: "Workload still in progress".to_string(),
                summary: "The current IME snapshot shows pending or in-progress work without a dominant failure pattern yet.".to_string(),
                likely_cause: Some("The device is still moving through the current IME cycle, so a stable failure signature has not formed yet.".to_string()),
                evidence: vec![
                    format!("{} event(s) are still in progress.", summary.in_progress),
                    format!("{} event(s) are still pending.", summary.pending),
                ],
                next_checks: vec![
                    "Re-check the logs after the next IME processing cycle to confirm whether the pending work resolves or fails.".to_string(),
                    "Use the timeline ordering to identify the most recent active app, download, or script phase.".to_string(),
                ],
                suggested_fixes: vec![
                    "Allow the current IME cycle to finish before changing the deployment unless a repeated stall pattern appears.".to_string(),
                ],
                focus_areas: vec![
                    "Most recent active timeline items".to_string(),
                    "Whether progress converts into success or a stable failure".to_string(),
                ],
                affected_source_files: Vec::new(),
                related_error_codes: Vec::new(),
            });
        } else if summary.total_events > 0 {
            insights.push(IntuneDiagnosticInsight {
                id: "no-dominant-blocker".to_string(),
                severity: IntuneDiagnosticSeverity::Info,
                category: IntuneDiagnosticCategory::General,
                remediation_priority: IntuneRemediationPriority::Monitor,
                title: "No dominant blocker detected".to_string(),
                summary: "The analyzed IME logs do not show a strong failure cluster in downloads, scripts, policy evaluation, or timeouts.".to_string(),
                likely_cause: Some("The current evidence set is not clustered around a single dominant failure path, so more correlation is needed before changing packaging or targeting.".to_string()),
                evidence: vec![
                    format!("{} event(s) succeeded.", summary.succeeded),
                    format!("{} total event(s) were analyzed.", summary.total_events),
                ],
                next_checks: vec![
                    "Inspect the timeline for the last non-success event if the user still reports a problem.".to_string(),
                    "Correlate IME activity with device state, portal assignment status, or Windows Event Logs if symptoms continue.".to_string(),
                ],
                suggested_fixes: vec![
                    "Do not change packaging or targeting yet; gather one failing sample with adjacent logs before tuning heuristics further.".to_string(),
                ],
                focus_areas: vec![
                    "Last non-success timeline event".to_string(),
                    "Correlation with portal assignment state and device conditions".to_string(),
                ],
                affected_source_files: Vec::new(),
                related_error_codes: Vec::new(),
            });
        }
    }

    insights
}

fn related_source_files(events: &[&IntuneEvent], limit: usize) -> Vec<String> {
    let mut files = Vec::new();

    for event in events {
        if files.contains(&event.source_file) {
            continue;
        }

        files.push(event.source_file.clone());
        if files.len() >= limit {
            break;
        }
    }

    files
}

fn related_error_codes(events: &[&IntuneEvent], limit: usize) -> Vec<String> {
    let mut labels = Vec::new();

    for event in events {
        let Some(error_code) = &event.error_code else {
            continue;
        };

        let lookup = lookup_error_code(error_code);
        let label = if lookup.found {
            format!("{} ({})", lookup.code_hex, lookup.description)
        } else {
            format!("{} ({})", error_code, lookup.description)
        };

        if labels.contains(&label) {
            continue;
        }

        labels.push(label);
        if labels.len() >= limit {
            break;
        }
    }

    labels
}

fn top_failed_download_labels(downloads: &[DownloadStat], limit: usize) -> Vec<String> {
    let mut label_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for download in downloads.iter().filter(|download| !download.success) {
        let label = if download.name.trim().is_empty() {
            format!("Affected content ID: {}", download.content_id)
        } else {
            format!("Affected content: {}", download.name)
        };

        *label_counts.entry(label).or_insert(0) += 1;
    }

    let mut sorted_counts: Vec<(String, usize)> = label_counts.into_iter().collect();
    sorted_counts.sort_by(|a, b| b.1.cmp(&a.1));

    sorted_counts
        .into_iter()
        .take(limit)
        .map(|(label, count)| {
            if count > 1 {
                format!("{} ({} times)", label, count)
            } else {
                label
            }
        })
        .collect()
}

#[derive(Clone)]
struct ErrorHint {
    code: String,
    description: String,
}

struct DownloadFailureCase {
    title: &'static str,
    summary: &'static str,
    likely_cause: &'static str,
    suggested_fixes: Vec<&'static str>,
}

fn classify_download_failure_case(
    events: &[&IntuneEvent],
    downloads: &[DownloadStat],
) -> DownloadFailureCase {
    if events.iter().any(|event| {
        event.status == IntuneStatus::Timeout
            || contains_any(
                &event.detail,
                &[
                    "stalled",
                    "not progressing",
                    "no progress",
                    "timed out",
                    "timeout",
                ],
            )
    }) {
        return DownloadFailureCase {
            title: "Content download stalled or timed out",
            summary: "The device started content acquisition, but AppWorkload shows the same payload stopping without forward progress before install-ready staging completed.",
            likely_cause: "Content transfer is starting but losing forward progress before staging completes.",
            suggested_fixes: vec![
                "Check for content-transfer stalls, Delivery Optimization blockage, or proxy/VPN interference before forcing another retry.",
                "If the same content repeatedly stalls, clear stale IME cache state on the test device and retry with fresh logs.",
                "Confirm the content source is reachable and the payload revision is still available in Intune.",
            ],
        };
    }

    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["hash validation", "hash mismatch", "hash"]))
    {
        return DownloadFailureCase {
            title: "Content hash or staging validation failed",
            summary: "The device downloaded content, but staging or hash verification indicates the package may be incomplete, stale, or mismatched.",
            likely_cause: "The downloaded payload does not match the content revision expected during staging or validation.",
            suggested_fixes: vec![
                "Re-upload or redistribute the app content in Intune so the device receives a clean package revision.",
                "Verify that the package contents and detection logic still match the deployed app version.",
                "Clear any stale cached content on the test device before retrying if hash mismatches keep repeating.",
            ],
        };
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &["staging", "content cached", "cache location"],
        )
    }) {
        return DownloadFailureCase {
            title: "Content staging failed after download",
            summary: "The workload reached caching or staging, but the local handoff into install-ready content did not complete successfully.",
            likely_cause: "The package transfer finished, but local cache handoff or disk-backed staging is failing.",
            suggested_fixes: vec![
                "Validate local disk space and permissions on the IME content cache path.",
                "Retry with a fresh content download if cached payloads appear stale or partially written.",
                "Check antivirus or endpoint protection exclusions if staging repeatedly stops after the download completes.",
            ],
        };
    }

    if repeated_retry_evidence(events).is_some() {
        return DownloadFailureCase {
            title: "Content download is retrying without completing",
            summary: "The same content is cycling through retry attempts, which points to a persistent transfer or staging blocker instead of a one-off transient miss.",
            likely_cause: "The retry loop is masking a persistent download or cache blocker that is not changing between attempts.",
            suggested_fixes: vec![
                "Review the first failed download attempt for the real cause instead of focusing only on the later retry lines.",
                "Validate network path, Delivery Optimization policy, and local cache health before forcing additional sync cycles.",
                "If retries begin after partial transfer, re-stage the content with a fresh package revision or cache reset on the test device.",
            ],
        };
    }

    if downloads
        .iter()
        .any(|download| !download.success && download.do_percentage == 0.0)
    {
        return DownloadFailureCase {
            title: "Content retrieval failed before local staging",
            summary: "The workload is failing during content acquisition rather than install, and the logs do not show healthy Delivery Optimization contribution.",
            likely_cause: "The device is failing before content ever reaches a healthy local cache or staging state.",
            suggested_fixes: vec![
                "Validate proxy, VPN, firewall, and Delivery Optimization reachability for the content source.",
                "Test the same deployment on a network path without restrictive content filtering.",
                "Confirm the app content is still available and correctly assigned in Intune.",
            ],
        };
    }

    DownloadFailureCase {
        title: "Content download failures detected",
        summary: "App content did not download cleanly, so enforcement may never reach install or detection stages.",
        likely_cause: "Content acquisition is failing early enough that install and detection phases cannot start reliably.",
        suggested_fixes: vec![
            "Confirm the app payload is still available and matches the expected content in Intune.",
            "Check device network reachability to Microsoft content endpoints and any proxy path in between.",
            "Retry with fresh logs after the next IME cycle to confirm whether this is a transient retrieval failure or a repeatable pattern.",
        ],
    }
}

fn best_error_hint(events: &[&IntuneEvent]) -> Option<ErrorHint> {
    for event in events {
        let Some(error_code) = &event.error_code else {
            continue;
        };

        let lookup = lookup_error_code(error_code);
        if lookup.found {
            return Some(ErrorHint {
                code: lookup.code_hex,
                description: lookup.description,
            });
        }

        return Some(ErrorHint {
            code: error_code.clone(),
            description: lookup.description,
        });
    }

    None
}

struct ScriptFailureCase {
    title: &'static str,
    summary: &'static str,
    likely_cause: &'static str,
}

fn classify_script_failure_case(events: &[&IntuneEvent]) -> ScriptFailureCase {
    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &[
                "execution policy",
                "digitally signed",
                "running scripts is disabled",
            ],
        )
    }) {
        return ScriptFailureCase {
            title: "Script execution policy or signing blocked execution",
            summary: "The script did not fail inside its own logic; PowerShell policy or signing requirements blocked it before it could run normally.",
            likely_cause: "PowerShell policy or signature requirements are preventing script startup.",
        };
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &["access is denied", "unauthorized", "permission denied"],
        )
    }) {
        return ScriptFailureCase {
            title: "Script execution failed due to permissions or access",
            summary: "The script path is being reached, but the execution context does not have access to one or more required resources.",
            likely_cause: "The IME execution context cannot reach or modify one of the resources the script expects.",
        };
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &[
                "cannot find path",
                "path not found",
                "file not found",
                "module",
                "not recognized",
            ],
        )
    }) {
        return ScriptFailureCase {
            title: "Script dependency or path resolution failed",
            summary: "The script is calling a path, command, or module that is not available in the IME execution context on the device.",
            likely_cause: "One or more script dependencies are missing or resolved differently under IME.",
        };
    }

    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["parsererror", "syntax error", "exception"]))
    {
        return ScriptFailureCase {
            title: "Script syntax or runtime errors detected",
            summary: "The script started but then failed because of a parser, command, or runtime error rather than a packaging or download issue.",
            likely_cause: "The script is running but failing inside its own logic or command flow.",
        };
    }

    if repeated_failure_groups(events, 2).is_empty() {
        ScriptFailureCase {
            title: "Script execution failures detected",
            summary: "Detection or remediation logic returned a non-zero outcome or never completed, which can block compliance or app enforcement.",
            likely_cause: "Detection or remediation logic is failing consistently enough to block downstream enforcement decisions.",
        }
    } else {
        ScriptFailureCase {
            title: "Recurring script or remediation failures detected",
            summary: "The same detection or remediation path is failing across multiple attempts, which points to a persistent script issue instead of a one-time transient failure.",
            likely_cause: "The same script path is re-entering failure with no device-state change between attempts.",
        }
    }
}

struct PolicyFailureCase {
    title: &'static str,
    summary: &'static str,
    likely_cause: &'static str,
    suggested_fixes: Vec<&'static str>,
}

fn classify_policy_failure_case(events: &[&IntuneEvent]) -> PolicyFailureCase {
    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["not applicable", "will not be enforced"]))
    {
        return PolicyFailureCase {
            title: "Applicability blocked enforcement",
            summary: "AppActionProcessor shows the deployment was evaluated, but the app was rejected as not applicable before enforcement could continue.",
            likely_cause: "Applicability logic is determining the target is not eligible, so enforcement never starts.",
            suggested_fixes: vec![
                "Review assignment targeting and applicability conditions to confirm the device should actually qualify.",
                "If the device should be included, correct the applicability logic instead of forcing repeated retries.",
                "If the device should not be targeted, adjust the assignment scope so the block is intentional and reviewable.",
            ],
        };
    }

    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["requirement rule", "requirements"]))
    {
        return PolicyFailureCase {
            title: "Requirement rules blocked enforcement",
            summary: "The assignment reached policy evaluation, but a requirement-rule decision prevented the app from entering the enforcement path.",
            likely_cause: "Requirement-rule evaluation is filtering the device out before the install workflow begins.",
            suggested_fixes: vec![
                "Validate every requirement-rule input on the affected device, especially OS version, architecture, and custom script results.",
                "Re-test the rule with the same device context that IME uses instead of assuming portal targeting is enough.",
                "Simplify overly broad requirement logic if it is masking the real intended eligibility check.",
            ],
        };
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &["detection rule", "detected", "already installed"],
        )
    }) {
        return PolicyFailureCase {
            title: "Detection-state evidence blocked enforcement",
            summary: "AppActionProcessor indicates the deployment was evaluated, but detection-state logic made IME treat the app as already present or otherwise not needing enforcement.",
            likely_cause: "Detection-state evidence is convincing IME that enforcement is unnecessary or already satisfied.",
            suggested_fixes: vec![
                "Verify that the detection rule is not falsely reporting success on the affected device.",
                "Compare detection-rule logic with the actual install footprint created by the package.",
                "If the app is truly installed, adjust the deployment intent instead of forcing another enforcement attempt.",
            ],
        };
    }

    PolicyFailureCase {
        title: "Policy applicability needs review",
        summary: "Assignment or applicability evaluation may be preventing enforcement even when content and scripts are available.",
        likely_cause: "The device is reaching policy evaluation, but assignment or applicability state is not lining up with the expected outcome.",
        suggested_fixes: vec![
            "Review assignment targeting, intent, and any deadlines or retry windows for the affected policy.",
            "Validate that prerequisite policies or dependent apps are not blocking the enforcement path.",
        ],
    }
}

fn install_failure_suggested_fixes(error_hint: Option<ErrorHint>) -> Vec<String> {
    let mut fixes = vec![
        "Validate the install command line, return-code mapping, and required install context for the affected app.".to_string(),
        "Check whether the detection rule is declaring failure because the installer succeeded but the post-install signal is wrong.".to_string(),
        "Review prerequisite scripts or dependencies if the installer only fails when launched by IME.".to_string(),
    ];

    if let Some(hint) = error_hint {
        let description = hint.description.to_ascii_lowercase();
        if description.contains("access is denied") {
            fixes.insert(
                0,
                "Run the installer in the same system or user context expected by Intune and fix any file, registry, or service permission gaps.".to_string(),
            );
        } else if description.contains("file not found") || description.contains("path not found") {
            fixes.insert(
                0,
                "Verify that the installer command references files that actually exist after IME staging and extraction.".to_string(),
            );
        }
    }

    fixes
}

fn script_failure_suggested_fixes(
    events: &[&IntuneEvent],
    error_hint: Option<ErrorHint>,
) -> Vec<String> {
    let detection_failures = events
        .iter()
        .any(|event| contains_any(&event.name, &["detection script", "detection"]));
    let remediation_failures = events
        .iter()
        .any(|event| contains_any(&event.name, &["remediation script", "remediation"]));

    let mut fixes = Vec::new();
    if detection_failures {
        fixes.push(
            "Correct detection-script logic first; a false negative there can block install success even when the app is already present.".to_string(),
        );
    }
    if remediation_failures {
        fixes.push(
            "If remediation failed, validate every command path and dependency under the same execution context IME uses on the device.".to_string(),
        );
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &[
                "execution policy",
                "digitally signed",
                "running scripts is disabled",
            ],
        )
    }) {
        fixes.push(
            "Adjust script signing or execution-policy handling so the script can run in the target IME context without bypass-only workarounds.".to_string(),
        );
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &[
                "cannot find path",
                "path not found",
                "file not found",
                "module",
                "not recognized",
            ],
        )
    }) {
        fixes.push(
            "Package all required script dependencies locally and validate every referenced command, module, and path under the exact IME context.".to_string(),
        );
    }

    if events
        .iter()
        .any(|event| event.status == IntuneStatus::Timeout)
        || !repeated_failure_groups(events, 2).is_empty()
    {
        fixes.push(
            "Stop repeated retry cycles until the blocking condition is fixed; recurring timeouts usually indicate the same script path is hanging on every attempt.".to_string(),
        );
    }

    if let Some(hint) = error_hint {
        let description = hint.description.to_ascii_lowercase();
        if description.contains("access is denied") {
            fixes.push(
                "Grant the script access to the filesystem, registry, certificate store, or service endpoints it needs, or move the action to a supported elevation context.".to_string(),
            );
        } else if description.contains("file not found") || description.contains("path not found") {
            fixes.push(
                "Package or create any required script dependencies locally before the script runs, and avoid relying on missing relative paths.".to_string(),
            );
        }
    }

    fixes.push(
        "Capture stdout and stderr from the failing script path and test the same logic outside IME to isolate environment assumptions.".to_string(),
    );
    fixes
}

fn top_event_detail_matches(events: &[&IntuneEvent], limit: usize) -> Vec<String> {
    let mut evidence_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let name_re = regex::Regex::new(r#"(?i)\"(?:ApplicationName|Name)\"\s*:\s*\"([^\",\}]+)"#).ok();

    for event in events {
        let snippet = event.detail.trim();
        if snippet.is_empty() {
            continue;
        }

        let extracted_name = name_re
            .as_ref()
            .and_then(|re| re.captures(snippet).map(|caps| caps[1].trim().to_string()));

        let evidence = if let Some(name) = extracted_name {
            if event.event_type == IntuneEventType::PowerShellScript
                || event.event_type == IntuneEventType::Remediation
            {
                format!("Failing script: {}", name)
            } else if event.event_type == IntuneEventType::PolicyEvaluation {
                format!("Affected policy: {}", name)
            } else {
                format!("Failing app: {}", name)
            }
        } else {
            format!("Observed detail: {}", snippet)
        };

        *evidence_counts.entry(evidence).or_insert(0) += 1;
    }

    let mut sorted_counts: Vec<(String, usize)> = evidence_counts.into_iter().collect();
    sorted_counts.sort_by(|a, b| b.1.cmp(&a.1));

    sorted_counts
        .into_iter()
        .take(limit)
        .map(|(evidence, count)| {
            if count > 1 {
                format!("{} ({} times)", evidence, count)
            } else {
                evidence
            }
        })
        .collect()
}

fn repeated_retry_evidence(events: &[&IntuneEvent]) -> Option<String> {
    let retry_count = events
        .iter()
        .filter(|event| {
            contains_any(
                &event.detail,
                &["retry", "retrying", "reattempt", "will retry"],
            )
        })
        .count();

    if retry_count > 0 {
        Some(format!(
            "Retry behavior was observed in {} failed download event(s).",
            retry_count
        ))
    } else {
        None
    }
}

fn stalled_download_evidence(events: &[&IntuneEvent]) -> Option<String> {
    let stall_count = events
        .iter()
        .filter(|event| {
            event.status == IntuneStatus::Timeout
                || contains_any(
                    &event.detail,
                    &[
                        "stalled",
                        "not progressing",
                        "no progress",
                        "timed out",
                        "timeout",
                    ],
                )
        })
        .count();

    if stall_count > 0 {
        Some(format!(
            "Stall or timeout evidence was observed in {} failed download event(s).",
            stall_count
        ))
    } else {
        None
    }
}

fn applicability_reason_evidence(events: &[&IntuneEvent]) -> Option<String> {
    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["not applicable", "will not be enforced"]))
    {
        return Some(
            "AppActionProcessor explicitly reported the app as not applicable or not enforceable for the evaluated target.".to_string(),
        );
    }

    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["requirement rule", "requirements"]))
    {
        return Some(
            "Requirement-rule evidence appears in the policy-evaluation flow for the affected app."
                .to_string(),
        );
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &["detection rule", "already installed", "detected"],
        )
    }) {
        return Some(
            "Detection-rule evidence appears to be short-circuiting enforcement for the affected app.".to_string(),
        );
    }

    None
}

fn script_scope_evidence(events: &[&IntuneEvent]) -> Vec<String> {
    let detection_count = events
        .iter()
        .filter(|event| contains_any(&event.name, &["detection script", "detection"]))
        .count();
    let remediation_count = events
        .iter()
        .filter(|event| contains_any(&event.name, &["remediation script", "remediation"]))
        .count();
    let mut evidence = Vec::new();

    if detection_count > 0 {
        evidence.push(format!(
            "Detection-script failures observed: {} event(s).",
            detection_count
        ));
    }
    if remediation_count > 0 {
        evidence.push(format!(
            "Remediation-script failures observed: {} event(s).",
            remediation_count
        ));
    }

    evidence
}

fn repeated_group_evidence(
    events: &[&IntuneEvent],
    minimum_occurrences: usize,
    prefix: &str,
) -> Vec<String> {
    repeated_failure_groups(events, minimum_occurrences)
        .into_iter()
        .map(|group| {
            format!(
                "{}: {} ({} occurrence(s)).",
                prefix, group.label, group.occurrences
            )
        })
        .collect()
}

#[derive(Debug, Clone)]
struct RepeatedFailureGroup {
    label: String,
    occurrences: usize,
}

fn repeated_failure_groups(
    events: &[&IntuneEvent],
    minimum_occurrences: usize,
) -> Vec<RepeatedFailureGroup> {
    let mut counts: HashMap<String, (String, usize)> = HashMap::new();

    for event in events {
        let source_identity = timeline::normalized_source_identity(&event.source_file);
        let key = if let Some(guid) = &event.guid {
            format!("{}|{:?}|{}", source_identity, event.event_type, guid)
        } else {
            format!(
                "{}|{:?}|{}",
                source_identity,
                event.event_type,
                normalize_group_label(&event.name)
            )
        };

        let entry = counts.entry(key).or_insert_with(|| (event.name.clone(), 0));
        entry.1 += 1;
    }

    let mut groups: Vec<RepeatedFailureGroup> = counts
        .into_values()
        .filter_map(|(label, occurrences)| {
            if occurrences >= minimum_occurrences {
                Some(RepeatedFailureGroup { label, occurrences })
            } else {
                None
            }
        })
        .collect();

    groups.sort_by(|left, right| {
        right
            .occurrences
            .cmp(&left.occurrences)
            .then_with(|| left.label.cmp(&right.label))
    });
    groups.truncate(2);
    groups
}

fn normalize_group_label(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .take(8)
        .collect::<Vec<_>>()
        .join(" ")
}

fn contains_any(value: &str, terms: &[&str]) -> bool {
    let normalized = value.to_ascii_lowercase();
    terms
        .iter()
        .any(|term| normalized.contains(&term.to_ascii_lowercase()))
}

fn top_event_labels(events: &[&IntuneEvent], limit: usize) -> Vec<String> {
    let mut label_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for event in events {
        let mut label = event.name.clone();
        if let Some(error_code) = &event.error_code {
            label.push_str(&format!(" (error {})", error_code));
        }

        let evidence = format!("Affected event: {}", label);
        *label_counts.entry(evidence).or_insert(0) += 1;
    }

    let mut sorted_counts: Vec<(String, usize)> = label_counts.into_iter().collect();
    sorted_counts.sort_by(|a, b| b.1.cmp(&a.1));

    sorted_counts
        .into_iter()
        .take(limit)
        .map(|(label, count)| {
            if count > 1 {
                format!("{} ({} times)", label, count)
            } else {
                label
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        build_diagnostics, build_diagnostics_confidence, build_repeated_failures, build_summary,
        build_timestamp_bounds, collect_input_paths, finalize_coverage, resolve_intune_input,
        CoverageAccumulator,
    };
    use crate::intune::models::{
        DownloadStat, IntuneDiagnosticSeverity, IntuneDiagnosticsConfidenceLevel,
        IntuneDiagnosticsFileCoverage, IntuneEvent, IntuneEventType, IntuneStatus, IntuneSummary,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn collect_input_paths_includes_ime_sidecar_logs_with_primary_log() {
        let test_dir = create_temp_dir("intune-aggregation");

        fs::write(test_dir.join("IntuneManagementExtension.log"), "primary")
            .expect("write primary log");
        fs::write(test_dir.join("AppWorkload.log"), "sidecar").expect("write app workload log");
        fs::write(test_dir.join("AppActionProcessor.log"), "app actions")
            .expect("write app action processor log");
        fs::write(test_dir.join("AgentExecutor.log"), "executor")
            .expect("write agent executor log");
        fs::write(test_dir.join("HealthScripts.log"), "health scripts")
            .expect("write health scripts log");
        fs::write(test_dir.join("ClientHealth.log"), "client health")
            .expect("write client health log");
        fs::write(test_dir.join("ClientCertCheck.log"), "client cert")
            .expect("write client cert check log");
        fs::write(test_dir.join("DeviceHealthMonitoring.log"), "device health")
            .expect("write device health monitoring log");
        fs::write(test_dir.join("Sensor.log"), "sensor").expect("write sensor log");
        fs::write(test_dir.join("Win32AppInventory.log"), "inventory")
            .expect("write win32 app inventory log");
        fs::write(test_dir.join("ImeUI.log"), "ui").expect("write ime ui log");
        fs::write(test_dir.join("random.log"), "other").expect("write unrelated log");

        let collected = collect_input_paths(&test_dir).expect("collect input paths");
        let file_names: Vec<String> = collected
            .iter()
            .filter_map(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .collect();

        assert_eq!(
            file_names,
            vec![
                "AgentExecutor.log".to_string(),
                "AppActionProcessor.log".to_string(),
                "AppWorkload.log".to_string(),
                "ClientCertCheck.log".to_string(),
                "ClientHealth.log".to_string(),
                "DeviceHealthMonitoring.log".to_string(),
                "HealthScripts.log".to_string(),
                "ImeUI.log".to_string(),
                "IntuneManagementExtension.log".to_string(),
                "Sensor.log".to_string(),
                "Win32AppInventory.log".to_string(),
            ]
        );

        fs::remove_dir_all(&test_dir).expect("remove temp dir");
    }

    #[test]
    fn collect_input_paths_reads_bundle_logs_from_manifest_guided_entry_points() {
        let bundle_dir = create_temp_dir("intune-bundle");
        let logs_dir = bundle_dir.join("evidence").join("logs");
        fs::create_dir_all(&logs_dir).expect("create logs dir");
        fs::write(logs_dir.join("IntuneManagementExtension.log"), "primary")
            .expect("write primary log");
        fs::write(logs_dir.join("AppWorkload.log"), "sidecar").expect("write sidecar");
        fs::write(bundle_dir.join("manifest.json"), sample_bundle_manifest())
            .expect("write manifest");

        let collected = collect_input_paths(&bundle_dir).expect("collect input paths");
        let file_names: Vec<String> = collected
            .iter()
            .filter_map(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .collect();

        assert_eq!(
            file_names,
            vec![
                "IntuneManagementExtension.log".to_string(),
                "AppWorkload.log".to_string(),
            ]
        );

        fs::remove_dir_all(&bundle_dir).expect("remove temp bundle dir");
    }

    #[test]
    fn resolve_intune_input_retains_bundle_metadata_and_allows_sparse_bundle() {
        let bundle_dir = create_temp_dir("intune-sparse-bundle");
        fs::create_dir_all(bundle_dir.join("evidence").join("logs"))
            .expect("create sparse logs dir");
        fs::write(bundle_dir.join("notes.md"), "notes").expect("write notes");
        fs::write(bundle_dir.join("manifest.json"), sample_bundle_manifest())
            .expect("write manifest");

        let resolved = resolve_intune_input(&bundle_dir).expect("resolve bundle input");

        assert!(resolved.source_paths.is_empty());
        let bundle = resolved.evidence_bundle.expect("bundle metadata");
        assert_eq!(bundle.bundle_id.as_deref(), Some("CMTRACE-123"));
        assert_eq!(bundle.device_name.as_deref(), Some("GELL-VM-5879648"));
        assert_eq!(bundle.available_primary_entry_points.len(), 1);
        assert!(bundle
            .available_primary_entry_points
            .iter()
            .any(|path| path.ends_with("evidence\\logs") || path.ends_with("evidence/logs")));

        fs::remove_dir_all(&bundle_dir).expect("remove temp sparse bundle dir");
    }

    fn sample_bundle_manifest() -> &'static str {
        r#"{
    "bundle": {
        "bundleId": "CMTRACE-123",
        "bundleLabel": "intune-endpoint-evidence",
        "createdUtc": "2026-03-12T16:00:54Z",
        "caseReference": "case-123",
        "summary": "Curated endpoint evidence bundle.",
        "device": {
            "deviceName": "GELL-VM-5879648",
            "primaryUser": "AzureAD\\AdamGell",
            "platform": "Windows",
            "osVersion": "Windows 11",
            "tenant": "CDWWorkspaceLab"
        }
    },
    "collection": {
        "collectorProfile": "intune-windows-endpoint-v1",
        "collectorVersion": "1.1.0",
        "collectedUtc": "2026-03-12T16:00:54Z",
        "results": {
            "artifactCounts": {
                "collected": 55,
                "missing": 7,
                "failed": 2,
                "skipped": 0
            }
        }
    },
    "intakeHints": {
        "manifestPath": "manifest.json",
        "notesPath": "notes.md",
        "evidenceRoot": "evidence",
        "primaryEntryPoints": [
            "evidence/logs",
            "evidence/registry",
            "evidence/event-logs",
            "evidence/exports",
            "evidence/screenshots",
            "evidence/command-output"
        ]
    },
    "artifacts": [
        {
            "relativePath": "evidence/logs/IntuneManagementExtension.log"
        },
        {
            "relativePath": "evidence/logs/AppWorkload.log"
        },
        {
            "relativePath": "evidence/command-output/mdmdiagnosticstool.txt"
        }
    ]
}"#
    }

    fn create_temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{}-{}", prefix, unique));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn build_diagnostics_reports_download_and_script_failures() {
        let events = vec![
            IntuneEvent {
                id: 1,
                event_type: IntuneEventType::PowerShellScript,
                name: "AgentExecutor Detection Script (abcd1234...)".to_string(),
                guid: None,
                status: IntuneStatus::Failed,
                start_time: Some("01-15-2024 10:00:05.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: Some("27".to_string()),
                detail: "Script failed".to_string(),
                source_file: "C:/Logs/AgentExecutor.log".to_string(),
                line_number: 12,
            },
            IntuneEvent {
                id: 2,
                event_type: IntuneEventType::PolicyEvaluation,
                name: "AppActionProcessor Applicability (abcd1234...)".to_string(),
                guid: None,
                status: IntuneStatus::Pending,
                start_time: Some("01-15-2024 10:01:05.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "Applicability pending".to_string(),
                source_file: "C:/Logs/AppActionProcessor.log".to_string(),
                line_number: 18,
            },
            IntuneEvent {
                id: 3,
                event_type: IntuneEventType::ContentDownload,
                name: "AppWorkload Staging (abcd1234...)".to_string(),
                guid: None,
                status: IntuneStatus::Failed,
                start_time: Some("01-15-2024 10:02:05.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "Hash validation failed after staging cached content".to_string(),
                source_file: "C:/Logs/AppWorkload.log".to_string(),
                line_number: 22,
            },
            IntuneEvent {
                id: 4,
                event_type: IntuneEventType::Win32App,
                name: "AppWorkload Install (abcd1234...)".to_string(),
                guid: None,
                status: IntuneStatus::Failed,
                start_time: Some("01-15-2024 10:03:05.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: Some("0x80070005".to_string()),
                detail: "Installer execution failed with error code: 0x80070005".to_string(),
                source_file: "C:/Logs/AppWorkload.log".to_string(),
                line_number: 28,
            },
        ];
        let downloads = vec![DownloadStat {
            content_id: "content-1".to_string(),
            name: "Contoso App Payload".to_string(),
            size_bytes: 10,
            speed_bps: 1.0,
            do_percentage: 0.0,
            duration_secs: 5.0,
            success: false,
            timestamp: Some("01-15-2024 10:00:00.000".to_string()),
        }];
        let summary = IntuneSummary {
            total_events: 4,
            win32_apps: 1,
            winget_apps: 0,
            scripts: 1,
            remediations: 0,
            succeeded: 0,
            failed: 3,
            in_progress: 0,
            pending: 1,
            timed_out: 0,
            total_downloads: 1,
            successful_downloads: 0,
            failed_downloads: 1,
            failed_scripts: 1,
            log_time_span: None,
        };

        let diagnostics = build_diagnostics(&events, &downloads, &summary);

        assert_eq!(diagnostics.len(), 4);
        assert_eq!(diagnostics[0].id, "download-failures");
        assert_eq!(diagnostics[0].severity, IntuneDiagnosticSeverity::Error);
        assert_eq!(
            diagnostics[0].title,
            "Content hash or staging validation failed"
        );
        assert!(diagnostics[0]
            .evidence
            .iter()
            .any(|item| item.contains("Contoso App Payload")));
        assert!(diagnostics[0]
            .suggested_fixes
            .iter()
            .any(|item| item.contains("Re-upload or redistribute")));
        assert!(diagnostics.iter().any(|item| item.id == "script-failures"));
        assert!(diagnostics
            .iter()
            .any(|item| item.id == "install-enforcement-failures"));
        assert!(diagnostics
            .iter()
            .any(|item| item.id == "policy-applicability"));

        let install = diagnostics
            .iter()
            .find(|item| item.id == "install-enforcement-failures")
            .expect("install diagnostic present");
        assert!(install
            .evidence
            .iter()
            .any(|item| item.contains("Access is denied")));
        assert!(install
            .suggested_fixes
            .iter()
            .any(|item| item.contains("same system or user context")));
    }

    #[test]
    fn build_repeated_failures_groups_same_reason_across_rotated_logs() {
        let events = vec![
            IntuneEvent {
                id: 1,
                event_type: IntuneEventType::Win32App,
                name: "Contoso App Install".to_string(),
                guid: Some("app-1".to_string()),
                status: IntuneStatus::Failed,
                start_time: Some("01-15-2024 10:00:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: Some("0x80070005".to_string()),
                detail: "Installer execution failed with error code: 0x80070005".to_string(),
                source_file: "C:/Logs/AppWorkload.log".to_string(),
                line_number: 12,
            },
            IntuneEvent {
                id: 2,
                event_type: IntuneEventType::Win32App,
                name: "Contoso App Install".to_string(),
                guid: Some("app-1".to_string()),
                status: IntuneStatus::Failed,
                start_time: Some("01-15-2024 10:05:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: Some("0x80070005".to_string()),
                detail: "Installer execution failed with error code: 0x80070005".to_string(),
                source_file: "C:/Logs/AppWorkload-1.log".to_string(),
                line_number: 18,
            },
        ];

        let repeated = build_repeated_failures(&events);
        assert_eq!(repeated.len(), 1);
        assert_eq!(repeated[0].occurrences, 2);
        assert_eq!(repeated[0].source_files.len(), 2);
        assert!(repeated[0].name.contains("Contoso App Install"));
        assert!(
            repeated[0].name.contains("Access is denied")
                || repeated[0].name.contains("0x80070005")
        );
    }

    #[test]
    fn finalize_coverage_marks_rotation_and_dominant_source() {
        let coverage = vec![
            CoverageAccumulator {
                coverage: IntuneDiagnosticsFileCoverage {
                    file_path: "C:/Logs/AppWorkload.log".to_string(),
                    event_count: 1,
                    download_count: 1,
                    timestamp_bounds: None,
                    is_rotated_segment: false,
                    rotation_group: None,
                },
                rotation_candidate: Some("appworkload".to_string()),
                is_explicit_rotated_segment: false,
            },
            CoverageAccumulator {
                coverage: IntuneDiagnosticsFileCoverage {
                    file_path: "C:/Logs/AppWorkload-1.log".to_string(),
                    event_count: 1,
                    download_count: 0,
                    timestamp_bounds: None,
                    is_rotated_segment: false,
                    rotation_group: None,
                },
                rotation_candidate: Some("appworkload".to_string()),
                is_explicit_rotated_segment: true,
            },
        ];
        let events = vec![IntuneEvent {
            id: 1,
            event_type: IntuneEventType::ContentDownload,
            name: "Download".to_string(),
            guid: None,
            status: IntuneStatus::Failed,
            start_time: Some("01-15-2024 10:00:00.000".to_string()),
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: "download failed".to_string(),
            source_file: "C:/Logs/AppWorkload.log".to_string(),
            line_number: 8,
        }];
        let downloads = vec![DownloadStat {
            content_id: "content-1".to_string(),
            name: "Payload".to_string(),
            size_bytes: 10,
            speed_bps: 1.0,
            do_percentage: 0.0,
            duration_secs: 5.0,
            success: false,
            timestamp: Some("01-15-2024 10:00:00.000".to_string()),
        }];

        let finalized = finalize_coverage(coverage, &events, &downloads);

        assert!(finalized.has_rotated_logs);
        assert_eq!(
            finalized.files[0].rotation_group.as_deref(),
            Some("appworkload")
        );
        assert!(finalized.files[1].is_rotated_segment);
        assert_eq!(
            finalized
                .dominant_source
                .as_ref()
                .map(|item| item.file_path.as_str()),
            Some("C:/Logs/AppWorkload.log")
        );
    }

    #[test]
    fn build_confidence_penalizes_missing_sidecars() {
        let summary = IntuneSummary {
            total_events: 2,
            win32_apps: 1,
            winget_apps: 0,
            scripts: 0,
            remediations: 0,
            succeeded: 0,
            failed: 1,
            in_progress: 1,
            pending: 0,
            timed_out: 0,
            total_downloads: 0,
            successful_downloads: 0,
            failed_downloads: 0,
            failed_scripts: 0,
            log_time_span: None,
        };
        let coverage = crate::intune::models::IntuneDiagnosticsCoverage {
            files: vec![IntuneDiagnosticsFileCoverage {
                file_path: "C:/Logs/IntuneManagementExtension.log".to_string(),
                event_count: 2,
                download_count: 0,
                timestamp_bounds: build_timestamp_bounds(
                    &[IntuneEvent {
                        id: 1,
                        event_type: IntuneEventType::Win32App,
                        name: "Contoso App".to_string(),
                        guid: None,
                        status: IntuneStatus::Failed,
                        start_time: Some("01-15-2024 10:00:00.000".to_string()),
                        end_time: None,
                        duration_secs: None,
                        error_code: None,
                        detail: "install failed".to_string(),
                        source_file: "C:/Logs/IntuneManagementExtension.log".to_string(),
                        line_number: 12,
                    }],
                    &[],
                ),
                is_rotated_segment: false,
                rotation_group: None,
            }],
            timestamp_bounds: None,
            has_rotated_logs: false,
            dominant_source: None,
        };
        let events = vec![
            IntuneEvent {
                id: 1,
                event_type: IntuneEventType::Win32App,
                name: "Contoso App".to_string(),
                guid: None,
                status: IntuneStatus::Failed,
                start_time: Some("01-15-2024 10:00:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "install failed".to_string(),
                source_file: "C:/Logs/IntuneManagementExtension.log".to_string(),
                line_number: 12,
            },
            IntuneEvent {
                id: 2,
                event_type: IntuneEventType::Win32App,
                name: "Contoso App".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("01-15-2024 10:05:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "install in progress".to_string(),
                source_file: "C:/Logs/IntuneManagementExtension.log".to_string(),
                line_number: 20,
            },
        ];

        let confidence = build_diagnostics_confidence(&summary, &coverage, &[], &events, &None);
        assert_eq!(confidence.level, IntuneDiagnosticsConfidenceLevel::Low);
        assert!(confidence
            .reasons
            .iter()
            .any(|reason| reason.contains("AppWorkload evidence was not available")));
    }

    #[test]
    fn build_summary_uses_content_download_events_when_stats_are_sparse() {
        let events = vec![IntuneEvent {
            id: 1,
            event_type: IntuneEventType::ContentDownload,
            name: "AppWorkload Download Stall (a1b2c3d4-e5f6-7890-abcd-ef1234567890)".to_string(),
            guid: Some("a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string()),
            status: IntuneStatus::Timeout,
            start_time: Some("01-15-2024 10:00:00.000".to_string()),
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: "Content download stalled with no progress".to_string(),
            source_file: "C:/Logs/AppWorkload.log".to_string(),
            line_number: 15,
        }];

        let summary = build_summary(&events, &[]);

        assert_eq!(summary.total_events, 1);
        assert_eq!(summary.total_downloads, 1);
        assert_eq!(summary.failed_downloads, 1);
        assert_eq!(summary.successful_downloads, 0);
    }

    #[test]
    fn build_summary_ignores_low_signal_auxiliary_successes_in_headline_counts() {
        let events = vec![
            IntuneEvent {
                id: 1,
                event_type: IntuneEventType::Other,
                name: "ClientHealth Heartbeat Sent".to_string(),
                guid: None,
                status: IntuneStatus::Success,
                start_time: Some("01-15-2024 10:00:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "The client health report was sent successfully. Done.".to_string(),
                source_file: "C:/Logs/ClientHealth.log".to_string(),
                line_number: 10,
            },
            IntuneEvent {
                id: 2,
                event_type: IntuneEventType::Other,
                name: "Win32AppInventory Delta (+2 ~0 -2)".to_string(),
                guid: None,
                status: IntuneStatus::Success,
                start_time: Some("01-15-2024 10:01:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "Computing delta inventory...Done. Add count = 2, Modify count = 0, Delete count = 2".to_string(),
                source_file: "C:/Logs/Win32AppInventory.log".to_string(),
                line_number: 18,
            },
            IntuneEvent {
                id: 3,
                event_type: IntuneEventType::Other,
                name: "ClientCertCheck Missing MDM Certificate".to_string(),
                guid: None,
                status: IntuneStatus::Failed,
                start_time: Some("01-15-2024 10:02:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "MDM certs found in LocalMachine count: 0".to_string(),
                source_file: "C:/Logs/ClientCertCheck.log".to_string(),
                line_number: 4,
            },
        ];

        let summary = build_summary(&events, &[]);

        assert_eq!(summary.total_events, 1);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn build_summary_rolls_up_download_stats_and_events_without_double_counting() {
        let events = vec![
            IntuneEvent {
                id: 1,
                event_type: IntuneEventType::ContentDownload,
                name: "AppWorkload Download (abcd1234...)".to_string(),
                guid: Some("a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string()),
                status: IntuneStatus::InProgress,
                start_time: Some("01-15-2024 10:00:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "Starting content download".to_string(),
                source_file: "C:/Logs/AppWorkload.log".to_string(),
                line_number: 8,
            },
            IntuneEvent {
                id: 2,
                event_type: IntuneEventType::ContentDownload,
                name: "AppWorkload Hash Validation (abcd1234...)".to_string(),
                guid: Some("a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string()),
                status: IntuneStatus::Failed,
                start_time: Some("01-15-2024 10:00:05.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "Hash validation failed after staging cached content".to_string(),
                source_file: "C:/Logs/AppWorkload.log".to_string(),
                line_number: 12,
            },
        ];
        let downloads = vec![DownloadStat {
            content_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            name: "Contoso App Payload".to_string(),
            size_bytes: 10,
            speed_bps: 1.0,
            do_percentage: 0.0,
            duration_secs: 5.0,
            success: false,
            timestamp: Some("01-15-2024 10:00:05.000".to_string()),
        }];

        let summary = build_summary(&events, &downloads);

        assert_eq!(summary.total_downloads, 1);
        assert_eq!(summary.failed_downloads, 1);
        assert_eq!(summary.successful_downloads, 0);
    }
}
