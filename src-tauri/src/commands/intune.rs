use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use serde::Serialize;
#[cfg(target_os = "windows")]
use tauri::Manager;
use tauri::{async_runtime, AppHandle, Emitter};

use crate::intune::download_stats;
use crate::intune::event_tracker;
use crate::intune::evtx_parser;
use crate::intune::guid_registry::GuidRegistry;
use crate::intune::ime_parser;
use crate::intune::models::{
    AppPolicyMetadata, DownloadStat, EventLogAnalysis, EvidenceBundleMetadata,
    IntuneAnalysisResult, IntuneDiagnosticsFileCoverage, IntuneDominantSource, IntuneEvent,
    IntuneEventType, IntuneStatus, IntuneSummary, IntuneTimestampBounds,
};
use crate::intune::policy_parser;
use crate::intune::timeline;

use super::intune_bundle;
use super::intune_diagnostics;

pub(crate) const IME_LOG_PATTERNS: &[&str] = &[
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

/// Sink for the verbose GUID-enrichment trace, off unless explicitly asked for.
///
/// The detail this carries is an organisation's app inventory: every registry
/// GUID with its application name, every enriched event name, and every download
/// name and content id. It was written to `%TEMP%/cmtrace-guid-diag.log` on every
/// analysis run, without the operator asking, and never cleaned up.
///
/// Nobody chose that. It is developer instrumentation for diagnosing GUID
/// enrichment, and the summary an operator actually needs already goes to the
/// application log. Set `CMTRACE_INTUNE_GUID_DIAG` to collect the verbose trace
/// while debugging; leave it unset and nothing is written to disk.
///
/// Implements `fmt::Write` so the existing `writeln!` call sites are unchanged
/// and discard when the trace is off.
struct GuidDiagLog(Option<String>);

impl GuidDiagLog {
    fn from_env() -> Self {
        Self(
            std::env::var_os("CMTRACE_INTUNE_GUID_DIAG")
                .filter(|value| !value.is_empty())
                .map(|_| String::new()),
        )
    }

    /// The collected trace, or `None` when collection was off.
    fn contents(&self) -> Option<&str> {
        self.0.as_deref().filter(|trace| !trace.is_empty())
    }

    /// Creates the trace file, refusing to write through anything that already exists.
    ///
    /// The name carries the process id and a monotonic stamp, and the file is opened with
    /// `create_new`, so two analyses cannot overwrite each other and the call fails rather than
    /// following a symlink an unprivileged user planted at a guessable path. The system temp
    /// directory is world-writable, so a fixed name there is the classic clobber target — and this
    /// trace is opt-in precisely because its contents are sensitive.
    fn create_file(&self) -> std::io::Result<(std::path::PathBuf, fs::File)> {
        Self::create_file_at(Self::trace_path())
    }

    /// A path no other analysis will pick, in the system temp directory.
    ///
    /// The sequence number is what makes that true rather than likely. Two analyses in the same
    /// process can land inside one clock tick, and a clock can move backwards, either of which
    /// would repeat a timestamp; because the file is opened exclusively, a repeat does not
    /// overwrite anything but does lose the trace the operator asked for.
    fn trace_path() -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        Self::trace_path_for(stamp)
    }

    /// The naming, with the clock supplied.
    ///
    /// Split so the sequence's contribution can be proved: a test that only calls `trace_path`
    /// passes whether or not the sequence exists, because successive clock reads on a fast machine
    /// happen to differ anyway. Holding the stamp fixed is the only way to show the collision case
    /// is handled.
    fn trace_path_for(stamp: u128) -> std::path::PathBuf {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "cmtrace-guid-diag-{}-{stamp}-{sequence}.log",
            std::process::id()
        ))
    }

    /// Creates `path` exclusively, readable only by the user who ran the analysis.
    ///
    /// Split from [`create_file`](Self::create_file) so the exclusive-open behaviour can be
    /// exercised against a path that already exists, which is the case that matters and which a
    /// test calling the composed function cannot reach.
    fn create_file_at(path: std::path::PathBuf) -> std::io::Result<(std::path::PathBuf, fs::File)> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);

        // The default umask leaves this world-readable, and the temp directory is shared. The
        // trace holds the app inventory this whole change exists to stop leaking, so on the one
        // path that does write it, only the owner may read it. Windows inherits the directory
        // ACL, which is already per-user for the profile temp directory.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let file = options.open(&path)?;
        Ok((path, file))
    }
}

impl FmtWrite for GuidDiagLog {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        if let Some(trace) = &mut self.0 {
            trace.push_str(text);
        }
        Ok(())
    }
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
    graph_api_enabled: bool,
    app: AppHandle,
) -> Result<IntuneAnalysisResult, crate::error::AppError> {
    // Attempt Graph API enrichment before spawning the blocking task.
    // We capture the resolved map here (on the async side) so the blocking
    // task doesn't need Send-unfriendly state references.
    #[cfg(target_os = "windows")]
    let graph_resolved = if graph_api_enabled {
        let graph_state = app.state::<crate::graph_api::GraphAuthState>();
        try_graph_prefetch(&graph_state)
    } else {
        None
    };
    #[cfg(not(target_os = "windows"))]
    let graph_resolved: Option<std::collections::HashMap<String, String>> = None;
    #[cfg(not(target_os = "windows"))]
    let _ = graph_api_enabled;

    Ok(async_runtime::spawn_blocking(move || {
        analyze_intune_logs_blocking(
            path,
            request_id,
            include_live_event_logs,
            graph_resolved,
            app,
        )
    })
    .await
    .map_err(|error| {
        crate::error::AppError::Internal(format!("Intune analysis task failed: {}", error))
    })??)
}

/// Pre-fetch all Intune apps from Graph API and return a guid→name map.
/// Returns None if auth isn't active or the call fails (non-blocking fallback).
#[cfg(target_os = "windows")]
fn try_graph_prefetch(state: &crate::graph_api::GraphAuthState) -> Option<HashMap<String, String>> {
    match crate::graph_api::fetch_all_apps(state) {
        Ok(apps) => {
            let map: HashMap<String, String> =
                apps.into_iter().map(|a| (a.id, a.display_name)).collect();
            if map.is_empty() {
                None
            } else {
                log::info!("event=graph_api_prefetch apps={}", map.len());
                Some(map)
            }
        }
        Err(e) => {
            log::warn!("event=graph_api_prefetch_failed error=\"{e}\"");
            None
        }
    }
}

fn analyze_intune_logs_blocking(
    path: String,
    request_id: String,
    include_live_event_logs: bool,
    graph_resolved: Option<HashMap<String, String>>,
    app: AppHandle,
) -> Result<IntuneAnalysisResult, String> {
    let analysis_started = Instant::now();
    log::info!("event=intune_analysis_start path=\"{}\"", path);
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
    let resolved_input = intune_bundle::resolve_intune_input(input_path)?;
    let source_paths = resolved_input.source_paths;
    let evidence_bundle = resolved_input.evidence_bundle;
    log::info!(
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

    // Build global GUID->name registry from all files
    let mut guid_registry = GuidRegistry::new();
    for processed_file in &processed_files {
        guid_registry.merge(&processed_file.guid_registry);
    }
    // Enrich the GUID registry with Graph API data (highest confidence source).
    // This fills in any GUIDs that weren't resolved from log lines.
    if let Some(ref graph_map) = graph_resolved {
        let mut graph_enriched = 0u32;
        for (guid, name) in graph_map {
            let normalized = guid.to_lowercase();
            guid_registry.insert(
                normalized,
                name.clone(),
                crate::intune::guid_registry::GuidNameSource::GraphApi,
            );
            graph_enriched += 1;
        }
        log::info!(
            "event=graph_api_enrichment entries_added={} total_registry={}",
            graph_enriched,
            guid_registry.len()
        );
    }

    let guid_registry_map = guid_registry.to_serializable();

    let mut all_events = Vec::new();
    let mut all_downloads = Vec::new();
    let mut coverage = Vec::new();
    let mut all_policy_metadata: HashMap<String, AppPolicyMetadata> = HashMap::new();

    for processed_file in processed_files {
        all_events.extend(processed_file.events);
        all_downloads.extend(processed_file.downloads);
        coverage.push(processed_file.coverage);
        all_policy_metadata.extend(
            processed_file
                .policy_metadata
                .into_iter()
                .map(|(k, v)| (k.to_lowercase(), v)),
        );
    }

    // Enrich event and download names using the global GUID registry
    let mut diag_buffer = GuidDiagLog::from_env();
    let mut enriched_events = 0u32;
    let mut enriched_downloads = 0u32;
    let mut missed_events = 0u32;
    let mut missed_downloads = 0u32;
    if !guid_registry.is_empty() {
        let _ = writeln!(
            diag_buffer,
            "event=guid_registry_global entries={}",
            guid_registry.len()
        );
        for (guid, entry) in guid_registry.iter() {
            let _ = writeln!(
                diag_buffer,
                "  guid={} name=\"{}\" source={:?}",
                guid, entry.name, entry.source
            );
        }

        for event in &mut all_events {
            if let Some(guid) = &event.guid {
                if let Some(enriched) = guid_registry.enrich_event_name(&event.name, guid) {
                    let _ = writeln!(
                        diag_buffer,
                        "event=guid_enriched_event old=\"{}\" new=\"{}\" guid={}",
                        event.name, enriched, guid
                    );
                    event.name = enriched;
                    enriched_events += 1;
                } else if event.name.ends_with(')') && event.name.contains('(') {
                    let _ = writeln!(
                        diag_buffer,
                        "event=guid_enrich_miss name=\"{}\" guid={} registry_has={}",
                        event.name,
                        guid,
                        guid_registry.resolve(guid).unwrap_or("NOT_FOUND")
                    );
                    missed_events += 1;
                }
            } else if event.name.ends_with(')') && event.name.contains('(') {
                let _ = writeln!(
                    diag_buffer,
                    "event=guid_enrich_skip_no_guid name=\"{}\"",
                    event.name
                );
                missed_events += 1;
            }
        }
        for dl in &mut all_downloads {
            if let Some(resolved) = guid_registry.resolve_fallback_name(&dl.name, &dl.content_id) {
                let _ = writeln!(
                    diag_buffer,
                    "event=guid_enriched_download old=\"{}\" new=\"{}\" guid={}",
                    dl.name, resolved, dl.content_id
                );
                dl.name = resolved;
                enriched_downloads += 1;
            } else if dl.name.starts_with("Download (") || dl.name.starts_with("Download:") {
                let _ = writeln!(
                    diag_buffer,
                    "event=guid_enrich_miss_download name=\"{}\" guid={} registry_has={}",
                    dl.name,
                    dl.content_id,
                    guid_registry.resolve(&dl.content_id).unwrap_or("NOT_FOUND")
                );
                missed_downloads += 1;
            }
        }
    }

    // Attach decoded script bodies to PowerShellScript events from policy metadata
    if !all_policy_metadata.is_empty() {
        for event in &mut all_events {
            if event.event_type == IntuneEventType::PowerShellScript {
                let lookup_guid = event.parent_app_guid.as_deref().or(event.guid.as_deref());
                if let Some(guid) = lookup_guid {
                    if let Some(policy) = all_policy_metadata.get(&guid.to_lowercase()) {
                        // Find the first script-type detection rule with a body
                        if let Some(rule) = policy
                            .detection_rules
                            .iter()
                            .find(|r| r.detection_type == 3 && r.script_body.is_some())
                        {
                            event.script_body = rule.script_body.clone();
                        }
                    }
                }
            }
        }
    }

    // Append pipeline summary and write diag file (verbose detail to file only, summary to stderr)
    {
        let _ = writeln!(
            diag_buffer,
            "event=pipeline_summary event_count={} download_count={} guid_registry_entries={}",
            all_events.len(),
            all_downloads.len(),
            guid_registry.len()
        );
        for (i, dl) in all_downloads.iter().enumerate() {
            let _ = writeln!(
                diag_buffer,
                "  download[{}] content_id={} name=\"{}\" success={} size={}",
                i, dl.content_id, dl.name, dl.success, dl.size_bytes
            );
        }
        log::info!(
            "event=guid_enrichment_summary registry={} enriched_events={} missed_events={} enriched_downloads={} missed_downloads={} total_downloads={}",
            guid_registry.len(), enriched_events, missed_events, enriched_downloads, missed_downloads, all_downloads.len()
        );
        if let Some(contents) = diag_buffer.contents() {
            match diag_buffer.create_file() {
                // Reported only once the bytes are actually down. Discarding the write result
                // logged success over a partial file, which is the same "looks fine, is not"
                // shape this change is about.
                Ok((diag_path, mut file)) => match file.write_all(contents.as_bytes()) {
                    Ok(()) => {
                        log::info!("event=guid_diag_written path=\"{}\"", diag_path.display())
                    }
                    Err(error) => log::warn!(
                        "event=guid_diag_write_failed path=\"{}\" error=\"{error}\"",
                        diag_path.display()
                    ),
                },
                Err(error) => log::warn!("event=guid_diag_write_failed error=\"{error}\""),
            }
        }
    }

    // Synthesize DownloadStat records from ContentDownload events for the
    // content ids the regex-based extractor produced nothing for. Synthesis
    // supplements extraction per id rather than being all-or-nothing: a
    // single spurious extracted stat used to suppress every synthesized
    // download and collapse the downloads panel.
    let synthesized_count = merge_synthesized_downloads(&mut all_downloads, &all_events);
    if synthesized_count > 0 {
        log::info!(
            "event=download_synthesized_from_events count={}",
            synthesized_count
        );
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
        let mut diagnostics = intune_diagnostics::build_diagnostics(&[], &all_downloads, &summary);
        let diagnostics_coverage = finalize_coverage(coverage, &[], &all_downloads);
        let repeated_failures = intune_diagnostics::build_repeated_failures(&[]);

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

        let diagnostics_confidence = intune_diagnostics::build_diagnostics_confidence(
            &summary,
            &diagnostics_coverage,
            &repeated_failures,
            &[],
            &event_log_analysis,
        );

        log::info!(
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
            policy_metadata: HashMap::new(),
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
    let mut diagnostics = intune_diagnostics::build_diagnostics(&events, &all_downloads, &summary);
    let diagnostics_coverage = finalize_coverage(coverage, &events, &all_downloads);
    let repeated_failures = intune_diagnostics::build_repeated_failures(&events);

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

    let diagnostics_confidence = intune_diagnostics::build_diagnostics_confidence(
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

    log::info!(
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
        policy_metadata: all_policy_metadata,
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

// The progress event keeps all fields explicit.
#[allow(clippy::too_many_arguments)]
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
pub(crate) struct ResolvedIntuneInput {
    pub(crate) source_paths: Vec<PathBuf>,
    pub(crate) evidence_bundle: Option<EvidenceBundleMetadata>,
}

#[derive(Debug, Clone)]
pub(crate) struct CoverageAccumulator {
    pub(crate) coverage: IntuneDiagnosticsFileCoverage,
    pub(crate) rotation_candidate: Option<String>,
    pub(crate) is_explicit_rotated_segment: bool,
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
    policy_metadata: HashMap<String, AppPolicyMetadata>,
}

#[derive(Debug, Clone)]
pub(crate) struct TimestampCandidate {
    pub(crate) parsed: chrono::NaiveDateTime,
    pub(crate) raw: String,
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
) -> crate::intune::models::IntuneDiagnosticsCoverage {
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

    crate::intune::models::IntuneDiagnosticsCoverage {
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
    log::info!("event=intune_analysis_file_start file=\"{}\"", source_file);
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

    let mut file_policies: HashMap<String, AppPolicyMetadata> = HashMap::new();
    #[allow(clippy::type_complexity)]
    let (file_events, file_downloads, file_timestamp_bounds, line_count): (
        Vec<IntuneEvent>,
        Vec<DownloadStat>,
        Option<IntuneTimestampBounds>,
        usize,
    ) = if lines.is_empty() {
        (Vec::new(), Vec::new(), None, 0usize)
    } else {
        file_guid_registry.ingest_lines(&lines);
        log::debug!(
            "event=guid_registry_file file=\"{}\" entries={}",
            source_file,
            file_guid_registry.len()
        );
        for (guid, entry) in file_guid_registry.iter() {
            log::debug!(
                "  guid={} name=\"{}\" source={:?}",
                guid,
                entry.name,
                entry.source
            );
        }
        let file_events = event_tracker::extract_events(&lines, &source_file, &file_guid_registry);
        let file_downloads =
            download_stats::extract_downloads(&lines, &source_file, &file_guid_registry);
        file_policies = policy_parser::extract_policy_metadata(&lines);
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

    log::info!(
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
        policy_metadata: file_policies,
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

pub(crate) fn update_timestamp_candidate(
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
/// Merge event-synthesized download records into the extracted stats.
///
/// The regex-based extractor is the higher-fidelity source, so an extracted
/// stat always wins for its content id; synthesis fills in only the ids the
/// extractor produced nothing for. Returns how many records were added.
fn merge_synthesized_downloads(downloads: &mut Vec<DownloadStat>, events: &[IntuneEvent]) -> usize {
    let extracted_ids: std::collections::HashSet<String> = downloads
        .iter()
        .map(|download| download.content_id.clone())
        .collect();
    let mut added = 0usize;
    for stat in synthesize_downloads_from_events(events) {
        if !extracted_ids.contains(&stat.content_id) {
            downloads.push(stat);
            added += 1;
        }
    }
    if added > 0 {
        // Keep the combined list chronological. The epoch is the ordering
        // truth — the timestamp *text* is MM-DD-YYYY, which reverses across a
        // year boundary — and text plus content id are deterministic
        // tie-breakers for records without a parseable timestamp.
        downloads.sort_by(|left, right| {
            left.timestamp_epoch
                .cmp(&right.timestamp_epoch)
                .then_with(|| left.timestamp.cmp(&right.timestamp))
                .then_with(|| left.content_id.cmp(&right.content_id))
        });
    }
    added
}

fn synthesize_downloads_from_events(events: &[IntuneEvent]) -> Vec<DownloadStat> {
    let mut by_guid: HashMap<String, Vec<&IntuneEvent>> = HashMap::new();
    for event in events {
        if event.event_type != IntuneEventType::ContentDownload {
            continue;
        }
        let key = event.guid.clone().unwrap_or_else(|| event.name.clone());
        by_guid.entry(key).or_default().push(event);
    }

    let mut downloads = Vec::new();
    for (content_id, group) in &by_guid {
        // Use the last event's status as the outcome
        let last = group.iter().max_by_key(|e| e.id).unwrap();
        let success = last.status == IntuneStatus::Success;
        let name = last.name.clone();
        let timestamp = last.start_time.clone().or_else(|| last.end_time.clone());

        let timestamp_epoch = timestamp
            .as_deref()
            .and_then(timeline::parse_timestamp)
            .map(|dt| dt.and_utc().timestamp_millis());

        downloads.push(DownloadStat {
            content_id: content_id.clone(),
            name,
            size_bytes: 0,
            speed_bps: 0.0,
            do_percentage: 0.0,
            duration_secs: last.duration_secs.unwrap_or(0.0),
            success,
            timestamp,
            timestamp_epoch,
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

    let normalized_name = intune_diagnostics::normalize_group_label(&event.name);
    if !normalized_name.is_empty() {
        return Some(format!(
            "name:{}|family:{}",
            normalized_name,
            timeline::normalized_source_identity(&event.source_file)
        ));
    }

    let normalized_detail = intune_diagnostics::normalize_group_label(&event.detail);
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

    let normalized_name = intune_diagnostics::normalize_group_label(&download.name);
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

#[cfg(test)]
mod guid_diag_tests {
    use super::GuidDiagLog;
    use std::fmt::Write as _;
    use std::fs;

    /// Serializes the env-var mutation these tests share; cargo runs them on threads.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Restores the variable on drop, so a failing assertion cannot leak the mutation.
    ///
    /// A plain restore after `body()` is skipped while unwinding, which would leave the trace
    /// enabled for every test that ran afterwards and turn one real failure into a cascade of
    /// unrelated ones.
    struct EnvRestore {
        previous: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(previous) => std::env::set_var("CMTRACE_INTUNE_GUID_DIAG", previous),
                None => std::env::remove_var("CMTRACE_INTUNE_GUID_DIAG"),
            }
        }
    }

    fn with_var<T>(value: Option<&str>, body: impl FnOnce() -> T) -> T {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let restore = EnvRestore {
            previous: std::env::var_os("CMTRACE_INTUNE_GUID_DIAG"),
            _lock: lock,
        };
        match value {
            Some(value) => std::env::set_var("CMTRACE_INTUNE_GUID_DIAG", value),
            None => std::env::remove_var("CMTRACE_INTUNE_GUID_DIAG"),
        }
        let outcome = body();
        drop(restore);
        outcome
    }

    #[test]
    fn collects_nothing_when_the_trace_was_not_asked_for() {
        // The trace carries an organisation's app inventory. Unset means nothing is retained, so
        // there is nothing for the caller to write to disk.
        with_var(None, || {
            let mut log = GuidDiagLog::from_env();
            let name = "Contoso Payroll";
            let _ = writeln!(log, "guid=abc name=\"{name}\"");
            assert!(log.contents().is_none(), "no trace may be retained");
        });
    }

    #[test]
    fn an_empty_value_does_not_enable_it() {
        // CMTRACE_INTUNE_GUID_DIAG= in a shell profile is not a request for the trace.
        with_var(Some(""), || {
            let mut log = GuidDiagLog::from_env();
            let name = "Contoso Payroll";
            let _ = writeln!(log, "guid=abc name=\"{name}\"");
            assert!(log.contents().is_none());
        });
    }

    #[test]
    fn collects_the_trace_when_asked_for() {
        with_var(Some("1"), || {
            let mut log = GuidDiagLog::from_env();
            let name = "Contoso Payroll";
            let _ = writeln!(log, "guid=abc name=\"{name}\"");
            let trace = log.contents().expect("the trace was requested");
            assert!(trace.contains("Contoso Payroll"), "got {trace:?}");
        });
    }

    #[test]
    fn an_enabled_trace_that_collected_nothing_reports_no_contents() {
        // Deliberately a statement about the sink, not about the file. In the real analysis the
        // pipeline summary always writes once the trace is on, so an enabled run does produce a
        // file; claiming otherwise here would be a test passing for a reason its name denies.
        with_var(Some("1"), || {
            let log = GuidDiagLog::from_env();
            assert!(log.contents().is_none());
        });
    }

    #[cfg(unix)]
    #[test]
    fn the_trace_file_is_readable_only_by_its_owner() {
        // The temp directory is shared and the default umask leaves new files world-readable.
        // This trace holds the app inventory the whole change exists to stop leaking, so on the
        // one path that does write it, nobody else on the machine may read it.
        use std::os::unix::fs::PermissionsExt;

        with_var(Some("1"), || {
            let log = GuidDiagLog::from_env();
            let (path, _file) = log.create_file().expect("creates");
            let mode = fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "got {:o}", mode & 0o777);
            let _ = fs::remove_file(&path);
        });
    }

    #[test]
    fn every_trace_path_is_distinct_even_within_one_clock_tick() {
        // The stamp is held fixed, which is the whole point: two analyses in one process can land
        // inside a single tick, and a clock can move backwards. Either repeats a timestamp, and
        // because the file is opened exclusively a repeat does not overwrite anything but does
        // lose the trace that was asked for. Calling trace_path in a loop would pass whether or
        // not the sequence existed, because successive clock reads happen to differ.
        let paths: std::collections::HashSet<_> =
            (0..256).map(|_| GuidDiagLog::trace_path_for(42)).collect();
        assert_eq!(
            paths.len(),
            256,
            "one clock tick must still give distinct paths"
        );
    }

    #[test]
    fn the_trace_file_refuses_to_write_through_something_that_exists() {
        // The system temp directory is world-writable, so a fixed name there is the classic
        // clobber and symlink-follow target, and this trace is opt-in precisely because its
        // contents are sensitive.
        with_var(Some("1"), || {
            let log = GuidDiagLog::from_env();
            let (first_path, _first) = log.create_file().expect("creates");
            assert!(first_path.exists());

            // A second call must not reuse the name, so no analysis can truncate another's trace.
            let (second_path, _second) = log.create_file().expect("creates");
            assert_ne!(first_path, second_path);

            // The helper itself is asked to open a path that already exists. Asserting on
            // OpenOptions directly would have proved only that the standard library works, and
            // would still pass if the helper dropped create_new.
            let refused = GuidDiagLog::create_file_at(first_path.clone());
            assert!(
                refused.is_err(),
                "create_file_at must refuse a path that already exists"
            );

            let _ = fs::remove_file(&first_path);
            let _ = fs::remove_file(&second_path);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{build_summary, build_timestamp_bounds, finalize_coverage, CoverageAccumulator};
    use crate::commands::intune_bundle::collect_input_paths;
    use crate::commands::intune_bundle::resolve_intune_input;
    use crate::commands::intune_diagnostics::{
        build_diagnostics, build_diagnostics_confidence, build_repeated_failures,
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

    #[test]
    fn one_spurious_extracted_stat_does_not_suppress_synthesized_downloads() {
        // The extractor produced a single (low-quality) stat for app A. The
        // ContentDownload events cover apps A and B; synthesis must fill in
        // B instead of being suppressed entirely, and must not duplicate A.
        let event = |id: u64, guid: &str, status: IntuneStatus| IntuneEvent {
            id,
            event_type: IntuneEventType::ContentDownload,
            name: format!("Download ({guid})"),
            guid: Some(guid.to_string()),
            status,
            start_time: Some("01-15-2024 10:00:05.000".to_string()),
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: "Content download".to_string(),
            source_file: "C:/Logs/AppWorkload.log".to_string(),
            line_number: 1,
            start_time_epoch: None,
            end_time_epoch: None,
            script_body: None,
            parent_app_guid: None,
        };
        let guid_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let guid_b = "11111111-2222-3333-4444-555555555555";
        let mut downloads = vec![DownloadStat {
            content_id: guid_a.to_string(),
            name: format!("Download ({guid_a})"),
            size_bytes: 0,
            speed_bps: 0.0,
            do_percentage: 0.0,
            duration_secs: 0.0,
            success: false,
            timestamp: Some("01-15-2024 10:00:00.000".to_string()),
            timestamp_epoch: None,
        }];
        let events = vec![
            event(1, guid_a, IntuneStatus::Failed),
            event(2, guid_b, IntuneStatus::Success),
        ];

        let added = super::merge_synthesized_downloads(&mut downloads, &events);

        assert_eq!(added, 1, "only the missing content id is synthesized");
        assert_eq!(downloads.len(), 2);
        assert_eq!(
            downloads
                .iter()
                .filter(|download| download.content_id == guid_a)
                .count(),
            1,
            "the extracted stat wins for its own content id"
        );
        let synthesized = downloads
            .iter()
            .find(|download| download.content_id == guid_b)
            .expect("the uncovered content id is filled in from events");
        assert!(synthesized.success);
    }

    #[test]
    fn merge_synthesized_downloads_still_covers_the_no_extraction_case() {
        let mut downloads: Vec<DownloadStat> = Vec::new();
        let events = vec![IntuneEvent {
            id: 1,
            event_type: IntuneEventType::ContentDownload,
            name: "Download (aaaa)".to_string(),
            guid: Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string()),
            status: IntuneStatus::Failed,
            start_time: Some("01-15-2024 10:00:05.000".to_string()),
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: "Content download".to_string(),
            source_file: "C:/Logs/AppWorkload.log".to_string(),
            line_number: 1,
            start_time_epoch: None,
            end_time_epoch: None,
            script_body: None,
            parent_app_guid: None,
        }];

        let added = super::merge_synthesized_downloads(&mut downloads, &events);
        assert_eq!(added, 1);
        assert_eq!(downloads.len(), 1);
        assert!(!downloads[0].success);
    }

    #[test]
    fn merged_downloads_sort_chronologically_across_a_year_boundary() {
        // The timestamp *text* is MM-DD-YYYY, so "12-31-2023 …" sorts after
        // "01-01-2024 …" lexically and a text sort shows reverse chronology
        // across years. The merge must order by the parsed epoch.
        let mut downloads = vec![DownloadStat {
            content_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
            name: "Older download".to_string(),
            size_bytes: 0,
            speed_bps: 0.0,
            do_percentage: 0.0,
            duration_secs: 0.0,
            success: true,
            timestamp: Some("12-31-2023 23:59:59.000".to_string()),
            timestamp_epoch: Some(1_704_067_199_000),
        }];
        let events = vec![IntuneEvent {
            id: 1,
            event_type: IntuneEventType::ContentDownload,
            name: "Newer download".to_string(),
            guid: Some("11111111-2222-3333-4444-555555555555".to_string()),
            status: IntuneStatus::Success,
            start_time: Some("01-01-2024 00:00:00.000".to_string()),
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: "Content download".to_string(),
            source_file: "C:/Logs/AppWorkload.log".to_string(),
            line_number: 1,
            start_time_epoch: None,
            end_time_epoch: None,
            script_body: None,
            parent_app_guid: None,
        }];

        let added = super::merge_synthesized_downloads(&mut downloads, &events);
        assert_eq!(added, 1);
        assert_eq!(
            downloads
                .iter()
                .map(|download| download.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Older download", "Newer download"],
            "the merged list must be chronological, not text-ordered"
        );
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
            timestamp_epoch: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
            start_time_epoch: None,
            end_time_epoch: None,
            script_body: None,
            parent_app_guid: None,
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
            timestamp_epoch: None,
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
                        start_time_epoch: None,
                        end_time_epoch: None,
                        script_body: None,
                        parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
            start_time_epoch: None,
            end_time_epoch: None,
            script_body: None,
            parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
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
            timestamp_epoch: None,
        }];

        let summary = build_summary(&events, &downloads);

        assert_eq!(summary.total_downloads, 1);
        assert_eq!(summary.failed_downloads, 1);
        assert_eq!(summary.successful_downloads, 0);
    }
}
