use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tauri::{AppHandle, Emitter, Runtime};

use crate::collector::artifacts::{self, CollectorContext};
use crate::collector::manifest;
use crate::collector::types::*;

pub const COLLECTION_PROGRESS_EVENT: &str = "collection-progress";

/// Run the full diagnostics collection pipeline.
///
/// All five collection categories (logs, registry, event logs, exports, commands)
/// run concurrently using `std::thread::scope`. Within each category, individual
/// artifacts are processed in parallel via Rayon.
pub fn run_collection<R: Runtime>(
    request_id: String,
    output_root: Option<String>,
    enabled_families: Option<Vec<String>>,
    app: AppHandle<R>,
) -> Result<CollectionResult, String> {
    let start = Instant::now();
    let mut profile = CollectionProfile::embedded();

    // Filter to only requested families when specified.
    if let Some(ref families) = enabled_families {
        profile.filter_by_families(families);
    }
    let total_items = profile.total_items();

    // Create the bundle directory.
    let bundle_id = generate_bundle_id();
    let bundle_root = resolve_bundle_root(output_root.as_deref(), &bundle_id)?;
    let evidence_root = bundle_root.join("evidence");

    // Create all subdirectories up front.
    for subdir in &["logs", "registry", "event-logs", "exports", "command-output"] {
        fs::create_dir_all(evidence_root.join(subdir)).map_err(|e| {
            format!("failed to create evidence subdirectory '{subdir}': {e}")
        })?;
    }

    // Shared state for concurrent collection.
    let completed = Arc::new(AtomicUsize::new(0));
    let results: Arc<Mutex<Vec<ArtifactResult>>> = Arc::new(Mutex::new(Vec::with_capacity(total_items)));

    // Emit initial progress.
    emit_progress(&app, &request_id, 0, total_items, "Starting collection...", None);

    // Run all 5 categories concurrently.
    let ctx_logs = CollectorContext {
        bundle_evidence_root: evidence_root.clone(),
        completed: Arc::clone(&completed),
        results: Arc::clone(&results),
    };
    let ctx_registry = CollectorContext {
        bundle_evidence_root: evidence_root.clone(),
        completed: Arc::clone(&completed),
        results: Arc::clone(&results),
    };
    let ctx_evtx = CollectorContext {
        bundle_evidence_root: evidence_root.clone(),
        completed: Arc::clone(&completed),
        results: Arc::clone(&results),
    };
    let ctx_exports = CollectorContext {
        bundle_evidence_root: evidence_root.clone(),
        completed: Arc::clone(&completed),
        results: Arc::clone(&results),
    };
    let ctx_commands = CollectorContext {
        bundle_evidence_root: evidence_root.clone(),
        completed: Arc::clone(&completed),
        results: Arc::clone(&results),
    };

    // Use a progress-reporting thread that periodically emits updates.
    let progress_completed = Arc::clone(&completed);
    let progress_app = app.clone();
    let progress_request_id = request_id.clone();
    let progress_handle = std::thread::spawn(move || {
        let mut last_reported = 0usize;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let current = progress_completed.load(Ordering::Relaxed);
            if current != last_reported {
                emit_progress(
                    &progress_app,
                    &progress_request_id,
                    current,
                    total_items,
                    "Collecting diagnostics...",
                    None,
                );
                last_reported = current;
            }
            if current >= total_items {
                break;
            }
        }
    });

    std::thread::scope(|s| {
        s.spawn(|| artifacts::collect_logs(&profile.logs, &ctx_logs));
        s.spawn(|| artifacts::export_registry_keys(&profile.registry, &ctx_registry));
        s.spawn(|| artifacts::copy_event_logs(&profile.event_logs, &ctx_evtx));
        s.spawn(|| artifacts::copy_exports(&profile.exports, &ctx_exports));
        s.spawn(|| artifacts::run_commands(&profile.commands, &ctx_commands));
    });

    // Wait for the progress thread to finish.
    let _ = progress_handle.join();

    // Aggregate results.
    let all_results = results.lock().expect("collector results mutex poisoned");
    let counts = compute_counts(&all_results);
    let gaps = compute_gaps(&all_results);
    let duration_ms = start.elapsed().as_millis() as u64;

    // Write manifest and notes.
    manifest::write_manifest(&bundle_root, &bundle_id, &profile, &all_results, &counts, duration_ms)?;
    manifest::write_notes(&bundle_root, &profile, &counts, duration_ms)?;

    // Final progress event.
    emit_progress(&app, &request_id, total_items, total_items, "Collection complete.", None);

    Ok(CollectionResult {
        bundle_path: bundle_root.to_string_lossy().into_owned(),
        bundle_id,
        artifact_counts: counts,
        duration_ms,
        gaps,
    })
}

fn generate_bundle_id() -> String {
    let now = chrono::Utc::now();
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    format!("CMTRACE-{}-{}", now.format("%Y%m%d-%H%M%S"), hostname)
}

fn resolve_bundle_root(output_root: Option<&str>, bundle_id: &str) -> Result<PathBuf, String> {
    let base = match output_root {
        Some(root) => PathBuf::from(root),
        None => {
            // Default: %ProgramData%\CmtraceOpen\Evidence\
            let program_data = std::env::var("ProgramData")
                .or_else(|_| std::env::var("PROGRAMDATA"))
                .unwrap_or_else(|_| {
                    // Fallback to temp directory on non-Windows or if ProgramData is unset.
                    std::env::temp_dir().to_string_lossy().into_owned()
                });
            PathBuf::from(program_data).join("CmtraceOpen").join("Evidence")
        }
    };

    let bundle_root = base.join(bundle_id);
    fs::create_dir_all(&bundle_root).map_err(|e| {
        format!("failed to create bundle root at '{}': {e}", bundle_root.display())
    })?;

    Ok(bundle_root)
}

fn compute_counts(results: &[ArtifactResult]) -> ArtifactCounts {
    let mut collected = 0u32;
    let mut missing = 0u32;
    let mut failed = 0u32;

    for r in results {
        match r.status {
            ArtifactStatus::Collected => collected += 1,
            ArtifactStatus::Missing => missing += 1,
            ArtifactStatus::Failed => failed += 1,
        }
    }

    ArtifactCounts {
        collected,
        missing,
        failed,
        total: results.len() as u32,
    }
}

fn compute_gaps(results: &[ArtifactResult]) -> Vec<CollectionGap> {
    results
        .iter()
        .filter(|r| !matches!(r.status, ArtifactStatus::Collected))
        .map(|r| CollectionGap {
            artifact_id: r.id.clone(),
            category: r.category.clone(),
            reason: r.error.clone().unwrap_or_else(|| format!("{:?}", r.status)),
        })
        .collect()
}

fn emit_progress<R: Runtime>(
    app: &AppHandle<R>,
    request_id: &str,
    completed_items: usize,
    total_items: usize,
    message: &str,
    current_item: Option<&str>,
) {
    let payload = CollectionProgressPayload {
        request_id: request_id.to_string(),
        message: message.to_string(),
        current_item: current_item.map(|s| s.to_string()),
        completed_items,
        total_items,
    };
    let _ = app.emit(COLLECTION_PROGRESS_EVENT, payload);
}
