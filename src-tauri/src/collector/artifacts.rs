use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rayon::prelude::*;

use crate::collector::types::*;
use crate::env_expand::expand_env_vars;

/// Shared context passed into each artifact collector.
pub struct CollectorContext {
    pub bundle_evidence_root: PathBuf,
    pub completed: Arc<AtomicUsize>,
    pub results: Arc<Mutex<Vec<ArtifactResult>>>,
}

#[derive(Clone, Copy)]
struct ArtifactDescriptor<'a> {
    id: &'a str,
    category: &'a str,
    family: &'a str,
    parse_hints: &'a [String],
    notes: &'a str,
}

#[derive(Default)]
struct CaptureTally {
    failed: usize,
    changed_count: usize,
    growth_count: usize,
    changed_sources: Vec<String>,
}

impl CaptureTally {
    fn record(&mut self, file_name: &std::ffi::OsStr, capture: &FileCapture) {
        if capture.inconsistent {
            self.failed += 1;
            self.changed_count += 1;
            self.growth_count += usize::from(capture.growth_observed);
            if self.changed_sources.len() < 8 {
                self.changed_sources
                    .push(file_name.to_string_lossy().chars().take(128).collect());
            }
        }
    }

    fn failure_reason(&self, copied: usize) -> String {
        let mut reason = format!("{copied} captured, {} copy or source-consistency failures; copy limited to initial opened length, captured files retained without repair", self.failed);
        if self.changed_count > 0 {
            reason.push_str(&format!(
                "; {} changed or unverified sources (first 8 filenames): {}",
                self.changed_count,
                self.changed_sources.join(", ")
            ));
        }
        if self.growth_count > 0 {
            reason.push_str(&format!("; growth beyond initial opened length observed in {} sources; copy limited to initial extent, raw prefixes retained", self.growth_count));
        }
        reason
    }
}

// ---------------------------------------------------------------------------
// Logs: glob-expand source_pattern, copy matching files
// ---------------------------------------------------------------------------

pub fn collect_logs(items: &[LogCollectionItem], ctx: &CollectorContext) {
    collect_logs_with_copy(items, ctx, secure_copy_file);
}

fn collect_logs_with_copy(
    items: &[LogCollectionItem],
    ctx: &CollectorContext,
    copy_file: impl Fn(&CollectorContext, &Path, &Path) -> Result<FileCapture, String> + Sync,
) {
    items.par_iter().for_each(|item| {
        let artifact = ArtifactDescriptor {
            id: &item.id,
            category: "logs",
            family: &item.family,
            parse_hints: &item.parse_hints,
            notes: &item.notes,
        };
        let pattern = expand_env_vars(&item.source_pattern);
        let dest_dir = ctx.bundle_evidence_root.join(&item.destination_folder);

        let entries = match glob::glob(&pattern) {
            Ok(paths) => paths,
            Err(_) => {
                push_result(
                    ctx,
                    artifact,
                    ArtifactStatus::Failed,
                    Vec::new(),
                    Some(format!("invalid glob pattern: {pattern}")),
                );
                ctx.completed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        let mut files = Vec::new();
        let mut tally = CaptureTally::default();
        let mut any_match = false;
        for entry in entries.flatten() {
            if entry.is_file() {
                any_match = true;
                let file_name = entry.file_name().unwrap_or_default();
                let dest_path = dest_dir.join(file_name);
                match copy_file(ctx, &entry, &dest_path) {
                    Ok(capture) => {
                        tally.record(file_name, &capture);
                        match collected_file(
                            ctx,
                            Some(entry.to_string_lossy().into_owned()),
                            &dest_path,
                            capture.bytes_copied,
                        ) {
                            Ok(file) => files.push(file),
                            Err(_) => tally.failed += 1,
                        }
                    }
                    Err(_) => tally.failed += 1,
                }
            }
        }

        if !any_match {
            push_result(
                ctx,
                artifact,
                ArtifactStatus::Missing,
                Vec::new(),
                Some(format!("no files matched: {pattern}")),
            );
        } else if tally.failed == 0 {
            let copied = files.len();
            push_result(
                ctx,
                artifact,
                ArtifactStatus::Collected,
                files,
                Some(format!("{copied} file(s) copied")),
            );
        } else {
            let copied = files.len();
            let reason = tally.failure_reason(copied);
            push_result(ctx, artifact, ArtifactStatus::Failed, files, Some(reason));
        }

        ctx.completed.fetch_add(1, Ordering::Relaxed);
    });
}

// ---------------------------------------------------------------------------
// Registry: run reg.exe export for each key (concurrent)
// ---------------------------------------------------------------------------

pub fn export_registry_keys(items: &[RegistryCollectionItem], ctx: &CollectorContext) {
    let reg_path = match resolve_system32_binary("reg.exe") {
        Ok(p) => p,
        Err(e) => {
            let msg = e.to_string();
            for item in items {
                push_result(
                    ctx,
                    ArtifactDescriptor {
                        id: &item.id,
                        category: "registry",
                        family: &item.family,
                        parse_hints: &item.parse_hints,
                        notes: &item.notes,
                    },
                    ArtifactStatus::Failed,
                    Vec::new(),
                    Some(msg.clone()),
                );
                ctx.completed.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    };

    let dest_dir = ctx.bundle_evidence_root.join("registry");

    items.par_iter().for_each(|item| {
        let artifact = ArtifactDescriptor {
            id: &item.id,
            category: "registry",
            family: &item.family,
            parse_hints: &item.parse_hints,
            notes: &item.notes,
        };
        let output_path = match prepare_destination(ctx, &dest_dir.join(&item.file_name)) {
            Ok(path) => path,
            Err(error) => {
                push_result(
                    ctx,
                    artifact,
                    ArtifactStatus::Failed,
                    Vec::new(),
                    Some(error),
                );
                ctx.completed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        match crate::process_util::hidden_command(&reg_path)
            .args(["export", &item.path, &output_path.to_string_lossy(), "/y"])
            .output()
        {
            Ok(output) if output.status.success() => {
                match collected_file(
                    ctx,
                    Some(item.path.clone()),
                    &output_path,
                    fs::metadata(&output_path)
                        .map(|metadata| metadata.len())
                        .unwrap_or(0),
                ) {
                    Ok(file) => {
                        push_result(ctx, artifact, ArtifactStatus::Collected, vec![file], None)
                    }
                    Err(error) => push_result(
                        ctx,
                        artifact,
                        ArtifactStatus::Failed,
                        Vec::new(),
                        Some(error),
                    ),
                }
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                // reg.exe returns exit code 1 when the key does not exist — treat as missing.
                if stderr.contains("unable to find") || stderr.contains("ERROR:") {
                    push_result(
                        ctx,
                        artifact,
                        ArtifactStatus::Missing,
                        Vec::new(),
                        Some(stderr),
                    );
                } else {
                    push_result(
                        ctx,
                        artifact,
                        ArtifactStatus::Failed,
                        Vec::new(),
                        Some(stderr),
                    );
                }
            }
            Err(e) => {
                push_result(
                    ctx,
                    artifact,
                    ArtifactStatus::Failed,
                    Vec::new(),
                    Some(format!("spawn failed: {e}")),
                );
            }
        }
        ctx.completed.fetch_add(1, Ordering::Relaxed);
    });
}

// ---------------------------------------------------------------------------
// Event logs: glob-expand source_pattern, copy .evtx files
// ---------------------------------------------------------------------------

pub fn copy_event_logs(items: &[EventLogCollectionItem], ctx: &CollectorContext) {
    copy_event_logs_with_copy(items, ctx, secure_copy_file);
}

fn copy_event_logs_with_copy(
    items: &[EventLogCollectionItem],
    ctx: &CollectorContext,
    copy_file: impl Fn(&CollectorContext, &Path, &Path) -> Result<FileCapture, String> + Sync,
) {
    items.par_iter().for_each(|item| {
        let artifact = ArtifactDescriptor {
            id: &item.id,
            category: "event-logs",
            family: &item.family,
            parse_hints: &item.parse_hints,
            notes: &item.notes,
        };
        let pattern = expand_env_vars(&item.source_pattern);
        let dest_dir = ctx.bundle_evidence_root.join(&item.destination_folder);

        let entries = match glob::glob(&pattern) {
            Ok(paths) => paths,
            Err(_) => {
                push_result(
                    ctx,
                    artifact,
                    ArtifactStatus::Failed,
                    Vec::new(),
                    Some(format!("invalid glob pattern: {pattern}")),
                );
                ctx.completed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        let mut files = Vec::new();
        let mut tally = CaptureTally::default();
        let mut any_match = false;
        for entry in entries.flatten() {
            if entry.is_file() {
                any_match = true;
                let file_name = entry.file_name().unwrap_or_default();
                let dest_path = dest_dir.join(file_name);
                match copy_file(ctx, &entry, &dest_path) {
                    Ok(capture) => {
                        tally.record(file_name, &capture);
                        match collected_file(
                            ctx,
                            Some(entry.to_string_lossy().into_owned()),
                            &dest_path,
                            capture.bytes_copied,
                        ) {
                            Ok(file) => files.push(file),
                            Err(_) => tally.failed += 1,
                        }
                    }
                    Err(_) => tally.failed += 1,
                }
            }
        }

        if !any_match {
            push_result(
                ctx,
                artifact,
                ArtifactStatus::Missing,
                Vec::new(),
                Some(format!("no files matched: {pattern}")),
            );
        } else if tally.failed == 0 {
            let copied = files.len();
            push_result(
                ctx,
                artifact,
                ArtifactStatus::Collected,
                files,
                Some(format!("{copied} file(s) copied")),
            );
        } else {
            let copied = files.len();
            push_result(
                ctx,
                artifact,
                ArtifactStatus::Failed,
                files,
                Some(tally.failure_reason(copied)),
            );
        }

        ctx.completed.fetch_add(1, Ordering::Relaxed);
    });
}

// ---------------------------------------------------------------------------
// File exports: copy specific files
// ---------------------------------------------------------------------------

pub fn copy_exports(items: &[FileExportItem], ctx: &CollectorContext) {
    copy_exports_with_copy(items, ctx, secure_copy_file);
}

fn copy_exports_with_copy(
    items: &[FileExportItem],
    ctx: &CollectorContext,
    copy_file: impl Fn(&CollectorContext, &Path, &Path) -> Result<FileCapture, String> + Sync,
) {
    items.par_iter().for_each(|item| {
        let artifact = ArtifactDescriptor {
            id: &item.id,
            category: "exports",
            family: &item.family,
            parse_hints: &item.parse_hints,
            notes: &item.notes,
        };
        let source = expand_env_vars(&item.source_path);
        let dest_dir = ctx.bundle_evidence_root.join(&item.destination_folder);

        // If source_path contains a wildcard, treat it as a glob.
        if source.contains('*') || source.contains('?') {
            let entries = match glob::glob(&source) {
                Ok(paths) => paths,
                Err(_) => {
                    push_result(
                        ctx,
                        artifact,
                        ArtifactStatus::Failed,
                        Vec::new(),
                        Some(format!("invalid glob: {source}")),
                    );
                    ctx.completed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let mut files = Vec::new();
            let mut tally = CaptureTally::default();
            let mut any_match = false;
            for entry in entries.flatten() {
                if entry.is_file() {
                    any_match = true;
                    let file_name = entry.file_name().unwrap_or_default();
                    let dest_path = dest_dir.join(file_name);
                    match copy_file(ctx, &entry, &dest_path) {
                        Ok(capture) => {
                            tally.record(file_name, &capture);
                            match collected_file(
                                ctx,
                                Some(entry.to_string_lossy().into_owned()),
                                &dest_path,
                                capture.bytes_copied,
                            ) {
                                Ok(file) => files.push(file),
                                Err(_) => tally.failed += 1,
                            }
                        }
                        Err(_) => tally.failed += 1,
                    }
                }
            }
            if !any_match {
                push_result(
                    ctx,
                    artifact,
                    ArtifactStatus::Missing,
                    Vec::new(),
                    Some(format!("no files matched: {source}")),
                );
            } else if tally.failed == 0 {
                let copied = files.len();
                push_result(
                    ctx,
                    artifact,
                    ArtifactStatus::Collected,
                    files,
                    Some(format!("{copied} file(s) copied")),
                );
            } else {
                let copied = files.len();
                push_result(
                    ctx,
                    artifact,
                    ArtifactStatus::Failed,
                    files,
                    Some(tally.failure_reason(copied)),
                );
            }
        } else {
            let source_path = Path::new(&source);
            if source_path.is_file() {
                let dest_name = item.file_name.as_deref().unwrap_or_else(|| {
                    source_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                });
                let dest_path = dest_dir.join(dest_name);
                match secure_copy_file(ctx, source_path, &dest_path) {
                    Ok(capture) => {
                        match collected_file(ctx, Some(source.clone()), &dest_path, capture.bytes_copied) {
                            Ok(file) => push_result(
                                ctx,
                                artifact,
                                if capture.inconsistent { ArtifactStatus::Failed } else { ArtifactStatus::Collected },
                                vec![file],
                                capture.inconsistent.then(|| {
                                    if capture.growth_observed {
                                        "growth beyond initial opened length observed; copy limited to initial extent, raw prefix retained without repair".to_string()
                                    } else {
                                        "source changed or consistency could not be verified; copy limited to initial opened length, captured bytes retained without repair".to_string()
                                    }
                                }),
                            ),
                            Err(error) => push_result(
                                ctx,
                                artifact,
                                ArtifactStatus::Failed,
                                Vec::new(),
                                Some(error),
                            ),
                        }
                    }
                    Err(e) => push_result(
                        ctx,
                        artifact,
                        ArtifactStatus::Failed,
                        Vec::new(),
                        Some(format!("copy failed: {e}")),
                    ),
                }
            } else {
                push_result(
                    ctx,
                    artifact,
                    ArtifactStatus::Missing,
                    Vec::new(),
                    Some(format!("file not found: {source}")),
                );
            }
        }

        ctx.completed.fetch_add(1, Ordering::Relaxed);
    });
}

// ---------------------------------------------------------------------------
// Commands: spawn processes, capture stdout (bounded parallelism)
// ---------------------------------------------------------------------------

pub fn run_commands(items: &[CommandCollectionItem], ctx: &CollectorContext) {
    let dest_dir = ctx.bundle_evidence_root.join("command-output");

    // Use a custom thread pool with limited parallelism for commands,
    // since they can be CPU/IO heavy.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());

    pool.install(|| {
        items.par_iter().for_each(|item| {
            let artifact = ArtifactDescriptor {
                id: &item.id,
                category: "command-output",
                family: &item.family,
                parse_hints: &item.parse_hints,
                notes: &item.notes,
            };
            let timeout = Duration::from_secs(item.timeout_secs.unwrap_or(120));
            let output_path = dest_dir.join(&item.file_name);

            // Special handling for mdmdiagnosticstool -zip: append output path.
            let mut args = item.arguments.clone();
            let mdm_zip_path = if item.id == "mdm-diag-tool" {
                match prepare_destination(ctx, &dest_dir.join("MDMDiagReport.zip")) {
                    Ok(zip_path) => {
                        args.push(zip_path.to_string_lossy().into_owned());
                        Some(zip_path)
                    }
                    Err(error) => {
                        push_result(
                            ctx,
                            artifact,
                            ArtifactStatus::Failed,
                            Vec::new(),
                            Some(error),
                        );
                        ctx.completed.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            } else {
                None
            };

            let spawn_result = crate::process_util::hidden_command(&item.command)
                .args(&args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn();

            match spawn_result {
                Ok(child) => {
                    match child.wait_with_output() {
                        Ok(output) => {
                            // Note: std::process doesn't have native timeout. For a true
                            // timeout we'd need tokio or a wait loop. wait_with_output is
                            // sufficient for most diagnostic commands which complete quickly.
                            let _ = timeout;

                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            let combined = if stderr.is_empty() {
                                stdout.into_owned()
                            } else {
                                format!("{stdout}\n--- STDERR ---\n{stderr}")
                            };

                            match secure_write_file(ctx, &output_path, combined.as_bytes()) {
                                Ok(bytes_written) => {
                                    let origin =
                                        Some(format!("{} {}", item.command, args.join(" ")));
                                    let mut files = Vec::new();
                                    let mut record_errors = Vec::new();
                                    match collected_file(
                                        ctx,
                                        origin.clone(),
                                        &output_path,
                                        bytes_written,
                                    ) {
                                        Ok(file) => files.push(file),
                                        Err(error) => record_errors.push(error),
                                    }
                                    if let Some(zip_path) = mdm_zip_path.as_ref() {
                                        if zip_path.is_file() {
                                            match collected_file(
                                                ctx,
                                                origin,
                                                zip_path,
                                                fs::metadata(zip_path)
                                                    .map(|metadata| metadata.len())
                                                    .unwrap_or(0),
                                            ) {
                                                Ok(file) => files.push(file),
                                                Err(error) => record_errors.push(error),
                                            }
                                        }
                                    }

                                    if !output.status.success() {
                                        record_errors.push(command_failure_detail(
                                            output.status.code(),
                                            &stderr,
                                        ));
                                    }

                                    if record_errors.is_empty() {
                                        push_result(
                                            ctx,
                                            artifact,
                                            ArtifactStatus::Collected,
                                            files,
                                            None,
                                        );
                                    } else {
                                        push_result(
                                            ctx,
                                            artifact,
                                            ArtifactStatus::Failed,
                                            files,
                                            Some(record_errors.join("; ")),
                                        );
                                    }
                                }
                                Err(e) => push_result(
                                    ctx,
                                    artifact,
                                    ArtifactStatus::Failed,
                                    Vec::new(),
                                    Some(format!("write failed: {e}")),
                                ),
                            }
                        }
                        Err(e) => {
                            push_result(
                                ctx,
                                artifact,
                                ArtifactStatus::Failed,
                                Vec::new(),
                                Some(format!("wait failed: {e}")),
                            );
                        }
                    }
                }
                Err(e) => {
                    // Command not found is common for optional tools — record as missing.
                    if e.kind() == std::io::ErrorKind::NotFound {
                        push_result(
                            ctx,
                            artifact,
                            ArtifactStatus::Missing,
                            Vec::new(),
                            Some(format!("command not found: {}", item.command)),
                        );
                    } else {
                        push_result(
                            ctx,
                            artifact,
                            ArtifactStatus::Failed,
                            Vec::new(),
                            Some(format!("spawn failed: {e}")),
                        );
                    }
                }
            }

            ctx.completed.fetch_add(1, Ordering::Relaxed);
        });
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn push_result(
    ctx: &CollectorContext,
    artifact: ArtifactDescriptor<'_>,
    status: ArtifactStatus,
    files: Vec<CollectedArtifactFile>,
    error: Option<String>,
) {
    if let Ok(mut results) = ctx.results.lock() {
        results.push(ArtifactResult {
            id: artifact.id.to_string(),
            category: artifact.category.to_string(),
            family: artifact.family.to_string(),
            parse_hints: artifact.parse_hints.to_vec(),
            notes: Some(artifact.notes.to_string()),
            status,
            files,
            error,
        });
    }
}

fn secure_copy_file(
    ctx: &CollectorContext,
    source_path: &Path,
    destination_path: &Path,
) -> Result<FileCapture, String> {
    secure_copy_file_with_observer(ctx, source_path, destination_path, |_| {})
}

fn secure_copy_file_with_observer(
    ctx: &CollectorContext,
    source_path: &Path,
    destination_path: &Path,
    after_read: impl FnMut(usize),
) -> Result<FileCapture, String> {
    let destination = prepare_destination(ctx, destination_path)?;
    let mut source =
        File::open(source_path).map_err(|error| format!("failed to open source file: {error}"))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| format!("failed to create exclusive destination: {error}"))?;
    match copy_source_with_observer(&mut source, source_path, &mut output, after_read) {
        Ok(capture) => Ok(capture),
        Err(error) => {
            drop(output);
            let _ = fs::remove_file(&destination);
            Err(format!("failed to copy source file: {error}"))
        }
    }
}

const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug)]
struct FileCapture {
    bytes_copied: u64,
    inconsistent: bool,
    growth_observed: bool,
}

// Copy at most the opening length, retaining that raw extent without record
// repair. A separate one-byte probe observes growth beyond it; probe bytes are
// not captured. Observable growth makes the retained prefix a failed capture.
// This is a live capture, not an atomic snapshot. The observer is a no-op in
// production and lets tests mutate a synthetic source at exact read boundaries.
// Checks detect observable changes; a same-size rewrite with restored mtime,
// or changes outside the observation interval can escape. Missing identity or
// mtime is unverified and reported.
fn copy_source_with_observer<W: Write>(
    source: &mut File,
    source_path: &Path,
    output: &mut W,
    mut after_read: impl FnMut(usize),
) -> std::io::Result<FileCapture> {
    let before = source.metadata()?;
    let identity = crate::fs_identity::file_identity(source, &before);
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut bytes_copied = 0_u64;
    while bytes_copied < before.len() {
        let limit = (before.len() - bytes_copied).min(buffer.len() as u64) as usize;
        let read = match source.read(&mut buffer[..limit]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        after_read(read);
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        bytes_copied += read as u64;
    }
    // Probe only after the initial extent was copied. If it ended short, the
    // count/metadata checks already report an inconsistent retained capture.
    let growth_observed = if bytes_copied == before.len() {
        let mut probe = [0_u8; 1];
        let read = loop {
            match source.read(&mut probe) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        after_read(read);
        read != 0
    } else {
        false
    };
    // Growth can also become visible after a zero-byte probe. Retain that
    // explicit observation in diagnostics rather than only a generic change.
    let after = source.metadata();
    let growth_observed = growth_observed
        || after
            .as_ref()
            .is_ok_and(|metadata| metadata.len() > before.len());
    // A failed post-copy inspection is uncertainty, not a complete capture.
    let changed = after.map_or(true, |after| {
        before.len() != after.len()
            || match (before.modified(), after.modified()) {
                (Ok(before_time), Ok(after_time)) => before_time != after_time,
                _ => true,
            }
            || bytes_copied != before.len()
    });
    let replaced = File::open(source_path).map_or(true, |current| {
        current.metadata().map_or(true, |metadata| {
            !capture_identities_match(
                identity,
                crate::fs_identity::file_identity(&current, &metadata),
            )
        })
    });
    Ok(FileCapture {
        bytes_copied,
        inconsistent: growth_observed || changed || replaced,
        growth_observed,
    })
}

fn capture_identities_match(
    before: Option<crate::fs_identity::FileIdentity>,
    after: Option<crate::fs_identity::FileIdentity>,
) -> bool {
    matches!((before, after), (Some(before), Some(after)) if before == after)
}

fn secure_write_file(
    ctx: &CollectorContext,
    destination_path: &Path,
    content: &[u8],
) -> Result<u64, String> {
    let destination = prepare_destination(ctx, destination_path)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| format!("failed to create exclusive destination: {error}"))?;
    if let Err(error) = output.write_all(content) {
        drop(output);
        let _ = fs::remove_file(&destination);
        return Err(format!("failed to write collected output: {error}"));
    }
    Ok(content.len() as u64)
}

fn prepare_destination(ctx: &CollectorContext, destination_path: &Path) -> Result<PathBuf, String> {
    let root_metadata = match fs::symlink_metadata(&ctx.bundle_evidence_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match fs::create_dir(&ctx.bundle_evidence_root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "failed to create evidence root exclusively: {error}"
                    ));
                }
            }
            fs::symlink_metadata(&ctx.bundle_evidence_root)
                .map_err(|error| format!("failed to inspect created evidence root: {error}"))?
        }
        Err(error) => return Err(format!("failed to inspect evidence root: {error}")),
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err("evidence root is not an exclusive physical directory".to_string());
    }

    let relative_path = destination_path
        .strip_prefix(&ctx.bundle_evidence_root)
        .map_err(|_| "destination is outside the evidence root".to_string())?;
    if relative_path.as_os_str().is_empty()
        || relative_path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "destination contains unsafe path components: {}",
            destination_path.display()
        ));
    }

    let canonical_root = ctx
        .bundle_evidence_root
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize evidence root: {error}"))?;
    let parent = relative_path
        .parent()
        .ok_or_else(|| "destination has no parent directory".to_string())?;
    let file_name = relative_path
        .file_name()
        .ok_or_else(|| "destination has no file name".to_string())?;
    let mut canonical_parent = canonical_root.clone();

    for component in parent.components() {
        let std::path::Component::Normal(segment) = component else {
            return Err("destination parent contains unsafe path components".to_string());
        };
        let candidate = canonical_parent.join(segment);
        let metadata = match fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&candidate) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(format!(
                            "failed to create destination directory exclusively: {error}"
                        ));
                    }
                }
                fs::symlink_metadata(&candidate).map_err(|error| {
                    format!("failed to inspect created destination parent: {error}")
                })?
            }
            Err(error) => {
                return Err(format!("failed to inspect destination parent: {error}"));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "destination parent is a symlink, reparse point, or non-directory: {}",
                candidate.display()
            ));
        }

        canonical_parent = candidate
            .canonicalize()
            .map_err(|error| format!("failed to canonicalize destination parent: {error}"))?;
        if !canonical_parent.starts_with(&canonical_root) {
            return Err(format!(
                "destination parent escaped evidence root: {}",
                canonical_parent.display()
            ));
        }
    }

    let destination = canonical_parent.join(file_name);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "destination is an existing symlink or reparse point: {}",
                    destination.display()
                ));
            }
            let canonical_destination = destination
                .canonicalize()
                .map_err(|error| format!("failed to canonicalize destination: {error}"))?;
            if !canonical_destination.starts_with(&canonical_root) {
                return Err(format!(
                    "destination escaped evidence root: {}",
                    canonical_destination.display()
                ));
            }
            return Err(format!(
                "destination already exists in exclusive bundle: {}",
                destination.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("failed to inspect destination: {error}")),
    }

    Ok(destination)
}

fn command_failure_detail(exit_code: Option<i32>, stderr: &str) -> String {
    let exit_description = exit_code
        .map(|code| format!("exit code {code}"))
        .unwrap_or_else(|| "no exit code".to_string());
    let stderr = sanitize_command_stderr(stderr);
    if stderr.is_empty() {
        format!("command failed with {exit_description}")
    } else {
        format!("command failed with {exit_description}: {stderr}")
    }
}

fn sanitize_command_stderr(stderr: &str) -> String {
    let collapsed = stderr.split_whitespace().collect::<Vec<_>>().join(" ");
    let url_query = regex::Regex::new(r"(?i)(https?://[^\s?]+)\?[^\s]+")
        .expect("valid URL query redaction regex");
    let secret_pair = regex::Regex::new(
        r"(?i)\b(access_token|token|sig|secret|password|client_secret)=([^&\s]+)",
    )
    .expect("valid secret-pair redaction regex");
    let bearer = regex::Regex::new(r"(?i)(authorization:\s*bearer\s+|bearer\s+)[^\s]+")
        .expect("valid bearer redaction regex");
    let redacted = url_query.replace_all(&collapsed, "$1?[redacted]");
    let redacted = secret_pair.replace_all(&redacted, "$1=[redacted]");
    let redacted = bearer.replace_all(&redacted, "$1[redacted]");
    let mut characters = redacted.chars();
    let mut bounded: String = characters.by_ref().take(512).collect();
    if characters.next().is_some() {
        bounded.push('…');
    }
    bounded
}

fn collected_file(
    ctx: &CollectorContext,
    origin_path: Option<String>,
    destination_path: &Path,
    bytes_copied: u64,
) -> Result<CollectedArtifactFile, String> {
    let evidence_root = ctx
        .bundle_evidence_root
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize evidence root: {error}"))?;
    let bundle_root = evidence_root
        .parent()
        .ok_or_else(|| "evidence root has no bundle parent".to_string())?;
    let destination = destination_path
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize collected file: {error}"))?;
    if !destination.starts_with(&evidence_root) {
        return Err(format!(
            "collected file escaped evidence root: {}",
            destination.display()
        ));
    }
    let relative_path = destination
        .strip_prefix(bundle_root)
        .map_err(|error| format!("failed to make collected file bundle-relative: {error}"))?
        .to_string_lossy()
        .replace('\\', "/");

    Ok(CollectedArtifactFile {
        relative_path,
        origin_path,
        bytes_copied,
    })
}

/// Resolve a binary from System32. Mirrors the pattern in `dsregcmd.rs`.
fn resolve_system32_binary(file_name: &str) -> Result<PathBuf, crate::error::AppError> {
    let Some(windir) = std::env::var_os("WINDIR") else {
        return Err(crate::error::AppError::PlatformUnsupported(
            "WINDIR is not set; could not resolve the Windows system path.".to_string(),
        ));
    };
    let path = PathBuf::from(windir).join("System32").join(file_name);
    if !path.is_file() {
        return Err(crate::error::AppError::Internal(format!(
            "Expected system binary not found at '{}'.",
            path.display()
        )));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::{collect_logs, run_commands, CollectorContext};
    use crate::collector::types::{ArtifactStatus, CommandCollectionItem, LogCollectionItem};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn event_and_wildcard_captures_retain_growth_details_and_raw_prefixes() {
        for event_logs in [true, false] {
            let root = create_temp_dir("collector-shared-tally");
            let evidence = root.join("evidence");
            let source = root.join("growing.evtx");
            fs::write(&source, b"raw prefix").unwrap();
            fs::write(root.join("failed.evtx"), b"unreadable fixture").unwrap();
            let results = Arc::new(Mutex::new(Vec::new()));
            let context = collector_context(evidence.clone(), Arc::clone(&results));
            let pattern = root.join("*.evtx").to_string_lossy().into_owned();
            let copy = |ctx: &CollectorContext, path: &Path, destination: &Path| {
                if path.file_name().unwrap() == "failed.evtx" {
                    return Err("synthetic copy failure".to_owned());
                }
                let mut appended = false;
                super::secure_copy_file_with_observer(ctx, path, destination, |read| {
                    if read > 0 && !appended {
                        fs::write(path, b"raw prefix plus later bytes").unwrap();
                        appended = true;
                    }
                })
            };
            if event_logs {
                super::copy_event_logs_with_copy(
                    &[super::EventLogCollectionItem {
                        id: "event".into(),
                        family: "synthetic".into(),
                        parse_hints: vec![],
                        source_pattern: pattern,
                        destination_folder: "captured".into(),
                        notes: String::new(),
                    }],
                    &context,
                    copy,
                );
            } else {
                super::copy_exports_with_copy(
                    &[super::FileExportItem {
                        id: "export".into(),
                        family: "synthetic".into(),
                        parse_hints: vec![],
                        source_path: pattern,
                        destination_folder: "captured".into(),
                        file_name: None,
                        notes: String::new(),
                    }],
                    &context,
                    copy,
                );
            }
            let results = results.lock().unwrap();
            assert!(matches!(results[0].status, ArtifactStatus::Failed));
            assert_eq!(results[0].files.len(), 1);
            assert_eq!(results[0].files[0].bytes_copied, 10);
            let reason = results[0].error.as_deref().unwrap();
            assert!(reason.contains("1 captured, 2 copy or source-consistency failures"));
            assert!(reason.contains("1 changed or unverified sources"));
            assert!(reason.contains("growing.evtx"));
            assert!(reason.contains("growth beyond initial opened length observed in 1 sources"));
            assert_eq!(
                fs::read(evidence.join("captured/growing.evtx")).unwrap(),
                b"raw prefix"
            );
            assert_eq!(fs::read(&source).unwrap(), b"raw prefix plus later bytes");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn capture_tally_bounds_detail_without_losing_failure_or_growth_counts() {
        let mut tally = super::CaptureTally::default();
        for index in 0..12 {
            let name = format!("{index}-{}", "界".repeat(200));
            tally.record(
                std::ffi::OsStr::new(&name),
                &super::FileCapture {
                    bytes_copied: 3,
                    inconsistent: true,
                    growth_observed: index % 2 == 0,
                },
            );
        }
        assert_eq!(tally.failed, 12);
        assert_eq!(tally.changed_count, 12);
        assert_eq!(tally.growth_count, 6);
        assert_eq!(tally.changed_sources.len(), 8);
        assert!(tally
            .changed_sources
            .iter()
            .all(|name| name.chars().count() == 128));
        assert!(tally.failure_reason(12).contains("observed in 6 sources"));
    }

    #[test]
    fn log_collection_preserves_partial_records_encoding_and_newlines() {
        // Checked-in PSADT capture anchors the frame shape. Append a prefix
        // from its first record to model a copy ending during a source write.
        let exemplar = include_str!("../../tests/fixtures/ccm/psadt_install.log");
        let first_record = exemplar
            .trim_start_matches('\u{feff}')
            .lines()
            .next()
            .unwrap();
        let partial = &first_record[..first_record.find("]LOG]!><").unwrap()];
        let text = format!("{exemplar}\r\n{partial}");
        let mut utf16 = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        for bytes in [text.as_bytes().to_vec(), utf16] {
            let root = create_temp_dir("collector-raw-records");
            let evidence_root = root.join("bundle").join("evidence");
            fs::create_dir_all(&evidence_root).expect("evidence root");
            let source = root.join("AgentExecutor.log");
            fs::write(&source, &bytes).expect("synthetic source");
            let results = Arc::new(Mutex::new(Vec::new()));
            let context = collector_context(evidence_root.clone(), Arc::clone(&results));
            collect_logs(
                &[LogCollectionItem {
                    id: "synthetic-ime".into(),
                    family: "intune-ime".into(),
                    parse_hints: vec!["cmtrace".into()],
                    source_pattern: source.to_string_lossy().into_owned(),
                    destination_folder: "logs".into(),
                    notes: "byte preservation".into(),
                }],
                &context,
            );
            assert_eq!(fs::read(&source).unwrap(), bytes, "source unchanged");
            assert_eq!(
                fs::read(evidence_root.join("logs/AgentExecutor.log")).unwrap(),
                bytes
            );
            let results = results.lock().unwrap();
            assert!(matches!(results[0].status, ArtifactStatus::Collected));
            assert_eq!(results[0].files[0].bytes_copied, bytes.len() as u64);
            drop(results);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn unavailable_identity_is_unverified_not_stable() {
        let root = create_temp_dir("collector-unknown-identity");
        let path = root.join("source.log");
        fs::write(&path, b"source").unwrap();
        let file = fs::File::open(&path).unwrap();
        let identity = crate::fs_identity::file_identity(&file, &file.metadata().unwrap());
        assert!(identity.is_some());
        assert!(super::capture_identities_match(identity, identity));
        assert!(!super::capture_identities_match(None, None));
        assert!(!super::capture_identities_match(identity, None));
        assert!(!super::capture_identities_match(None, identity));
        drop(file);
        fs::remove_dir_all(root).unwrap();
    }

    // Framing and metadata grammar anchored in the checked-in IME fixture:
    // crates/cmtraceopen-parser/tests/fixtures/intune/windows/scripts/multiline-ccm-record/AgentExecutor.log.
    // Payloads and byte lengths below are synthetic boundary stressors; they
    // contain no identifiers or text copied from the user's private capture.
    #[test]
    fn changed_log_capture_remains_in_failed_artifact_manifest() {
        let root = create_temp_dir("collector-retained-consistency");
        let bundle = root.join("bundle");
        fs::create_dir(&bundle).unwrap();
        let source = root.join("source.log");
        fs::write(&source, b"<![LOG[partial").unwrap();
        let results = Arc::new(Mutex::new(Vec::new()));
        let context = collector_context(bundle.join("evidence"), Arc::clone(&results));
        super::collect_logs_with_copy(
            &[LogCollectionItem {
                id: "synthetic-log".to_string(),
                family: "intune-ime".to_string(),
                parse_hints: vec!["cmtrace".to_string()],
                source_pattern: source.to_string_lossy().to_string(),
                destination_folder: "logs".to_string(),
                notes: "synthetic source-consistency regression".to_string(),
            }],
            &context,
            |ctx, path, destination| {
                let mut changed = false;
                super::secure_copy_file_with_observer(ctx, path, destination, |read| {
                    if read > 0 && !changed {
                        fs::write(path, b"<![LOG[partial]LOG]!><time=\"01:00:00\">").unwrap();
                        changed = true;
                    }
                })
            },
        );
        let captured = bundle.join("evidence/logs/source.log");
        assert_eq!(fs::read(&captured).unwrap(), b"<![LOG[partial");
        let results = results.lock().unwrap();
        assert!(matches!(results[0].status, ArtifactStatus::Failed));
        assert_eq!(results[0].files.len(), 1);
        assert_eq!(results[0].files[0].bytes_copied, 14);
        let counts = crate::collector::types::ArtifactCounts {
            collected: 0,
            missing: 0,
            failed: 1,
            total: 1,
        };
        crate::collector::manifest::write_manifest(
            &bundle,
            "synthetic",
            &crate::collector::types::CollectionProfile::embedded(),
            &results,
            &counts,
            1,
        )
        .unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(bundle.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["artifacts"][0]["relativePath"],
            "evidence/logs/source.log"
        );
        assert_eq!(manifest["artifacts"][0]["status"], "failed");
        assert_eq!(manifest["artifacts"][0]["bytesCopied"], 14);
        assert!(manifest["collection"]["results"]["gaps"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("source-consistency"));
        assert!(manifest["collection"]["results"]["gaps"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("source.log"));
        let reason = manifest["collection"]["results"]["gaps"][0]["reason"]
            .as_str()
            .unwrap();
        assert!(reason.contains("growth beyond initial opened length"));
        assert!(reason.contains("copy limited to initial extent"));
        // Failed consistency must remain inspectable as raw evidence in Log Explorer.
        let details = crate::commands::bundle_ops::inspect_evidence_bundle(
            bundle.to_string_lossy().into_owned(),
        )
        .unwrap();
        assert_eq!(details.artifacts.len(), 1);
        assert_eq!(details.artifacts[0].status, "failed");
        assert!(details.artifacts[0].exists_on_disk);
        assert_eq!(
            details.artifacts[0].intake.kind,
            crate::commands::bundle_ops::EvidenceArtifactIntakeKind::Log
        );
        let listing =
            crate::commands::file_ops::list_log_folder(bundle.to_string_lossy().into_owned())
                .unwrap();
        assert!(listing
            .entries
            .iter()
            .any(|entry| entry.name == "source.log"));
        drop(results);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copy_bounds_growing_source_to_initial_extent_without_repair() {
        let root = create_temp_dir("collector-growing-source");
        let path = root.join("source.log");
        let initial = b"<![LOG[partial";
        fs::write(&path, initial).unwrap();
        let mut source = fs::File::open(&path).unwrap();
        let mut captured = Vec::new();
        let mut appends = 0;
        let result = super::copy_source_with_observer(&mut source, &path, &mut captured, |read| {
            if read > 0 && appends < 4 {
                let mut writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
                std::io::Write::write_all(&mut writer, b"synthetic growth").unwrap();
                appends += 1;
            }
        })
        .unwrap();
        assert_eq!(captured, initial);
        assert_eq!(result.bytes_copied, initial.len() as u64);
        assert!(result.inconsistent);
        assert!(result.growth_observed);
        assert!(fs::read(&path).unwrap().starts_with(initial));
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copy_reports_append_after_observed_eof_and_retains_partial_bytes() {
        let root = create_temp_dir("collector-append-consistency");
        let path = root.join("source.log");
        fs::write(&path, b"<![LOG[partial").unwrap();
        let mut source = fs::File::open(&path).unwrap();
        let mut captured = Vec::new();
        let result = super::copy_source_with_observer(&mut source, &path, &mut captured, |read| {
            if read == 0 {
                fs::write(&path, b"<![LOG[partial]LOG]!><time=\"01:00:00\">").unwrap();
            }
        })
        .unwrap();
        assert_eq!(captured, b"<![LOG[partial");
        assert!(result.inconsistent);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copy_reports_in_place_truncation_and_preserves_hybrid_bytes() {
        let root = create_temp_dir("collector-truncate-consistency");
        let path = root.join("source.log");
        let initial = vec![b'a'; super::COPY_BUFFER_BYTES * 3];
        fs::write(&path, &initial).unwrap();
        let mut replacement = vec![b'b'; super::COPY_BUFFER_BYTES];
        replacement.extend_from_slice(b"component=\"AgentExecutor\" context=\"\" type=\"1\">\n");
        let mut source = fs::File::open(&path).unwrap();
        let mut captured = Vec::new();
        let mut changed = false;
        let result = super::copy_source_with_observer(&mut source, &path, &mut captured, |read| {
            if read > 0 && !changed {
                fs::write(&path, &replacement).unwrap();
                changed = true;
            }
        })
        .unwrap();
        let mut expected = vec![b'a'; super::COPY_BUFFER_BYTES];
        expected.extend_from_slice(&replacement[super::COPY_BUFFER_BYTES..]);
        assert_eq!(captured, expected);
        assert!(result.inconsistent);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copy_reports_rotated_path_but_retains_original_open_file() {
        let root = create_temp_dir("collector-rotation-consistency");
        let path = root.join("source.log");
        let initial = vec![b'a'; super::COPY_BUFFER_BYTES * 2];
        fs::write(&path, &initial).unwrap();
        let mut source = fs::File::open(&path).unwrap();
        let mut captured = Vec::new();
        let mut changed = false;
        let result = super::copy_source_with_observer(&mut source, &path, &mut captured, |read| {
            if read > 0 && !changed {
                fs::rename(&path, root.join("rotated.log")).unwrap();
                fs::write(&path, &initial).unwrap();
                changed = true;
            }
        })
        .unwrap();
        assert_eq!(captured, initial);
        assert!(result.inconsistent);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copy_detects_same_size_rewrite_with_changed_mtime() {
        assert_same_size_rewrite(false);
    }

    #[test]
    fn same_size_rewrite_with_restored_mtime_is_an_explicit_detection_limit() {
        assert_same_size_rewrite(true);
    }

    fn assert_same_size_rewrite(restore_mtime: bool) {
        let root = create_temp_dir("collector-same-size-consistency");
        let path = root.join("source.log");
        let opening = b"<![LOG[";
        let closing = b"]LOG]!><time=\"01:00:00\" date=\"10-11-2026\" component=\"AgentExecutor\" context=\"\" type=\"1\" thread=\"1\" file=\"\">\n";
        let mut initial = opening.to_vec();
        initial.resize(super::COPY_BUFFER_BYTES - closing.len(), b'a');
        initial.extend_from_slice(closing);
        initial.extend_from_slice(opening);
        initial.resize(super::COPY_BUFFER_BYTES * 2 - closing.len(), b'a');
        initial.extend_from_slice(closing);
        let mut replacement = opening.to_vec();
        replacement.resize(super::COPY_BUFFER_BYTES, b'b');
        replacement.extend_from_slice(closing);
        replacement.extend_from_slice(opening);
        replacement.resize(initial.len() - closing.len(), b'b');
        replacement.extend_from_slice(closing);
        assert_eq!(initial.len(), replacement.len());
        use cmtraceopen_parser::models::log_entry::LogFormat;
        use cmtraceopen_parser::parser::ccm::logical::parse_ime_entries;
        for generation in [&initial, &replacement] {
            let (records, errors) =
                parse_ime_entries(std::str::from_utf8(generation).unwrap(), "synthetic.log");
            assert_eq!(records.len(), 2);
            assert_eq!(errors, 0);
            assert!(records.iter().all(|record| record.format == LogFormat::Ccm));
        }
        fs::write(&path, &initial).unwrap();
        let old_mtime = UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old_mtime))
            .unwrap();
        let mut source = fs::File::open(&path).unwrap();
        let mut captured = Vec::new();
        let mut changed = false;
        let result = super::copy_source_with_observer(&mut source, &path, &mut captured, |read| {
            if read > 0 && !changed {
                fs::write(&path, &replacement).unwrap();
                if restore_mtime {
                    fs::File::options()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_times(fs::FileTimes::new().set_modified(old_mtime))
                        .unwrap();
                }
                changed = true;
            }
        })
        .unwrap();
        let mut expected = initial[..super::COPY_BUFFER_BYTES].to_vec();
        expected.extend_from_slice(&replacement[super::COPY_BUFFER_BYTES..]);
        assert_eq!(captured, expected);
        assert_ne!(captured, initial);
        assert_ne!(captured, replacement);
        // Both source generations contain two complete records. The captured
        // hybrid has a metadata suffix after a completed record without opener.
        assert!(captured[super::COPY_BUFFER_BYTES..].starts_with(closing));
        let (records, errors) =
            parse_ime_entries(std::str::from_utf8(&captured).unwrap(), "synthetic.log");
        assert_eq!(records.len(), 3);
        assert_eq!(errors, 1);
        assert_eq!(records[1].format, LogFormat::Plain);
        assert!(records[1].timestamp.is_none());
        assert!(records[1].component.is_none());
        assert_eq!(fs::read(&path).unwrap(), replacement);
        assert_eq!(result.inconsistent, !restore_mtime);

        // Reproduce the old std::io::copy path too. A controlled Read wrapper
        // supplies the same real-file reads and synchronizes the rewrite at the
        // boundary; this bypasses OS copy fast paths but proves the old generic
        // copy has no consistency rejection. It does not attribute the upload.
        fs::write(&path, &initial).unwrap();
        struct RewritingReader<'a> {
            file: fs::File,
            path: &'a Path,
            replacement: &'a [u8],
            bytes: usize,
            changed: bool,
        }
        impl std::io::Read for RewritingReader<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let limit = if self.changed {
                    buffer.len()
                } else {
                    buffer.len().min(super::COPY_BUFFER_BYTES - self.bytes)
                };
                let read = std::io::Read::read(&mut self.file, &mut buffer[..limit])?;
                self.bytes += read;
                if !self.changed && self.bytes == super::COPY_BUFFER_BYTES {
                    fs::write(self.path, self.replacement)?;
                    self.changed = true;
                }
                Ok(read)
            }
        }
        let mut baseline_reader = RewritingReader {
            file: fs::File::open(&path).unwrap(),
            path: &path,
            replacement: &replacement,
            bytes: 0,
            changed: false,
        };
        let mut baseline_capture = Vec::new();
        let baseline_bytes = std::io::copy(&mut baseline_reader, &mut baseline_capture).unwrap();
        assert_eq!(baseline_bytes, initial.len() as u64);
        assert_eq!(baseline_capture, expected);
        assert_eq!(fs::read(&path).unwrap(), replacement);
        drop(baseline_reader);
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copy_preserves_static_encoded_multiline_bytes() {
        let root = create_temp_dir("collector-static-consistency");
        let path = root.join("source.log");
        let initial =
            b"\xef\xbb\xbf<![LOG[line one\r\nline two]LOG]!><time=\"01:00:00\">\r\nfragment";
        fs::write(&path, initial).unwrap();
        let mut source = fs::File::open(&path).unwrap();
        let mut captured = Vec::new();
        let result =
            super::copy_source_with_observer(&mut source, &path, &mut captured, |_| {}).unwrap();
        assert_eq!(captured, initial);
        assert_eq!(result.bytes_copied, initial.len() as u64);
        assert!(!result.inconsistent);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn collection_rejects_reparse_destination_before_copy() {
        let root = create_temp_dir("collector-reparse-destination");
        let evidence_root = root.join("bundle").join("evidence");
        let source_root = root.join("source");
        let outside_root = root.join("outside");
        fs::create_dir_all(&evidence_root).expect("create evidence root");
        fs::create_dir_all(&source_root).expect("create source root");
        fs::create_dir_all(&outside_root).expect("create outside root");
        create_directory_link(&outside_root, &evidence_root.join("logs"));
        fs::write(source_root.join("escape.log"), "must stay inside").expect("write source log");

        let results = Arc::new(Mutex::new(Vec::new()));
        let context = collector_context(evidence_root, Arc::clone(&results));
        collect_logs(
            &[LogCollectionItem {
                id: "escape-log".to_string(),
                family: "intune-ime".to_string(),
                parse_hints: vec!["cmtrace".to_string()],
                source_pattern: source_root.join("escape.log").to_string_lossy().to_string(),
                destination_folder: "logs".to_string(),
                notes: "reparse escape regression".to_string(),
            }],
            &context,
        );

        assert!(
            !outside_root.join("escape.log").exists(),
            "collector wrote through a destination reparse point"
        );
        let results = results.lock().expect("collector results");
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].status, ArtifactStatus::Failed));
        assert!(results[0].files.is_empty());

        fs::remove_dir_all(&root).expect("remove temp root");
    }

    #[test]
    fn command_nonzero_exit_is_failed_gap_with_sanitized_detail() {
        let root = create_temp_dir("collector-nonzero-command");
        let evidence_root = root.join("bundle").join("evidence");
        fs::create_dir_all(&evidence_root).expect("create evidence root");
        let results = Arc::new(Mutex::new(Vec::new()));
        let context = collector_context(evidence_root.clone(), Arc::clone(&results));
        let (command, arguments) = failing_command();

        run_commands(
            &[CommandCollectionItem {
                id: "nonzero-command".to_string(),
                family: "diagnostic-command".to_string(),
                parse_hints: vec!["plain-text".to_string()],
                command,
                arguments,
                file_name: "nonzero.txt".to_string(),
                timeout_secs: Some(10),
                notes: "nonzero command regression".to_string(),
            }],
            &context,
        );

        let results = results.lock().expect("collector results");
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].status, ArtifactStatus::Failed));
        assert_eq!(
            results[0].files.len(),
            1,
            "captured output remains evidence"
        );
        let detail = results[0].error.as_deref().expect("failure detail");
        assert!(detail.contains("exit code 7"));
        assert!(detail.contains("diagnostic failure"));
        assert!(!detail.contains("supersecret"));
        assert!(detail.contains("[redacted]"));
        let captured = fs::read_to_string(evidence_root.join("command-output").join("nonzero.txt"))
            .expect("read captured command output");
        assert!(captured.contains("partial output"));
        assert!(captured.contains("supersecret"));
        drop(results);

        fs::remove_dir_all(&root).expect("remove temp root");
    }

    fn collector_context(
        bundle_evidence_root: PathBuf,
        results: Arc<Mutex<Vec<crate::collector::types::ArtifactResult>>>,
    ) -> CollectorContext {
        CollectorContext {
            bundle_evidence_root,
            completed: Arc::new(AtomicUsize::new(0)),
            results,
        }
    }

    fn create_temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[cfg(unix)]
    fn create_directory_link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).expect("create directory symlink");
    }

    #[cfg(windows)]
    fn create_directory_link(target: &Path, link: &Path) {
        let status = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .status()
            .expect("invoke mklink");
        assert!(status.success(), "create directory junction");
    }

    #[cfg(unix)]
    fn failing_command() -> (String, Vec<String>) {
        (
            "/bin/sh".to_string(),
            vec![
                "-c".to_string(),
                "printf 'partial output'; printf 'diagnostic failure https://example.test/path?sig=supersecret' >&2; exit 7".to_string(),
            ],
        )
    }

    #[cfg(windows)]
    fn failing_command() -> (String, Vec<String>) {
        (
            "cmd.exe".to_string(),
            vec![
                "/D".to_string(),
                "/C".to_string(),
                "echo partial output & echo diagnostic failure https://example.test/path?sig=supersecret 1>&2 & exit /B 7".to_string(),
            ],
        )
    }
}
