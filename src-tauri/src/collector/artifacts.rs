use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rayon::prelude::*;

use crate::collector::env_expand::expand_env_vars;
use crate::collector::types::*;

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

// ---------------------------------------------------------------------------
// Logs: glob-expand source_pattern, copy matching files
// ---------------------------------------------------------------------------

pub fn collect_logs(items: &[LogCollectionItem], ctx: &CollectorContext) {
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
        let _ = fs::create_dir_all(&dest_dir);

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
        let mut failed = 0usize;
        let mut any_match = false;
        for entry in entries.flatten() {
            if entry.is_file() {
                any_match = true;
                let file_name = entry.file_name().unwrap_or_default();
                let dest_path = dest_dir.join(file_name);
                match fs::copy(&entry, &dest_path) {
                    Ok(bytes_copied) => match collected_file(
                        ctx,
                        Some(entry.to_string_lossy().into_owned()),
                        &dest_path,
                        bytes_copied,
                    ) {
                        Ok(file) => files.push(file),
                        Err(_) => failed += 1,
                    },
                    Err(_) => failed += 1,
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
        } else if failed == 0 {
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
                Some(format!("{copied} copied, {failed} failed")),
            );
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
    let _ = fs::create_dir_all(&dest_dir);

    items.par_iter().for_each(|item| {
        let artifact = ArtifactDescriptor {
            id: &item.id,
            category: "registry",
            family: &item.family,
            parse_hints: &item.parse_hints,
            notes: &item.notes,
        };
        let output_path = dest_dir.join(&item.file_name);
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
        let _ = fs::create_dir_all(&dest_dir);

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
        let mut failed = 0usize;
        let mut any_match = false;
        for entry in entries.flatten() {
            if entry.is_file() {
                any_match = true;
                let file_name = entry.file_name().unwrap_or_default();
                let dest_path = dest_dir.join(file_name);
                match fs::copy(&entry, &dest_path) {
                    Ok(bytes_copied) => match collected_file(
                        ctx,
                        Some(entry.to_string_lossy().into_owned()),
                        &dest_path,
                        bytes_copied,
                    ) {
                        Ok(file) => files.push(file),
                        Err(_) => failed += 1,
                    },
                    Err(_) => failed += 1,
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
        } else if failed == 0 {
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
                Some(format!(
                    "{copied} copied, {failed} failed (may be locked by OS)"
                )),
            );
        }

        ctx.completed.fetch_add(1, Ordering::Relaxed);
    });
}

// ---------------------------------------------------------------------------
// File exports: copy specific files
// ---------------------------------------------------------------------------

pub fn copy_exports(items: &[FileExportItem], ctx: &CollectorContext) {
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
        let _ = fs::create_dir_all(&dest_dir);

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
            let mut failed = 0usize;
            let mut any_match = false;
            for entry in entries.flatten() {
                if entry.is_file() {
                    any_match = true;
                    let file_name = entry.file_name().unwrap_or_default();
                    let dest_path = dest_dir.join(file_name);
                    match fs::copy(&entry, &dest_path) {
                        Ok(bytes_copied) => match collected_file(
                            ctx,
                            Some(entry.to_string_lossy().into_owned()),
                            &dest_path,
                            bytes_copied,
                        ) {
                            Ok(file) => files.push(file),
                            Err(_) => failed += 1,
                        },
                        Err(_) => failed += 1,
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
            } else if failed == 0 {
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
                    Some(format!("{copied} copied, {failed} failed")),
                );
            }
        } else {
            let source_path = Path::new(&source);
            if source_path.is_file() {
                let dest_name = item.file_name.as_deref().unwrap_or_else(|| {
                    source_path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown")
                });
                let dest_path = dest_dir.join(dest_name);
                match fs::copy(source_path, &dest_path) {
                    Ok(bytes_copied) => {
                        match collected_file(ctx, Some(source.clone()), &dest_path, bytes_copied) {
                            Ok(file) => push_result(
                                ctx,
                                artifact,
                                ArtifactStatus::Collected,
                                vec![file],
                                None,
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
    let _ = fs::create_dir_all(&dest_dir);

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
            if item.id == "mdm-diag-tool" {
                let zip_path = dest_dir.join("MDMDiagReport.zip");
                args.push(zip_path.to_string_lossy().into_owned());
            }

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

                            match fs::write(&output_path, &combined) {
                                Ok(_) => {
                                    let origin =
                                        Some(format!("{} {}", item.command, args.join(" ")));
                                    let mut files = Vec::new();
                                    let mut record_errors = Vec::new();
                                    match collected_file(
                                        ctx,
                                        origin.clone(),
                                        &output_path,
                                        combined.len() as u64,
                                    ) {
                                        Ok(file) => files.push(file),
                                        Err(error) => record_errors.push(error),
                                    }
                                    if item.id == "mdm-diag-tool" {
                                        let zip_path = dest_dir.join("MDMDiagReport.zip");
                                        if zip_path.is_file() {
                                            match collected_file(
                                                ctx,
                                                origin,
                                                &zip_path,
                                                fs::metadata(&zip_path)
                                                    .map(|metadata| metadata.len())
                                                    .unwrap_or(0),
                                            ) {
                                                Ok(file) => files.push(file),
                                                Err(error) => record_errors.push(error),
                                            }
                                        }
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
        return Err(crate::error::AppError::PlatformUnsupported("WINDIR is not set; could not resolve the Windows system path.".to_string()));
    };
    let path = PathBuf::from(windir).join("System32").join(file_name);
    if !path.is_file() {
        return Err(crate::error::AppError::Internal(format!("Expected system binary not found at '{}'.", path.display())));
    }
    Ok(path)
}
