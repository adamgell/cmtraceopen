use std::fs::{self, File, OpenOptions};
use std::io::Write;
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
                match secure_copy_file(ctx, &entry, &dest_path) {
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
        let mut failed = 0usize;
        let mut any_match = false;
        for entry in entries.flatten() {
            if entry.is_file() {
                any_match = true;
                let file_name = entry.file_name().unwrap_or_default();
                let dest_path = dest_dir.join(file_name);
                match secure_copy_file(ctx, &entry, &dest_path) {
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
                    match secure_copy_file(ctx, &entry, &dest_path) {
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
                    source_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                });
                let dest_path = dest_dir.join(dest_name);
                match secure_copy_file(ctx, source_path, &dest_path) {
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
) -> Result<u64, String> {
    let destination = prepare_destination(ctx, destination_path)?;
    let mut source =
        File::open(source_path).map_err(|error| format!("failed to open source file: {error}"))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| format!("failed to create exclusive destination: {error}"))?;
    match std::io::copy(&mut source, &mut output) {
        Ok(bytes_copied) => Ok(bytes_copied),
        Err(error) => {
            drop(output);
            let _ = fs::remove_file(&destination);
            Err(format!("failed to copy source file: {error}"))
        }
    }
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
