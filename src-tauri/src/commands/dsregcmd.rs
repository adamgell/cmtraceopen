#[cfg(target_os = "windows")]
use crate::dsregcmd::connectivity;
use crate::dsregcmd::{registry, DsregcmdAnalysisResult};

use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use std::ffi::c_void;
use std::fs;
#[cfg(target_os = "windows")]
use std::fs::File;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::ptr::{null, null_mut};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdCaptureResult {
    pub input: String,
    pub bundle_path: Option<String>,
    pub evidence_file_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DsregcmdPathSourceKind {
    File,
    Folder,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdResolvedSource {
    pub input: String,
    pub bundle_path: Option<String>,
    pub resolved_path: Option<String>,
    pub evidence_file_path: Option<String>,
}

#[tauri::command]
pub async fn analyze_dsregcmd(
    input: String,
    bundle_path: Option<String>,
) -> Result<DsregcmdAnalysisResult, crate::error::AppError> {
    // The whole analysis path is blocking work: plain-text parsing is CPU
    // bound and the bundle path performs synchronous filesystem walks plus
    // connectivity and SCP probes. Run it on the blocking pool so the
    // command thread stays free for every other IPC call while the analysis
    // is in flight (issue #627).
    tokio::task::spawn_blocking(move || analyze_dsregcmd_blocking(&input, bundle_path.as_deref()))
        .await
        .map_err(|join_error| {
            crate::error::AppError::Internal(format!(
                "DsRegCmd analysis worker failed: {}",
                join_error
            ))
        })?
}

fn analyze_dsregcmd_blocking(
    input: &str,
    bundle_path: Option<&str>,
) -> Result<DsregcmdAnalysisResult, crate::error::AppError> {
    log::info!(
        "event=dsregcmd_analysis_start input_chars={} input_lines={}",
        input.len(),
        input.lines().count()
    );

    // The evidence is read here because this crate owns the I/O; the assembly
    // and the projection happen in the parser crate, so the value that leaves
    // this command is the published one and neither the workspace nor a file it
    // writes can obtain an unprojected analysis to copy (issue #556).
    //
    // The readers behind `load_bundle_evidence` are also what the responsiveness
    // measurement slows down, so each of them keeps its own simulated-I/O hook
    // (issue #627).
    let evidence = bundle_path.map(load_bundle_evidence).unwrap_or_default();

    let result = crate::dsregcmd::analyze_text_with_evidence(input, evidence)?;

    log::info!(
        "event=dsregcmd_analysis_complete diagnostics_count={} join_type={:?}",
        result.diagnostics.len(),
        result.derived.join_type
    );

    Ok(result)
}

/// Read every evidence artifact a capture bundle holds.
///
/// Each artifact has its own reader, and each reader is slowed down on its own
/// by [`simulate_bundle_io_delay`], so the responsiveness measurement can
/// attribute a stall to a named reader rather than to "the bundle path".
fn load_bundle_evidence(bundle_path: &str) -> crate::dsregcmd::DsregcmdBundleEvidence {
    let bundle = Path::new(bundle_path);

    simulate_bundle_io_delay("bundle-policy-evidence");
    let policy_evidence = registry::load_whfb_policy_evidence(bundle);
    simulate_bundle_io_delay("bundle-os-version-evidence");
    let os_version = registry::load_os_version_evidence(bundle);
    simulate_bundle_io_delay("bundle-proxy-evidence");
    let proxy_evidence = registry::load_proxy_evidence(bundle);
    simulate_bundle_io_delay("bundle-enrollment-evidence");
    let enrollment_evidence = registry::load_enrollment_evidence(bundle);
    simulate_bundle_io_delay("bundle-active-evidence");
    let active_evidence = load_active_evidence_from_bundle(bundle);
    simulate_bundle_io_delay("bundle-scheduled-task-evidence");
    let scheduled_task_evidence = load_scheduled_task_evidence_from_bundle(bundle);
    simulate_bundle_io_delay("bundle-event-log-analysis");
    let event_log_analysis = load_event_log_from_bundle(bundle);

    crate::dsregcmd::DsregcmdBundleEvidence {
        policy_evidence,
        os_version,
        proxy_evidence,
        enrollment_evidence,
        active_evidence,
        scheduled_task_evidence,
        event_log_analysis,
    }
}

/// Project raw `dsregcmd /status` text for an egress path that holds the
/// capture itself rather than an analysis of it.
///
/// The workspace's "copy status text" clipboard path is the one place this lane
/// publishes the capture text, and the frontend has to hold that text to display
/// it and to hand it back for analysis, so it cannot be handed a projected copy
/// to publish instead. Masking at the clipboard call site would be the per-lane
/// hygiene rule issue #556 rejects; the workspace asks for the projection here
/// instead, and the projection itself is the crate's.
#[tauri::command]
pub fn redact_dsregcmd_status_text(input: String) -> String {
    crate::dsregcmd::redacted_status_text(&input)
}

/// A capture bundle projected for hand-off.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdShareableBundle {
    /// Where the projected bundle was written.
    pub bundle_path: String,
    /// How many files it holds, the manifest included.
    pub artifact_count: usize,
}

/// Write a projected copy of a capture bundle that may leave the machine.
///
/// The working bundle stays raw. It is the analyzer's own input — the captured
/// command output and every evidence file are read back by `load_bundle_evidence`
/// and by the ESP lane's bundle reader — so masking those files where they are
/// *stored* would change what those readers conclude rather than what anyone
/// publishes. This is the hand-off instead: the same files, projected once,
/// written under `destination_root` and handed back as the path a support
/// engineer can archive or attach (issue #628).
///
/// The projection belongs to the parser crate, so this asks for the
/// classification the analysis path already uses rather than declaring a second
/// list of identity fields here, and it reads the bundle layout through the same
/// constants the analysis path reads it with — a bundle this cannot resolve is
/// one the analyzer cannot read either.
#[tauri::command]
pub async fn export_dsregcmd_shareable_bundle(
    bundle_path: String,
    destination_root: String,
) -> Result<DsregcmdShareableBundle, crate::error::AppError> {
    // Projecting a bundle walks its tree and then reads and writes every
    // artifact, which is the same blocking class as the live capture and the
    // bundle analysis, so it moves off the command thread alongside them
    // (issue #627).
    tokio::task::spawn_blocking(move || {
        export_dsregcmd_shareable_bundle_blocking(&bundle_path, &destination_root)
    })
    .await
    .map_err(|join_error| {
        crate::error::AppError::Internal(format!(
            "DsRegCmd shareable export worker failed: {}",
            join_error
        ))
    })?
}

/// The export itself, run off the command thread.
fn export_dsregcmd_shareable_bundle_blocking(
    bundle_path: &str,
    destination_root: &str,
) -> Result<DsregcmdShareableBundle, crate::error::AppError> {
    let bundle_root = resolve_canonical_bundle_root_from_folder_path(Path::new(bundle_path))
        .ok_or_else(|| {
            crate::error::AppError::InvalidInput(
                "Selected folder is not a supported dsregcmd evidence bundle location. Choose the bundle root, the bundle's evidence folder, or the bundle's command-output folder.".to_string(),
            )
        })?;

    // Every input is required rather than merely read if present. A bundle with
    // no command output would leave the classification with nothing to read, and
    // the artefact written from it would look projected without being projected
    // — the one failure mode this hand-off exists to prevent.
    let capture_text = read_bundle_capture_text(&bundle_root).ok_or_else(|| {
        crate::error::AppError::InvalidInput(format!(
            "Resolved bundle root '{}' does not contain dsregcmd evidence. Expected '{}' or '{}'.",
            bundle_root.display(),
            DSREGCMD_EVIDENCE_RELATIVE_PATH.join("/"),
            DSREGCMD_TOP_LEVEL_FALLBACK_FILE
        ))
    })?;

    let evidence = load_bundle_evidence(&bundle_root.to_string_lossy());
    let artifacts = read_bundle_text_artifacts(&bundle_root)?;

    let projected = crate::dsregcmd::redacted_bundle_artifacts(&capture_text, evidence, artifacts);

    let shareable_root = create_shareable_bundle_root(Path::new(destination_root))?;
    let artifact_count = write_shareable_bundle(&shareable_root, &projected)?;

    log::info!(
        "event=dsregcmd_shareable_export_complete bundle_path={} artifact_count={}",
        shareable_root.display(),
        artifact_count
    );

    Ok(DsregcmdShareableBundle {
        bundle_path: shareable_root.to_string_lossy().to_string(),
        artifact_count,
    })
}

/// The captured `dsregcmd /status` text a bundle holds, where the analysis path
/// looks for it.
fn read_bundle_capture_text(bundle_root: &Path) -> Option<String> {
    let evidence_file_path = DSREGCMD_EVIDENCE_RELATIVE_PATH
        .iter()
        .fold(bundle_root.to_path_buf(), |path, segment| {
            path.join(segment)
        });

    read_bundle_artifact_text(&evidence_file_path)
        .ok()
        .or_else(|| {
            read_bundle_artifact_text(&bundle_root.join(DSREGCMD_TOP_LEVEL_FALLBACK_FILE)).ok()
        })
}

/// Read every artifact under `bundle_root` as text, ordered by path so one
/// bundle always projects to the same output.
///
/// The bytes are decoded with the lane's decoder rather than read as UTF-8: a
/// real capture's registry exports are frequently UTF-16LE, and reading them as
/// UTF-8 would reject the whole export rather than decode it.
///
/// Nothing is skipped, either way. An artifact that cannot be read at all is an
/// error, because a hand-off that quietly dropped evidence would publish a
/// bundle that looks complete.
fn read_bundle_text_artifacts(
    bundle_root: &Path,
) -> Result<Vec<crate::dsregcmd::DsregcmdBundleArtifact>, crate::error::AppError> {
    let mut paths = Vec::new();
    collect_bundle_files(bundle_root, &mut paths)?;
    paths.sort();

    let mut artifacts = Vec::with_capacity(paths.len());
    for path in paths {
        let relative_path = path
            .strip_prefix(bundle_root)
            .map_err(|error| {
                crate::error::AppError::Internal(format!(
                    "Failed to resolve the bundle-relative path of '{}': {}",
                    path.display(),
                    error
                ))
            })?
            .to_string_lossy()
            .replace('\\', "/");

        let text = read_bundle_artifact_text(&path)?;

        artifacts.push(crate::dsregcmd::DsregcmdBundleArtifact {
            relative_path,
            text,
        });
    }

    Ok(artifacts)
}

/// Decode one bundle artifact's bytes into text.
///
/// Content that is still not text once decoded is an error rather than an
/// artifact shipped as mojibake. Every decoder this lane uses succeeds on any
/// byte sequence, so a NUL surviving the decode is the signal that the file was
/// never a text artifact — and publishing it would corrupt evidence silently
/// where failing says so.
fn read_bundle_artifact_text(path: &Path) -> Result<String, crate::error::AppError> {
    let bytes = fs::read(path).map_err(|error| {
        crate::error::AppError::Internal(format!(
            "Failed to read the capture bundle artifact '{}': {}",
            path.display(),
            error
        ))
    })?;

    let text = crate::dsregcmd::registry::decode_reg_content(&bytes).ok_or_else(|| {
        crate::error::AppError::Internal(format!(
            "Failed to decode the capture bundle artifact '{}'.",
            path.display()
        ))
    })?;

    if text.contains('\0') {
        return Err(crate::error::AppError::Internal(format!(
            "The capture bundle artifact '{}' is not text: it still holds NUL characters after decoding.",
            path.display()
        )));
    }

    Ok(text)
}

fn collect_bundle_files(
    directory: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), crate::error::AppError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        crate::error::AppError::Internal(format!(
            "Failed to read the capture bundle folder '{}': {}",
            directory.display(),
            error
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|error| {
            crate::error::AppError::Internal(format!(
                "Failed to read an entry of the capture bundle folder '{}': {}",
                directory.display(),
                error
            ))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            crate::error::AppError::Internal(format!(
                "Failed to inspect the capture bundle entry '{}': {}",
                entry.path().display(),
                error
            ))
        })?;

        if file_type.is_dir() {
            collect_bundle_files(&entry.path(), out)?;
        } else if file_type.is_file() {
            out.push(entry.path());
        }
    }

    Ok(())
}

/// Create a fresh folder under `destination_root` for one projected bundle.
///
/// A new folder per export rather than a fixed name, so a second export cannot
/// overwrite a bundle someone already sent, and a half-written folder is never
/// mistaken for the previous one.
fn create_shareable_bundle_root(
    destination_root: &Path,
) -> Result<PathBuf, crate::error::AppError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis();
    let bundle_path = destination_root.join(format!(
        "cmtraceopen-dsregcmd-shareable-{}-{}",
        std::process::id(),
        timestamp
    ));

    fs::create_dir_all(&bundle_path).map_err(|error| {
        crate::error::AppError::Internal(format!(
            "Failed to create the shareable bundle folder '{}': {}",
            bundle_path.display(),
            error
        ))
    })?;

    Ok(bundle_path)
}

/// Write the projected artifacts under `destination`, returning how many files
/// the bundle now holds.
///
/// The captured manifest is rewritten rather than copied, so a bundle found
/// later without its conversation says what it is: a projection of a capture
/// rather than a capture.
fn write_shareable_bundle(
    destination: &Path,
    artifacts: &[crate::dsregcmd::DsregcmdBundleArtifact],
) -> Result<usize, crate::error::AppError> {
    let mut written = 0;

    for artifact in artifacts {
        if artifact.relative_path == MANIFEST_FILE {
            continue;
        }

        let relative = Path::new(&artifact.relative_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(crate::error::AppError::Internal(format!(
                "Refusing to write the projected artifact '{}': it is not a bundle-relative path.",
                artifact.relative_path
            )));
        }

        let output_path = destination.join(relative);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                crate::error::AppError::Internal(format!(
                    "Failed to create the projected evidence folder '{}': {}",
                    parent.display(),
                    error
                ))
            })?;
        }
        fs::write(&output_path, &artifact.text).map_err(|error| {
            crate::error::AppError::Internal(format!(
                "Failed to write the projected artifact '{}': {}",
                output_path.display(),
                error
            ))
        })?;
        written += 1;
    }

    write_shareable_manifest(destination)?;
    Ok(written + 1)
}

fn write_shareable_manifest(destination: &Path) -> Result<(), crate::error::AppError> {
    let manifest_path = destination.join(MANIFEST_FILE);
    fs::write(
        &manifest_path,
        format!(
            "{{\n  \"manifestPath\": \"{MANIFEST_FILE}\",\n  \"source\": \"live-dsregcmd-capture\",\n  \"projection\": \"dsregcmd-redacted\"\n}}\n"
        ),
    )
    .map_err(|error| {
        crate::error::AppError::Internal(format!(
            "Failed to write the shareable manifest '{}': {}",
            manifest_path.display(),
            error
        ))
    })
}

#[cfg(debug_assertions)]
fn simulate_bundle_io_delay(stage: &str) {
    let delay_ms = std::env::var("CMTRACE_SIMULATE_BUNDLE_IO_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(0);

    if delay_ms == 0 {
        return;
    }

    log::debug!(
        "event=dsregcmd_simulated_bundle_io stage={} delay_ms={}",
        stage,
        delay_ms
    );
    std::thread::sleep(Duration::from_millis(delay_ms));
}

#[cfg(not(debug_assertions))]
#[inline(always)]
fn simulate_bundle_io_delay(_stage: &str) {}

fn load_active_evidence_from_bundle(
    bundle_path: &Path,
) -> Option<crate::dsregcmd::DsregcmdActiveEvidence> {
    let connectivity_dir = bundle_path.join("evidence").join("connectivity");

    let tests_path = connectivity_dir.join("endpoint-tests.json");
    let scp_path = connectivity_dir.join("scp-query.json");

    let connectivity_tests: Vec<crate::dsregcmd::DsregcmdConnectivityResult> =
        match std::fs::read_to_string(&tests_path) {
            Ok(json) => match serde_json::from_str(&json) {
                Ok(tests) => tests,
                Err(error) => {
                    log::warn!(
                        "event=dsregcmd_connectivity_tests_parse_failed path={} error={}",
                        ARTIFACT_ENDPOINT_TESTS,
                        error
                    );
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        };

    let scp_query: Option<crate::dsregcmd::DsregcmdScpQueryResult> =
        match std::fs::read_to_string(&scp_path) {
            Ok(json) => match serde_json::from_str(&json) {
                Ok(query) => Some(query),
                Err(error) => {
                    log::warn!(
                        "event=dsregcmd_scp_query_parse_failed path={} error={}",
                        ARTIFACT_SCP_QUERY,
                        error
                    );
                    None
                }
            },
            Err(_) => None,
        };

    if connectivity_tests.is_empty() && scp_query.is_none() {
        return None;
    }

    Some(crate::dsregcmd::DsregcmdActiveEvidence {
        connectivity_tests,
        scp_query,
    })
}

fn load_event_log_from_bundle(
    bundle_path: &Path,
) -> Option<crate::intune::models::EventLogAnalysis> {
    let path = bundle_path
        .join("evidence")
        .join("event-logs")
        .join("dsregcmd-events.json");
    match std::fs::read_to_string(&path) {
        Ok(json) => match serde_json::from_str(&json) {
            Ok(analysis) => Some(analysis),
            Err(error) => {
                log::warn!(
                    "event=dsregcmd_event_log_parse_failed path={} error={}",
                    ARTIFACT_EVENT_LOGS,
                    error
                );
                None
            }
        },
        Err(_) => None,
    }
}

fn load_scheduled_task_evidence_from_bundle(
    bundle_path: &Path,
) -> Option<crate::dsregcmd::DsregcmdScheduledTaskEvidence> {
    let path = bundle_path
        .join("evidence")
        .join("scheduled-tasks")
        .join("enterprise-mgmt-tasks.json");
    match std::fs::read_to_string(&path) {
        Ok(json) => match serde_json::from_str(&json) {
            Ok(evidence) => Some(evidence),
            Err(error) => {
                log::warn!(
                    "event=dsregcmd_scheduled_tasks_parse_failed path={} error={}",
                    ARTIFACT_SCHEDULED_TASKS,
                    error
                );
                None
            }
        },
        Err(_) => None,
    }
}

#[tauri::command]
pub async fn capture_dsregcmd() -> Result<DsregcmdCaptureResult, crate::error::AppError> {
    // Live capture shells out to dsregcmd.exe and then stages the bundle,
    // which exports registry evidence, runs live connectivity and SCP
    // diagnostics, collects event logs, and shells out again for scheduled
    // tasks. It is the same blocking class as the bundle analysis readers,
    // so it moves off the command thread alongside them (issue #627).
    tokio::task::spawn_blocking(capture_dsregcmd_impl)
        .await
        .map_err(|join_error| {
            crate::error::AppError::Internal(format!(
                "DsRegCmd capture worker failed: {}",
                join_error
            ))
        })?
}

#[tauri::command]
pub fn load_dsregcmd_source(
    kind: DsregcmdPathSourceKind,
    path: String,
) -> Result<DsregcmdResolvedSource, crate::error::AppError> {
    load_dsregcmd_source_impl(kind, Path::new(&path))
}

#[cfg(target_os = "windows")]
fn capture_dsregcmd_impl() -> Result<DsregcmdCaptureResult, crate::error::AppError> {
    log::info!("event=dsregcmd_capture_start platform=windows");

    cleanup_old_capture_bundles();

    let dsregcmd_path = resolve_system32_binary("dsregcmd.exe")?;
    verify_dsregcmd_signature(&dsregcmd_path)?;

    let output = crate::process_util::hidden_command(&dsregcmd_path)
        .arg("/status")
        .output()
        .map_err(|error| {
            crate::error::AppError::Internal(format!(
                "Failed to execute '{}' /status: {}",
                dsregcmd_path.display(),
                error
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let exit_code = output.status.code().unwrap_or_default();
        return Err(crate::error::AppError::Internal(if stderr.is_empty() {
            format!("dsregcmd.exe /status failed with exit code {}", exit_code)
        } else {
            format!(
                "dsregcmd.exe /status failed with exit code {}: {}",
                exit_code, stderr
            )
        }));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let capture_bundle = stage_live_capture_bundle(&stdout)?;

    log::info!(
        "event=dsregcmd_capture_complete platform=windows stdout_chars={} stdout_lines={} bundle_path={}",
        stdout.len(),
        stdout.lines().count(),
        capture_bundle.bundle_path.display()
    );

    Ok(DsregcmdCaptureResult {
        input: stdout,
        bundle_path: Some(capture_bundle.bundle_path.to_string_lossy().to_string()),
        evidence_file_path: Some(
            capture_bundle
                .evidence_file_path
                .to_string_lossy()
                .to_string(),
        ),
    })
}

#[cfg(not(target_os = "windows"))]
fn capture_dsregcmd_impl() -> Result<DsregcmdCaptureResult, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported(
        "dsregcmd capture is only supported on Windows.".to_string(),
    ))
}

#[cfg(target_os = "windows")]
fn load_dsregcmd_source_impl(
    kind: DsregcmdPathSourceKind,
    path: &Path,
) -> Result<DsregcmdResolvedSource, crate::error::AppError> {
    match kind {
        DsregcmdPathSourceKind::File => {
            let input = fs::read_to_string(path).map_err(|error| {
                crate::error::AppError::Internal(format!(
                    "Failed to read the dsregcmd file '{}': {}",
                    path.display(),
                    error
                ))
            })?;
            let bundle_path = resolve_bundle_root_from_file_path(path)
                .map(|value| value.to_string_lossy().to_string());
            Ok(DsregcmdResolvedSource {
                input,
                bundle_path,
                resolved_path: Some(path.to_string_lossy().to_string()),
                evidence_file_path: Some(path.to_string_lossy().to_string()),
            })
        }
        DsregcmdPathSourceKind::Folder => {
            let (bundle_path, evidence_file_path) = resolve_folder_bundle_evidence(path)?;
            let input = fs::read_to_string(&evidence_file_path).map_err(|error| {
                crate::error::AppError::Internal(format!(
                    "Failed to read the dsregcmd evidence file '{}': {}",
                    evidence_file_path.display(),
                    error
                ))
            })?;
            Ok(DsregcmdResolvedSource {
                input,
                bundle_path: Some(bundle_path.to_string_lossy().to_string()),
                resolved_path: Some(evidence_file_path.to_string_lossy().to_string()),
                evidence_file_path: Some(evidence_file_path.to_string_lossy().to_string()),
            })
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn load_dsregcmd_source_impl(
    _kind: DsregcmdPathSourceKind,
    _path: &Path,
) -> Result<DsregcmdResolvedSource, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported(
        "dsregcmd source loading is only supported on Windows.".to_string(),
    ))
}

#[cfg(target_os = "windows")]
struct LiveCaptureBundle {
    bundle_path: PathBuf,
    evidence_file_path: PathBuf,
}

#[cfg(target_os = "windows")]
struct RegistryExportSpec {
    key_path: &'static str,
    file_name: &'static str,
}

#[cfg(target_os = "windows")]
const LIVE_CAPTURE_REGISTRY_EXPORTS: &[RegistryExportSpec] = &[
    RegistryExportSpec {
        key_path: r"HKLM\SOFTWARE\Microsoft\PolicyManager\Current\Device",
        file_name: "policymanager-device.reg",
    },
    RegistryExportSpec {
        key_path: r"HKLM\SOFTWARE\Microsoft\PolicyManager\Providers",
        file_name: "policymanager-providers.reg",
    },
    RegistryExportSpec {
        key_path: r"HKCU\Software\Policies",
        file_name: "hkcu-policies.reg",
    },
    RegistryExportSpec {
        key_path: r"HKLM\Software\Policies",
        file_name: "hklm-policies.reg",
    },
    RegistryExportSpec {
        key_path: r"HKCU\Software\Microsoft\Policies",
        file_name: "hkcu-microsoft-policies.reg",
    },
    RegistryExportSpec {
        key_path: r"HKLM\Software\Microsoft\Policies",
        file_name: "hklm-microsoft-policies.reg",
    },
    RegistryExportSpec {
        key_path: r"HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo",
        file_name: "cdj-joininfo.reg",
    },
    RegistryExportSpec {
        key_path: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD",
        file_name: "cdj-aad.reg",
    },
    RegistryExportSpec {
        key_path: r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        file_name: "os-version.reg",
    },
    RegistryExportSpec {
        key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc\Parameters\Connections",
        file_name: "proxy-connections.reg",
    },
    RegistryExportSpec {
        key_path: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        file_name: "proxy-internet-settings.reg",
    },
    RegistryExportSpec {
        key_path: r"HKLM\SOFTWARE\Microsoft\Enrollments",
        file_name: "enrollments.reg",
    },
];

// The bundle layout is not platform-specific. A capture is *taken* on Windows,
// but reading a bundle back is ordinary file I/O: the analysis path already
// reads one on every platform, and so does the hand-off that projects one.
const DSREGCMD_EVIDENCE_RELATIVE_PATH: [&str; 3] =
    ["evidence", "command-output", "dsregcmd-status.txt"];
const DSREGCMD_TOP_LEVEL_FALLBACK_FILE: &str = "dsregcmd-status.txt";
const MANIFEST_FILE: &str = "manifest.json";
const EVIDENCE_FOLDER_NAME: &str = "evidence";
const COMMAND_OUTPUT_FOLDER_NAME: &str = "command-output";

// The bundle-relative name each evidence reader logs when its artifact does not
// parse. Not the path it was read from: `tauri_plugin_log` persists these
// warnings in the OS application log directory, so an absolute path there
// carries the user profile component of whoever ran the capture, and an
// application log attached to a support case would expose it.
const ARTIFACT_ENDPOINT_TESTS: &str = "evidence/connectivity/endpoint-tests.json";
const ARTIFACT_SCP_QUERY: &str = "evidence/connectivity/scp-query.json";
const ARTIFACT_EVENT_LOGS: &str = "evidence/event-logs/dsregcmd-events.json";
const ARTIFACT_SCHEDULED_TASKS: &str = "evidence/scheduled-tasks/enterprise-mgmt-tasks.json";

/// Stage the live capture into its bundle.
///
/// The bundle is this lane's working store, not its export: it lives under the
/// OS temp root (`create_capture_bundle_root`), and every file in it is an input
/// the analyzer reads back — the captured `dsregcmd /status` text through
/// `load_dsregcmd_source`, the connectivity, SCP and event-log evidence through
/// `load_bundle_evidence`, and the same command output again through the ESP
/// lane's bundle reader. It is written as captured for exactly that reason:
/// masking it here would change what those readers conclude rather than what
/// anyone publishes (a projected `User Identity` cannot fire
/// `builtin-admin-cannot-join`, a projected SCP domain cannot be compared with
/// the tenant the capture reports, and a projected device id changes the ESP
/// identity fingerprint). The projection belongs at the boundary that publishes
/// a value, which for this lane is `analyze_text_with_evidence` and
/// `redacted_status_text`. The folder is not private, though: its path is handed
/// to the frontend, the sidebar renders it, and a support engineer can open or
/// archive it — so any path that hands this bundle, or a file in it, to a user
/// or another machine must project that content first, and the residual gap is
/// recorded in the pull request rather than implied away here.
#[cfg(target_os = "windows")]
fn stage_live_capture_bundle(stdout: &str) -> Result<LiveCaptureBundle, crate::error::AppError> {
    let bundle_path = create_capture_bundle_root()?;
    let evidence_command_output = bundle_path.join("evidence").join("command-output");
    let evidence_registry = bundle_path.join("evidence").join("registry");
    fs::create_dir_all(&evidence_command_output).map_err(|error| {
        crate::error::AppError::Internal(format!(
            "Failed to create the live capture command-output folder '{}': {}",
            evidence_command_output.display(),
            error
        ))
    })?;
    fs::create_dir_all(&evidence_registry).map_err(|error| {
        crate::error::AppError::Internal(format!(
            "Failed to create the live capture registry folder '{}': {}",
            evidence_registry.display(),
            error
        ))
    })?;

    let evidence_file_path = evidence_command_output.join("dsregcmd-status.txt");
    fs::write(&evidence_file_path, stdout).map_err(|error| {
        crate::error::AppError::Internal(format!(
            "Failed to write the live dsregcmd capture to '{}': {}",
            evidence_file_path.display(),
            error
        ))
    })?;

    let manifest_path = bundle_path.join("manifest.json");
    fs::write(
        &manifest_path,
        "{\n  \"manifestPath\": \"manifest.json\",\n  \"source\": \"live-dsregcmd-capture\"\n}\n",
    )
    .map_err(|error| {
        crate::error::AppError::Internal(format!(
            "Failed to write the live capture manifest '{}': {}",
            manifest_path.display(),
            error
        ))
    })?;

    simulate_bundle_io_delay("capture-registry-export");
    export_live_registry_evidence(&evidence_registry);

    // Phase 3: Active diagnostics (connectivity + SCP)
    let evidence_connectivity = bundle_path.join("evidence").join("connectivity");
    if fs::create_dir_all(&evidence_connectivity).is_ok() {
        simulate_bundle_io_delay("capture-active-diagnostics");
        let active_evidence = connectivity::run_active_diagnostics();
        if let Ok(json) = serde_json::to_string_pretty(&active_evidence.connectivity_tests) {
            let _ = fs::write(evidence_connectivity.join("endpoint-tests.json"), json);
        }
        if let Some(ref scp) = active_evidence.scp_query {
            if let Ok(json) = serde_json::to_string_pretty(scp) {
                let _ = fs::write(evidence_connectivity.join("scp-query.json"), json);
            }
        }
    }

    // Phase 4: Event log collection
    simulate_bundle_io_delay("capture-event-log-collection");
    let event_log_analysis = crate::dsregcmd::event_logs::collect_dsregcmd_event_logs();
    if let Some(ref analysis) = event_log_analysis {
        let evidence_event_logs = bundle_path.join("evidence").join("event-logs");
        if fs::create_dir_all(&evidence_event_logs).is_ok() {
            if let Ok(json) = serde_json::to_string_pretty(analysis) {
                let _ = fs::write(evidence_event_logs.join("dsregcmd-events.json"), json);
            }
        }
    }

    // Phase 5: Scheduled task evidence (EnterpriseMgmt GUIDs)
    simulate_bundle_io_delay("capture-scheduled-task-evidence");
    let scheduled_task_evidence = collect_enterprise_mgmt_task_guids();
    let evidence_scheduled_tasks = bundle_path.join("evidence").join("scheduled-tasks");
    if fs::create_dir_all(&evidence_scheduled_tasks).is_ok() {
        if let Ok(json) = serde_json::to_string_pretty(&scheduled_task_evidence) {
            let _ = fs::write(
                evidence_scheduled_tasks.join("enterprise-mgmt-tasks.json"),
                json,
            );
        }
    }

    Ok(LiveCaptureBundle {
        bundle_path,
        evidence_file_path,
    })
}

#[cfg(target_os = "windows")]
fn resolve_bundle_root_from_file_path(path: &Path) -> Option<PathBuf> {
    let mut candidate = path.parent();

    while let Some(directory) = candidate {
        if directory.join(MANIFEST_FILE).is_file() {
            return Some(directory.to_path_buf());
        }

        candidate = directory.parent();
    }

    None
}

#[cfg(target_os = "windows")]
fn resolve_folder_bundle_evidence(
    folder_path: &Path,
) -> Result<(PathBuf, PathBuf), crate::error::AppError> {
    let bundle_root = resolve_canonical_bundle_root_from_folder_path(folder_path).ok_or_else(|| {
        crate::error::AppError::InvalidInput("Selected folder is not a supported dsregcmd evidence bundle location. Choose the bundle root, the bundle's evidence folder, or the bundle's command-output folder.".to_string())
    })?;

    let evidence_file_path = DSREGCMD_EVIDENCE_RELATIVE_PATH
        .iter()
        .fold(bundle_root.clone(), |path, segment| path.join(segment));
    if evidence_file_path.is_file() {
        return Ok((bundle_root, evidence_file_path));
    }

    let top_level_path = bundle_root.join(DSREGCMD_TOP_LEVEL_FALLBACK_FILE);
    if top_level_path.is_file() {
        return Ok((bundle_root, top_level_path));
    }

    Err(crate::error::AppError::InvalidInput(format!(
        "Resolved bundle root does not contain dsregcmd evidence. Expected '{}' or '{}'.",
        DSREGCMD_EVIDENCE_RELATIVE_PATH.join("/"),
        DSREGCMD_TOP_LEVEL_FALLBACK_FILE
    )))
}

/// Resolve the bundle root a folder selects.
///
/// Not platform-gated: reading a bundle is ordinary path inspection, and the
/// hand-off projects an existing bundle on any platform. Only *taking* a live
/// capture is Windows-specific.
fn resolve_canonical_bundle_root_from_folder_path(folder_path: &Path) -> Option<PathBuf> {
    if folder_path.join(MANIFEST_FILE).is_file() {
        return Some(folder_path.to_path_buf());
    }

    if path_ends_with_directory(folder_path, COMMAND_OUTPUT_FOLDER_NAME) {
        let bundle_root = folder_path.parent().and_then(Path::parent);
        if let Some(bundle_root) = bundle_root {
            if bundle_root.join(MANIFEST_FILE).is_file() {
                return Some(bundle_root.to_path_buf());
            }
        }
    }

    if path_ends_with_directory(folder_path, EVIDENCE_FOLDER_NAME) {
        if let Some(bundle_root) = folder_path.parent() {
            if bundle_root.join(MANIFEST_FILE).is_file() {
                return Some(bundle_root.to_path_buf());
            }
        }
    }

    let mut candidate = Some(folder_path);
    while let Some(directory) = candidate {
        if directory.join(MANIFEST_FILE).is_file() {
            return Some(directory.to_path_buf());
        }

        candidate = directory.parent();
    }

    None
}

fn path_ends_with_directory(path: &Path, directory_name: &str) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case(directory_name))
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn create_capture_bundle_root() -> Result<PathBuf, crate::error::AppError> {
    let temp_root = std::env::temp_dir();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis();
    let bundle_path = temp_root.join(format!(
        "cmtraceopen-dsregcmd-capture-{}-{}",
        std::process::id(),
        timestamp
    ));
    fs::create_dir_all(&bundle_path).map_err(|error| {
        crate::error::AppError::Internal(format!(
            "Failed to create the live capture bundle root '{}': {}",
            bundle_path.display(),
            error
        ))
    })?;
    Ok(bundle_path)
}

#[cfg(target_os = "windows")]
fn export_live_registry_evidence(registry_root: &Path) {
    let Ok(reg_path) = resolve_system32_binary("reg.exe") else {
        log::warn!(
            "event=dsregcmd_registry_export_skipped reason=reg_not_found registry_root={}",
            registry_root.display()
        );
        return;
    };

    for export in LIVE_CAPTURE_REGISTRY_EXPORTS {
        let output_path = registry_root.join(export.file_name);
        match crate::process_util::hidden_command(&reg_path)
            .args([
                "export",
                export.key_path,
                &output_path.to_string_lossy(),
                "/y",
            ])
            .output()
        {
            Ok(output) if output.status.success() => {
                log::info!(
                    "event=dsregcmd_registry_export_complete key={} file={}",
                    export.key_path,
                    output_path.display()
                );
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                log::error!(
                    "event=dsregcmd_registry_export_failed key={} file={} exit_code={} stderr={}",
                    export.key_path,
                    output_path.display(),
                    output.status.code().unwrap_or_default(),
                    stderr
                );
            }
            Err(error) => {
                log::error!(
                    "event=dsregcmd_registry_export_failed key={} file={} error={}",
                    export.key_path,
                    output_path.display(),
                    error
                );
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn collect_enterprise_mgmt_task_guids() -> crate::dsregcmd::DsregcmdScheduledTaskEvidence {
    use regex::Regex;

    let mut evidence = crate::dsregcmd::DsregcmdScheduledTaskEvidence::default();

    let schtasks_path = match resolve_system32_binary("schtasks.exe") {
        Ok(p) => p,
        Err(e) => {
            log::warn!("event=dsregcmd_schtasks_skipped reason={e}");
            return evidence;
        }
    };

    let output = match crate::process_util::hidden_command(&schtasks_path)
        .args([
            "/query",
            "/TN",
            r"\Microsoft\Windows\EnterpriseMgmt",
            "/FO",
            "LIST",
        ])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            log::error!("event=dsregcmd_schtasks_failed error={e}");
            return evidence;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        log::error!(
            "event=dsregcmd_schtasks_failed exit_code={} stderr={}",
            output.status.code().unwrap_or_default(),
            stderr
        );
        return evidence;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let guid_re = Regex::new(
        r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
    )
    .expect("valid GUID regex");

    let mut seen = std::collections::HashSet::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("TaskName:") {
            continue;
        }
        for cap in guid_re.find_iter(trimmed) {
            let guid = cap.as_str().to_string();
            if seen.insert(guid.to_ascii_uppercase()) {
                evidence.enterprise_mgmt_guids.push(guid);
            }
        }
    }

    log::info!(
        "event=dsregcmd_schtasks_complete guid_count={}",
        evidence.enterprise_mgmt_guids.len()
    );

    evidence
}

#[cfg(target_os = "windows")]
fn cleanup_old_capture_bundles() {
    let temp_root = std::env::temp_dir();
    let Ok(entries) = fs::read_dir(&temp_root) else {
        return;
    };

    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(24 * 60 * 60))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.starts_with("cmtraceopen-dsregcmd-capture-") {
            continue;
        }

        let is_old = entry
            .metadata()
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .map(|modified| modified <= cutoff)
            .unwrap_or(false);

        if is_old {
            let _ = fs::remove_dir_all(&path);
        }
    }
}

#[cfg(target_os = "windows")]
fn resolve_system32_binary(file_name: &str) -> Result<PathBuf, crate::error::AppError> {
    let Some(windir) = std::env::var_os("WINDIR") else {
        return Err(crate::error::AppError::Internal(
            "WINDIR is not set; could not resolve the Windows system path.".to_string(),
        ));
    };

    let path = PathBuf::from(windir).join("System32").join(file_name);
    if !path.is_file() {
        return Err(crate::error::AppError::Internal(format!(
            "Expected Windows system binary was not found at '{}'.",
            path.display()
        )));
    }

    Ok(path)
}

#[cfg(target_os = "windows")]
fn verify_dsregcmd_signature(dsregcmd_path: &Path) -> Result<(), crate::error::AppError> {
    let mut wide_path = dsregcmd_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    let mut file_info = WinTrustFileInfo {
        cb_struct: std::mem::size_of::<WinTrustFileInfo>() as u32,
        pcwsz_file_path: wide_path.as_mut_ptr(),
        h_file: 0,
        pg_known_subject: null(),
    };

    // WTD_REVOKE_NONE: no revocation network check. Acceptable for a local
    // signed system binary; keeps verification offline and deterministic.
    let mut trust_data = WinTrustData {
        cb_struct: std::mem::size_of::<WinTrustData>() as u32,
        p_policy_callback_data: null_mut(),
        p_sip_client_data: null_mut(),
        dw_ui_choice: WTD_UI_NONE,
        fdw_revocation_checks: WTD_REVOKE_NONE,
        dw_union_choice: WTD_CHOICE_FILE,
        anonymous: WinTrustDataChoice {
            p_file: &mut file_info,
        },
        dw_state_action: WTD_STATEACTION_IGNORE,
        h_wvtstate_data: 0,
        pwsz_url_reference: null(),
        dw_prov_flags: 0,
        dw_ui_context: 0,
        p_signature_settings: null_mut(),
    };

    let status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut trust_data as *mut _ as *mut c_void,
        )
    };

    if status == 0 {
        return Ok(());
    }

    if status as u32 == TRUST_E_NOSIGNATURE && verify_catalog_signature(dsregcmd_path)? {
        log::info!(
            "event=dsregcmd_signature_verification_fallback method=catalog status=valid path={}",
            dsregcmd_path.display()
        );
        return Ok(());
    }

    Err(crate::error::AppError::Internal(format!(
        "Refusing to execute '{}': expected a valid Authenticode signature but WinVerifyTrust returned {}.",
        dsregcmd_path.display(),
        format_winverifytrust_status(status)
    )))
}

#[cfg(target_os = "windows")]
fn verify_catalog_signature(dsregcmd_path: &Path) -> Result<bool, crate::error::AppError> {
    let file = File::open(dsregcmd_path).map_err(|error| {
        crate::error::AppError::Internal(format!(
            "Failed to open '{}' for catalog signature verification: {}",
            dsregcmd_path.display(),
            error
        ))
    })?;
    let file_handle = file.as_raw_handle() as isize;

    let mut cat_admin_handle = 0isize;
    let acquired =
        unsafe { CryptCATAdminAcquireContext(&mut cat_admin_handle, &DRIVER_ACTION_VERIFY, 0) };
    if acquired == 0 {
        return Err(crate::error::AppError::Internal(format!(
            "Failed to acquire a catalog admin context for '{}': {}",
            dsregcmd_path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let cat_admin = CatalogAdminHandle(cat_admin_handle);

    let mut hash_len = 0u32;
    let hash_size_status =
        unsafe { CryptCATAdminCalcHashFromFileHandle(file_handle, &mut hash_len, null_mut(), 0) };
    if hash_size_status == 0 && hash_len == 0 {
        return Err(crate::error::AppError::Internal(format!(
            "Failed to determine the catalog hash size for '{}': {}",
            dsregcmd_path.display(),
            std::io::Error::last_os_error()
        )));
    }

    let mut hash = vec![0u8; hash_len as usize];
    let hash_status = unsafe {
        CryptCATAdminCalcHashFromFileHandle(file_handle, &mut hash_len, hash.as_mut_ptr(), 0)
    };
    if hash_status == 0 {
        return Err(crate::error::AppError::Internal(format!(
            "Failed to calculate the catalog hash for '{}': {}",
            dsregcmd_path.display(),
            std::io::Error::last_os_error()
        )));
    }
    hash.truncate(hash_len as usize);

    let mut previous_catalog_context = 0isize;
    let catalog_context = unsafe {
        CryptCATAdminEnumCatalogFromHash(
            cat_admin.0,
            hash.as_ptr(),
            hash_len,
            0,
            &mut previous_catalog_context,
        )
    };
    if catalog_context == 0 {
        return Ok(false);
    }
    let catalog = CatalogContextHandle {
        admin_handle: cat_admin.0,
        catalog_handle: catalog_context,
    };

    let mut catalog_info = CatalogInfo {
        cb_struct: std::mem::size_of::<CatalogInfo>() as u32,
        wsz_catalog_file: [0; 260],
    };
    let catalog_info_status =
        unsafe { CryptCATCatalogInfoFromContext(catalog.catalog_handle, &mut catalog_info, 0) };
    if catalog_info_status == 0 {
        return Err(crate::error::AppError::Internal(format!(
            "Failed to read catalog metadata for '{}': {}",
            dsregcmd_path.display(),
            std::io::Error::last_os_error()
        )));
    }

    let member_tag = hex_encode_wide(&hash);
    let member_path = dsregcmd_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    let mut catalog_trust_info = WinTrustCatalogInfo {
        cb_struct: std::mem::size_of::<WinTrustCatalogInfo>() as u32,
        dw_catalog_version: 0,
        pcwsz_catalog_file_path: catalog_info.wsz_catalog_file.as_ptr(),
        pcwsz_member_tag: member_tag.as_ptr(),
        pcwsz_member_file_path: member_path.as_ptr(),
        h_member_file: file_handle,
        pb_calculated_file_hash: hash.as_mut_ptr(),
        cb_calculated_file_hash: hash_len,
        pc_catalog_context: null_mut(),
        h_cat_admin: cat_admin.0,
    };

    let mut trust_data = WinTrustData {
        cb_struct: std::mem::size_of::<WinTrustData>() as u32,
        p_policy_callback_data: null_mut(),
        p_sip_client_data: null_mut(),
        dw_ui_choice: WTD_UI_NONE,
        fdw_revocation_checks: WTD_REVOKE_NONE,
        dw_union_choice: WTD_CHOICE_CATALOG,
        anonymous: WinTrustDataChoice {
            p_catalog: &mut catalog_trust_info,
        },
        dw_state_action: WTD_STATEACTION_IGNORE,
        h_wvtstate_data: 0,
        pwsz_url_reference: null(),
        dw_prov_flags: 0,
        dw_ui_context: 0,
        p_signature_settings: null_mut(),
    };

    let status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut trust_data as *mut _ as *mut c_void,
        )
    };

    Ok(status == 0)
}

#[cfg(target_os = "windows")]
fn hex_encode_wide(bytes: &[u8]) -> Vec<u16> {
    let mut wide = Vec::with_capacity((bytes.len() * 2) + 1);
    for byte in bytes {
        let upper = byte >> 4;
        let lower = byte & 0x0F;
        wide.push(nibble_to_hex(upper) as u16);
        wide.push(nibble_to_hex(lower) as u16);
    }
    wide.push(0);
    wide
}

#[cfg(target_os = "windows")]
const fn nibble_to_hex(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'A' + (nibble - 10),
    }
}

#[cfg(target_os = "windows")]
fn format_winverifytrust_status(status: i32) -> String {
    match status as u32 {
        0x800B0100 => "0x800B0100 (TRUST_E_NOSIGNATURE)".to_string(),
        0x800B0101 => "0x800B0101 (CERT_E_EXPIRED)".to_string(),
        0x800B0109 => "0x800B0109 (CERT_E_UNTRUSTEDROOT)".to_string(),
        0x80096010 => "0x80096010 (TRUST_E_BAD_DIGEST)".to_string(),
        code => format!("0x{code:08X}"),
    }
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WinTrustFileInfo {
    cb_struct: u32,
    pcwsz_file_path: *mut u16,
    h_file: isize,
    pg_known_subject: *const Guid,
}

#[cfg(target_os = "windows")]
#[repr(C)]
union WinTrustDataChoice {
    p_file: *mut WinTrustFileInfo,
    p_catalog: *mut WinTrustCatalogInfo,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WinTrustData {
    cb_struct: u32,
    p_policy_callback_data: *mut c_void,
    p_sip_client_data: *mut c_void,
    dw_ui_choice: u32,
    fdw_revocation_checks: u32,
    dw_union_choice: u32,
    anonymous: WinTrustDataChoice,
    dw_state_action: u32,
    h_wvtstate_data: isize,
    pwsz_url_reference: *const u16,
    dw_prov_flags: u32,
    dw_ui_context: u32,
    p_signature_settings: *mut c_void,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WinTrustCatalogInfo {
    cb_struct: u32,
    dw_catalog_version: u32,
    pcwsz_catalog_file_path: *const u16,
    pcwsz_member_tag: *const u16,
    pcwsz_member_file_path: *const u16,
    h_member_file: isize,
    pb_calculated_file_hash: *mut u8,
    cb_calculated_file_hash: u32,
    pc_catalog_context: *mut c_void,
    h_cat_admin: isize,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct CatalogInfo {
    cb_struct: u32,
    wsz_catalog_file: [u16; 260],
}

#[cfg(target_os = "windows")]
struct CatalogAdminHandle(isize);

#[cfg(target_os = "windows")]
impl Drop for CatalogAdminHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                CryptCATAdminReleaseContext(self.0, 0);
            }
        }
    }
}

#[cfg(target_os = "windows")]
struct CatalogContextHandle {
    admin_handle: isize,
    catalog_handle: isize,
}

#[cfg(target_os = "windows")]
impl Drop for CatalogContextHandle {
    fn drop(&mut self) {
        if self.catalog_handle != 0 {
            unsafe {
                CryptCATAdminReleaseCatalogContext(self.admin_handle, self.catalog_handle, 0);
            }
        }
    }
}

#[cfg(target_os = "windows")]
const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
    data1: 0x00AAC56B,
    data2: 0xCD44,
    data3: 0x11D0,
    data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

#[cfg(target_os = "windows")]
const WTD_UI_NONE: u32 = 2;
#[cfg(target_os = "windows")]
const WTD_REVOKE_NONE: u32 = 0;
#[cfg(target_os = "windows")]
const WTD_CHOICE_FILE: u32 = 1;
#[cfg(target_os = "windows")]
const WTD_CHOICE_CATALOG: u32 = 2;
#[cfg(target_os = "windows")]
const WTD_STATEACTION_IGNORE: u32 = 0;
#[cfg(target_os = "windows")]
const TRUST_E_NOSIGNATURE: u32 = 0x800B0100;

#[cfg(target_os = "windows")]
const DRIVER_ACTION_VERIFY: Guid = Guid {
    data1: 0xF750E6C3,
    data2: 0x38EE,
    data3: 0x11D1,
    data4: [0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

#[cfg(target_os = "windows")]
#[link(name = "wintrust")]
extern "system" {
    fn WinVerifyTrust(hwnd: *mut c_void, pg_action_id: *const Guid, p_wvt_data: *mut c_void)
        -> i32;
    fn CryptCATAdminAcquireContext(
        ph_cat_admin: *mut isize,
        pg_subsystem: *const Guid,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminCalcHashFromFileHandle(
        h_file: isize,
        pcb_hash: *mut u32,
        pb_hash: *mut u8,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminEnumCatalogFromHash(
        h_cat_admin: isize,
        pb_hash: *const u8,
        cb_hash: u32,
        dw_flags: u32,
        ph_prev_cat_info: *mut isize,
    ) -> isize;
    fn CryptCATCatalogInfoFromContext(
        h_cat_info: isize,
        ps_cat_info: *mut CatalogInfo,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminReleaseCatalogContext(
        h_cat_admin: isize,
        h_cat_info: isize,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminReleaseContext(h_cat_admin: isize, dw_flags: u32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::analyze_dsregcmd;
    #[cfg(not(target_os = "windows"))]
    use super::capture_dsregcmd;
    use super::export_dsregcmd_shareable_bundle_blocking;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    const DSREGCMD_SAMPLE: &str = r#"
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+
 AzureAdJoined : YES
 DomainJoined = NO
 WorkplaceJoined : NO
 EnterpriseJoined : NO
 TenantId : 11111111-2222-3333-4444-555555555555
 DeviceId : abcdefab-1111-2222-3333-abcdefabcdef
 TenantName : Contoso
 MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
 dmComplianceUrl : https://portal.manage.microsoft.com/Compliance
 AzureAdPrt : YES
 AzureAdPrtUpdateTime : 2025-03-10 10:00:00.000 UTC
 Previous Prt Attempt : 2025-03-10 09:55:00.000 UTC
 Attempt Status : 0xc000006d
 HTTP status : 401
 User Context : SYSTEM
 SessionIsNotRemote : NO
 AD Connectivity Test : PASS
 DRS Discovery Test : FAIL [0x801c0021]
 Client ErrorCode : 0x801c03f2
 KeySignTest : PASSED
 AadRecoveryEnabled : NO
 DeviceCertificateValidity : [ 2025-03-01 00:00:00.000 UTC -- 2025-03-20 00:00:00.000 UTC ]
"#;

    static DSREGCMD_TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn dsregcmd_test_env_lock() -> &'static Mutex<()> {
        DSREGCMD_TEST_ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    struct SimulatedBundleIoEnvGuard;

    impl SimulatedBundleIoEnvGuard {
        fn set(delay_ms: u64) -> Self {
            std::env::set_var("CMTRACE_SIMULATE_BUNDLE_IO_MS", delay_ms.to_string());
            Self
        }
    }

    impl Drop for SimulatedBundleIoEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("CMTRACE_SIMULATE_BUNDLE_IO_MS");
        }
    }

    fn write_bundle_json<T: serde::Serialize>(path: &Path, value: &T) {
        let json = serde_json::to_string_pretty(value).expect("serialize bundle fixture");
        std::fs::write(path, json).expect("write bundle fixture");
    }

    fn build_dsregcmd_bundle_fixture() -> tempfile::TempDir {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command_output_dir = temp_dir.path().join("evidence").join("command-output");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        let connectivity_dir = temp_dir.path().join("evidence").join("connectivity");
        let event_logs_dir = temp_dir.path().join("evidence").join("event-logs");
        let scheduled_tasks_dir = temp_dir.path().join("evidence").join("scheduled-tasks");

        std::fs::create_dir_all(&command_output_dir).expect("create command output dir");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");
        std::fs::create_dir_all(&connectivity_dir).expect("create connectivity dir");
        std::fs::create_dir_all(&event_logs_dir).expect("create event logs dir");
        std::fs::create_dir_all(&scheduled_tasks_dir).expect("create scheduled tasks dir");

        std::fs::write(
            temp_dir.path().join("manifest.json"),
            "{\n  \"manifestPath\": \"manifest.json\"\n}\n",
        )
        .expect("write manifest");
        std::fs::write(
            command_output_dir.join("dsregcmd-status.txt"),
            DSREGCMD_SAMPLE,
        )
        .expect("write dsregcmd status sample");

        std::fs::write(
            registry_dir.join("policymanager-device.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\Current\Device\PassportForWork\Policies]
    "UsePassportForWork"=dword:00000001
    "DisablePostLogonProvisioning"=dword:00000000
    "EnablePinRecovery"=dword:00000001
"#,
        )
        .expect("write current registry sample");
        std::fs::write(
            registry_dir.join("policymanager-providers.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\Providers\{11111111-1111-1111-1111-111111111111}\default\Device\PassportForWork\Policies]
    "UsePassportForWork"=dword:00000001
    "DisablePostLogonProvisioning"=dword:00000000
"#,
        )
        .expect("write provider registry sample");
        std::fs::write(
            registry_dir.join("os-version.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion]
    "CurrentBuild"="22631"
    "DisplayVersion"="23H2"
    "ProductName"="Windows 11 Enterprise"
    "UBR"=dword:00000FA0
    "EditionID"="Enterprise"
"#,
        )
        .expect("write os version sample");
        std::fs::write(
            registry_dir.join("proxy-internet-settings.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings]
    "ProxyEnable"=dword:00000001
    "ProxyServer"="http://proxy.contoso.com:8080"
    "ProxyOverride"="*.contoso.com;localhost"
    "AutoConfigURL"="http://wpad.contoso.com/wpad.dat"
"#,
        )
        .expect("write proxy sample");
        std::fs::write(
            registry_dir.join("enrollments.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\{11111111-2222-3333-4444-555555555555}]
    "UPN"="user@contoso.com"
    "ProviderID"="MS DM Server"
    "EnrollmentState"=dword:00000001
"#,
        )
        .expect("write enrollment sample");

        let connectivity_tests = vec![crate::dsregcmd::DsregcmdConnectivityResult {
            endpoint: "https://enterpriseregistration.windows.net".to_string(),
            reachable: true,
            status_code: Some(200),
            latency_ms: Some(42),
            error_message: None,
            timestamp: "2026-09-18T00:00:00Z".to_string(),
        }];
        write_bundle_json(
            &connectivity_dir.join("endpoint-tests.json"),
            &connectivity_tests,
        );
        write_bundle_json(
            &connectivity_dir.join("scp-query.json"),
            &crate::dsregcmd::DsregcmdScpQueryResult {
                scp_found: true,
                tenant_domain: Some("contoso.com".to_string()),
                azuread_id: Some("11111111-2222-3333-4444-555555555555".to_string()),
                keywords: vec!["azureADId:11111111-2222-3333-4444-555555555555".to_string()],
                domain_controller: Some("dc1.contoso.com".to_string()),
                error: None,
            },
        );
        write_bundle_json(
            &scheduled_tasks_dir.join("enterprise-mgmt-tasks.json"),
            &crate::dsregcmd::DsregcmdScheduledTaskEvidence {
                enterprise_mgmt_guids: vec!["{11111111-2222-3333-4444-555555555555}".to_string()],
            },
        );
        write_bundle_json(
            &event_logs_dir.join("dsregcmd-events.json"),
            &crate::intune::models::EventLogAnalysis::default(),
        );

        temp_dir
    }

    #[test]
    fn bundle_analysis_no_longer_blocks_the_command_thread_on_slow_storage() {
        let _env_guard = dsregcmd_test_env_lock()
            .lock()
            .expect("lock dsregcmd env guard");
        let _simulated_io = SimulatedBundleIoEnvGuard::set(150);
        let bundle = build_dsregcmd_bundle_fixture();

        // A current-thread runtime models Tauri's serialized command dispatch:
        // one worker runs everything. Before the seam moved the analysis to
        // the blocking pool, a synchronous command stalled every other queued
        // task for the full analysis duration.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime");
        runtime.block_on(async move {
            let spawned_at = Instant::now();
            let unrelated_task = tokio::spawn(async move { spawned_at.elapsed() });

            let analysis_started = Instant::now();
            let result = analyze_dsregcmd(
                DSREGCMD_SAMPLE.to_string(),
                Some(bundle.path().to_string_lossy().to_string()),
            )
            .await
            .expect("analyze dsregcmd bundle fixture");
            let total_analysis_duration = analysis_started.elapsed();
            let unrelated_latency = unrelated_task.await.expect("join unrelated latency task");

            assert!(result.active_evidence.is_some(), "expected active evidence");
            assert!(
                result.scheduled_task_evidence.is_some(),
                "expected scheduled task evidence"
            );
            assert!(
                result.event_log_analysis.is_some(),
                "expected event log analysis"
            );

            println!(
                "bundle_analysis_no_longer_blocks_the_command_thread_on_slow_storage total_analysis_ms={} unrelated_task_latency_ms={}",
                total_analysis_duration.as_millis(),
                unrelated_latency.as_millis()
            );

            assert!(
                total_analysis_duration >= Duration::from_millis(7 * 140),
                "expected simulated bundle analysis to take at least 980ms, saw {:?}",
                total_analysis_duration
            );
            assert!(
                unrelated_latency < Duration::from_millis(100),
                "expected the command thread to stay responsive while the analysis runs off-thread; total={:?} unrelated={:?}",
                total_analysis_duration,
                unrelated_latency
            );
        });
    }

    // -----------------------------------------------------------------------
    // The shareable bundle hand-off (issue #628)
    // -----------------------------------------------------------------------

    const EXPORT_TENANT_ID: &str = "8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90";
    const EXPORT_TENANT_DOMAIN: &str = "contoso.onmicrosoft.com";
    const EXPORT_ON_PREMISES_DOMAIN: &str = "corp.contoso.com";
    const EXPORT_DEVICE_ID: &str = "4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b";
    const EXPORT_THUMBPRINT: &str = "8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D";
    const EXPORT_UPN: &str = "adele.vance@contoso.onmicrosoft.com";
    const EXPORT_COMPUTER: &str = "HELPDESK-LAPTOP01.corp.contoso.com";

    /// Every identifier the hand-off has to keep out of a shareable artefact,
    /// with the class it belongs to for the failure message.
    const EXPORT_IDENTIFIERS: &[(&str, &str)] = &[
        ("tenant id", EXPORT_TENANT_ID),
        ("tenant domain", EXPORT_TENANT_DOMAIN),
        ("on-premises domain", EXPORT_ON_PREMISES_DOMAIN),
        ("device id", EXPORT_DEVICE_ID),
        ("certificate thumbprint", EXPORT_THUMBPRINT),
        ("user principal name", EXPORT_UPN),
        ("event log computer name", EXPORT_COMPUTER),
    ];

    /// Every artifact a bundle of this shape is expected to export, so a
    /// projection that quietly dropped evidence fails rather than passes on the
    /// files it happened to write.
    const EXPORT_EXPECTED_ARTIFACTS: &[&str] = &[
        "manifest.json",
        "evidence/command-output/dsregcmd-status.txt",
        "evidence/registry/cdj-joininfo.reg",
        "evidence/connectivity/scp-query.json",
        "evidence/event-logs/dsregcmd-events.json",
    ];

    /// A bundle laid out the way a live capture lays one out, with an identifier
    /// of every masked class planted in more than one artifact — including the
    /// occurrences no shaped rule reaches, such as the tenant id sitting
    /// unlabelled in a registry key path.
    fn build_shareable_export_fixture() -> tempfile::TempDir {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command_output_dir = temp_dir.path().join("evidence").join("command-output");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        let connectivity_dir = temp_dir.path().join("evidence").join("connectivity");
        let event_logs_dir = temp_dir.path().join("evidence").join("event-logs");

        std::fs::create_dir_all(&command_output_dir).expect("create command output dir");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");
        std::fs::create_dir_all(&connectivity_dir).expect("create connectivity dir");
        std::fs::create_dir_all(&event_logs_dir).expect("create event logs dir");

        std::fs::write(
            temp_dir.path().join("manifest.json"),
            "{\n  \"manifestPath\": \"manifest.json\",\n  \"source\": \"live-dsregcmd-capture\"\n}\n",
        )
        .expect("write manifest");

        std::fs::write(
            command_output_dir.join("dsregcmd-status.txt"),
            format!(
                " AzureAdJoined : YES\n \
                 DomainJoined : YES\n \
                 TenantId : {EXPORT_TENANT_ID}\n \
                 TenantName : {EXPORT_TENANT_DOMAIN}\n \
                 DomainName : {EXPORT_ON_PREMISES_DOMAIN}\n \
                 DeviceId : {EXPORT_DEVICE_ID}\n \
                 Thumbprint : {EXPORT_THUMBPRINT}\n \
                 User Identity : {EXPORT_UPN}\n"
            ),
        )
        .expect("write dsregcmd status sample");

        std::fs::write(
            registry_dir.join("cdj-joininfo.reg"),
            format!(
                "Windows Registry Editor Version 5.00\n\n\
                 [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo\\{EXPORT_TENANT_ID}]\n\
                 \"UserEmail\"=\"{EXPORT_UPN}\"\n\
                 \"IdpDomain\"=\"{EXPORT_TENANT_DOMAIN}\"\n"
            ),
        )
        .expect("write cloud domain join sample");

        write_bundle_json(
            &connectivity_dir.join("scp-query.json"),
            &crate::dsregcmd::DsregcmdScpQueryResult {
                scp_found: true,
                tenant_domain: Some(EXPORT_TENANT_DOMAIN.to_string()),
                azuread_id: Some(EXPORT_TENANT_ID.to_string()),
                keywords: vec![format!("azureADId:{EXPORT_TENANT_ID}")],
                domain_controller: Some(format!("dc1.{EXPORT_ON_PREMISES_DOMAIN}")),
                error: None,
            },
        );
        write_bundle_json(
            &event_logs_dir.join("dsregcmd-events.json"),
            &crate::intune::models::EventLogAnalysis {
                source_kind: crate::intune::models::EventLogAnalysisSource::Live,
                entries: vec![crate::intune::models::EventLogEntry {
                    id: 1,
                    channel: crate::intune::models::EventLogChannel::AadOperational,
                    channel_display: "AAD Operational".to_string(),
                    provider: "Microsoft-Windows-AAD".to_string(),
                    event_id: 1103,
                    severity: crate::intune::models::EventLogSeverity::Error,
                    timestamp: "2026-08-26T09:15:00Z".to_string(),
                    computer: Some(EXPORT_COMPUTER.to_string()),
                    message: format!("registration failed for {EXPORT_UPN}"),
                    correlation_activity_id: None,
                    source_file: "AAD.evtx".to_string(),
                }],
                ..Default::default()
            },
        );

        temp_dir
    }

    /// Every file in a bundle tree, read as text and joined, so one assertion
    /// covers the whole artefact instead of the file a leak was expected in.
    fn read_bundle_tree_text(root: &Path) -> String {
        let mut files = Vec::new();
        collect_files_for_test(root, &mut files);
        files.sort();
        files
            .iter()
            .map(|path| std::fs::read_to_string(path).expect("read bundle artifact"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn collect_files_for_test(directory: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(directory).expect("read bundle folder") {
            let entry = entry.expect("read bundle entry");
            let path = entry.path();
            if path.is_dir() {
                collect_files_for_test(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    /// The acceptance criteria at the command layer: the artefact a support
    /// engineer would send carries none of the identifiers, it carries every
    /// artifact the bundle held, and the working copy the analyzer reads is left
    /// exactly as it was.
    #[test]
    fn exporting_writes_a_shareable_bundle_and_leaves_the_working_copy_raw() {
        let bundle = build_shareable_export_fixture();
        let raw_before = read_bundle_tree_text(bundle.path());
        for (label, marker) in EXPORT_IDENTIFIERS {
            assert!(
                raw_before.contains(marker),
                "the fixture no longer plants the {label}; the export assertion is vacuous"
            );
        }

        let destination = tempfile::tempdir().expect("create destination dir");
        let exported = export_dsregcmd_shareable_bundle_blocking(
            &bundle.path().to_string_lossy(),
            &destination.path().to_string_lossy(),
        )
        .expect("export the shareable bundle");

        let shareable_root = Path::new(&exported.bundle_path);
        for expected in EXPORT_EXPECTED_ARTIFACTS {
            assert!(
                shareable_root.join(expected).is_file(),
                "the shareable bundle is missing '{expected}'"
            );
        }
        assert_eq!(
            exported.artifact_count,
            EXPORT_EXPECTED_ARTIFACTS.len(),
            "the export did not carry every artifact the bundle held"
        );

        let shareable = read_bundle_tree_text(shareable_root);
        for (label, marker) in EXPORT_IDENTIFIERS {
            assert!(
                !shareable.contains(marker),
                "the shareable bundle leaks the {label} ({marker}): {shareable}"
            );
        }
        assert!(
            shareable.contains("\"projection\": \"dsregcmd-redacted\""),
            "the shareable bundle does not say that it is a projection: {shareable}"
        );

        assert_eq!(
            read_bundle_tree_text(bundle.path()),
            raw_before,
            "exporting rewrote the working bundle instead of projecting a copy"
        );
    }

    #[test]
    fn exporting_refuses_a_folder_that_is_not_a_bundle() {
        let not_a_bundle = tempfile::tempdir().expect("create temp dir");
        let destination = tempfile::tempdir().expect("create destination dir");

        let error = export_dsregcmd_shareable_bundle_blocking(
            &not_a_bundle.path().to_string_lossy(),
            &destination.path().to_string_lossy(),
        )
        .expect_err("expected a non-bundle folder to be refused");

        assert!(
            error
                .to_string()
                .contains("not a supported dsregcmd evidence bundle"),
            "expected the bundle-location error, saw: {error}"
        );
    }

    /// A bundle with no command output classifies nothing, and an artefact
    /// written from it would look projected without being projected.
    #[test]
    fn exporting_refuses_a_bundle_with_no_command_output() {
        let bundle = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            bundle.path().join("manifest.json"),
            "{\n  \"manifestPath\": \"manifest.json\"\n}\n",
        )
        .expect("write manifest");
        let destination = tempfile::tempdir().expect("create destination dir");

        let error = export_dsregcmd_shareable_bundle_blocking(
            &bundle.path().to_string_lossy(),
            &destination.path().to_string_lossy(),
        )
        .expect_err("expected a bundle with no command output to be refused");

        assert!(
            error
                .to_string()
                .contains("does not contain dsregcmd evidence"),
            "expected the missing-evidence error, saw: {error}"
        );
    }

    /// A minimal bundle holding one planted registry artifact, written with the
    /// bytes supplied.
    fn build_bundle_with_registry_artifact(contents: &[u8]) -> tempfile::TempDir {
        let bundle = tempfile::tempdir().expect("create temp dir");
        let command_output_dir = bundle.path().join("evidence").join("command-output");
        let registry_dir = bundle.path().join("evidence").join("registry");
        std::fs::create_dir_all(&command_output_dir).expect("create command output dir");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");

        std::fs::write(
            bundle.path().join("manifest.json"),
            "{\n  \"manifestPath\": \"manifest.json\"\n}\n",
        )
        .expect("write manifest");
        std::fs::write(
            command_output_dir.join("dsregcmd-status.txt"),
            format!(
                " AzureAdJoined : YES\n TenantId : {EXPORT_TENANT_ID}\n TenantName : {EXPORT_TENANT_DOMAIN}\n"
            ),
        )
        .expect("write dsregcmd status sample");
        std::fs::write(registry_dir.join("enrollments.reg"), contents)
            .expect("write registry artifact");

        bundle
    }

    /// A real capture's `.reg` exports are frequently UTF-16LE, because that is
    /// what `reg.exe` writes. Reading an artifact as UTF-8 alone rejected the
    /// whole export, so the decode order is pinned here rather than assumed.
    #[test]
    fn exporting_decodes_a_utf16le_registry_artifact_rather_than_rejecting_it() {
        let reg_content = format!(
            "Windows Registry Editor Version 5.00\r\n\r\n\
             [HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments]\r\n\
             \"UPN\"=\"{EXPORT_UPN}\"\r\n"
        );
        let mut utf16 = vec![0xFF, 0xFE];
        for unit in reg_content.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }

        let bundle = build_bundle_with_registry_artifact(&utf16);
        let destination = tempfile::tempdir().expect("create destination dir");
        let exported = export_dsregcmd_shareable_bundle_blocking(
            &bundle.path().to_string_lossy(),
            &destination.path().to_string_lossy(),
        )
        .expect("export a bundle whose registry artifact is UTF-16LE");

        let shareable = read_bundle_tree_text(Path::new(&exported.bundle_path));
        assert!(
            shareable.contains("Windows Registry Editor Version 5.00"),
            "the UTF-16 export was not decoded into readable text: {shareable}"
        );
        assert!(
            !shareable.contains(EXPORT_UPN),
            "the decoded artifact still leaks the enrollment user principal name: {shareable}"
        );
    }

    /// Binary content has no text representation, and shipping it as mojibake
    /// would corrupt evidence silently where failing says so.
    #[test]
    fn exporting_refuses_an_artifact_that_is_not_text() {
        let binary = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10";

        let bundle = build_bundle_with_registry_artifact(binary);
        let destination = tempfile::tempdir().expect("create destination dir");
        let error = export_dsregcmd_shareable_bundle_blocking(
            &bundle.path().to_string_lossy(),
            &destination.path().to_string_lossy(),
        )
        .expect_err("expected a non-text artifact to be refused");

        assert!(
            error.to_string().contains("is not text"),
            "expected the non-text-artifact error, saw: {error}"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn capture_command_returns_clear_error_on_unsupported_platform() {
        let error = tauri::async_runtime::block_on(capture_dsregcmd())
            .expect_err("expected unsupported platform error");
        assert!(error.to_string().contains("only supported on Windows"));
    }
    #[test]
    fn network_issue_and_endpoint_unreachable_both_fire() {
        use super::analyze_dsregcmd;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let connectivity_dir = temp_dir.path().join("evidence").join("connectivity");
        std::fs::create_dir_all(&connectivity_dir).expect("create connectivity dir");
        std::fs::write(
            connectivity_dir.join("endpoint-tests.json"),
            r#"[{"endpoint":"https://enterpriseregistration.windows.net","reachable":false,"statusCode":null,"latencyMs":100,"errorMessage":"timeout","timestamp":"2026-01-01T00:00:00Z"}]"#,
        )
        .expect("write endpoint tests");

        let input = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 AzureAdPrt : NO
 DRS Discovery Test : FAIL [0x801c0021]
 Server Message : ERROR_WINHTTP_TIMEOUT
"#;

        // The command is async since the bundle analysis moved to the blocking
        // pool (issue #627), so a test reaches it through the runtime.
        let result = tauri::async_runtime::block_on(analyze_dsregcmd(
            input.to_string(),
            Some(temp_dir.path().to_string_lossy().to_string()),
        ))
        .expect("analyze dsregcmd");

        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.id == "endpoint-unreachable-drs"),
            "endpoint-unreachable-drs should fire for the unreachable DRS endpoint"
        );
        assert!(
            result.diagnostics.iter().any(|d| d.id == "network-issue"),
            "network-issue carries the marker code from the capture text and is independent evidence"
        );
    }
}
