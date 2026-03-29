use crate::dsregcmd::{analyze_text, registry, rules, DsregcmdAnalysisResult};
#[cfg(target_os = "windows")]
use crate::dsregcmd::connectivity;

use serde::{Deserialize, Serialize};
use std::path::Path;
#[cfg(target_os = "windows")]
use std::ffi::c_void;
#[cfg(target_os = "windows")]
use std::fs::{self, File};
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::ptr::{null, null_mut};
#[cfg(target_os = "windows")]
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
pub fn analyze_dsregcmd(
    input: String,
    bundle_path: Option<String>,
) -> Result<DsregcmdAnalysisResult, crate::error::AppError> {
    eprintln!(
        "event=dsregcmd_analysis_start input_chars={} input_lines={}",
        input.len(),
        input.lines().count()
    );

    let mut result = analyze_text(&input)?;

    if let Some(bundle_path) = bundle_path.as_deref() {
        let bp = Path::new(bundle_path);
        result.policy_evidence = registry::load_whfb_policy_evidence(bp);
        result.os_version = registry::load_os_version_evidence(bp);
        result.proxy_evidence = registry::load_proxy_evidence(bp);
        result.enrollment_evidence = registry::load_enrollment_evidence(bp);
        result.active_evidence = load_active_evidence_from_bundle(bp);
        result.scheduled_task_evidence = load_scheduled_task_evidence_from_bundle(bp);
        result.event_log_analysis = load_event_log_from_bundle(bp);
    }

    rules::apply_enrollment_cross_reference(&mut result);

    // Run extended diagnostics (Phase 2, 3, 4) after all evidence is loaded
    let mut extended = rules::build_extended_diagnostics(&result);
    extended.append(&mut rules::build_active_diagnostics_rules(&result));
    extended.append(&mut rules::build_event_log_diagnostics(&result));
    result.diagnostics.append(&mut extended);

    eprintln!(
        "event=dsregcmd_analysis_complete diagnostics_count={} join_type={:?}",
        result.diagnostics.len(),
        result.derived.join_type
    );

    Ok(result)
}

fn load_active_evidence_from_bundle(
    bundle_path: &Path,
) -> Option<crate::dsregcmd::DsregcmdActiveEvidence> {
    let connectivity_dir = bundle_path.join("evidence").join("connectivity");

    let tests_path = connectivity_dir.join("endpoint-tests.json");
    let scp_path = connectivity_dir.join("scp-query.json");

    let connectivity_tests: Vec<crate::dsregcmd::DsregcmdConnectivityResult> =
        std::fs::read_to_string(&tests_path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();

    let scp_query: Option<crate::dsregcmd::DsregcmdScpQueryResult> =
        std::fs::read_to_string(&scp_path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok());

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
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
}

fn load_scheduled_task_evidence_from_bundle(
    bundle_path: &Path,
) -> Option<crate::dsregcmd::DsregcmdScheduledTaskEvidence> {
    let path = bundle_path
        .join("evidence")
        .join("scheduled-tasks")
        .join("enterprise-mgmt-tasks.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
}


#[tauri::command]
pub fn capture_dsregcmd() -> Result<DsregcmdCaptureResult, crate::error::AppError> {
    capture_dsregcmd_impl()
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
    eprintln!("event=dsregcmd_capture_start platform=windows");

    cleanup_old_capture_bundles();

    let dsregcmd_path = resolve_system32_binary("dsregcmd.exe")?;
    verify_dsregcmd_signature(&dsregcmd_path)?;

    let output = std::process::Command::new(&dsregcmd_path)
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

    eprintln!(
        "event=dsregcmd_capture_complete platform=windows stdout_chars={} stdout_lines={} bundle_path={}",
        stdout.len(),
        stdout.lines().count(),
        capture_bundle.bundle_path.display()
    );

    Ok(DsregcmdCaptureResult {
        input: stdout,
        bundle_path: Some(capture_bundle.bundle_path.to_string_lossy().to_string()),
        evidence_file_path: Some(capture_bundle.evidence_file_path.to_string_lossy().to_string()),
    })
}

#[cfg(not(target_os = "windows"))]
fn capture_dsregcmd_impl() -> Result<DsregcmdCaptureResult, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported("dsregcmd capture is only supported on Windows.".to_string()))
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
    Err(crate::error::AppError::PlatformUnsupported("dsregcmd source loading is only supported on Windows.".to_string()))
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

#[cfg(target_os = "windows")]
const DSREGCMD_EVIDENCE_RELATIVE_PATH: [&str; 3] = ["evidence", "command-output", "dsregcmd-status.txt"];
#[cfg(target_os = "windows")]
const DSREGCMD_TOP_LEVEL_FALLBACK_FILE: &str = "dsregcmd-status.txt";
#[cfg(target_os = "windows")]
const MANIFEST_FILE: &str = "manifest.json";
#[cfg(target_os = "windows")]
const EVIDENCE_FOLDER_NAME: &str = "evidence";
#[cfg(target_os = "windows")]
const COMMAND_OUTPUT_FOLDER_NAME: &str = "command-output";

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

    export_live_registry_evidence(&evidence_registry);

    // Phase 3: Active diagnostics (connectivity + SCP)
    let evidence_connectivity = bundle_path.join("evidence").join("connectivity");
    if fs::create_dir_all(&evidence_connectivity).is_ok() {
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
fn resolve_folder_bundle_evidence(folder_path: &Path) -> Result<(PathBuf, PathBuf), crate::error::AppError> {
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
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
        eprintln!(
            "event=dsregcmd_registry_export_skipped reason=reg_not_found registry_root={}",
            registry_root.display()
        );
        return;
    };

    for export in LIVE_CAPTURE_REGISTRY_EXPORTS {
        let output_path = registry_root.join(export.file_name);
        match std::process::Command::new(&reg_path)
            .args(["export", export.key_path, &output_path.to_string_lossy(), "/y"])
            .output()
        {
            Ok(output) if output.status.success() => {
                eprintln!(
                    "event=dsregcmd_registry_export_complete key={} file={}",
                    export.key_path,
                    output_path.display()
                );
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                eprintln!(
                    "event=dsregcmd_registry_export_failed key={} file={} exit_code={} stderr={}",
                    export.key_path,
                    output_path.display(),
                    output.status.code().unwrap_or_default(),
                    stderr
                );
            }
            Err(error) => {
                eprintln!(
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
            eprintln!("event=dsregcmd_schtasks_skipped reason={e}");
            return evidence;
        }
    };

    let output = match std::process::Command::new(&schtasks_path)
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
            eprintln!("event=dsregcmd_schtasks_failed error={e}");
            return evidence;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        eprintln!(
            "event=dsregcmd_schtasks_failed exit_code={} stderr={}",
            output.status.code().unwrap_or_default(),
            stderr
        );
        return evidence;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let guid_re = Regex::new(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}")
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

    eprintln!(
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
        return Err(crate::error::AppError::Internal("WINDIR is not set; could not resolve the Windows system path.".to_string()));
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
        eprintln!(
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
    let acquired = unsafe {
        CryptCATAdminAcquireContext(&mut cat_admin_handle, &DRIVER_ACTION_VERIFY, 0)
    };
    if acquired == 0 {
        return Err(crate::error::AppError::Internal(format!(
            "Failed to acquire a catalog admin context for '{}': {}",
            dsregcmd_path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let cat_admin = CatalogAdminHandle(cat_admin_handle);

    let mut hash_len = 0u32;
    let hash_size_status = unsafe {
        CryptCATAdminCalcHashFromFileHandle(file_handle, &mut hash_len, null_mut(), 0)
    };
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
    let catalog_info_status = unsafe {
        CryptCATCatalogInfoFromContext(catalog.catalog_handle, &mut catalog_info, 0)
    };
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
    fn WinVerifyTrust(hwnd: *mut c_void, pg_action_id: *const Guid, p_wvt_data: *mut c_void) -> i32;
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
    #[cfg(not(target_os = "windows"))]
    use super::capture_dsregcmd;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn capture_command_returns_clear_error_on_unsupported_platform() {
        let error = capture_dsregcmd().expect_err("expected unsupported platform error");
        assert!(error.to_string().contains("only supported on Windows"));
    }
}
