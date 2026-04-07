//! Windows device scanner for Secure Boot certificate state.
//!
//! On non-Windows platforms this module provides only a stub that returns
//! `AppError::PlatformUnsupported`. The real implementation compiles only on
//! `target_os = "windows"`.

use super::models::SecureBootScanState;

// ---------------------------------------------------------------------------
// Non-Windows stub
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
pub fn scan_device() -> Result<SecureBootScanState, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported(
        "Secure Boot device scan is only supported on Windows".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn scan_device() -> Result<SecureBootScanState, crate::error::AppError> {
    let mut state = SecureBootScanState::default();

    read_registry(&mut state);
    check_filesystem(&mut state);
    run_powershell_checks(&mut state);

    Ok(state)
}

// ---------------------------------------------------------------------------
// Registry helpers (Windows only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn read_registry(state: &mut SecureBootScanState) {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // --- HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State ---------------
    if let Ok(key) = hklm.open_subkey_with_flags(
        r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        KEY_READ,
    ) {
        state.secure_boot_enabled = key.get_value::<u32, _>("UEFISecureBootEnabled").ok().map(|v| v != 0);
    }

    // --- HKLM\SYSTEM\CurrentControlSet\Control\Secureboot ----------------------
    let secureboot_key_path = r"SYSTEM\CurrentControlSet\Control\Secureboot";
    if let Ok(key) = hklm.open_subkey_with_flags(secureboot_key_path, KEY_READ) {
        state.managed_opt_in = key.get_value::<u32, _>("MicrosoftUpdateManagedOptIn").ok();
        state.available_updates = key.get_value::<u32, _>("AvailableUpdates").ok();
        state.uefi_ca2023_status = key.get_value::<u32, _>("UEFICA2023Status").ok();
        state.uefi_ca2023_error = key.get_value::<u32, _>("UEFICA2023Error").ok();
    }

    // --- HKLM\...\SecureBoot\Servicing ------------------------------------------
    let servicing_key_path = r"SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing";
    if let Ok(key) = hklm.open_subkey_with_flags(servicing_key_path, KEY_READ) {
        state.uefi_ca2023_capable = key
            .get_value::<u32, _>("WindowsUEFICA2023Capable")
            .ok();
    }

    // --- HKLM\...\SecureBoot\Servicing\DeviceAttributes -------------------------
    let device_attr_path =
        r"SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes";
    if let Ok(key) = hklm.open_subkey_with_flags(device_attr_path, KEY_READ) {
        state.oem_manufacturer = key
            .get_value::<String, _>("OEMManufacturerName")
            .ok()
            .or_else(|| key.get_value::<String, _>("OEMManufacturer").ok());
        state.oem_model = key
            .get_value::<String, _>("OEMModelNumber")
            .ok()
            .or_else(|| key.get_value::<String, _>("OEMModel").ok());
        state.firmware_version = key.get_value::<String, _>("FirmwareVersion").ok();
        state.firmware_date = key
            .get_value::<String, _>("FirmwareReleaseDate")
            .ok()
            .or_else(|| key.get_value::<String, _>("FirmwareDate").ok());
    }

    // --- HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection ---------------
    if let Ok(key) = hklm.open_subkey_with_flags(
        r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        KEY_READ,
    ) {
        state.telemetry_level = key.get_value::<u32, _>("AllowTelemetry").ok();
    }

    // --- HKLM\SOFTWARE\Mindcore\Secureboot ---------------------------------------
    if let Ok(key) =
        hklm.open_subkey_with_flags(r"SOFTWARE\Mindcore\Secureboot", KEY_READ)
    {
        state.managed_opt_in_date = key.get_value::<String, _>("ManagedOptInDate").ok();
    }

    // --- Pending reboot indicators -----------------------------------------------
    let mut reboot_sources: Vec<String> = Vec::new();

    // CBS RebootPending
    if hklm
        .open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            KEY_READ,
        )
        .is_ok()
    {
        reboot_sources.push("CBS".to_string());
    }

    // Windows Update RebootRequired
    if hklm
        .open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            KEY_READ,
        )
        .is_ok()
    {
        reboot_sources.push("WindowsUpdate".to_string());
    }

    // PendingFileRenameOperations
    if let Ok(key) = hklm.open_subkey_with_flags(
        r"SYSTEM\CurrentControlSet\Control\Session Manager",
        KEY_READ,
    ) {
        if let Ok(values) = key.get_value::<Vec<String>, _>("PendingFileRenameOperations") {
            if !values.is_empty() {
                reboot_sources.push("PendingFileRename".to_string());
            }
        }
    }

    // Windows Update PostRebootReporting
    if hklm
        .open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting",
            KEY_READ,
        )
        .is_ok()
    {
        reboot_sources.push("WUPostReboot".to_string());
    }

    state.pending_reboot_sources = reboot_sources;

    // --- Raw registry dump -------------------------------------------------------
    state.raw_registry_dump = Some(build_raw_registry_dump(&hklm));
}

/// Enumerates all values under the Secureboot and Servicing keys into a
/// human-readable string for debugging.
#[cfg(target_os = "windows")]
fn build_raw_registry_dump(hklm: &winreg::RegKey) -> String {
    use winreg::enums::KEY_READ;

    let mut lines: Vec<String> = Vec::new();

    let paths = [
        r"SYSTEM\CurrentControlSet\Control\Secureboot",
        r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        r"SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing",
        r"SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes",
    ];

    for path in &paths {
        lines.push(format!("[HKLM\\{}]", path));
        match hklm.open_subkey_with_flags(path, KEY_READ) {
            Ok(key) => {
                for value_res in key.enum_values() {
                    match value_res {
                        Ok((name, data)) => {
                            lines.push(format!("  {} = {:?}", name, data));
                        }
                        Err(e) => {
                            lines.push(format!("  <error enumerating value: {}>", e));
                        }
                    }
                }
            }
            Err(e) => {
                lines.push(format!("  <key not found: {}>", e));
            }
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// File system checks (Windows only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn check_filesystem(state: &mut SecureBootScanState) {
    use std::path::Path;

    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());

    // %SystemRoot%\System32\SecureBootUpdates\
    let payload_dir = Path::new(&system_root).join(r"System32\SecureBootUpdates");
    if payload_dir.exists() && payload_dir.is_dir() {
        state.payload_folder_exists = Some(true);
        let bin_count = std::fs::read_dir(&payload_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .and_then(|ext| ext.to_str())
                            .map(|ext| ext.eq_ignore_ascii_case("bin"))
                            .unwrap_or(false)
                    })
                    .count() as u32
            })
            .unwrap_or(0);
        state.payload_bin_count = Some(bin_count);
    } else {
        state.payload_folder_exists = Some(false);
        state.payload_bin_count = Some(0);
    }

    // %SystemRoot%\System32\WinCsFlags.exe
    let wincs_path = Path::new(&system_root).join(r"System32\WinCsFlags.exe");
    state.wincs_available = Some(wincs_path.exists());
}

// ---------------------------------------------------------------------------
// PowerShell supplementary checks (Windows only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn run_powershell_checks(state: &mut SecureBootScanState) {
    // DiagTrack service
    if let Some(json) = run_powershell(
        r#"Get-Service -Name DiagTrack -ErrorAction SilentlyContinue | Select-Object Status,StartType | ConvertTo-Json -Compress"#,
    ) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
            state.diagtrack_running = val["Status"]
                .as_str()
                .map(|s| s.eq_ignore_ascii_case("Running"));
            state.diagtrack_start_type = val["StartType"].as_str().map(|s| s.to_string());
        }
    }

    // OS caption / build
    if let Some(json) = run_powershell(
        r#"Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object Caption,BuildNumber | ConvertTo-Json -Compress"#,
    ) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
            state.os_caption = val["Caption"].as_str().map(|s| s.to_string());
            state.os_build = val["BuildNumber"].as_str().map(|s| s.to_string());
        }
    }

    // Scheduled task
    let task_name = r#"Microsoft\Windows\PI\Secure-Boot-Update"#;
    let ps_task = r#"Get-ScheduledTaskInfo -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction SilentlyContinue | Select-Object LastRunTime,LastTaskResult | ConvertTo-Json -Compress"#.to_string();
    if let Some(json) = run_powershell(&ps_task) {
        // Any result means the task exists
        state.scheduled_task_exists = Some(true);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
            state.scheduled_task_last_run = val["LastRunTime"].as_str().map(|s| s.to_string());
            state.scheduled_task_last_result =
                val["LastTaskResult"].as_u64().map(|n| format!("{:#010x}", n));
        }
    } else {
        state.scheduled_task_exists = Some(false);
    }

    // TPM
    if let Some(json) = run_powershell(
        r#"Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue | Select-Object IsPresent,IsEnabled_InitialValue,IsActivated_InitialValue,SpecVersion | ConvertTo-Json -Compress"#,
    ) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
            state.tpm_present = val["IsPresent"].as_bool();
            state.tpm_enabled = val["IsEnabled_InitialValue"].as_bool();
            state.tpm_activated = val["IsActivated_InitialValue"].as_bool();
            state.tpm_spec_version = val["SpecVersion"].as_str().map(|s| s.to_string());
        }
    }

    // BitLocker (system drive only)
    if let Some(json) = run_powershell(
        r#"$v=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue; if($v){$v|Select-Object ProtectionStatus,EncryptionPercentage,KeyProtector|ConvertTo-Json -Compress}else{'null'}"#,
    ) {
        if json != "null" {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
                state.bitlocker_protection_on = val["ProtectionStatus"]
                    .as_str()
                    .map(|s| s.eq_ignore_ascii_case("On"));
                state.bitlocker_encryption_status = val["EncryptionPercentage"]
                    .as_str()
                    .map(|s| s.to_string());
                if let Some(protectors) = val["KeyProtector"].as_array() {
                    state.bitlocker_key_protectors = protectors
                        .iter()
                        .filter_map(|p| {
                            p["KeyProtectorType"].as_str().map(|s| s.to_string())
                        })
                        .collect();
                }
            }
        }
    }

    // Disk partition style (system disk)
    if let Some(json) = run_powershell(
        r#"$disk=Get-Disk|Where-Object{$_.IsBoot -eq $true}|Select-Object -First 1 PartitionStyle; if($disk){$disk|ConvertTo-Json -Compress}else{'null'}"#,
    ) {
        if json != "null" {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
                state.disk_partition_style = val["PartitionStyle"].as_str().map(|s| s.to_string());
            }
        }
    }

    // Device/computer name
    if let Some(json) = run_powershell(
        r#"[PSCustomObject]@{Name=$env:COMPUTERNAME}|ConvertTo-Json -Compress"#,
    ) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
            state.device_name = val["Name"].as_str().map(|s| s.to_string());
        }
    }

    // Suppress the unused variable warning on task_name
    let _ = task_name;
}

/// Execute a single PowerShell command with `-NoProfile -NonInteractive` and
/// return its stdout trimmed, or `None` on failure / empty output.
#[cfg(target_os = "windows")]
fn run_powershell(command: &str) -> Option<String> {
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            command,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() || stdout == "null" {
        None
    } else {
        Some(stdout)
    }
}
