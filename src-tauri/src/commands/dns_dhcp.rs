use serde::Serialize;
use tauri::AppHandle;

/// Result of checking DNS server logging configuration.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsLoggingStatus {
    /// Whether the DNS Server service is installed on this machine.
    pub dns_server_installed: bool,
    /// Whether DNS debug logging is enabled (writes to dns.log).
    pub debug_logging_enabled: bool,
    /// The path where debug logs are written, if configured.
    pub log_file_path: Option<String>,
    /// Whether DHCP Server service is installed on this machine.
    pub dhcp_server_installed: bool,
    /// A trusted saved baseline can currently be restored without a detected conflict.
    pub can_restore_logging: bool,
    /// Bounded recovery/ownership diagnostic; never raw PowerShell output.
    pub restore_error: Option<String>,
}

/// Check DNS/DHCP server logging status on this machine.
#[tauri::command]
pub async fn check_dns_logging_status() -> Result<DnsLoggingStatus, String> {
    #[cfg(target_os = "windows")]
    {
        tauri::async_runtime::spawn_blocking(check_dns_logging_status_windows)
            .await
            .map_err(|_| "DNS logging status could not be checked.".to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(DnsLoggingStatus {
            dns_server_installed: false,
            debug_logging_enabled: false,
            log_file_path: None,
            dhcp_server_installed: false,
            can_restore_logging: false,
            restore_error: None,
        })
    }
}

/// Enable DNS debug logging on this machine via PowerShell.
/// Requires the app to be running elevated (Administrator).
#[tauri::command]
pub async fn enable_dns_debug_logging() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        tauri::async_runtime::spawn_blocking(|| set_dns_debug_logging_windows(true))
            .await
            .map_err(|_| {
                "DNS logging operation was interrupted. Scan this server to check recovery."
                    .to_string()
            })?
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("DNS debug logging can only be enabled on Windows Server.".to_string())
    }
}

/// Restore the diagnostic values saved before this tool enabled logging.
/// Missing, untrusted or conflicting recovery state never authorizes a write.
#[tauri::command]
pub async fn disable_dns_debug_logging() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        tauri::async_runtime::spawn_blocking(|| set_dns_debug_logging_windows(false))
            .await
            .map_err(|_| {
                "DNS logging operation was interrupted. Scan this server to check recovery."
                    .to_string()
            })?
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("DNS debug logging can only be changed on Windows Server.".to_string())
    }
}

#[cfg(target_os = "windows")]
fn check_dns_logging_status_windows() -> DnsLoggingStatus {
    // Check DNS Server service via sc.exe (read-only)
    let dns_installed = crate::process_util::hidden_command("sc.exe")
        .args(["query", "DNS"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    // Check DHCP Server service via sc.exe (read-only)
    let dhcp_installed = crate::process_util::hidden_command("sc.exe")
        .args(["query", "DHCPServer"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let (can_restore_logging, restore_error) = match run_dns_logging_action("Status") {
        Ok(available) => (available, None),
        Err(error) => (false, Some(error)),
    };

    if !dns_installed {
        return DnsLoggingStatus {
            dns_server_installed: false,
            debug_logging_enabled: false,
            log_file_path: None,
            dhcp_server_installed: dhcp_installed,
            can_restore_logging,
            restore_error,
        };
    }

    // Read DNS logging config from the registry (read-only, no PowerShell cmdlets).
    // HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
    //   LogLevel (DWORD) — nonzero means debug logging is enabled
    //   LogFilePath (REG_SZ) — path to the debug log file
    let output = crate::process_util::hidden_command("reg.exe")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters",
            "/v",
            "LogLevel",
        ])
        .output();

    let debug_enabled = match &output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // Output format: "    LogLevel    REG_DWORD    0x0000ffff"
            // Any nonzero value means logging is enabled
            stdout
                .lines()
                .find(|l| l.contains("LogLevel"))
                .and_then(|l| {
                    l.split_whitespace()
                        .last()
                        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                })
                .map(|v| v != 0)
                .unwrap_or(false)
        }
        _ => false,
    };

    let log_path_output = crate::process_util::hidden_command("reg.exe")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters",
            "/v",
            "LogFilePath",
        ])
        .output();

    let log_path = match &log_path_output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout
                .lines()
                .find(|l| l.contains("LogFilePath"))
                .and_then(|l| {
                    // "    LogFilePath    REG_SZ    C:\Logs\dns.log"
                    let parts: Vec<&str> = l.splitn(4, "    ").collect();
                    parts.last().map(|s| s.trim().to_string())
                })
                .filter(|p| !p.is_empty())
        }
        _ => None,
    };

    DnsLoggingStatus {
        dns_server_installed: true,
        debug_logging_enabled: debug_enabled,
        log_file_path: log_path,
        dhcp_server_installed: dhcp_installed,
        can_restore_logging,
        restore_error,
    }
}

#[cfg(target_os = "windows")]
fn set_dns_debug_logging_windows(enable: bool) -> Result<String, String> {
    run_dns_logging_action(if enable { "Enable" } else { "Disable" })?;
    Ok(if enable {
        "DNS debug logging enabled. Prior settings were saved for Disable. Review the server's log retention and rollover configuration.".to_string()
    } else {
        "Prior DNS logging settings restored. Logging configured before this app may remain enabled.".to_string()
    })
}

#[cfg(target_os = "windows")]
fn run_dns_logging_action(action: &str) -> Result<bool, String> {
    // Only the three fixed callers above supply this action; no user input is
    // interpolated into PowerShell and no registry/DNS value crosses IPC.
    let script = format!(
        "{}\nInvoke-CmtDnsAction '{}' | ConvertTo-Json -Compress",
        include_str!("dns_logging.ps1"),
        action,
    );
    let output = crate::process_util::run_complete_command(
        crate::process_util::hidden_command("powershell.exe").args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ]),
        std::time::Duration::from_secs(30),
        4096,
        4096,
    )
    .map_err(|_| {
        "DNS logging operation did not finish. Scan this server to check saved recovery settings."
            .to_string()
    })?;
    if !output.status.success() {
        return Err("DNS logging operation failed. Run as Administrator and scan this server to check recovery.".to_string());
    }
    decode_dns_logging_result(&output.stdout)
}

#[cfg(any(test, target_os = "windows"))]
fn decode_dns_logging_result(stdout: &[u8]) -> Result<bool, String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ResultEnvelope {
        can_restore_logging: bool,
        error_code: serde_json::Value,
    }
    let result: ResultEnvelope = serde_json::from_slice(stdout).map_err(|_| {
        "DNS logging returned an invalid result. Scan this server before trying again.".to_string()
    })?;
    let error = match result.error_code {
        serde_json::Value::Null => return Ok(result.can_restore_logging),
        serde_json::Value::String(code) => match code.as_str() {
            "DNS_CONFLICT" => "DNS settings differ from the saved or expected configuration. Recovery is retained; review and reconcile the saved settings manually before retrying.",
            "DNS_CONFIG_UNSUPPORTED" => "This server's DNS diagnostics do not match the supported configuration schema. Automatic changes are unavailable; any saved recovery is retained.",
            "DNS_STORE_UNTRUSTED" => "The DNS recovery store has unsupported ownership or permissions. Automatic changes are unavailable; no permissions were changed.",
            "DNS_RECORD_INVALID" => "The saved DNS recovery record is invalid. Automatic changes are blocked; the record is retained for manual review.",
            "DNS_ALREADY_OWNED" => "Prior DNS settings are already saved. Use Disable to restore them before enabling again.",
            "DNS_NOT_OWNED" => "This app has no saved DNS settings to restore. DNS configuration was not changed.",
            "DNS_ALREADY_ENABLED" => "The requested DNS logging settings are already enabled. This app has not taken ownership of them.",
            "DNS_BUSY" => "Another DNS logging operation is active. Wait for it to finish, then scan this server again.",
            "DNS_READ_FAILED" => "DNS configuration could not be read. Run as Administrator and check the DNS Server tools; any saved recovery is retained.",
            "DNS_APPLY_FAILED" | "DNS_VERIFY_FAILED" => "The DNS change could not be verified. Saved recovery is retained; scan this server before retrying or reconcile the settings manually.",
            _ => "The DNS recovery store or lock could not be accessed. Run as Administrator and scan this server before retrying.",
        },
        _ => "DNS logging returned an invalid result. Scan this server before trying again.",
    };
    Err(error.to_string())
}

#[cfg(test)]
mod diagnostics_tests {
    use super::decode_dns_logging_result;

    #[cfg(target_os = "windows")]
    #[test]
    fn powershell_restore_contract_uses_only_mocked_dns_and_temporary_storage() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../scripts/dns-logging.test.ps1");
        let output = crate::process_util::run_complete_command(
            crate::process_util::hidden_command("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-File"])
                .arg(script),
            std::time::Duration::from_secs(60),
            64 * 1024,
            64 * 1024,
        )
        .expect("mocked PowerShell contract must finish");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn recovery_status_requires_a_complete_typed_response() {
        assert_eq!(
            decode_dns_logging_result(br#"{"canRestoreLogging":true,"errorCode":null}"#),
            Ok(true)
        );
        for input in [
            br#"{"canRestoreLogging":true}"#.as_slice(),
            br#"{"canRestoreLogging":"true","errorCode":null}"#.as_slice(),
            br#"{"canRestoreLogging":true,"errorCode":null,"extra":1}"#.as_slice(),
            br#"{"canRestoreLogging":true,"errorCode":{}}"#.as_slice(),
        ] {
            assert!(decode_dns_logging_result(input).is_err());
        }
    }

    #[test]
    fn failures_never_echo_external_text_or_offer_recovery() {
        let error = decode_dns_logging_result(
            br#"{"canRestoreLogging":true,"errorCode":"private server details"}"#,
        )
        .unwrap_err();
        assert!(!error.contains("private"));
        let conflict =
            decode_dns_logging_result(br#"{"canRestoreLogging":false,"errorCode":"DNS_CONFLICT"}"#)
                .unwrap_err();
        assert!(conflict.contains("Recovery is retained"));
    }
}

// ---------------------------------------------------------------------------
// Domain-wide DNS/DHCP log collection
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
const DNS_DHCP_COLLECTION_PROGRESS_EVENT: &str = "dns-dhcp-collection-progress";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct DnsDhcpCollectionProgress {
    pub request_id: String,
    pub message: String,
    pub current_server: Option<String>,
    pub completed_servers: u32,
    pub total_servers: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct DnsDhcpServerResult {
    pub server: String,
    pub status: String,
    pub files_collected: u32,
    pub bytes_copied: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsDhcpCollectionResult {
    pub bundle_path: String,
    pub servers: Vec<DnsDhcpServerResult>,
    pub total_files: u32,
    pub total_bytes: u64,
    pub duration_ms: u64,
}

/// Collect DNS and DHCP logs from domain controllers via UNC admin shares.
/// Auto-discovers DCs from AD if no explicit list is provided.
#[tauri::command]
pub async fn collect_dns_dhcp_from_domain(
    request_id: String,
    output_root: Option<String>,
    servers: Option<Vec<String>>,
    app: AppHandle,
) -> Result<DnsDhcpCollectionResult, crate::error::AppError> {
    #[cfg(target_os = "windows")]
    {
        tokio::task::spawn_blocking(move || {
            collect_dns_dhcp_blocking(request_id, output_root, servers, app)
        })
        .await
        .map_err(|e| crate::error::AppError::Internal(format!("collection task failed: {e}")))?
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (request_id, output_root, servers, app);
        Err(crate::error::AppError::PlatformUnsupported(
            "DNS/DHCP domain collection is only supported on Windows.".to_string(),
        ))
    }
}

#[cfg(target_os = "windows")]
fn is_local_server(server: &str) -> bool {
    if let Ok(hostname) = std::env::var("COMPUTERNAME") {
        // Compare the server name (which may be FQDN) against local hostname
        let server_short = server.split('.').next().unwrap_or(server);
        hostname.eq_ignore_ascii_case(server_short)
    } else {
        false
    }
}

#[cfg(target_os = "windows")]
fn collect_dns_dhcp_blocking(
    request_id: String,
    output_root: Option<String>,
    servers: Option<Vec<String>>,
    app: AppHandle,
) -> Result<DnsDhcpCollectionResult, crate::error::AppError> {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::Instant;
    use tauri::Emitter;

    let start = Instant::now();

    // Discover or use provided server list
    let server_list = match servers {
        Some(s) if !s.is_empty() => s,
        _ => discover_domain_controllers()?,
    };

    let total_servers = server_list.len() as u32;

    // Create output directory
    let root = output_root.unwrap_or_else(|| {
        let desktop = std::env::var("USERPROFILE")
            .map(|p| PathBuf::from(p).join("Desktop"))
            .unwrap_or_else(|_| PathBuf::from("C:\\Users\\Public\\Desktop"));
        desktop
            .join("DnsDhcpCollection")
            .to_string_lossy()
            .to_string()
    });
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let bundle_dir = PathBuf::from(&root).join(format!("dns-dhcp-{}", timestamp));
    fs::create_dir_all(&bundle_dir).map_err(|e| {
        crate::error::AppError::Internal(format!("Failed to create output dir: {e}"))
    })?;

    let mut all_results = Vec::new();
    let mut total_files: u32 = 0;
    let mut total_bytes: u64 = 0;

    for (i, server) in server_list.iter().enumerate() {
        // Emit progress
        let _ = app.emit(
            DNS_DHCP_COLLECTION_PROGRESS_EVENT,
            DnsDhcpCollectionProgress {
                request_id: request_id.clone(),
                message: format!("Collecting from {} ({}/{})", server, i + 1, total_servers),
                current_server: Some(server.clone()),
                completed_servers: i as u32,
                total_servers,
            },
        );

        let server_dir = bundle_dir.join(server);
        fs::create_dir_all(&server_dir).ok();

        let mut result = DnsDhcpServerResult {
            server: server.clone(),
            status: "collected".to_string(),
            files_collected: 0,
            bytes_copied: 0,
            errors: Vec::new(),
        };

        // Check UNC access
        let unc_base = format!("\\\\{}\\C$\\Windows\\System32", server);
        if !Path::new(&unc_base).exists() {
            result.status = "unreachable".to_string();
            result
                .errors
                .push(format!("Cannot access \\\\{}\\C$ admin share", server));
            all_results.push(result);
            continue;
        }

        // Collect DNS debug log
        let dns_paths = [
            format!("{}\\dns\\dns.log", unc_base),
            format!("{}\\dns\\DNSServer_debug.log", unc_base),
        ];
        for dns_path in &dns_paths {
            if fs::metadata(dns_path).is_ok() {
                let dest = server_dir.join("dns-debug.log");
                match fs::copy(dns_path, &dest) {
                    Ok(bytes) => {
                        result.files_collected += 1;
                        result.bytes_copied += bytes;
                        log::info!("Copied DNS debug log from {} ({} bytes)", server, bytes);
                    }
                    Err(e) => {
                        result
                            .errors
                            .push(format!("Failed to copy DNS debug log: {e}"));
                    }
                }
                break;
            }
        }

        // Collect DNS audit EVTX via wevtutil (handles locked files)
        let is_local = is_local_server(server);
        let evtx_dest = server_dir.join("dns-audit.evtx");

        if is_local {
            // Local server: use wevtutil epl to export the live event log
            let wevtutil_result = crate::process_util::hidden_command("wevtutil.exe")
                .args([
                    "epl",
                    "Microsoft-Windows-DNSServer/Audit",
                    &evtx_dest.to_string_lossy(),
                    "/ow:true",
                ])
                .output();

            match wevtutil_result {
                Ok(o) if o.status.success() => {
                    if let Ok(meta) = fs::metadata(&evtx_dest) {
                        result.files_collected += 1;
                        result.bytes_copied += meta.len();
                    }
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    let msg = stderr.trim();
                    if !msg.is_empty() {
                        result
                            .errors
                            .push(format!("wevtutil export DNS audit: {msg}"));
                    }
                }
                Err(e) => {
                    result
                        .errors
                        .push(format!("Failed to run wevtutil for DNS audit: {e}"));
                }
            }
        } else {
            // Remote server: try UNC copy (may fail if file is locked)
            let evtx_paths = [
                format!(
                    "{}\\winevt\\Logs\\Microsoft-Windows-DNSServer%4Audit.evtx",
                    unc_base
                ),
                format!("{}\\winevt\\Logs\\DNS Server.evtx", unc_base),
            ];
            for evtx_path in &evtx_paths {
                if Path::new(evtx_path).exists() {
                    match fs::copy(evtx_path, &evtx_dest) {
                        Ok(bytes) => {
                            result.files_collected += 1;
                            result.bytes_copied += bytes;
                            break;
                        }
                        Err(e) => {
                            let file_name = Path::new(evtx_path)
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy();
                            result
                                .errors
                                .push(format!("Failed to copy {file_name}: {e}"));
                        }
                    }
                }
            }
        }

        // Collect DHCP logs
        let dhcp_dir = format!("{}\\dhcp", unc_base);
        if Path::new(&dhcp_dir).is_dir() {
            let dhcp_dest = server_dir.join("dhcp");
            fs::create_dir_all(&dhcp_dest).ok();

            if let Ok(entries) = fs::read_dir(&dhcp_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    if (name.starts_with("dhcpsrvlog") || name.starts_with("dhcpv6srvlog"))
                        && name.ends_with(".log")
                    {
                        let dest = dhcp_dest.join(entry.file_name());
                        match fs::copy(entry.path(), &dest) {
                            Ok(bytes) => {
                                result.files_collected += 1;
                                result.bytes_copied += bytes;
                            }
                            Err(e) => {
                                result.errors.push(format!(
                                    "Failed to copy DHCP log {}: {e}",
                                    entry.file_name().to_string_lossy()
                                ));
                            }
                        }
                    }
                }
            }
        }

        total_files += result.files_collected;
        total_bytes += result.bytes_copied;
        all_results.push(result);
    }

    // Final progress
    let _ = app.emit(
        DNS_DHCP_COLLECTION_PROGRESS_EVENT,
        DnsDhcpCollectionProgress {
            request_id: request_id.clone(),
            message: "Collection complete".to_string(),
            current_server: None,
            completed_servers: total_servers,
            total_servers,
        },
    );

    Ok(DnsDhcpCollectionResult {
        bundle_path: bundle_dir.to_string_lossy().to_string(),
        servers: all_results,
        total_files,
        total_bytes,
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

#[cfg(target_os = "windows")]
fn discover_domain_controllers() -> Result<Vec<String>, crate::error::AppError> {
    // Use PowerShell to query AD for domain controllers
    let output = crate::process_util::hidden_command("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | ForEach-Object { $_.Name }",
        ])
        .output()
        .map_err(|e| crate::error::AppError::Internal(format!("Failed to query AD: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::error::AppError::Internal(format!(
            "Failed to discover domain controllers: {}",
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let servers: Vec<String> = stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    if servers.is_empty() {
        return Err(crate::error::AppError::Internal(
            "No domain controllers found. Ensure this machine is domain-joined.".to_string(),
        ));
    }

    Ok(servers)
}
