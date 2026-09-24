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
}

/// Check DNS/DHCP server logging status on this machine.
#[tauri::command]
pub fn check_dns_logging_status() -> DnsLoggingStatus {
    #[cfg(target_os = "windows")]
    {
        check_dns_logging_status_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        DnsLoggingStatus {
            dns_server_installed: false,
            debug_logging_enabled: false,
            log_file_path: None,
            dhcp_server_installed: false,
        }
    }
}

/// The diagnostic switches this feature owns.
///
/// The reader parses query records, so it needs the query category with the
/// answers, one packet direction and one transport. The cmdlet requires at least
/// one option from each of those groups, which is why the list is these five and
/// not a single flag.
///
/// `-All` would also flip categories this feature never reads — notifications,
/// Dynamic Update, zone transfers, packet capture, write-back, and the event-log
/// switches — on what may be a production resolver. Enabling and disabling use
/// this one list, so neither direction disturbs a setting an operator chose.
#[cfg(any(test, target_os = "windows"))]
const OWNED_DIAGNOSTIC_SWITCHES: [&str; 5] = [
    "Queries",
    "Answers",
    "ReceivePackets",
    "UdpPackets",
    "EnableLoggingToFile",
];

/// Build the PowerShell that sets this feature's switches, and report the log
/// path so the caller can name it.
#[cfg(any(test, target_os = "windows"))]
fn diagnostics_command(enable: bool) -> String {
    let value = if enable { "$true" } else { "$false" };
    let switches = OWNED_DIAGNOSTIC_SWITCHES
        .iter()
        .map(|name| format!("-{name} {value}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "Set-DnsServerDiagnostics {switches}; \
         $s = (Get-DnsServer).ServerSetting; \
         Write-Output \"LogFilePath=$($s.LogFilePath)\""
    )
}

/// Enable DNS debug logging on this machine via PowerShell.
/// Requires the app to be running elevated (Administrator).
#[tauri::command]
pub fn enable_dns_debug_logging() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        set_dns_debug_logging_windows(true)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("DNS debug logging can only be enabled on Windows Server.".to_string())
    }
}

/// Turn off the DNS debug logging this feature enabled.
///
/// The switch it is left as it was set, from the same place it was set, and it
/// clears exactly the switches `enable` set, so a server that already logged
/// something else keeps doing it.
#[tauri::command]
pub fn disable_dns_debug_logging() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        set_dns_debug_logging_windows(false)
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

    if !dns_installed {
        return DnsLoggingStatus {
            dns_server_installed: false,
            debug_logging_enabled: false,
            log_file_path: None,
            dhcp_server_installed: dhcp_installed,
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
    }
}

#[cfg(target_os = "windows")]
fn set_dns_debug_logging_windows(enable: bool) -> Result<String, String> {
    let output = crate::process_util::hidden_command("powershell.exe")
        .args(["-NoProfile", "-Command", &diagnostics_command(enable)])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let action = if enable { "enable" } else { "disable" };
        return Err(format!(
            "Failed to {action} DNS logging (run as Administrator): {}",
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let log_path = stdout
        .lines()
        .find(|l| l.starts_with("LogFilePath="))
        .map(|l| l.trim_start_matches("LogFilePath=").trim().to_string())
        .unwrap_or_else(|| "C:\\Windows\\System32\\dns\\dns.log".to_string());

    Ok(if enable {
        format!(
            "DNS debug logging enabled. Log file: {log_path}. This file grows with query volume \
             and is not rotated by the DNS service; plan for its retention."
        )
    } else {
        format!("DNS debug logging disabled. Log file: {log_path}")
    })
}

#[cfg(test)]
mod diagnostics_tests {
    use super::{diagnostics_command, OWNED_DIAGNOSTIC_SWITCHES};

    /// Enable and disable must differ in the value only: if they ever drift apart,
    /// disabling stops restoring what enabling changed.
    #[test]
    fn enabling_and_disabling_set_the_same_switches() {
        let on = diagnostics_command(true);
        let off = diagnostics_command(false);

        assert!(on.contains("$true"));
        assert!(off.contains("$false"));
        assert_eq!(
            on.replace("$true", "$false"),
            off,
            "the two directions must set the same switches"
        );
    }

    /// `-All` is what this replaced: it flips every category, including ones the
    /// reader never parses.
    #[test]
    fn the_command_names_every_switch_and_never_uses_all() {
        let command = diagnostics_command(true);

        assert!(!command.contains("-All"));
        for name in OWNED_DIAGNOSTIC_SWITCHES {
            assert!(command.contains(&format!("-{name} $true")), "{name}");
        }
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
