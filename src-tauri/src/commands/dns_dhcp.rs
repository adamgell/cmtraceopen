use serde::Serialize;

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

/// Enable DNS debug logging on this machine via PowerShell.
/// Requires the app to be running elevated (Administrator).
#[tauri::command]
pub fn enable_dns_debug_logging() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        enable_dns_debug_logging_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("DNS debug logging can only be enabled on Windows Server.".to_string())
    }
}

#[cfg(target_os = "windows")]
fn check_dns_logging_status_windows() -> DnsLoggingStatus {
    // Check DNS Server service
    let dns_installed = std::process::Command::new("sc.exe")
        .args(["query", "DNS"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    // Check DHCP Server service
    let dhcp_installed = std::process::Command::new("sc.exe")
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

    // Query DNS debug logging config via PowerShell
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "try { $d = Get-DnsServerDiagnostics; $s = (Get-DnsServer).ServerSetting; \
             Write-Output \"EnableLoggingToFile=$($d.EnableLoggingToFile)\"; \
             Write-Output \"LogFilePath=$($s.LogFilePath)\" } \
             catch { Write-Output 'ERROR' }",
        ])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let debug_enabled = stdout.contains("EnableLoggingToFile=True");
            let log_path = stdout
                .lines()
                .find(|l| l.starts_with("LogFilePath="))
                .map(|l| l.trim_start_matches("LogFilePath=").trim().to_string())
                .filter(|p| !p.is_empty());

            DnsLoggingStatus {
                dns_server_installed: true,
                debug_logging_enabled: debug_enabled,
                log_file_path: log_path,
                dhcp_server_installed: dhcp_installed,
            }
        }
        Err(_) => DnsLoggingStatus {
            dns_server_installed: true,
            debug_logging_enabled: false,
            log_file_path: None,
            dhcp_server_installed: dhcp_installed,
        },
    }
}

#[cfg(target_os = "windows")]
fn enable_dns_debug_logging_windows() -> Result<String, String> {
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "Set-DnsServerDiagnostics -All $true; \
             $s = (Get-DnsServer).ServerSetting; \
             Write-Output \"LogFilePath=$($s.LogFilePath)\"",
        ])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Failed to enable DNS logging (run as Administrator): {}",
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let log_path = stdout
        .lines()
        .find(|l| l.starts_with("LogFilePath="))
        .map(|l| l.trim_start_matches("LogFilePath=").trim().to_string())
        .unwrap_or_else(|| "C:\\Windows\\System32\\dns\\dns.log".to_string());

    Ok(format!("DNS debug logging enabled. Log file: {}", log_path))
}
