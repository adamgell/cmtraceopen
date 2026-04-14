use crate::dsregcmd::models::DsregcmdActiveEvidence;
#[cfg(target_os = "windows")]
use crate::dsregcmd::models::{DsregcmdConnectivityResult, DsregcmdScpQueryResult};

#[cfg(target_os = "windows")]
const TEST_ENDPOINTS: &[&str] = &[
    "https://enterpriseregistration.windows.net",
    "https://login.microsoftonline.com",
    "https://device.login.microsoftonline.com",
    "https://autologon.microsoftazuread-sso.com",
];

#[cfg(target_os = "windows")]
const ENDPOINT_TIMEOUT_SECS: u64 = 10;

#[cfg(target_os = "windows")]
pub fn test_endpoint_connectivity() -> Vec<DsregcmdConnectivityResult> {
    let mut results = Vec::new();

    for endpoint in TEST_ENDPOINTS {
        let start = std::time::Instant::now();
        let timestamp = chrono::Utc::now().to_rfc3339();

        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(std::time::Duration::from_secs(ENDPOINT_TIMEOUT_SECS)))
            .timeout_recv_response(Some(std::time::Duration::from_secs(ENDPOINT_TIMEOUT_SECS)))
            .http_status_as_error(false)
            .build()
            .new_agent();

        match agent.head(*endpoint).call() {
            Ok(response) => {
                let latency = start.elapsed().as_millis() as u64;
                results.push(DsregcmdConnectivityResult {
                    endpoint: endpoint.to_string(),
                    reachable: true,
                    status_code: Some(response.status().as_u16()),
                    latency_ms: Some(latency),
                    error_message: None,
                    timestamp,
                });
            }
            Err(e) => {
                let latency = start.elapsed().as_millis() as u64;
                results.push(DsregcmdConnectivityResult {
                    endpoint: endpoint.to_string(),
                    reachable: false,
                    status_code: None,
                    latency_ms: Some(latency),
                    error_message: Some(e.to_string()),
                    timestamp,
                });
            }
        }
    }

    results
}

#[cfg(target_os = "windows")]
pub fn query_scp() -> DsregcmdScpQueryResult {
    let mut result = DsregcmdScpQueryResult::default();

    // Try to find a domain controller via nltest
    let dc_output = std::process::Command::new("nltest")
        .arg("/dsgetdc:")
        .output();

    match dc_output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("DC:") {
                    result.domain_controller =
                        Some(trimmed.trim_start_matches("DC:").trim().trim_start_matches("\\\\").to_string());
                    break;
                }
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let exit_code = output.status.code().unwrap_or_default();
            result.error = Some(format!(
                "nltest /dsgetdc: failed (exit code {}): {}",
                exit_code,
                if stderr.is_empty() { "(no stderr)" } else { &stderr }
            ));
            return result;
        }
        Err(e) => {
            result.error = Some(format!("nltest not available: {e}"));
            return result;
        }
    }

    // Query SCP via PowerShell
    let ps_script = r#"
try {
    $scp = [ADSI]"LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration,$((Get-ADForest).Name)"
    if ($scp.keywords) {
        $scp.keywords | ForEach-Object { Write-Output $_ }
    } else {
        Write-Output "SCP_NOT_FOUND"
    }
} catch {
    Write-Output "SCP_ERROR: $_"
}
"#;

    let ps_output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
        .output();

    match ps_output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

            if lines.iter().any(|l| l.contains("SCP_NOT_FOUND")) {
                result.error = Some("SCP object exists but has no keywords.".to_string());
                return result;
            }

            if let Some(error_line) = lines.iter().find(|l| l.starts_with("SCP_ERROR:")) {
                result.error = Some(error_line.to_string());
                return result;
            }

            result.scp_found = true;
            result.keywords = lines.iter().map(|l| l.to_string()).collect();

            for keyword in &result.keywords {
                if let Some(domain) = keyword.strip_prefix("azureADName:") {
                    result.tenant_domain = Some(domain.trim().to_string());
                }
                if let Some(id) = keyword.strip_prefix("azureADId:") {
                    result.azuread_id = Some(id.trim().to_string());
                }
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            result.error = Some(format!("PowerShell SCP query failed: {stderr}"));
        }
        Err(e) => {
            result.error = Some(format!("PowerShell not available: {e}"));
        }
    }

    result
}

#[cfg(target_os = "windows")]
pub fn run_active_diagnostics() -> DsregcmdActiveEvidence {
    let connectivity_tests = test_endpoint_connectivity();
    let scp_query = Some(query_scp());

    DsregcmdActiveEvidence {
        connectivity_tests,
        scp_query,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_active_diagnostics() -> DsregcmdActiveEvidence {
    DsregcmdActiveEvidence::default()
}
