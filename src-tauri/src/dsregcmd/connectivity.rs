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

/// The failure to report for a failed SCP query, keeping an earlier `nltest`
/// failure alongside it.
///
/// `nltest` failing is not fatal on its own — the SCP query can succeed without a
/// domain controller name — so it is carried rather than returned. When the SCP
/// query *does* fail, both failures belong in the report: dropping `nltest` lost
/// the evidence of a directory lookup that had already failed.
///
/// PowerShell reports an LDAP failure on stdout and still exits successfully, so
/// the caller reaches this for both exit-status failures and self-reported ones.
///
/// Gated like its callers rather than left ungated: the only non-test caller is
/// `query_scp`, which is itself Windows-only, so on Linux the function was dead
/// code in the library build and `-D warnings` rejected the crate. Including
/// `test` keeps the string-combining logic covered on every platform.
#[cfg(any(target_os = "windows", test))]
fn scp_failure_message(nltest_error: &Option<String>, scp_failure: &str) -> String {
    match nltest_error {
        Some(nltest) => format!("{nltest}; {scp_failure}"),
        None => scp_failure.to_string(),
    }
}

#[cfg(target_os = "windows")]
pub fn query_scp() -> DsregcmdScpQueryResult {
    let mut result = DsregcmdScpQueryResult::default();
    let mut nltest_error: Option<String> = None;

    // Try to find a domain controller via nltest. Failure here is not fatal:
    // the PowerShell SCP query below can still succeed without a DC name.
    let dc_output = crate::process_util::hidden_command("nltest")
        .arg("/dsgetdc:")
        .output();

    match dc_output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("DC:") {
                    result.domain_controller = Some(
                        trimmed
                            .trim_start_matches("DC:")
                            .trim()
                            .trim_start_matches("\\\\")
                            .to_string(),
                    );
                    break;
                }
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let exit_code = output.status.code().unwrap_or_default();
            nltest_error = Some(format!(
                "nltest /dsgetdc: failed (exit code {}): {}",
                exit_code,
                if stderr.is_empty() {
                    "(no stderr)"
                } else {
                    &stderr
                }
            ));
        }
        Err(e) => {
            nltest_error = Some(format!("nltest not available: {e}"));
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

    let ps_output = crate::process_util::hidden_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
        .output();

    match ps_output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();

            if lines.iter().any(|l| l.contains("SCP_NOT_FOUND")) {
                result.error = Some(scp_failure_message(
                    &nltest_error,
                    "SCP object exists but has no keywords.",
                ));
                return result;
            }

            if let Some(error_line) = lines.iter().find(|l| l.starts_with("SCP_ERROR:")) {
                result.error = Some(scp_failure_message(&nltest_error, error_line));
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
            result.error = Some(scp_failure_message(
                &nltest_error,
                &format!("PowerShell SCP query failed: {stderr}"),
            ));
        }
        Err(e) => {
            result.error = Some(scp_failure_message(
                &nltest_error,
                &format!("PowerShell not available: {e}"),
            ));
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

#[cfg(test)]
mod tests {
    use super::scp_failure_message;

    /// PowerShell reports an LDAP failure on stdout and still exits successfully,
    /// so the `SCP_ERROR:` branch reads as a success to the exit status. An
    /// `nltest` failure that preceded it was being dropped there, which reported
    /// a healthy directory alongside a failed SCP query.
    #[test]
    fn an_nltest_failure_survives_a_powershell_reported_scp_error() {
        let nltest = Some(
            "nltest /dsgetdc: failed (exit code 1): ERROR_NO_SUCH_DOMAIN".to_string(),
        );

        let message = scp_failure_message(&nltest, "SCP_ERROR: LDAP error 0x20");

        assert!(message.contains("nltest"), "nltest failure kept: {message}");
        assert!(
            message.contains("SCP_ERROR: LDAP error 0x20"),
            "SCP failure kept: {message}"
        );
    }

    /// The same for the other self-reported branch, which has the same shape.
    #[test]
    fn an_nltest_failure_survives_a_missing_scp_keyword_set() {
        let nltest = Some("nltest not available: not found".to_string());

        let message = scp_failure_message(&nltest, "SCP object exists but has no keywords.");

        assert!(message.contains("nltest not available"), "{message}");
        assert!(message.contains("SCP object exists"), "{message}");
    }

    /// With no `nltest` failure there is nothing to combine, so the SCP failure
    /// is reported as it is.
    #[test]
    fn a_lone_scp_failure_reports_only_itself() {
        assert_eq!(
            scp_failure_message(&None, "SCP object exists but has no keywords."),
            "SCP object exists but has no keywords."
        );
    }
}
