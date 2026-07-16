use crate::dsregcmd::models::{
    DsregcmdAnalysisResult, DsregcmdDiagnosticInsight, DsregcmdJoinType,
};
use crate::intune::models::IntuneDiagnosticSeverity;

use super::derive::issue;

/// Cross-reference enrollment registry entries with scheduled task GUIDs
/// to upgrade `mdm_enrolled` when dsregcmd output lacks MDM URLs.
pub fn apply_enrollment_cross_reference(result: &mut DsregcmdAnalysisResult) {
    if result.derived.mdm_enrolled.is_some() {
        return;
    }
    if let (Some(enrollment), Some(tasks)) =
        (&result.enrollment_evidence, &result.scheduled_task_evidence)
    {
        let confirmed = enrollment.enrollments.iter().any(|e| {
            e.enrollment_state == Some(1)
                && e.guid.as_ref().is_some_and(|g| {
                    tasks
                        .enterprise_mgmt_guids
                        .iter()
                        .any(|t| t.eq_ignore_ascii_case(g))
                })
        });
        if confirmed {
            result.derived.mdm_enrolled = Some(true);
        }
    }
}

/// Extended diagnostics based on registry evidence collected in Phase 2.
pub fn build_extended_diagnostics(
    result: &DsregcmdAnalysisResult,
) -> Vec<DsregcmdDiagnosticInsight> {
    let mut diagnostics = Vec::new();

    if let Some(os) = result.os_version.as_ref() {
        let build_num = os
            .current_build
            .as_deref()
            .and_then(|b| b.parse::<u32>().ok());

        let cloud_trust_configured = result
            .policy_evidence
            .use_cloud_trust_for_on_prem_auth
            .display_value
            == Some(true);

        if let Some(build) = build_num {
            if build < 22000 && cloud_trust_configured {
                diagnostics.push(issue(
                    "os-build-below-cloud-trust",
                    IntuneDiagnosticSeverity::Warning,
                    "configuration",
                    "OS build is below the minimum required for cloud trust",
                    "Cloud trust for on-premises authentication requires Windows 11 (build 22000+), but this device is running an older build.",
                    vec![
                        format!("CurrentBuild: {build}"),
                        "UseCloudTrustForOnPremAuth: YES".to_string(),
                    ],
                    vec!["Upgrade the OS to Windows 11 or later to use cloud trust.".to_string()],
                    vec!["Upgrade the device OS or switch to certificate-based on-premises authentication.".to_string()],
                ));
            }

            if build < 19041 {
                diagnostics.push(issue(
                    "os-build-outdated",
                    IntuneDiagnosticSeverity::Info,
                    "configuration",
                    "OS build is older than Windows 10 version 2004",
                    "This device is running a build prior to 19041 (Windows 10 2004). Some modern device registration features may not be available.",
                    vec![format!("CurrentBuild: {build}")],
                    vec!["Confirm the OS version is still in support and meets tenant requirements.".to_string()],
                    Vec::new(),
                ));
            }
        }
    }

    if let Some(proxy) = result.proxy_evidence.as_ref() {
        let proxy_detected = proxy.proxy_enabled == Some(true)
            || proxy.proxy_server.is_some()
            || proxy.auto_config_url.is_some();

        if proxy_detected {
            diagnostics.push(issue(
                "proxy-configured",
                IntuneDiagnosticSeverity::Info,
                "network",
                "Proxy configuration detected",
                "The device has proxy settings configured, which can affect connectivity to Entra ID endpoints.",
                vec![
                    format!("ProxyEnabled: {}", proxy.proxy_enabled.map(|v| if v { "YES" } else { "NO" }).unwrap_or("(not set)")),
                    format!("ProxyServer: {}", proxy.proxy_server.as_deref().unwrap_or("(not set)")),
                    format!("AutoConfigURL: {}", proxy.auto_config_url.as_deref().unwrap_or("(not set)")),
                ],
                vec!["Confirm the proxy allows traffic to required Microsoft Entra endpoints.".to_string()],
                Vec::new(),
            ));
        }

        let has_join_failures = result
            .diagnostics
            .iter()
            .any(|d| d.severity == IntuneDiagnosticSeverity::Error);

        if proxy.wpad_detected && has_join_failures {
            diagnostics.push(issue(
                "proxy-wpad-with-join-failure",
                IntuneDiagnosticSeverity::Warning,
                "network",
                "WPAD proxy detected alongside join failures",
                "The device is using WPAD proxy auto-discovery, which can cause intermittent connectivity failures during device registration if the SYSTEM context cannot resolve the WPAD endpoint.",
                vec![
                    format!("AutoConfigURL: {}", proxy.auto_config_url.as_deref().unwrap_or("(wpad)")),
                ],
                vec![
                    "Verify the SYSTEM context can resolve the WPAD endpoint.".to_string(),
                    "Consider configuring explicit WinHTTP proxy for the machine context.".to_string(),
                ],
                vec!["Configure an explicit proxy or ensure WPAD resolves from the machine context.".to_string()],
            ));
        }
    }

    if let Some(enrollment) = result.enrollment_evidence.as_ref() {
        let is_joined = result.facts.join_state.azure_ad_joined == Some(true);

        if enrollment.enrollment_count == 0
            && is_joined
            && result.derived.mdm_enrolled != Some(true)
        {
            diagnostics.push(issue(
                "enrollment-missing-on-joined",
                IntuneDiagnosticSeverity::Warning,
                "configuration",
                "No MDM enrollment found on a joined device",
                "The device is Entra ID joined but has no enrollment entries in the registry, which may indicate MDM enrollment has not completed or was removed.",
                vec![format!("EnrollmentCount: {}", enrollment.enrollment_count)],
                vec![
                    "Check whether automatic MDM enrollment is configured for this tenant and user scope.".to_string(),
                    "Verify enrollment status in the Intune portal for this device.".to_string(),
                ],
                vec!["Trigger MDM enrollment or re-register the device.".to_string()],
            ));
        }

        if enrollment.enrollment_count > 1 {
            diagnostics.push(issue(
                "multiple-enrollments",
                IntuneDiagnosticSeverity::Info,
                "configuration",
                "Multiple MDM enrollment entries detected",
                "The device has more than one enrollment entry in the registry, which can indicate dual management or stale enrollment records.",
                vec![format!("EnrollmentCount: {}", enrollment.enrollment_count)],
                vec!["Review enrollment entries and confirm only the expected MDM enrollment is active.".to_string()],
                Vec::new(),
            ));
        }
    }

    // MDM confirmed via registry cross-reference (no dsregcmd MDM URLs)
    let mdm_urls_absent = result.facts.management_details.mdm_url.is_none()
        && result.facts.management_details.mdm_compliance_url.is_none();
    if result.derived.mdm_enrolled == Some(true) && mdm_urls_absent {
        let mut evidence_lines = Vec::new();
        if let (Some(ref enrollment), Some(ref tasks)) =
            (&result.enrollment_evidence, &result.scheduled_task_evidence)
        {
            for entry in &enrollment.enrollments {
                let guid_matched = entry.enrollment_state == Some(1)
                    && entry.guid.as_ref().is_some_and(|g| {
                        tasks
                            .enterprise_mgmt_guids
                            .iter()
                            .any(|t| t.eq_ignore_ascii_case(g))
                    });
                if guid_matched {
                    let guid_display = entry.guid.as_deref().unwrap_or("(unknown)");
                    let upn_display = entry.upn.as_deref().unwrap_or("(no UPN)");
                    evidence_lines.push(format!(
                        "GUID: {} — UPN: {} — EnrollmentState: 1 — matched scheduled task",
                        guid_display, upn_display
                    ));
                }
            }
            evidence_lines.push(format!(
                "EnterpriseMgmt scheduled task GUIDs: {}",
                if tasks.enterprise_mgmt_guids.is_empty() {
                    "(none)".to_string()
                } else {
                    tasks.enterprise_mgmt_guids.join(", ")
                }
            ));
        }
        diagnostics.push(issue(
            "mdm-confirmed-via-registry",
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "MDM enrollment confirmed via scheduled tasks and registry",
            "The dsregcmd output does not contain MDM URLs, but the device has active enrollment entries in the registry whose GUIDs match scheduled tasks under \\Microsoft\\Windows\\EnterpriseMgmt. This confirms the device is MDM-enrolled.",
            evidence_lines,
            vec![
                "The dsregcmd MDM URL fields are tenant-dependent and often absent on enrolled devices.".to_string(),
                "The registry cross-reference with scheduled tasks provides a definitive enrollment signal.".to_string(),
            ],
            Vec::new(),
        ));
    }

    diagnostics
}

/// Phase 3: Rules for active diagnostics (connectivity + SCP).
pub fn build_active_diagnostics_rules(
    result: &DsregcmdAnalysisResult,
) -> Vec<DsregcmdDiagnosticInsight> {
    let mut diagnostics = Vec::new();

    let active = match result.active_evidence.as_ref() {
        Some(a) => a,
        None => return diagnostics,
    };

    let has_join_failures = result
        .diagnostics
        .iter()
        .any(|d| d.severity == IntuneDiagnosticSeverity::Error);

    for test in &active.connectivity_tests {
        if !test.reachable {
            let endpoint_lower = test.endpoint.to_ascii_lowercase();

            if endpoint_lower.contains("enterpriseregistration") && has_join_failures {
                diagnostics.push(issue(
                    "endpoint-unreachable-drs",
                    IntuneDiagnosticSeverity::Error,
                    "connectivity",
                    "DRS endpoint is unreachable and join is failing",
                    "The device cannot reach enterpriseregistration.windows.net, which is required for device registration.",
                    vec![
                        format!("Endpoint: {}", test.endpoint),
                        format!("Error: {}", test.error_message.as_deref().unwrap_or("(unknown)")),
                    ],
                    vec!["Restore network access to the DRS endpoint before retrying join.".to_string()],
                    vec!["Fix firewall, proxy, or DNS rules blocking the DRS endpoint.".to_string()],
                ));
            }

            if endpoint_lower.contains("login.microsoftonline.com")
                && !endpoint_lower.contains("device.login")
            {
                diagnostics.push(issue(
                    "endpoint-unreachable-login",
                    IntuneDiagnosticSeverity::Error,
                    "connectivity",
                    "Microsoft Entra login endpoint is unreachable",
                    "The device cannot reach login.microsoftonline.com, which is required for authentication.",
                    vec![
                        format!("Endpoint: {}", test.endpoint),
                        format!("Error: {}", test.error_message.as_deref().unwrap_or("(unknown)")),
                    ],
                    vec!["Restore connectivity to login.microsoftonline.com.".to_string()],
                    vec!["Fix network path to the Microsoft Entra login endpoint.".to_string()],
                ));
            }

            if endpoint_lower.contains("device.login") {
                diagnostics.push(issue(
                    "endpoint-unreachable-device-login",
                    IntuneDiagnosticSeverity::Error,
                    "connectivity",
                    "Device login endpoint is unreachable",
                    "The device cannot reach device.login.microsoftonline.com, which is needed for device code flows and conditional access.",
                    vec![
                        format!("Endpoint: {}", test.endpoint),
                        format!("Error: {}", test.error_message.as_deref().unwrap_or("(unknown)")),
                    ],
                    vec!["Restore connectivity to device.login.microsoftonline.com.".to_string()],
                    vec!["Fix network path to the device login endpoint.".to_string()],
                ));
            }

            let is_hybrid = result.derived.join_type == DsregcmdJoinType::HybridEntraIdJoined
                || result.facts.join_state.domain_joined == Some(true);

            if endpoint_lower.contains("autologon") && is_hybrid {
                diagnostics.push(issue(
                    "seamless-sso-unreachable",
                    IntuneDiagnosticSeverity::Warning,
                    "connectivity",
                    "Seamless SSO endpoint is unreachable on a hybrid device",
                    "The device cannot reach autologon.microsoftazuread-sso.com, which is used for seamless SSO on hybrid-joined devices.",
                    vec![
                        format!("Endpoint: {}", test.endpoint),
                        format!("Error: {}", test.error_message.as_deref().unwrap_or("(unknown)")),
                    ],
                    vec!["Check whether seamless SSO is configured and the endpoint is reachable.".to_string()],
                    Vec::new(),
                ));
            }
        }

        if let Some(latency) = test.latency_ms {
            if latency > 2000 {
                diagnostics.push(issue(
                    "endpoint-high-latency",
                    IntuneDiagnosticSeverity::Warning,
                    "connectivity",
                    "High latency detected to an authentication endpoint",
                    &format!(
                        "The connectivity test to {} completed but took {}ms, which exceeds the 2000ms threshold and may cause timeouts during registration.",
                        test.endpoint, latency
                    ),
                    vec![
                        format!("Endpoint: {}", test.endpoint),
                        format!("Latency: {}ms", latency),
                    ],
                    vec!["Investigate network path quality and proxy overhead for this endpoint.".to_string()],
                    Vec::new(),
                ));
            }
        }
    }

    if let Some(scp) = active.scp_query.as_ref() {
        let is_domain_joined = result.facts.join_state.domain_joined == Some(true);

        if !scp.scp_found && is_domain_joined {
            diagnostics.push(issue(
                "scp-not-found",
                IntuneDiagnosticSeverity::Error,
                "configuration",
                "Service Connection Point not found in Active Directory",
                "The device is domain-joined but no SCP was found for hybrid join configuration. This prevents automatic tenant discovery.",
                vec![
                    format!("SCP found: NO"),
                    format!("Error: {}", scp.error.as_deref().unwrap_or("(none)")),
                ],
                vec![
                    "Verify the SCP is configured in Active Directory for this forest.".to_string(),
                    "Check Azure AD Connect SCP configuration.".to_string(),
                ],
                vec!["Configure the SCP in Active Directory using Azure AD Connect or manually.".to_string()],
            ));
        }

        if scp.scp_found {
            let dsregcmd_tenant = result.facts.tenant_details.domain_name.as_deref();
            let scp_tenant = scp.tenant_domain.as_deref();

            if let (Some(dsregcmd_domain), Some(scp_domain)) = (dsregcmd_tenant, scp_tenant) {
                if !dsregcmd_domain.eq_ignore_ascii_case(scp_domain) {
                    diagnostics.push(issue(
                        "scp-tenant-mismatch-active",
                        IntuneDiagnosticSeverity::Error,
                        "configuration",
                        "SCP tenant domain does not match dsregcmd tenant",
                        "The SCP in Active Directory points to a different tenant than what dsregcmd reports. This can cause hybrid join to target the wrong tenant.",
                        vec![
                            format!("SCP tenant: {scp_domain}"),
                            format!("dsregcmd tenant: {dsregcmd_domain}"),
                        ],
                        vec!["Update the SCP to point to the correct verified tenant domain.".to_string()],
                        vec!["Correct the SCP tenant targeting in Active Directory.".to_string()],
                    ));
                }
            }
        }
    }

    diagnostics
}

/// Phase 4: Rules based on event log evidence.
pub fn build_event_log_diagnostics(
    result: &DsregcmdAnalysisResult,
) -> Vec<DsregcmdDiagnosticInsight> {
    let mut diagnostics = Vec::new();

    let event_log = match result.event_log_analysis.as_ref() {
        Some(a) => a,
        None => return diagnostics,
    };

    let has_join_failures = result.diagnostics.iter().any(|d| {
        d.severity == IntuneDiagnosticSeverity::Error
            && (d.category == "authentication"
                || d.category == "join"
                || d.category == "configuration")
    });

    let has_tpm_errors = result.diagnostics.iter().any(|d| d.id.starts_with("tpm-"));

    // Check for time sync issues near join failures
    let time_sync_errors = event_log.entries.iter().any(|e| {
        let channel_display = e.channel_display.to_ascii_lowercase();
        let message_lower = e.message.to_ascii_lowercase();
        (channel_display.contains("time service") || channel_display.contains("system"))
            && (message_lower.contains("time skew")
                || message_lower.contains("time synchronization")
                || message_lower.contains("clock"))
    });

    if time_sync_errors && has_join_failures {
        diagnostics.push(issue(
            "event-log-time-skew",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "Event logs show time synchronization issues near join failures",
            "The Windows event logs contain time sync or clock skew events that may correlate with authentication or join failures.",
            vec!["Time sync events detected in System or Time Service logs.".to_string()],
            vec![
                "Check device clock accuracy and NTP configuration.".to_string(),
                "Review whether time skew is causing certificate validation or token failures.".to_string(),
            ],
            vec!["Fix time synchronization before retrying device registration.".to_string()],
        ));
    }

    // Check for DPAPI failures near TPM errors
    let dpapi_failures = event_log.entries.iter().any(|e| {
        let channel_display = e.channel_display.to_ascii_lowercase();
        let message_lower = e.message.to_ascii_lowercase();
        channel_display.contains("dpapi")
            && (message_lower.contains("failed")
                || message_lower.contains("error")
                || message_lower.contains("cannot"))
    });

    if dpapi_failures && has_tpm_errors {
        diagnostics.push(issue(
            "event-log-dpapi-failure",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "DPAPI key failures detected alongside TPM errors",
            "The DPAPI operational log shows key protection failures that may be related to the TPM issues observed in the dsregcmd output.",
            vec!["DPAPI operational log errors present alongside TPM diagnostics.".to_string()],
            vec![
                "Check TPM health and whether DPAPI key material is protected by the TPM.".to_string(),
                "Review whether clearing the TPM or re-provisioning keys would resolve the issue.".to_string(),
            ],
            Vec::new(),
        ));
    }

    // Check for AAD operational errors
    let aad_errors = event_log
        .entries
        .iter()
        .filter(|e| {
            let channel_display = e.channel_display.to_ascii_lowercase();
            channel_display.contains("aad")
                && e.severity.is_error_or_warning()
                && !matches!(e.severity, crate::intune::models::EventLogSeverity::Warning)
        })
        .count();

    if aad_errors > 0 {
        diagnostics.push(issue(
            "event-log-aad-errors",
            IntuneDiagnosticSeverity::Info,
            "authentication",
            "AAD operational event log errors present",
            &format!(
                "The AAD Operational event log contains {} error(s) that may provide additional context for authentication or join issues.",
                aad_errors
            ),
            vec![format!("AAD Operational error count: {aad_errors}")],
            vec!["Review the AAD Operational event log entries for additional diagnostic detail.".to_string()],
            Vec::new(),
        ));
    }

    diagnostics
}
