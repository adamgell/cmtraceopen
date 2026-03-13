use chrono::{DateTime, NaiveDateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::dsregcmd::models::{
    DsregcmdAnalysisResult, DsregcmdDerived, DsregcmdDiagnosticInsight, DsregcmdFacts,
    DsregcmdJoinType,
};
use crate::intune::models::IntuneDiagnosticSeverity;

const NETWORK_ERROR_MARKERS: &[&str] = &[
    "ERROR_WINHTTP_TIMEOUT",
    "ERROR_WINHTTP_NAME_NOT_RESOLVED",
    "ERROR_WINHTTP_CANNOT_CONNECT",
    "ERROR_WINHTTP_CONNECTION_ERROR",
];

static CERTIFICATE_TIMESTAMP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: UTC|Z)?|\d{1,2}/\d{1,2}/\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: UTC|Z)?",
    )
    .expect("valid certificate timestamp regex")
});

pub fn analyze_facts(facts: DsregcmdFacts, raw_input: &str) -> DsregcmdAnalysisResult {
    let derived = derive_facts(&facts, raw_input);
    let diagnostics = build_diagnostics(&facts, &derived);

    DsregcmdAnalysisResult {
        facts,
        derived,
        diagnostics,
    }
}

fn derive_facts(facts: &DsregcmdFacts, raw_input: &str) -> DsregcmdDerived {
    let join_type = derive_join_type(facts);
    let join_type_label = join_type_label(join_type).to_string();
    let mdm_enrolled = facts
        .management_details
        .mdm_url
        .as_ref()
        .map(|_| true)
        .or_else(|| {
            if facts.management_details.mdm_compliance_url.is_some() {
                Some(true)
            } else {
                Some(false)
            }
        });
    let missing_mdm = mdm_enrolled.map(|value| !value);
    let compliance_url_present = facts
        .management_details
        .mdm_compliance_url
        .as_ref()
        .map(|_| true)
        .or(Some(false));
    let missing_compliance_url = compliance_url_present.map(|value| !value);
    let azure_ad_prt_present = facts.sso_state.azure_ad_prt;
    let prt_reference_time = facts
        .diagnostics
        .client_time
        .as_deref()
        .and_then(parse_dsregcmd_timestamp)
        .or_else(|| Some(Utc::now()));
    let prt_last_update = facts
        .sso_state
        .azure_ad_prt_update_time
        .as_deref()
        .and_then(parse_dsregcmd_timestamp);
    let prt_age_hours = match (prt_reference_time, prt_last_update) {
        (Some(reference_time), Some(last_update)) => Some(
            reference_time
                .signed_duration_since(last_update)
                .num_minutes() as f64
                / 60.0,
        ),
        _ => None,
    };
    let stale_prt = prt_age_hours.map(|hours| hours > 4.0);
    let tpm_protected = facts.device_details.tpm_protected;
    let (certificate_valid_from, certificate_valid_to) = facts
        .device_details
        .device_certificate_validity
        .as_deref()
        .map(parse_certificate_validity)
        .unwrap_or((None, None));
    let certificate_days_remaining = match (prt_reference_time, certificate_valid_to) {
        (Some(reference_time), Some(valid_to)) => {
            Some(valid_to.signed_duration_since(reference_time).num_days())
        }
        _ => None,
    };
    let certificate_expiring_soon = certificate_days_remaining.map(|days| days < 30);
    let network_error_code = detect_network_error(raw_input);
    let has_network_error = network_error_code.is_some();
    let remote_session_system = match (
        facts.diagnostics.user_context.as_deref(),
        facts.user_state.session_is_not_remote,
    ) {
        (Some(user_context), Some(false)) if user_context.eq_ignore_ascii_case("SYSTEM") => {
            Some(true)
        }
        (Some(_), Some(_)) => Some(false),
        _ => None,
    };

    DsregcmdDerived {
        join_type,
        join_type_label,
        mdm_enrolled,
        missing_mdm,
        compliance_url_present,
        missing_compliance_url,
        azure_ad_prt_present,
        stale_prt,
        prt_last_update,
        prt_reference_time,
        prt_age_hours,
        tpm_protected,
        certificate_valid_from,
        certificate_valid_to,
        certificate_expiring_soon,
        certificate_days_remaining,
        network_error_code,
        has_network_error,
        remote_session_system,
    }
}

fn build_diagnostics(
    facts: &DsregcmdFacts,
    derived: &DsregcmdDerived,
) -> Vec<DsregcmdDiagnosticInsight> {
    let mut diagnostics = Vec::new();
    let aggregated_errors = aggregated_error_text(facts);

    if facts.join_state.azure_ad_joined == Some(false) {
        diagnostics.push(issue(
            "not-aadj",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "Device is not Entra ID joined",
            "AzureAdJoined is NO, so this device is not currently joined to Entra ID.",
            vec![render_bool("AzureAdJoined", facts.join_state.azure_ad_joined)],
            vec![
                "Confirm whether the device should be Entra ID joined or hybrid joined.".to_string(),
                "Review the registration section for client or server error codes.".to_string(),
            ],
            vec![
                "Retry the join or registration workflow from the intended user context.".to_string(),
                "Check tenant targeting, licensing, and connectivity to Entra device registration endpoints.".to_string(),
            ],
        ));
    }

    if is_missing(&facts.tenant_details.tenant_id) {
        diagnostics.push(issue(
            "missing-tenant",
            IntuneDiagnosticSeverity::Error,
            "configuration",
            "Tenant identifier is missing",
            "The dsregcmd output did not include TenantId, which usually indicates registration never completed or the device is not properly scoped to a tenant.",
            vec![render_optional("TenantId", &facts.tenant_details.tenant_id)],
            vec![
                "Verify the device is targeting the expected Entra tenant.".to_string(),
                "Check registration errors and the join server endpoints in the dsregcmd output.".to_string(),
            ],
            vec![
                "Re-run device registration after confirming tenant discovery and network access.".to_string(),
            ],
        ));
    }

    if is_missing(&facts.device_details.device_id) {
        diagnostics.push(issue(
            "missing-deviceid",
            IntuneDiagnosticSeverity::Error,
            "configuration",
            "Device identifier is missing",
            "The dsregcmd output did not include DeviceId, so the device is not presenting a stable Entra device identity.",
            vec![render_optional("DeviceId", &facts.device_details.device_id)],
            vec![
                "Check whether the device certificate and join state are populated.".to_string(),
                "Review previous registration attempts and pre-join test results.".to_string(),
            ],
            vec![
                "Complete or repair device registration before troubleshooting downstream MDM or PRT issues.".to_string(),
            ],
        ));
    }

    if contains_text(&facts.registration.client_error_code, "0x801c03f2")
        || contains_text(&facts.registration.server_error_code, "directoryerror")
        || aggregated_errors.contains("directory sync pending")
    {
        diagnostics.push(issue(
            "entra-sync-pending",
            IntuneDiagnosticSeverity::Error,
            "sync",
            "Directory synchronization appears to be pending",
            "The registration errors match the common hybrid join state where the device object has not fully synchronized to Entra ID yet.",
            vec![
                render_optional("Client ErrorCode", &facts.registration.client_error_code),
                render_optional("Server ErrorCode", &facts.registration.server_error_code),
            ],
            vec![
                "Confirm the corresponding on-premises device object has synchronized to Entra ID.".to_string(),
                "Check Azure AD Connect or Cloud Sync health and object writeback timing.".to_string(),
            ],
            vec![
                "Wait for directory synchronization to complete, then retry registration.".to_string(),
            ],
        ));
    }

    if aggregated_errors.contains("aadsts50155") {
        diagnostics.push(issue(
            "aadsts50155",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "Device authentication failed with AADSTS50155",
            "The tenant rejected the authentication request because device authentication requirements were not satisfied.",
            vec![
                render_optional("Server Message", &facts.registration.server_message),
                render_optional(
                    "Server Error Description",
                    &facts.registration.server_error_description,
                ),
            ],
            vec![
                "Confirm the device object exists and is enabled in Entra ID.".to_string(),
                "Validate certificate trust and device authentication state.".to_string(),
            ],
            vec![
                "Repair the device registration or remove stale device objects before retrying sign-in.".to_string(),
            ],
        ));
    }

    if aggregated_errors.contains("aadsts50034") {
        diagnostics.push(issue(
            "aadsts50034",
            IntuneDiagnosticSeverity::Error,
            "user",
            "User account was not found in the tenant",
            "The dsregcmd error fields contain AADSTS50034, which points to an unknown or mismatched user account during sign-in or registration.",
            vec![render_optional("Server Message", &facts.registration.server_message)],
            vec![
                "Check the user identity shown in the diagnostics block.".to_string(),
                "Confirm the user belongs to the expected tenant and is synchronized.".to_string(),
            ],
            vec![
                "Retry the sign-in flow with the correct tenant-aligned user account.".to_string(),
            ],
        ));
    }

    push_test_failure(
        &mut diagnostics,
        "drs-discovery-failed",
        "discovery",
        "DRS discovery test failed",
        &facts.pre_join_tests.drs_discovery_test,
        vec![
            "Validate DNS resolution and reachability for the join service URLs.".to_string(),
            "Check whether the tenant discovery endpoints are correct for this tenant.".to_string(),
        ],
        vec!["Resolve discovery failures before retrying registration.".to_string()],
    );
    push_test_failure(
        &mut diagnostics,
        "drs-connectivity-failed",
        "connectivity",
        "DRS connectivity test failed",
        &facts.pre_join_tests.drs_connectivity_test,
        vec![
            "Verify outbound HTTPS connectivity to the DRS endpoint.".to_string(),
            "Check proxy, TLS inspection, and firewall behavior.".to_string(),
        ],
        vec!["Restore connectivity to the DRS service and re-run dsregcmd.".to_string()],
    );
    push_test_failure(
        &mut diagnostics,
        "ad-connectivity-failed",
        "connectivity",
        "Active Directory connectivity test failed",
        &facts.pre_join_tests.ad_connectivity_test,
        vec![
            "Confirm the device can reach a domain controller.".to_string(),
            "Review VPN, line-of-sight, and DNS configuration for domain connectivity.".to_string(),
        ],
        vec!["Restore AD connectivity before retrying hybrid join.".to_string()],
    );
    push_test_failure(
        &mut diagnostics,
        "ad-config-failed",
        "configuration",
        "Active Directory configuration test failed",
        &facts.pre_join_tests.ad_configuration_test,
        vec![
            "Review SCP configuration and tenant targeting in on-premises Active Directory."
                .to_string(),
            "Confirm the domain is configured for hybrid join.".to_string(),
        ],
        vec!["Correct the AD hybrid join configuration and retry registration.".to_string()],
    );

    if facts.sso_state.azure_ad_prt == Some(false) {
        diagnostics.push(issue(
            "no-azure-prt",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "No Azure AD PRT is present",
            "AzureAdPrt is NO, so the current sign-in context does not have a Primary Refresh Token available.",
            vec![render_bool("AzureAdPrt", facts.sso_state.azure_ad_prt)],
            vec![
                "Check the diagnostics block for the last PRT acquisition attempt.".to_string(),
                "Review WAM, credentials, and device authentication health.".to_string(),
            ],
            vec![
                "Have the user sign out and back in after correcting registration or credential issues.".to_string(),
            ],
        ));
    }

    if contains_text(&facts.diagnostics.attempt_status, "0xc000006d") {
        diagnostics.push(issue(
            "invalid-credentials",
            IntuneDiagnosticSeverity::Error,
            "credentials",
            "PRT acquisition failed because credentials were rejected",
            "Attempt Status contains 0xc000006d, which maps to invalid credentials during the sign-in flow.",
            vec![render_optional("Attempt Status", &facts.diagnostics.attempt_status)],
            vec![
                "Check whether the user recently changed their password or entered the wrong credentials.".to_string(),
                "Review the credential type and user identity fields in the diagnostics section.".to_string(),
            ],
            vec![
                "Retry authentication with the correct credentials or refreshed password.".to_string(),
            ],
        ));
    }

    if contains_text(&facts.registration.server_error_description, "aadsts50126") {
        diagnostics.push(issue(
            "aadsts50126-detailed",
            IntuneDiagnosticSeverity::Error,
            "credentials",
            "Server error description reports AADSTS50126",
            "The detailed server error description indicates invalid username or password during authentication.",
            vec![render_optional(
                "Server Error Description",
                &facts.registration.server_error_description,
            )],
            vec![
                "Compare the user identity in dsregcmd with the expected sign-in account.".to_string(),
                "Review conditional access or federation prompts that may have redirected the flow.".to_string(),
            ],
            vec![
                "Retry sign-in with valid credentials after confirming the correct account.".to_string(),
            ],
        ));
    }

    if aggregated_errors.contains("aadsts90002")
        || aggregated_errors.contains("tenant uuid not found")
    {
        diagnostics.push(issue(
            "tenant-uuid-not-found",
            IntuneDiagnosticSeverity::Error,
            "dynamic",
            "Tenant identifier could not be resolved",
            "The aggregated dsregcmd error fields contain an AADSTS90002-style tenant lookup failure.",
            vec![
                render_optional("TenantId", &facts.tenant_details.tenant_id),
                render_optional("Server Message", &facts.registration.server_message),
            ],
            vec![
                "Verify the tenant ID and tenant discovery URLs in the capture.".to_string(),
                "Confirm the user and device are targeting the correct cloud tenant.".to_string(),
            ],
            vec!["Correct the tenant targeting information and retry registration.".to_string()],
        ));
    }

    if aggregated_errors.contains("1312") || aggregated_errors.contains("1317") {
        diagnostics.push(issue(
            "ad-replication-issue",
            IntuneDiagnosticSeverity::Error,
            "dynamic",
            "Directory replication or lookup issue detected",
            "The aggregated registration errors contain 1312 or 1317, which commonly show up during AD replication or object lookup problems.",
            vec![
                render_optional("Client ErrorCode", &facts.registration.client_error_code),
                render_optional("Server ErrorCode", &facts.registration.server_error_code),
            ],
            vec![
                "Check the health of the on-premises AD object and replication status.".to_string(),
                "Verify the computer account exists and is consistent across domain controllers.".to_string(),
            ],
            vec!["Resolve the directory replication issue, then retry hybrid join.".to_string()],
        ));
    }

    if let Some(device_auth_status) = facts.device_details.device_auth_status.as_deref() {
        if !device_auth_status.eq_ignore_ascii_case("SUCCESS") {
            diagnostics.push(issue(
                "device-auth-failed",
                IntuneDiagnosticSeverity::Error,
                "authentication",
                "Device authentication status is not SUCCESS",
                "DeviceAuthStatus reports a failing or incomplete state, so the device is not currently authenticating cleanly with Entra ID.",
                vec![render_optional(
                    "DeviceAuthStatus",
                    &facts.device_details.device_auth_status,
                )],
                vec![
                    "Compare device authentication status with certificate, TPM, and join state details.".to_string(),
                    "Look for upstream registration or certificate errors in the capture.".to_string(),
                ],
                vec!["Repair device registration and certificate trust before retrying authentication.".to_string()],
            ));
        }
    }

    if derived.missing_mdm == Some(true) {
        diagnostics.push(issue(
            "no-mdm",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "MDM enrollment URL is missing",
            "No MdmUrl was present in the capture, so dsregcmd does not show active MDM enrollment information.",
            vec![render_optional("MdmUrl", &facts.management_details.mdm_url)],
            vec![
                "Confirm the device should be enrolled into MDM for this tenant.".to_string(),
                "Review automatic enrollment scope and licensing.".to_string(),
            ],
            vec!["Trigger or repair MDM enrollment after confirming tenant policy scope.".to_string()],
        ));
    }

    if derived.missing_compliance_url == Some(true) {
        diagnostics.push(issue(
            "no-compliance",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "Compliance URL is missing",
            "No MdmComplianceUrl was present, so the device is missing the normal compliance service endpoint in dsregcmd.",
            vec![render_optional(
                "MdmComplianceUrl",
                &facts.management_details.mdm_compliance_url,
            )],
            vec![
                "Check whether the device is enrolled to the expected MDM authority.".to_string(),
                "Compare with another healthy device from the same tenant.".to_string(),
            ],
            vec!["Repair enrollment if the device should be managed and compliance-capable.".to_string()],
        ));
    }

    if facts.user_state.ngc_set == Some(false) {
        diagnostics.push(issue(
            "ngc-not-set",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "Windows Hello for Business is not set",
            "NgcSet is NO, so a Windows Hello for Business container is not configured for the current user context.",
            vec![render_bool("NgcSet", facts.user_state.ngc_set)],
            vec![
                "Check whether WHfB is expected on this device and user.".to_string(),
                "Review prereq state and provisioning policy details.".to_string(),
            ],
            vec!["Provision or re-provision Windows Hello for Business if required.".to_string()],
        ));
    }

    if facts.user_state.wam_default_set == Some(false) {
        diagnostics.push(issue(
            "wam-not-default",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "Web Account Manager default account is not set",
            "WamDefaultSet is NO, which often lines up with user sign-in or token acquisition issues.",
            vec![render_bool("WamDefaultSet", facts.user_state.wam_default_set)],
            vec![
                "Check the signed-in account and WAM authority values.".to_string(),
                "Review whether the user is fully signed in to Windows with a work account.".to_string(),
            ],
            vec!["Refresh the account session or sign in again to restore WAM defaults.".to_string()],
        ));
    }

    if contains_text(&facts.registration.server_message, "aadsts50126") {
        diagnostics.push(issue(
            "aadsts50126",
            IntuneDiagnosticSeverity::Warning,
            "credentials",
            "Server message reports AADSTS50126",
            "The high-level server message indicates invalid credentials or an authentication mismatch.",
            vec![render_optional("Server Message", &facts.registration.server_message)],
            vec![
                "Compare the user identity, credential type, and endpoint URI in the diagnostics block.".to_string(),
            ],
            vec!["Retry sign-in with the correct account and credentials.".to_string()],
        ));
    }

    if let Some(network_error_code) = derived.network_error_code.as_deref() {
        diagnostics.push(issue(
            "network-issue",
            IntuneDiagnosticSeverity::Warning,
            "network",
            "Network connectivity marker detected",
            &format!(
                "The capture contains {}, which points to a network, DNS, proxy, or transport-layer problem during registration or token acquisition.",
                network_error_code
            ),
            vec![
                format!("NetworkErrorCode: {}", network_error_code),
                render_optional("HTTP Error", &facts.diagnostics.http_error),
                render_optional("Endpoint URI", &facts.diagnostics.endpoint_uri),
            ],
            vec![
                "Test name resolution and HTTPS connectivity to the endpoint URI.".to_string(),
                "Check WinHTTP proxy configuration and outbound firewall policy.".to_string(),
            ],
            vec!["Resolve the network path issue and re-run dsregcmd /status.".to_string()],
        ));
    }

    if derived.stale_prt == Some(true) {
        let age_text = derived
            .prt_age_hours
            .map(|hours| format!("{hours:.1} hours"))
            .unwrap_or_else(|| "more than 4 hours".to_string());
        diagnostics.push(issue(
            "stale-prt",
            IntuneDiagnosticSeverity::Warning,
            "dynamic",
            "Azure AD PRT appears stale",
            &format!(
                "AzureAdPrtUpdateTime is older than the 4-hour threshold ({age_text})."
            ),
            vec![
                render_optional(
                    "AzureAdPrtUpdateTime",
                    &facts.sso_state.azure_ad_prt_update_time,
                ),
                render_optional("Client Time", &facts.diagnostics.client_time),
            ],
            vec![
                "Check whether token renewal is being blocked by sign-in, network, or device auth issues.".to_string(),
                "Review the last PRT acquisition attempt and any AADSTS codes.".to_string(),
            ],
            vec!["Refresh the user sign-in session after fixing the root cause.".to_string()],
        ));
    }

    if facts.device_details.tpm_protected == Some(false) {
        diagnostics.push(issue(
            "no-tpm-protection",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "Device keys are not TPM protected",
            "TpmProtected is NO, so the device registration keys are not currently backed by TPM protection.",
            vec![render_bool("TpmProtected", facts.device_details.tpm_protected)],
            vec![
                "Confirm whether the device has a healthy TPM and that it is available to Windows.".to_string(),
                "Compare the key provider and key container details with a healthy device.".to_string(),
            ],
            vec!["Resolve TPM availability issues or re-register the device using hardware-backed keys.".to_string()],
        ));
    }

    if let Some(logon_cert_template_ready) = facts.registration.logon_cert_template_ready.as_deref()
    {
        if !logon_cert_template_ready.contains("StateReady") {
            diagnostics.push(issue(
                "logon-cert-not-ready",
                IntuneDiagnosticSeverity::Warning,
                "configuration",
                "Logon certificate template is not ready",
                "LogonCertTemplateReady is present but does not report StateReady.",
                vec![render_optional(
                    "LogonCertTemplateReady",
                    &facts.registration.logon_cert_template_ready,
                )],
                vec![
                    "Review certificate enrollment prerequisites and issuance policy.".to_string(),
                    "Check whether the device can reach the issuing CA or enrollment service."
                        .to_string(),
                ],
                vec![
                    "Resolve certificate enrollment prerequisites and retry the registration flow."
                        .to_string(),
                ],
            ));
        }
    }

    if derived.certificate_expiring_soon == Some(true) {
        let certificate_summary = match derived.certificate_days_remaining {
            Some(days_remaining) if days_remaining < 0 => {
                format!(
                    "The device certificate already expired {} days ago.",
                    days_remaining.abs()
                )
            }
            Some(days_remaining) => {
                format!("The device certificate expires in {} days.", days_remaining)
            }
            None => "The device certificate validity window is near expiry.".to_string(),
        };
        diagnostics.push(issue(
            "cert-expiring-soon",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "Device certificate validity is near expiry",
            &certificate_summary,
            vec![render_optional(
                "DeviceCertificateValidity",
                &facts.device_details.device_certificate_validity,
            )],
            vec![
                "Check whether automatic device certificate renewal is functioning.".to_string(),
                "Review device auth state and certificate enrollment prerequisites.".to_string(),
            ],
            vec![
                "Renew or repair the device certificate before authentication starts failing."
                    .to_string(),
            ],
        ));
    }

    if derived.remote_session_system == Some(true) {
        diagnostics.push(issue(
            "remote-session-system",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "Capture was taken as SYSTEM in a remote session",
            "The diagnostics block shows User Context as SYSTEM while SessionIsNotRemote is NO, which can produce misleading token and user-state output.",
            vec![
                render_optional("User Context", &facts.diagnostics.user_context),
                render_bool("SessionIsNotRemote", facts.user_state.session_is_not_remote),
            ],
            vec![
                "Compare with a capture taken interactively as the affected user.".to_string(),
                "Be cautious when interpreting PRT and WAM fields from SYSTEM remote sessions.".to_string(),
            ],
            vec!["Re-run dsregcmd /status in the intended interactive user session when possible.".to_string()],
        ));
    }

    if facts.join_state.workplace_joined == Some(false) {
        diagnostics.push(issue(
            "not-workplace-joined",
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "Workplace join is not present",
            "WorkplaceJoined is NO.",
            vec![render_bool("WorkplaceJoined", facts.join_state.workplace_joined)],
            vec!["This is informational unless workplace join is specifically expected for the scenario.".to_string()],
            Vec::new(),
        ));
    }

    if facts.join_state.domain_joined == Some(true) {
        diagnostics.push(issue(
            "onprem-domain-joined",
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "Device is joined to on-premises Active Directory",
            "DomainJoined is YES.",
            vec![render_bool("DomainJoined", facts.join_state.domain_joined)],
            vec!["Use this together with AzureAdJoined to understand whether the device is hybrid joined.".to_string()],
            Vec::new(),
        ));
    }

    match derived.join_type {
        DsregcmdJoinType::EntraIdJoined => diagnostics.push(issue(
            "join-type-entraid",
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "Join type is Entra ID Joined",
            "AzureAdJoined is YES and DomainJoined is NO.",
            vec![format!("JoinType: {}", derived.join_type_label)],
            vec!["This is the expected join state for cloud-only Entra ID joined devices.".to_string()],
            Vec::new(),
        )),
        DsregcmdJoinType::HybridEntraIdJoined => diagnostics.push(issue(
            "join-type-hybrid",
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "Join type is Hybrid Entra ID Joined",
            "AzureAdJoined is YES and DomainJoined is YES.",
            vec![format!("JoinType: {}", derived.join_type_label)],
            vec!["Hybrid join scenarios depend on both AD connectivity and Entra registration health.".to_string()],
            Vec::new(),
        )),
        _ => {}
    }

    if facts.user_state.ngc_set == Some(false)
        && equals_text(&facts.registration.pre_req_result, "WillProvision")
    {
        diagnostics.push(issue(
            "ngc-will-provision",
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "Windows Hello for Business is expected to provision",
            "NgcSet is NO but PreReqResult is WillProvision, which means prerequisites are satisfied and provisioning is expected later.",
            vec![
                render_bool("NgcSet", facts.user_state.ngc_set),
                render_optional("PreReqResult", &facts.registration.pre_req_result),
            ],
            vec!["Monitor the next sign-in or policy refresh to confirm WHfB provisioning completes.".to_string()],
            Vec::new(),
        ));
    }

    if facts.join_state.enterprise_joined == Some(true) {
        diagnostics.push(issue(
            "enterprise-joined",
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "EnterpriseJoined is enabled",
            "EnterpriseJoined is YES.",
            vec![render_bool("EnterpriseJoined", facts.join_state.enterprise_joined)],
            vec!["Use this as additional context when reviewing legacy join or federation scenarios.".to_string()],
            Vec::new(),
        ));
    }

    if derived.join_type == DsregcmdJoinType::HybridEntraIdJoined
        && contains_text(&facts.pre_join_tests.fallback_to_sync_join, "enabled")
    {
        diagnostics.push(issue(
            "hybrid-fallback-enabled",
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "Hybrid join fallback to sync-join is enabled",
            "Fallback to Sync-Join reports ENABLED while the device is hybrid joined.",
            vec![render_optional(
                "Fallback to Sync-Join",
                &facts.pre_join_tests.fallback_to_sync_join,
            )],
            vec![
                "This is informational context for hybrid join timing and registration behavior."
                    .to_string(),
            ],
            Vec::new(),
        ));
    }

    diagnostics
}

fn derive_join_type(facts: &DsregcmdFacts) -> DsregcmdJoinType {
    match (
        facts.join_state.azure_ad_joined,
        facts.join_state.domain_joined,
    ) {
        (Some(true), Some(true)) => DsregcmdJoinType::HybridEntraIdJoined,
        (Some(true), Some(false)) => DsregcmdJoinType::EntraIdJoined,
        (Some(false), _) => DsregcmdJoinType::NotJoined,
        _ => DsregcmdJoinType::Unknown,
    }
}

fn join_type_label(join_type: DsregcmdJoinType) -> &'static str {
    match join_type {
        DsregcmdJoinType::HybridEntraIdJoined => "Hybrid Entra ID Joined",
        DsregcmdJoinType::EntraIdJoined => "Entra ID Joined",
        DsregcmdJoinType::NotJoined => "Not Joined",
        DsregcmdJoinType::Unknown => "Unknown",
    }
}

fn parse_dsregcmd_timestamp(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(parsed.with_timezone(&Utc));
    }

    for format in [
        "%Y-%m-%d %H:%M:%S%.f UTC",
        "%Y-%m-%d %H:%M:%S UTC",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S%.f UTC",
        "%m/%d/%Y %H:%M:%S UTC",
        "%m/%d/%Y %H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S",
    ] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(trimmed, format) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(parsed, Utc));
        }
    }

    None
}

fn parse_certificate_validity(value: &str) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    let timestamps: Vec<DateTime<Utc>> = CERTIFICATE_TIMESTAMP_RE
        .find_iter(value)
        .filter_map(|capture| parse_dsregcmd_timestamp(capture.as_str()))
        .collect();

    match timestamps.as_slice() {
        [valid_from, valid_to, ..] => (Some(*valid_from), Some(*valid_to)),
        [valid_to] => (None, Some(*valid_to)),
        _ => (None, None),
    }
}

fn detect_network_error(raw_input: &str) -> Option<String> {
    let uppercase = raw_input.to_ascii_uppercase();
    NETWORK_ERROR_MARKERS
        .iter()
        .find(|marker| uppercase.contains(**marker))
        .map(|marker| (*marker).to_string())
}

fn aggregated_error_text(facts: &DsregcmdFacts) -> String {
    [
        facts.registration.client_error_code.as_deref(),
        facts.registration.server_error_code.as_deref(),
        facts.registration.server_message.as_deref(),
        facts.registration.server_error_description.as_deref(),
        facts.diagnostics.attempt_status.as_deref(),
        facts.diagnostics.http_error.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase()
}

fn push_test_failure(
    diagnostics: &mut Vec<DsregcmdDiagnosticInsight>,
    id: &str,
    category: &str,
    title: &str,
    field: &Option<String>,
    next_checks: Vec<String>,
    suggested_fixes: Vec<String>,
) {
    let Some(value) = field.as_deref() else {
        return;
    };

    if !value.to_ascii_uppercase().contains("FAIL") {
        return;
    }

    let mut evidence = vec![format!("Result: {value}")];
    if let Some(detail) = extract_bracket_detail(value) {
        evidence.push(format!("Detail: {detail}"));
    }

    diagnostics.push(issue(
        id,
        IntuneDiagnosticSeverity::Error,
        category,
        title,
        &format!("{title}."),
        evidence,
        next_checks,
        suggested_fixes,
    ));
}

fn extract_bracket_detail(value: &str) -> Option<String> {
    let start = value.find('[')?;
    let end = value[start + 1..].find(']')?;
    let detail = &value[start + 1..start + 1 + end];
    (!detail.trim().is_empty()).then(|| detail.trim().to_string())
}

#[expect(
    clippy::too_many_arguments,
    reason = "diagnostic construction keeps explicit backend contract fields together"
)]
fn issue(
    id: &str,
    severity: IntuneDiagnosticSeverity,
    category: &str,
    title: &str,
    summary: &str,
    evidence: Vec<String>,
    next_checks: Vec<String>,
    suggested_fixes: Vec<String>,
) -> DsregcmdDiagnosticInsight {
    DsregcmdDiagnosticInsight {
        id: id.to_string(),
        severity,
        category: category.to_string(),
        title: title.to_string(),
        summary: summary.to_string(),
        evidence,
        next_checks,
        suggested_fixes,
    }
}

fn render_optional(label: &str, value: &Option<String>) -> String {
    match value {
        Some(value) => format!("{label}: {value}"),
        None => format!("{label}: (missing)"),
    }
}

fn render_bool(label: &str, value: Option<bool>) -> String {
    match value {
        Some(true) => format!("{label}: YES"),
        Some(false) => format!("{label}: NO"),
        None => format!("{label}: (unknown)"),
    }
}

fn contains_text(field: &Option<String>, needle: &str) -> bool {
    field
        .as_deref()
        .map(|value| {
            value
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        })
        .unwrap_or(false)
}

fn equals_text(field: &Option<String>, expected: &str) -> bool {
    field
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

fn is_missing(field: &Option<String>) -> bool {
    field.is_none()
}

#[cfg(test)]
mod tests {
    use super::analyze_facts;
    use crate::dsregcmd::models::DsregcmdJoinType;
    use crate::dsregcmd::parser::parse_dsregcmd;
    use crate::intune::models::IntuneDiagnosticSeverity;

    const HYBRID_SAMPLE: &str = r#"
 AzureAdJoined : YES
 DomainJoined : YES
 WorkplaceJoined : NO
 EnterpriseJoined : YES
 NgcSet : NO
 TenantId : 11111111-2222-3333-4444-555555555555
 TenantName : Contoso
 DeviceId : abcdefab-1111-2222-3333-abcdefabcdef
 DeviceAuthStatus : FAILED. Device is either disabled or deleted
 MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
 MdmComplianceUrl : https://portal.manage.microsoft.com/Compliance
 AzureAdPrt : YES
 AzureAdPrtUpdateTime : 2025-03-10 05:00:00.000 UTC
 TpmProtected : NO
 DeviceCertificateValidity : [ 2025-03-01 00:00:00.000 UTC -- 2025-03-20 00:00:00.000 UTC ]
 Previous Prt Attempt : 2025-03-10 08:30:00.000 UTC
 Attempt Status : 0xc000006d
 User Context : SYSTEM
 SessionIsNotRemote : NO
 Client Time : 2025-03-10 10:30:00.000 UTC
 DRS Discovery Test : FAIL [0x801c0021]
 AD Connectivity Test : FAIL [0x54b]
 Fallback to Sync-Join : ENABLED
 Server Message : AADSTS50126 Invalid username or password ERROR_WINHTTP_TIMEOUT
 Server Error Description : AADSTS50126: Invalid username or password.
 LogonCertTemplateReady : Pending
 PreReqResult : WillProvision
"#;

    const NOT_JOINED_SAMPLE: &str = r#"
 AzureAdJoined : NO
 DomainJoined : NO
 WorkplaceJoined : NO
 TenantId : -
 DeviceId : -
 MdmUrl : -
 MdmComplianceUrl : -
 AzureAdPrt : NO
"#;

    #[test]
    fn derives_join_type_and_high_value_flags() {
        let facts = parse_dsregcmd(HYBRID_SAMPLE).expect("parse hybrid sample");
        let analysis = analyze_facts(facts, HYBRID_SAMPLE);

        assert_eq!(
            analysis.derived.join_type,
            DsregcmdJoinType::HybridEntraIdJoined
        );
        assert_eq!(analysis.derived.azure_ad_prt_present, Some(true));
        assert_eq!(analysis.derived.stale_prt, Some(true));
        assert_eq!(analysis.derived.tpm_protected, Some(false));
        assert_eq!(analysis.derived.certificate_expiring_soon, Some(true));
        assert_eq!(
            analysis.derived.network_error_code.as_deref(),
            Some("ERROR_WINHTTP_TIMEOUT")
        );
        assert_eq!(analysis.derived.remote_session_system, Some(true));
    }

    #[test]
    fn emits_expected_error_warning_and_info_rules() {
        let facts = parse_dsregcmd(HYBRID_SAMPLE).expect("parse hybrid sample");
        let analysis = analyze_facts(facts, HYBRID_SAMPLE);
        let ids: Vec<&str> = analysis
            .diagnostics
            .iter()
            .map(|item| item.id.as_str())
            .collect();

        for expected in [
            "device-auth-failed",
            "drs-discovery-failed",
            "ad-connectivity-failed",
            "invalid-credentials",
            "aadsts50126-detailed",
            "aadsts50126",
            "network-issue",
            "stale-prt",
            "no-tpm-protection",
            "logon-cert-not-ready",
            "cert-expiring-soon",
            "remote-session-system",
            "join-type-hybrid",
            "hybrid-fallback-enabled",
            "ngc-will-provision",
            "enterprise-joined",
        ] {
            assert!(ids.contains(&expected), "missing diagnostic: {expected}");
        }

        let remote_rule = analysis
            .diagnostics
            .iter()
            .find(|item| item.id == "remote-session-system")
            .expect("remote session rule present");
        assert_eq!(remote_rule.severity, IntuneDiagnosticSeverity::Warning);
    }

    #[test]
    fn emits_core_not_joined_rules() {
        let facts = parse_dsregcmd(NOT_JOINED_SAMPLE).expect("parse not joined sample");
        let analysis = analyze_facts(facts, NOT_JOINED_SAMPLE);
        let ids: Vec<&str> = analysis
            .diagnostics
            .iter()
            .map(|item| item.id.as_str())
            .collect();

        assert_eq!(analysis.derived.join_type, DsregcmdJoinType::NotJoined);
        for expected in [
            "not-aadj",
            "missing-tenant",
            "missing-deviceid",
            "no-azure-prt",
            "no-mdm",
            "no-compliance",
            "not-workplace-joined",
        ] {
            assert!(ids.contains(&expected), "missing diagnostic: {expected}");
        }
    }
}
