use crate::dsregcmd::models::{
    DsregcmdAnalysisResult, DsregcmdDiagnosticInsight, DsregcmdFacts, DsregcmdJoinType,
};
use crate::intune::models::IntuneDiagnosticSeverity;

use super::derive::{
    aggregated_error_text, contains_text, derive_facts, equals_text, has_code, is_failure,
    is_failure_text, is_missing, issue, push_test_failure, render_bool, render_optional,
    render_phase_code_evidence,
};

// Re-export public items that external callers depend on.
pub use super::extended::{
    apply_enrollment_cross_reference, build_active_diagnostics_rules,
    build_event_log_diagnostics, build_extended_diagnostics,
};

pub fn analyze_facts(facts: DsregcmdFacts, raw_input: &str) -> DsregcmdAnalysisResult {
    let derived = derive_facts(&facts, raw_input);
    let diagnostics = build_diagnostics(&facts, &derived);

    DsregcmdAnalysisResult {
        facts,
        derived,
        diagnostics,
        policy_evidence: Default::default(),
        os_version: None,
        proxy_evidence: None,
        enrollment_evidence: None,
        active_evidence: None,
        scheduled_task_evidence: None,
        event_log_analysis: None,
    }
}

fn build_diagnostics(
    facts: &DsregcmdFacts,
    derived: &super::models::DsregcmdDerived,
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

    if has_code(facts, "0xcaa90017") {
        diagnostics.push(issue(
            "adal-protocol-not-supported",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "Federation service does not support the required WS-Trust protocol",
            "The failure pattern matches ERROR_ADAL_PROTOCOL_NOT_SUPPORTED (0xcaa90017), which means the federated identity provider is not exposing the WS-Trust protocol flow that hybrid join expects.",
            vec![render_phase_code_evidence(facts, "0xcaa90017")],
            vec![
                "Review federation settings and confirm the on-premises identity provider supports WS-Trust for device registration flows.".to_string(),
                "Check whether the endpoint returned by federation metadata matches the protocol expected by Windows.".to_string(),
            ],
            vec!["Enable or repair the required WS-Trust support in the identity provider.".to_string()],
        ));
    }

    if has_code(facts, "0xcaa9002c") {
        diagnostics.push(issue(
            "adal-parse-xml-failed",
            IntuneDiagnosticSeverity::Error,
            "configuration",
            "Federation metadata XML could not be parsed",
            "The failure pattern matches ERROR_ADAL_FAILED_TO_PARSE_XML (0xcaa9002c), which usually means the MEX or WS-Trust endpoint returned malformed or unexpected XML.",
            vec![render_phase_code_evidence(facts, "0xcaa9002c")],
            vec![
                "Inspect the MEX endpoint response for valid XML and correct WS-Trust metadata.".to_string(),
                "Check whether a proxy is replacing the expected federation XML with an HTML or otherwise modified response.".to_string(),
            ],
            vec!["Repair the federation metadata response so it returns valid XML.".to_string()],
        ));
    }

    if has_code(facts, "0xcaa90023") {
        diagnostics.push(issue(
            "adal-password-endpoint-missing",
            IntuneDiagnosticSeverity::Error,
            "configuration",
            "Federation metadata is missing the username or password endpoint",
            "The failure pattern matches ERROR_ADAL_COULDNOT_DISCOVER_USERNAME_PASSWORD_ENDPOINT (0xcaa90023), which means the MEX response does not advertise the WS-Trust endpoint Windows expects to use.",
            vec![render_phase_code_evidence(facts, "0xcaa90023")],
            vec![
                "Review the MEX response for the required WS-Trust username/password endpoints.".to_string(),
                "Confirm the identity provider publishes the correct endpoints for federated hybrid join.".to_string(),
            ],
            vec!["Fix the federation metadata so the required endpoints are advertised.".to_string()],
        ));
    }

    if has_code(facts, "0xcaa82ee2") {
        diagnostics.push(issue(
            "adal-timeout",
            IntuneDiagnosticSeverity::Error,
            "network",
            "Federated authentication timed out",
            "The failure pattern matches ERROR_ADAL_INTERNET_TIMEOUT (0xcaa82ee2), which means the device could not complete communication with Microsoft Entra or the federation endpoint in time.",
            vec![render_phase_code_evidence(facts, "0xcaa82ee2")],
            vec![
                "Verify connectivity to https://login.microsoftonline.com and the federated identity provider from the effective system or user context.".to_string(),
                "Check proxy behavior, network stability, and endpoint reachability.".to_string(),
            ],
            vec!["Resolve the network timeout path before retrying authentication.".to_string()],
        ));
    }

    if has_code(facts, "0xcaa82efe") {
        diagnostics.push(issue(
            "adal-connection-aborted",
            IntuneDiagnosticSeverity::Error,
            "network",
            "Federated authentication connection was aborted",
            "The failure pattern matches ERROR_ADAL_INTERNET_CONNECTION_ABORTED (0xcaa82efe), which means the connection to the authorization endpoint terminated unexpectedly.",
            vec![render_phase_code_evidence(facts, "0xcaa82efe")],
            vec![
                "Check for unstable network links or intermediary devices terminating the connection.".to_string(),
                "Retry from a more stable network path and compare results.".to_string(),
            ],
            vec!["Stabilize the network path or endpoint availability before retrying.".to_string()],
        ));
    }

    if has_code(facts, "0xcaa82f8f") {
        diagnostics.push(issue(
            "adal-secure-failure",
            IntuneDiagnosticSeverity::Error,
            "network",
            "TLS validation failed during federated authentication",
            "The failure pattern matches ERROR_ADAL_INTERNET_SECURE_FAILURE (0xcaa82f8f), which usually means certificate validation or time skew blocked the secure connection.",
            vec![render_phase_code_evidence(facts, "0xcaa82f8f")],
            vec![
                "Check device time skew and certificate trust for the federated endpoint.".to_string(),
                "Review whether TLS inspection or certificate replacement is breaking trust.".to_string(),
            ],
            vec!["Fix certificate trust or time skew before retrying federated authentication.".to_string()],
        ));
    }

    if has_code(facts, "0xcaa82efd") {
        diagnostics.push(issue(
            "adal-cannot-connect",
            IntuneDiagnosticSeverity::Error,
            "network",
            "The device could not connect to the federated or Microsoft Entra endpoint",
            "The failure pattern matches ERROR_ADAL_INTERNET_CANNOT_CONNECT (0xcaa82efd), which means the connection to the authentication endpoint could not be established.",
            vec![render_phase_code_evidence(facts, "0xcaa82efd")],
            vec![
                "Check endpoint URI reachability and whether outbound proxy rules allow the traffic.".to_string(),
                "Validate DNS resolution and HTTPS connectivity for the authentication endpoint.".to_string(),
            ],
            vec!["Restore connectivity to the authentication endpoint and retry.".to_string()],
        ));
    }

    if has_code(facts, "0xcaa20003") {
        diagnostics.push(issue(
            "adal-invalid-grant",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "Microsoft Entra rejected the federated assertion as an invalid grant",
            "The failure pattern matches ERROR_ADAL_SERVER_ERROR_INVALID_GRANT (0xcaa20003), which means Microsoft Entra rejected the SAML assertion supplied by the federated identity provider.",
            vec![render_phase_code_evidence(facts, "0xcaa20003")],
            vec![
                "Review federation logs and server error details for why the assertion was rejected.".to_string(),
                "Check claim issuance rules and token content from the identity provider.".to_string(),
            ],
            vec!["Repair the federation assertion flow before retrying sign-in.".to_string()],
        ));
    }

    if has_code(facts, "0xcaa90014") {
        diagnostics.push(issue(
            "adal-wstrust-request-failed",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "The WS-Trust request failed with a server-side fault",
            "The failure pattern matches ERROR_ADAL_WSTRUST_REQUEST_SECURITYTOKEN_FAILED (0xcaa90014), which means the federation service returned a WS-Trust fault instead of the expected assertion.",
            vec![render_phase_code_evidence(facts, "0xcaa90014")],
            vec![
                "Review federation server logs for the specific WS-Trust fault returned to the device.".to_string(),
                "Check whether metadata, claim rules, or certificate trust issues are causing the failure.".to_string(),
            ],
            vec!["Repair the WS-Trust issuance path before retrying authentication.".to_string()],
        ));
    }

    if has_code(facts, "0xcaa90006") {
        diagnostics.push(issue(
            "adal-token-request-failed",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "The federated token request failed before an access token was returned",
            "The failure pattern matches ERROR_ADAL_WSTRUST_TOKEN_REQUEST_FAIL (0xcaa90006), which means the device could not complete token acquisition against the WS-Trust endpoint.",
            vec![render_phase_code_evidence(facts, "0xcaa90006")],
            vec![
                "Check the underlying federation endpoint error and whether the request reached the token service.".to_string(),
                "Review WS-Trust endpoint health and metadata correctness.".to_string(),
            ],
            vec!["Resolve the WS-Trust token issuance failure and retry.".to_string()],
        ));
    }

    if has_code(facts, "0xcaa1002d") {
        diagnostics.push(issue(
            "adal-operation-pending",
            IntuneDiagnosticSeverity::Warning,
            "authentication",
            "The federated authentication operation is still reported as pending",
            "The failure pattern matches ERROR_ADAL_OPERATION_PENDING (0xcaa1002d), which is a broad ADAL failure that usually needs the underlying suberror or server code to narrow down the root cause.",
            vec![render_phase_code_evidence(facts, "0xcaa1002d")],
            vec![
                "Check any accompanying federation server or suberror details in the capture.".to_string(),
                "Look for a more specific network, WS-Trust, or server-side error in the surrounding fields.".to_string(),
            ],
            Vec::new(),
        ));
    }

    if contains_text(&facts.registration.client_error_code, "0x801c001d")
        || contains_text(&facts.pre_join_tests.ad_configuration_test, "0x801c001d")
    {
        diagnostics.push(issue(
            "scp-read-failed",
            IntuneDiagnosticSeverity::Error,
            "configuration",
            "Service Connection Point lookup failed",
            "The failure pattern matches DSREG_AUTOJOIN_ADCONFIG_READ_FAILED (0x801c001d), which usually means the device could not read or validate the Service Connection Point for hybrid join.",
            vec![
                render_optional("AD Configuration Test", &facts.pre_join_tests.ad_configuration_test),
                render_optional("Client ErrorCode", &facts.registration.client_error_code),
            ],
            vec![
                "Verify the SCP exists in the correct forest and points to the expected verified tenant domain.".to_string(),
                "Check whether the device can read the SCP from a reachable domain controller.".to_string(),
            ],
            vec![
                "Correct the hybrid join SCP configuration before retrying registration.".to_string(),
            ],
        ));
    }

    if contains_text(&facts.registration.client_error_code, "0x801c0021")
        || contains_text(&facts.pre_join_tests.drs_discovery_test, "0x801c0021")
    {
        diagnostics.push(issue(
            "drs-discovery-code",
            IntuneDiagnosticSeverity::Error,
            "discovery",
            "DRS discovery metadata retrieval failed",
            "The failure pattern matches DSREG_AUTOJOIN_DISC_FAILED (0x801c0021), which points to tenant discovery metadata retrieval failing before registration can proceed.",
            vec![
                render_optional("DRS Discovery Test", &facts.pre_join_tests.drs_discovery_test),
                render_optional("Client ErrorCode", &facts.registration.client_error_code),
            ],
            vec![
                "Verify access to https://enterpriseregistration.windows.net from the effective system context.".to_string(),
                "Check proxy, DNS, and TLS inspection behavior around discovery endpoints.".to_string(),
            ],
            vec!["Restore discovery endpoint access and retry hybrid join.".to_string()],
        ));
    }

    if contains_text(&facts.registration.client_error_code, "0x801c001f")
        || contains_text(&facts.pre_join_tests.drs_discovery_test, "0x801c001f")
    {
        diagnostics.push(issue(
            "drs-discovery-timeout",
            IntuneDiagnosticSeverity::Error,
            "network",
            "DRS discovery timed out",
            "The failure pattern matches DSREG_AUTOJOIN_DISC_WAIT_TIMEOUT (0x801c001f), which usually indicates the discovery endpoint could not be reached reliably from the current system context.",
            vec![
                render_optional("DRS Discovery Test", &facts.pre_join_tests.drs_discovery_test),
                render_optional("Client ErrorCode", &facts.registration.client_error_code),
            ],
            vec![
                "Confirm outbound HTTPS connectivity to https://enterpriseregistration.windows.net.".to_string(),
                "Check WinHTTP proxy configuration and whether the computer account can authenticate through the proxy.".to_string(),
            ],
            vec!["Resolve the discovery timeout path before retrying join.".to_string()],
        ));
    }

    if contains_text(&facts.registration.client_error_code, "0x801c003d") {
        diagnostics.push(issue(
            "user-realm-discovery-failed",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "User realm discovery failed",
            "The failure pattern matches DSREG_AUTOJOIN_USERREALM_DISCOVERY_FAILED (0x801c003d), which means the device could not determine whether the user domain is managed or federated.",
            vec![render_optional("Client ErrorCode", &facts.registration.client_error_code)],
            vec![
                "Verify the user realm lookup can reach https://login.microsoftonline.com from the system context.".to_string(),
                "Check whether proxy requirements or tenant domain configuration are interfering with realm discovery.".to_string(),
            ],
            vec!["Restore user realm discovery before retrying hybrid join.".to_string()],
        ));
    }

    if contains_text(&facts.registration.client_error_code, "0x8007000d")
        || contains_text(&facts.diagnostics.http_error, "0x8007000d")
    {
        diagnostics.push(issue(
            "invalid-discovery-response",
            IntuneDiagnosticSeverity::Error,
            "network",
            "Discovery response could not be parsed",
            "The failure pattern matches E_INVALIDDATA (0x8007000d), which often happens when a proxy or intermediary returns HTML or a modified response instead of the expected discovery JSON.",
            vec![
                render_optional("Client ErrorCode", &facts.registration.client_error_code),
                render_optional("HTTP Error", &facts.diagnostics.http_error),
                render_optional("Endpoint URI", &facts.diagnostics.endpoint_uri),
            ],
            vec![
                "Check whether an outbound proxy is intercepting or rewriting the discovery response.".to_string(),
                "Compare the endpoint behavior from the system context against a healthy device.".to_string(),
            ],
            vec!["Fix the proxy or response path so discovery returns the expected JSON.".to_string()],
        ));
    }

    if contains_text(&facts.registration.client_error_code, "0x801c0002") {
        diagnostics.push(issue(
            "join-device-authentication-error",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "Join failed because device authentication was rejected",
            "The failure pattern matches DSREG_E_DEVICE_AUTHENTICATION_ERROR (0x801c0002), which means the DRS service rejected device authentication during join.",
            vec![
                render_optional("Client ErrorCode", &facts.registration.client_error_code),
                render_optional("Server ErrorCode", &facts.registration.server_error_code),
                render_optional("Server Message", &facts.registration.server_message),
            ],
            vec![
                "Validate the device certificate, device object state, and sync status in Entra ID.".to_string(),
                "Check whether the server error indicates an authentication mismatch or stale registration state.".to_string(),
            ],
            vec!["Repair device registration state before retrying join.".to_string()],
        ));
    }

    if contains_text(&facts.registration.client_error_code, "0x801c0006") {
        diagnostics.push(issue(
            "join-internal-service-error",
            IntuneDiagnosticSeverity::Error,
            "join",
            "Join failed because the registration service returned an internal error",
            "The failure pattern matches DSREG_E_DEVICE_INTERNALSERVICE_ERROR (0x801c0006), which means the DRS service returned an internal failure during join processing.",
            vec![
                render_optional("Client ErrorCode", &facts.registration.client_error_code),
                render_optional("Server ErrorCode", &facts.registration.server_error_code),
                render_optional("Server Message", &facts.registration.server_message),
            ],
            vec![
                "Check whether the failure is transient or whether server-side throttling or directory errors are also present.".to_string(),
                "Compare with another registration attempt after a short wait.".to_string(),
            ],
            vec!["Retry the join after confirming the service-side condition has cleared.".to_string()],
        ));
    }

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

    if contains_text(&facts.diagnostics.attempt_status, "0xc000006a") {
        diagnostics.push(issue(
            "wrong-password",
            IntuneDiagnosticSeverity::Error,
            "credentials",
            "PRT acquisition failed because the password was rejected",
            "Attempt Status contains 0xc000006a, which maps to STATUS_WRONG_PASSWORD during PRT acquisition.",
            vec![
                render_optional("Attempt Status", &facts.diagnostics.attempt_status),
                render_optional("User Identity", &facts.diagnostics.user_identity),
            ],
            vec![
                "Check whether the user recently changed their password and Entra password sync has not completed yet.".to_string(),
                "Confirm the user is signing in with the intended UPN and password.".to_string(),
            ],
            vec!["Retry sign-in after password sync finishes or after correcting credentials.".to_string()],
        ));
    }

    if contains_text(&facts.diagnostics.attempt_status, "0xc00000d0") {
        diagnostics.push(issue(
            "request-not-accepted",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "PRT request was not accepted by the authentication endpoint",
            "Attempt Status contains 0xc00000d0, which lines up with an HTTP 400-style rejection from the Microsoft Entra or WS-Trust endpoint.",
            vec![
                render_optional("Attempt Status", &facts.diagnostics.attempt_status),
                render_optional("HTTP Status", &facts.diagnostics.http_status.as_ref().map(|value| value.to_string())),
                render_optional("Endpoint URI", &facts.diagnostics.endpoint_uri),
            ],
            vec![
                "Review server error details and endpoint URI for the rejected request.".to_string(),
                "Check for federation or proxy behavior that alters the request flow.".to_string(),
            ],
            vec!["Resolve the endpoint rejection cause before retrying PRT acquisition.".to_string()],
        ));
    }

    if contains_text(&facts.diagnostics.attempt_status, "0xc000023c")
        || contains_text(&facts.diagnostics.attempt_status, "0xc00000be")
        || contains_text(&facts.diagnostics.attempt_status, "0xc00000c4")
    {
        diagnostics.push(issue(
            "prt-network-path-error",
            IntuneDiagnosticSeverity::Error,
            "network",
            "PRT acquisition failed because the network path was unavailable",
            "Attempt Status matches a documented network-path failure during PRT acquisition, which usually means the required Microsoft Entra or federation endpoint was unreachable or the connection failed mid-flight.",
            vec![
                render_optional("Attempt Status", &facts.diagnostics.attempt_status),
                render_optional("Endpoint URI", &facts.diagnostics.endpoint_uri),
                render_optional("HTTP Error", &facts.diagnostics.http_error),
            ],
            vec![
                "Check network reachability to the endpoint URI from the current device context.".to_string(),
                "Review proxy requirements and intermittent network stability issues.".to_string(),
            ],
            vec!["Restore the endpoint network path and retry token acquisition.".to_string()],
        ));
    }

    if contains_text(&facts.diagnostics.attempt_status, "0xc000005f") {
        diagnostics.push(issue(
            "prt-user-realm-not-found",
            IntuneDiagnosticSeverity::Error,
            "user",
            "PRT acquisition could not resolve the user realm",
            "Attempt Status contains 0xc000005f, which usually means Microsoft Entra could not find the user's domain during realm discovery.",
            vec![
                render_optional("Attempt Status", &facts.diagnostics.attempt_status),
                render_optional("User Identity", &facts.diagnostics.user_identity),
            ],
            vec![
                "Check whether the user's UPN suffix is a verified custom domain in the target tenant.".to_string(),
                "If the on-premises domain is nonroutable, review Alternate Login ID configuration.".to_string(),
            ],
            vec!["Correct the user realm or UPN configuration before retrying sign-in.".to_string()],
        ));
    }

    if contains_text(&facts.diagnostics.attempt_status, "0xc004844c") {
        diagnostics.push(issue(
            "malformed-upn",
            IntuneDiagnosticSeverity::Error,
            "user",
            "The user principal name format is invalid for PRT acquisition",
            "Attempt Status contains 0xc004844c, which indicates the user's UPN is not in the expected internet-style format.",
            vec![
                render_optional("Attempt Status", &facts.diagnostics.attempt_status),
                render_optional("User Identity", &facts.diagnostics.user_identity),
            ],
            vec![
                "Validate the returned UPN format for the signed-in user.".to_string(),
                "For hybrid join, compare with whoami /upn on the device and confirm the domain controller returns the expected value.".to_string(),
            ],
            vec!["Correct the user's UPN formatting or Alternate Login ID configuration.".to_string()],
        ));
    }

    if contains_text(&facts.diagnostics.attempt_status, "0xc0048442") {
        diagnostics.push(issue(
            "missing-user-sid-in-token",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "The returned identity token did not include a user SID",
            "Attempt Status contains 0xc0048442, which means the token returned by Microsoft Entra did not contain the expected user SID claim.",
            vec![
                render_optional("Attempt Status", &facts.diagnostics.attempt_status),
                render_optional("Endpoint URI", &facts.diagnostics.endpoint_uri),
            ],
            vec![
                "Check whether a network proxy is rewriting or interfering with the token response.".to_string(),
                "Compare the behavior from another network path without TLS or proxy interception.".to_string(),
            ],
            vec!["Fix the token response path before retrying sign-in.".to_string()],
        ));
    }

    if contains_text(&facts.diagnostics.attempt_status, "0xc00484c1") {
        diagnostics.push(issue(
            "wstrust-empty-saml",
            IntuneDiagnosticSeverity::Error,
            "authentication",
            "The WS-Trust endpoint returned an unusable SAML response",
            "Attempt Status contains 0xc00484c1, which indicates the WS-Trust response did not contain the expected SAML tokens for federated authentication.",
            vec![
                render_optional("Attempt Status", &facts.diagnostics.attempt_status),
                render_optional("Endpoint URI", &facts.diagnostics.endpoint_uri),
            ],
            vec![
                "Review the WS-Trust endpoint response and whether a proxy is modifying it.".to_string(),
                "Check federation logs for server-side faults during token issuance.".to_string(),
            ],
            vec!["Repair the WS-Trust response path before retrying authentication.".to_string()],
        ));
    }

    if contains_text(&facts.diagnostics.attempt_status, "0xc004848b")
        || contains_text(&facts.diagnostics.attempt_status, "0xc004848c")
    {
        diagnostics.push(issue(
            "mex-endpoint-misconfigured",
            IntuneDiagnosticSeverity::Error,
            "configuration",
            "The federation MEX metadata is missing required endpoints",
            "Attempt Status matches the documented MEX endpoint misconfiguration where password or certificate URLs are missing from the federation metadata response.",
            vec![
                render_optional("Attempt Status", &facts.diagnostics.attempt_status),
                render_optional("Endpoint URI", &facts.diagnostics.endpoint_uri),
            ],
            vec![
                "Review the federation MEX response for missing WS-Trust password or certificate endpoints.".to_string(),
                "Check whether a proxy is modifying the federation metadata response.".to_string(),
            ],
            vec!["Fix the MEX configuration to advertise the required endpoints.".to_string()],
        ));
    }

    if contains_text(&facts.diagnostics.attempt_status, "0xc00cee4f") {
        diagnostics.push(issue(
            "federation-xml-dtd-prohibited",
            IntuneDiagnosticSeverity::Error,
            "configuration",
            "The federation XML response included a prohibited DTD",
            "Attempt Status contains 0xc00cee4f, which means the WS-Trust XML response included a DTD that the parser rejects.",
            vec![
                render_optional("Attempt Status", &facts.diagnostics.attempt_status),
                render_optional("Endpoint URI", &facts.diagnostics.endpoint_uri),
            ],
            vec![
                "Inspect the federation XML response for a DTD or other invalid additions.".to_string(),
                "Check whether the identity provider or proxy is modifying the XML document.".to_string(),
            ],
            vec!["Remove the DTD from the federation XML response and retry authentication.".to_string()],
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

    if has_code(facts, "0x80090016") {
        diagnostics.push(issue(
            "tpm-bad-keyset",
            IntuneDiagnosticSeverity::Error,
            "configuration",
            "TPM key material is missing or invalid",
            "The failure pattern matches NTE_BAD_KEYSET (0x80090016), which usually means the TPM-backed keyset no longer exists or the device image was prepared from a bad joined-state source.",
            vec![render_phase_code_evidence(facts, "0x80090016")],
            vec![
                "Check whether the TPM was cleared or whether the device image came from a machine that was already registered or joined.".to_string(),
                "Compare with device registration history and account recovery behavior on the machine.".to_string(),
            ],
            vec!["Repair or re-register the device after correcting the TPM keyset issue.".to_string()],
        ));
    }

    if has_code(facts, "0x80290407") {
        diagnostics.push(issue(
            "tpm-internal-error",
            IntuneDiagnosticSeverity::Error,
            "configuration",
            "The TPM reported an internal failure during join",
            "The failure pattern matches TPM_E_PCP_INTERNAL_ERROR (0x80290407), which indicates a TPM failure that can block TPM-backed device registration.",
            vec![render_phase_code_evidence(facts, "0x80290407")],
            vec![
                "Check TPM health and whether Windows can use the TPM normally on this device.".to_string(),
                "Compare with a retry that uses a non-TPM path if the platform and Windows version support it.".to_string(),
            ],
            vec!["Resolve or bypass the unhealthy TPM path before retrying join.".to_string()],
        ));
    }

    if has_code(facts, "0x80280036") {
        diagnostics.push(issue(
            "tpm-not-fips",
            IntuneDiagnosticSeverity::Error,
            "configuration",
            "The TPM is in an unsupported FIPS mode for this flow",
            "The failure pattern matches TPM_E_NOTFIPS (0x80280036), which means the TPM state is not supported for this registration flow.",
            vec![render_phase_code_evidence(facts, "0x80280036")],
            vec![
                "Review the TPM configuration and whether the device is enforcing a TPM mode unsupported for this join path.".to_string(),
                "Check whether the Windows version can fall back to a non-TPM registration path.".to_string(),
            ],
            vec!["Correct the TPM mode or use a supported fallback path before retrying.".to_string()],
        ));
    }

    if has_code(facts, "0x80090031") {
        diagnostics.push(issue(
            "tpm-locked-out",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "The TPM appears to be locked out temporarily",
            "The failure pattern matches NTE_AUTHENTICATION_IGNORED (0x80090031), which is commonly a transient TPM lockout or anti-hammering condition.",
            vec![render_phase_code_evidence(facts, "0x80090031")],
            vec![
                "Wait for the TPM lockout cool-down period to expire before retrying.".to_string(),
                "Check whether repeated recent authentication failures triggered TPM anti-hammering.".to_string(),
            ],
            Vec::new(),
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
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "MDM enrollment URL is not present",
            "MdmComplianceUrl is present but MdmUrl is not. That usually means the capture is incomplete or the tenant advertises only part of the management metadata, not that the device is definitively broken.",
            vec![
                render_optional("MdmUrl", &facts.management_details.mdm_url),
                render_optional(
                    "MdmComplianceUrl",
                    &facts.management_details.mdm_compliance_url,
                ),
            ],
            vec![
                "Confirm whether this tenant and user are actually in scope for automatic MDM enrollment.".to_string(),
                "Compare with a healthy capture from the same org before treating missing MDM metadata as a failure.".to_string(),
            ],
            Vec::new(),
        ));
    }

    if derived.missing_compliance_url == Some(true) {
        diagnostics.push(issue(
            "no-compliance",
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "Compliance URL is not present",
            "MdmUrl is present but MdmComplianceUrl is not. dsregcmd management fields are tenant- and scope-dependent, so this is context rather than proof of an enrollment problem.",
            vec![render_optional(
                "MdmComplianceUrl",
                &facts.management_details.mdm_compliance_url,
            )],
            vec![
                "Confirm whether compliance reporting is expected for this org and user scope.".to_string(),
                "Compare with another healthy capture from the same tenant before escalating.".to_string(),
            ],
            Vec::new(),
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

    let has_specific_network_issue = diagnostics.iter().any(|item| {
        matches!(
            item.id.as_str(),
            "drs-discovery-timeout"
                | "invalid-discovery-response"
                | "prt-network-path-error"
                | "adal-timeout"
                | "adal-connection-aborted"
                | "adal-secure-failure"
                | "adal-cannot-connect"
        )
    });

    if let Some(network_error_code) = derived.network_error_code.as_deref() {
        if !has_specific_network_issue {
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
        let has_specific_tpm_issue = diagnostics.iter().any(|item| {
            matches!(
                item.id.as_str(),
                "tpm-bad-keyset" | "tpm-internal-error" | "tpm-not-fips" | "tpm-locked-out"
            )
        });
        if !has_specific_tpm_issue {
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
    }

    if let Some(logon_cert_template_ready) = facts.registration.logon_cert_template_ready.as_deref()
    {
        if !logon_cert_template_ready.contains("StateReady")
            && equals_text(&facts.registration.cert_enrollment, "enrollment authority")
        {
            diagnostics.push(issue(
                "logon-cert-not-ready",
                IntuneDiagnosticSeverity::Info,
                "configuration",
                "Logon certificate template is not ready",
                "LogonCertTemplateReady is present but does not report StateReady. This is supporting context for Windows Hello certificate-trust readiness, not a standalone device health failure.",
                vec![render_optional(
                    "LogonCertTemplateReady",
                    &facts.registration.logon_cert_template_ready,
                )],
                vec![
                    "Review certificate enrollment prerequisites and issuance policy.".to_string(),
                    "Check whether the device can reach the issuing CA or enrollment service when certificate-trust WHfB is expected."
                        .to_string(),
                ],
                Vec::new(),
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

    if facts.join_state.workplace_joined == Some(true) {
        diagnostics.push(issue(
            "workplace-joined-present",
            IntuneDiagnosticSeverity::Info,
            "configuration",
            "Workplace join is present",
            "WorkplaceJoined is YES.",
            vec![render_bool("WorkplaceJoined", facts.join_state.workplace_joined)],
            vec![
                "Workplace join is scenario-specific and is not required for most standard Entra joined device flows.".to_string(),
                "Confirm that this registration is expected before treating it as important during triage.".to_string(),
            ],
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

    if is_failure_text(&facts.post_join_diagnostics.key_sign_test) {
        diagnostics.push(issue(
            "ngc-key-sign-failed",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "Windows Hello key health check failed",
            "KeySignTest did not pass, which means the device could not validate the current Windows Hello key material during post-join diagnostics.",
            vec![render_optional(
                "KeySignTest",
                &facts.post_join_diagnostics.key_sign_test,
            )],
            vec![
                "Re-run dsregcmd /status from an elevated prompt because KeySignTest requires elevation to be reliable.".to_string(),
                "Check whether the device is entering a recovery or re-registration flow for Windows Hello for Business.".to_string(),
            ],
            vec![
                "Repair or recover the Windows Hello key state before expecting WHfB sign-in to behave normally.".to_string(),
            ],
        ));
    }

    if facts.post_join_diagnostics.aad_recovery_enabled == Some(true) {
        diagnostics.push(issue(
            "ngc-recovery-enabled",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "Windows Hello key recovery is enabled",
            "AadRecoveryEnabled is YES, which means the current device key state is marked for recovery and the next sign-in may trigger device recovery or re-registration behavior.",
            vec![render_bool(
                "AadRecoveryEnabled",
                facts.post_join_diagnostics.aad_recovery_enabled,
            )],
            vec![
                "Confirm whether recent WHfB sign-in, PIN reset, or recovery prompts were observed on the device.".to_string(),
                "Review adjacent device registration or Hello for Business logs for the recovery trigger.".to_string(),
            ],
            vec![
                "Allow the device recovery flow to complete and then capture dsregcmd again to confirm the key state stabilizes.".to_string(),
            ],
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

    // ── DSRegTool integration — Phase 1 quick-win rules ──────────────────────

    // Built-in Administrator account detection
    {
        let is_builtin_admin = contains_text(&facts.diagnostics.user_identity, "administrator")
            || facts
                .diagnostics
                .user_identity
                .as_deref()
                .map(|id| id.trim().ends_with("-500"))
                .unwrap_or(false);
        if is_builtin_admin
            && matches!(
                derived.join_type,
                DsregcmdJoinType::NotJoined | DsregcmdJoinType::Unknown
            )
        {
            diagnostics.push(issue(
                "builtin-admin-cannot-join",
                IntuneDiagnosticSeverity::Error,
                "user",
                "Built-in Administrator account cannot perform Azure AD Join",
                "The user identity appears to be the built-in Administrator account (or SID ending in -500), which cannot perform Azure AD Join.",
                vec![render_optional("User Identity", &facts.diagnostics.user_identity)],
                vec![
                    "Sign in with a standard user or non-built-in admin account.".to_string(),
                ],
                vec![
                    "Create or use a non-built-in administrator account.".to_string(),
                ],
            ));
        }
    }

    // Device sync status inference — sync pending
    if facts.join_state.domain_joined == Some(true)
        && facts.join_state.azure_ad_joined == Some(false)
        && facts.pre_join_tests.ad_connectivity_test.is_some()
        && facts.pre_join_tests.ad_configuration_test.is_some()
        && !is_failure(&facts.pre_join_tests.ad_connectivity_test)
        && !is_failure(&facts.pre_join_tests.ad_configuration_test)
        && !diagnostics.iter().any(|item| item.id == "entra-sync-pending")
    {
        diagnostics.push(issue(
            "entra-sync-pending-inference",
            IntuneDiagnosticSeverity::Warning,
            "sync",
            "Domain-joined device not yet synced to Entra ID",
            "The device is domain-joined but not Azure AD joined, and pre-join AD tests are not failing. This commonly indicates the device object has not yet been synchronized to Entra ID via Azure AD Connect or Cloud Sync.",
            vec![
                render_bool("DomainJoined", facts.join_state.domain_joined),
                render_bool("AzureAdJoined", facts.join_state.azure_ad_joined),
            ],
            vec![
                "Check Azure AD Connect or Cloud Sync health and verify the device object exists on-premises.".to_string(),
                "Confirm the OU containing the computer object is in scope for directory synchronization.".to_string(),
            ],
            vec![
                "Wait for the next sync cycle or force a delta sync, then retry registration.".to_string(),
            ],
        ));
    }

    // Device sync status inference — fallback to sync-join active (non-hybrid)
    if derived.join_type != DsregcmdJoinType::HybridEntraIdJoined
        && (contains_text(&facts.pre_join_tests.fallback_to_sync_join, "enabled")
            || contains_text(&facts.pre_join_tests.fallback_to_sync_join, "yes"))
    {
        diagnostics.push(issue(
            "fallback-sync-join-active",
            IntuneDiagnosticSeverity::Info,
            "sync",
            "Sync-join fallback is active on a device not yet hybrid-joined",
            "Fallback to Sync-Join is active on a device that is not hybrid-joined, which means the device will rely on directory synchronization to complete its join rather than the immediate online path.",
            vec![render_optional(
                "Fallback to Sync-Join",
                &facts.pre_join_tests.fallback_to_sync_join,
            )],
            vec![
                "Monitor Azure AD Connect sync cycles for the device object to appear in Entra ID.".to_string(),
            ],
            Vec::new(),
        ));
    }

    // Enhanced SCP heuristic — SCP verification needed
    {
        let has_drs_discovery_failure = is_failure(&facts.pre_join_tests.drs_discovery_test);
        let is_domain_joined_not_hybrid = facts.join_state.domain_joined == Some(true)
            && matches!(
                derived.join_type,
                DsregcmdJoinType::HybridEntraIdJoined | DsregcmdJoinType::NotJoined
            );
        if has_drs_discovery_failure && is_domain_joined_not_hybrid {
            diagnostics.push(issue(
                "scp-verify-needed",
                IntuneDiagnosticSeverity::Warning,
                "discovery",
                "DRS discovery failed — verify Service Connection Point (SCP) configuration",
                "DRS discovery failed on a domain-joined device. In hybrid join scenarios, this commonly points to a missing, misconfigured, or unreachable Service Connection Point (SCP) in Active Directory.",
                vec![
                    render_optional("DRS Discovery Test", &facts.pre_join_tests.drs_discovery_test),
                    render_bool("DomainJoined", facts.join_state.domain_joined),
                ],
                vec![
                    "Verify the SCP exists in Active Directory under CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration,DC=...".to_string(),
                    "Confirm the SCP points to the correct verified tenant domain.".to_string(),
                ],
                vec![
                    "Create or correct the SCP using Azure AD Connect or manually in Active Directory.".to_string(),
                ],
            ));
        }
    }

    // Enhanced SCP heuristic — SCP tenant mismatch hint
    if is_failure(&facts.pre_join_tests.drs_discovery_test)
        && is_failure(&facts.pre_join_tests.ad_configuration_test)
        && facts.tenant_details.tenant_id.is_some()
    {
        diagnostics.push(issue(
            "scp-tenant-mismatch-hint",
            IntuneDiagnosticSeverity::Warning,
            "configuration",
            "Check SCP tenant alignment after migration or reconfiguration",
            "Both DRS discovery and AD configuration tests failed while tenant details are present. This pattern can occur when the SCP points to a different tenant than expected, such as after a tenant migration or domain reconfiguration.",
            vec![
                render_optional("DRS Discovery Test", &facts.pre_join_tests.drs_discovery_test),
                render_optional("AD Configuration Test", &facts.pre_join_tests.ad_configuration_test),
                render_optional("TenantId", &facts.tenant_details.tenant_id),
            ],
            vec![
                "Compare the tenant ID in the SCP with the expected target tenant.".to_string(),
                "Check if the organization recently migrated tenants or reconfigured hybrid join.".to_string(),
            ],
            vec![
                "Update the SCP to point to the correct tenant domain and re-run Azure AD Connect.".to_string(),
            ],
        ));
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::analyze_facts;
    use crate::dsregcmd::models::{
        DsregcmdCaptureConfidence, DsregcmdDiagnosticPhase, DsregcmdJoinType,
    };
    use crate::dsregcmd::parser::parse_dsregcmd;
    use crate::intune::models::IntuneDiagnosticSeverity;
    use chrono::Utc;

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
 CertEnrollment : enrollment authority
 LogonCertTemplateReady : Pending
 PreReqResult : WillProvision
 KeySignTest : FAILED
 AadRecoveryEnabled : YES
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

    const PHASE_AWARE_SAMPLE: &str = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 WorkplaceJoined : NO
 TenantId : 11111111-2222-3333-4444-555555555555
 DeviceId : abcdefab-1111-2222-3333-abcdefabcdef
 DRS Discovery Test : FAIL [0x801c0021/0x80072ee2]
 AD Configuration Test : FAIL [0x801c001d]
 Client ErrorCode : 0x801c001d
 Error Phase : discover
 Attempt Status : 0xc004844c
 User Identity : user@contoso.local
 Endpoint URI : https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/token/
 HTTP Error : 0x8007000d
 HTTP status : 400
 AzureAdPrt : NO
"#;

    const ADAL_AND_TPM_SAMPLE: &str = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 WorkplaceJoined : NO
 TenantId : 11111111-2222-3333-4444-555555555555
 DeviceId : abcdefab-1111-2222-3333-abcdefabcdef
 Token Acquisition Test : FAIL [0xcaa90017]
 Client ErrorCode : 0xcaa9002c
 Attempt Status : 0xcaa90023
 HTTP Error : 0xcaa82f8f
 Server ErrorDescription : 0xcaa20003
 Server Message : 0xcaa90014 0xcaa90006 0xcaa1002d
 Endpoint URI : https://fs.contoso.com/adfs/services/trust/mex
 AzureAdPrt : NO
 DeviceAuthStatus : FAILED
 TpmProtected : NO
 Server ErrorCode : 0x80090016 0x80290407 0x80280036 0x80090031
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
        assert_eq!(analysis.derived.dominant_phase, DsregcmdDiagnosticPhase::PostJoin);
        assert_eq!(
            analysis.derived.capture_confidence,
            DsregcmdCaptureConfidence::Low
        );
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
        ] {
            assert!(ids.contains(&expected), "missing diagnostic: {expected}");
        }
    }

    #[test]
    fn missing_mdm_urls_do_not_create_warnings_by_default() {
        let facts = parse_dsregcmd(NOT_JOINED_SAMPLE).expect("parse not joined sample");
        let analysis = analyze_facts(facts, NOT_JOINED_SAMPLE);

        assert_eq!(analysis.derived.mdm_enrolled, None);
        assert_eq!(analysis.derived.missing_mdm, None);
        assert_eq!(analysis.derived.missing_compliance_url, None);
        assert!(!analysis
            .diagnostics
            .iter()
            .any(|item| item.id == "no-mdm" || item.id == "no-compliance"));
    }

    #[test]
    fn ngc_prereq_fields_stay_lightweight_when_context_is_healthy() {
        let sample = r#"
 AzureAdJoined : YES
 DomainJoined : YES
 WorkplaceJoined : NO
 TenantId : 11111111-2222-3333-4444-555555555555
 DeviceId : abcdefab-1111-2222-3333-abcdefabcdef
 AzureAdPrt : YES
 AzureAdPrtUpdateTime : 2025-03-10 09:00:00.000 UTC
 Client Time : 2025-03-10 10:00:00.000 UTC
 NgcSet : NO
 IsDeviceJoined : YES
 IsUserAzureAD : YES
 PolicyEnabled : YES
 PostLogonEnabled : YES
 DeviceEligible : YES
 SessionIsNotRemote : YES
 CertEnrollment : none
 PreReqResult : WillProvision
 KeySignTest : PASSED
 AadRecoveryEnabled : NO
"#;

        let facts = parse_dsregcmd(sample).expect("parse ngc sample");
        let analysis = analyze_facts(facts, sample);

        assert!(analysis.diagnostics.iter().any(|item| item.id == "ngc-will-provision"));
        assert!(!analysis
            .diagnostics
            .iter()
            .any(|item| {
                item.id == "ngc-not-set"
                    || item.id == "logon-cert-not-ready"
                    || item.id == "ngc-key-sign-failed"
                    || item.id == "ngc-recovery-enabled"
            }));
    }

    #[test]
    fn emits_ngc_post_join_health_diagnostics_when_present() {
        let sample = r#"
 AzureAdJoined : YES
 DomainJoined : NO
 WorkplaceJoined : NO
 NgcSet : YES
 KeySignTest : FAILED
 AadRecoveryEnabled : YES
 AzureAdPrt : YES
"#;

        let facts = parse_dsregcmd(sample).expect("parse ngc post join sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis
            .diagnostics
            .iter()
            .map(|item| item.id.as_str())
            .collect();

        assert!(ids.contains(&"ngc-key-sign-failed"));
        assert!(ids.contains(&"ngc-recovery-enabled"));
    }

    #[test]
    fn emits_phase_aware_discovery_and_prt_code_diagnostics() {
        let facts = parse_dsregcmd(PHASE_AWARE_SAMPLE).expect("parse phase aware sample");
        let analysis = analyze_facts(facts, PHASE_AWARE_SAMPLE);
        let ids: Vec<&str> = analysis
            .diagnostics
            .iter()
            .map(|item| item.id.as_str())
            .collect();

        for expected in [
            "scp-read-failed",
            "drs-discovery-code",
            "invalid-discovery-response",
            "malformed-upn",
            "no-azure-prt",
        ] {
            assert!(ids.contains(&expected), "missing diagnostic: {expected}");
        }

        assert_eq!(analysis.derived.dominant_phase, DsregcmdDiagnosticPhase::Discover);
    }

    #[test]
    fn emits_remaining_adal_and_tpm_mappings() {
        let facts = parse_dsregcmd(ADAL_AND_TPM_SAMPLE).expect("parse adal and tpm sample");
        let analysis = analyze_facts(facts, ADAL_AND_TPM_SAMPLE);
        let ids: Vec<&str> = analysis
            .diagnostics
            .iter()
            .map(|item| item.id.as_str())
            .collect();

        for expected in [
            "adal-protocol-not-supported",
            "adal-parse-xml-failed",
            "adal-password-endpoint-missing",
            "adal-secure-failure",
            "adal-invalid-grant",
            "adal-wstrust-request-failed",
            "adal-token-request-failed",
            "adal-operation-pending",
            "tpm-bad-keyset",
            "tpm-internal-error",
            "tpm-not-fips",
            "tpm-locked-out",
        ] {
            assert!(ids.contains(&expected), "missing diagnostic: {expected}");
        }
    }

    #[test]
    fn derives_high_capture_confidence_for_recent_interactive_capture() {
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string();
        let sample = format!(
            "\n AzureAdJoined : YES\n DomainJoined : YES\n AzureAdPrt : YES\n AzureAdPrtUpdateTime : {now}\n Client Time : {now}\n User Context : UN-ELEVATED User\n SessionIsNotRemote : YES\n"
        );

        let facts = parse_dsregcmd(&sample).expect("parse high confidence sample");
        let analysis = analyze_facts(facts, &sample);

        assert_eq!(analysis.derived.capture_confidence, DsregcmdCaptureConfidence::High);
    }

    #[test]
    fn derives_low_capture_confidence_for_remote_system_capture() {
        let sample = r#"
 AzureAdJoined : YES
 DomainJoined : YES
 AzureAdPrt : YES
 AzureAdPrtUpdateTime : 2025-03-10 05:00:00.000 UTC
 Client Time : 2025-03-10 10:30:00.000 UTC
 User Context : SYSTEM
 SessionIsNotRemote : NO
"#;

        let facts = parse_dsregcmd(sample).expect("parse low confidence sample");
        let analysis = analyze_facts(facts, sample);

        assert_eq!(analysis.derived.capture_confidence, DsregcmdCaptureConfidence::Low);
    }

    #[test]
    fn emits_builtin_admin_cannot_join_for_administrator_identity() {
        let sample = r#"
 AzureAdJoined : NO
 DomainJoined : NO
 WorkplaceJoined : NO
 AzureAdPrt : NO
 User Identity : Administrator
"#;
        let facts = parse_dsregcmd(sample).expect("parse admin sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis.diagnostics.iter().map(|i| i.id.as_str()).collect();

        assert!(ids.contains(&"builtin-admin-cannot-join"), "missing builtin-admin-cannot-join");
        let rule = analysis.diagnostics.iter().find(|i| i.id == "builtin-admin-cannot-join").unwrap();
        assert_eq!(rule.severity, IntuneDiagnosticSeverity::Error);
    }

    #[test]
    fn emits_builtin_admin_for_sid_ending_in_500() {
        let sample = r#"
 AzureAdJoined : NO
 DomainJoined : NO
 WorkplaceJoined : NO
 AzureAdPrt : NO
 User Identity : S-1-5-21-3623811015-3361044348-30300820-500
"#;
        let facts = parse_dsregcmd(sample).expect("parse sid admin sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis.diagnostics.iter().map(|i| i.id.as_str()).collect();

        assert!(ids.contains(&"builtin-admin-cannot-join"), "missing builtin-admin-cannot-join for SID -500");
    }

    #[test]
    fn does_not_emit_builtin_admin_when_already_joined() {
        let sample = r#"
 AzureAdJoined : YES
 DomainJoined : NO
 WorkplaceJoined : NO
 AzureAdPrt : YES
 User Identity : Administrator
"#;
        let facts = parse_dsregcmd(sample).expect("parse joined admin sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis.diagnostics.iter().map(|i| i.id.as_str()).collect();

        assert!(!ids.contains(&"builtin-admin-cannot-join"), "should not fire when already joined");
    }

    #[test]
    fn emits_entra_sync_pending_inference_for_domain_joined_not_aad() {
        let sample = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 WorkplaceJoined : NO
 AzureAdPrt : NO
 AD Connectivity Test : PASSED
 AD Configuration Test : PASSED
"#;
        let facts = parse_dsregcmd(sample).expect("parse sync pending sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis.diagnostics.iter().map(|i| i.id.as_str()).collect();

        assert!(ids.contains(&"entra-sync-pending-inference"), "missing entra-sync-pending-inference");
        let rule = analysis.diagnostics.iter().find(|i| i.id == "entra-sync-pending-inference").unwrap();
        assert_eq!(rule.severity, IntuneDiagnosticSeverity::Warning);
    }

    #[test]
    fn does_not_emit_sync_pending_inference_when_ad_tests_fail() {
        let sample = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 WorkplaceJoined : NO
 AzureAdPrt : NO
 AD Connectivity Test : FAIL [0x54b]
 AD Configuration Test : PASSED
"#;
        let facts = parse_dsregcmd(sample).expect("parse ad fail sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis.diagnostics.iter().map(|i| i.id.as_str()).collect();

        assert!(!ids.contains(&"entra-sync-pending-inference"), "should not fire when AD tests fail");
    }

    #[test]
    fn emits_fallback_sync_join_active_for_not_joined_device() {
        let sample = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 WorkplaceJoined : NO
 AzureAdPrt : NO
 Fallback to Sync-Join : ENABLED
"#;
        let facts = parse_dsregcmd(sample).expect("parse fallback sync sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis.diagnostics.iter().map(|i| i.id.as_str()).collect();

        assert!(ids.contains(&"fallback-sync-join-active"), "missing fallback-sync-join-active");
        let rule = analysis.diagnostics.iter().find(|i| i.id == "fallback-sync-join-active").unwrap();
        assert_eq!(rule.severity, IntuneDiagnosticSeverity::Info);
    }

    #[test]
    fn emits_scp_verify_needed_for_drs_failure_on_domain_joined() {
        let sample = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 WorkplaceJoined : NO
 AzureAdPrt : NO
 DRS Discovery Test : FAIL [0x801c0021]
"#;
        let facts = parse_dsregcmd(sample).expect("parse scp verify sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis.diagnostics.iter().map(|i| i.id.as_str()).collect();

        assert!(ids.contains(&"scp-verify-needed"), "missing scp-verify-needed");
        let rule = analysis.diagnostics.iter().find(|i| i.id == "scp-verify-needed").unwrap();
        assert_eq!(rule.severity, IntuneDiagnosticSeverity::Warning);
    }

    #[test]
    fn does_not_emit_scp_verify_when_not_domain_joined() {
        let sample = r#"
 AzureAdJoined : NO
 DomainJoined : NO
 WorkplaceJoined : NO
 AzureAdPrt : NO
 DRS Discovery Test : FAIL [0x801c0021]
"#;
        let facts = parse_dsregcmd(sample).expect("parse scp non-domain sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis.diagnostics.iter().map(|i| i.id.as_str()).collect();

        assert!(!ids.contains(&"scp-verify-needed"), "should not fire when not domain-joined");
    }

    #[test]
    fn emits_scp_tenant_mismatch_hint_when_both_tests_fail() {
        let sample = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 WorkplaceJoined : NO
 TenantId : 11111111-2222-3333-4444-555555555555
 AzureAdPrt : NO
 DRS Discovery Test : FAIL [0x801c0021]
 AD Configuration Test : FAIL [0x801c001d]
"#;
        let facts = parse_dsregcmd(sample).expect("parse tenant mismatch sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis.diagnostics.iter().map(|i| i.id.as_str()).collect();

        assert!(ids.contains(&"scp-tenant-mismatch-hint"), "missing scp-tenant-mismatch-hint");
        let rule = analysis.diagnostics.iter().find(|i| i.id == "scp-tenant-mismatch-hint").unwrap();
        assert_eq!(rule.severity, IntuneDiagnosticSeverity::Warning);
    }

    #[test]
    fn does_not_emit_scp_tenant_mismatch_without_tenant_id() {
        let sample = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 WorkplaceJoined : NO
 AzureAdPrt : NO
 DRS Discovery Test : FAIL [0x801c0021]
 AD Configuration Test : FAIL [0x801c001d]
"#;
        let facts = parse_dsregcmd(sample).expect("parse no tenant sample");
        let analysis = analyze_facts(facts, sample);
        let ids: Vec<&str> = analysis.diagnostics.iter().map(|i| i.id.as_str()).collect();

        assert!(!ids.contains(&"scp-tenant-mismatch-hint"), "should not fire without tenant ID");
    }

    #[test]
    fn mdm_confirmed_via_registry_diagnostic_fires_when_cross_referenced() {
        use crate::dsregcmd::models::{
            DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence,
            DsregcmdScheduledTaskEvidence,
        };
        use super::{apply_enrollment_cross_reference, build_extended_diagnostics};

        let facts = parse_dsregcmd(NOT_JOINED_SAMPLE).expect("parse sample");
        let mut result = analyze_facts(facts, NOT_JOINED_SAMPLE);

        result.enrollment_evidence = Some(DsregcmdEnrollmentEvidence {
            enrollment_count: 1,
            enrollments: vec![DsregcmdEnrollmentEntry {
                guid: Some("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_string()),
                upn: Some("user@contoso.com".to_string()),
                provider_id: Some("MS DM Server".to_string()),
                enrollment_state: Some(1),
            }],
        });
        result.scheduled_task_evidence = Some(DsregcmdScheduledTaskEvidence {
            enterprise_mgmt_guids: vec![
                "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_string(),
            ],
        });

        assert_eq!(result.derived.mdm_enrolled, None);
        apply_enrollment_cross_reference(&mut result);
        assert_eq!(result.derived.mdm_enrolled, Some(true));

        let extended = build_extended_diagnostics(&result);
        assert!(
            extended.iter().any(|d| d.id == "mdm-confirmed-via-registry"),
            "should fire mdm-confirmed-via-registry diagnostic"
        );
    }

    #[test]
    fn mdm_not_confirmed_without_matching_scheduled_task() {
        use crate::dsregcmd::models::{
            DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence,
            DsregcmdScheduledTaskEvidence,
        };
        use super::apply_enrollment_cross_reference;

        let facts = parse_dsregcmd(NOT_JOINED_SAMPLE).expect("parse sample");
        let mut result = analyze_facts(facts, NOT_JOINED_SAMPLE);

        // Enrollment state=1 but GUID doesn't match any scheduled task
        result.enrollment_evidence = Some(DsregcmdEnrollmentEvidence {
            enrollment_count: 1,
            enrollments: vec![DsregcmdEnrollmentEntry {
                guid: Some("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_string()),
                upn: Some("user@contoso.com".to_string()),
                provider_id: Some("MS DM Server".to_string()),
                enrollment_state: Some(1),
            }],
        });
        result.scheduled_task_evidence = Some(DsregcmdScheduledTaskEvidence {
            enterprise_mgmt_guids: vec![
                "{99999999-8888-7777-6666-555555555555}".to_string(),
            ],
        });

        // Cross-reference should NOT upgrade because GUIDs don't match
        apply_enrollment_cross_reference(&mut result);
        assert_eq!(result.derived.mdm_enrolled, None, "should stay None when GUIDs don't match");
    }

    /// Regression: on a joined device with enrollment_count == 0 but cross-reference
    /// confirming MDM, the "enrollment-missing-on-joined" warning must NOT fire.
    const JOINED_NO_MDM_URLS_SAMPLE: &str = r#"
 AzureAdJoined : YES
 DomainJoined : NO
 WorkplaceJoined : NO
 TenantId : 11111111-2222-3333-4444-555555555555
 DeviceId : abcdefab-1111-2222-3333-abcdefabcdef
 AzureAdPrt : YES
 AzureAdPrtUpdateTime : 2025-03-10 05:00:00.000 UTC
"#;

    #[test]
    fn enrollment_missing_warning_suppressed_when_cross_reference_confirms_mdm() {
        use crate::dsregcmd::models::{
            DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence,
            DsregcmdScheduledTaskEvidence,
        };
        use super::{apply_enrollment_cross_reference, build_extended_diagnostics};

        let facts = parse_dsregcmd(JOINED_NO_MDM_URLS_SAMPLE).expect("parse sample");
        let mut result = analyze_facts(facts, JOINED_NO_MDM_URLS_SAMPLE);

        // enrollment_count is 0 in registry evidence, but scheduled tasks have matching GUIDs
        result.enrollment_evidence = Some(DsregcmdEnrollmentEvidence {
            enrollment_count: 0,
            enrollments: vec![DsregcmdEnrollmentEntry {
                guid: Some("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_string()),
                upn: Some("user@contoso.com".to_string()),
                provider_id: Some("MS DM Server".to_string()),
                enrollment_state: Some(1),
            }],
        });
        result.scheduled_task_evidence = Some(DsregcmdScheduledTaskEvidence {
            enterprise_mgmt_guids: vec![
                "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_string(),
            ],
        });

        apply_enrollment_cross_reference(&mut result);
        assert_eq!(result.derived.mdm_enrolled, Some(true));

        let extended = build_extended_diagnostics(&result);

        // The cross-reference info diagnostic SHOULD fire
        assert!(
            extended.iter().any(|d| d.id == "mdm-confirmed-via-registry"),
            "should fire mdm-confirmed-via-registry diagnostic"
        );

        // The enrollment-missing warning should NOT fire — MDM was confirmed
        assert!(
            !extended.iter().any(|d| d.id == "enrollment-missing-on-joined"),
            "enrollment-missing-on-joined should be suppressed when cross-reference confirms MDM"
        );
    }
}
