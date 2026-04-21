use regex::Regex;

use crate::dsregcmd::models::DsregcmdFacts;
use std::sync::OnceLock;

fn field_line_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"(?m)^\s*([^\r\n:=][^\r\n:=]*?)\s*[:=]\s*([^\r\n]*)\s*$")
        .expect("valid dsregcmd field regex")
})
}

pub fn parse_dsregcmd(input: &str) -> Result<DsregcmdFacts, String> {
    if input.trim().is_empty() {
        return Err("dsregcmd input was empty".to_string());
    }

    let mut facts = DsregcmdFacts::default();
    let mut recognized_fields = 0usize;

    for captures in field_line_re().captures_iter(input) {
        let Some(raw_key) = captures.get(1) else {
            continue;
        };
        let Some(raw_value) = captures.get(2) else {
            continue;
        };

        let key = normalize_key(raw_key.as_str());
        let value = raw_value.as_str().trim();

        if apply_field(&mut facts, &key, value) {
            recognized_fields += 1;
        }
    }

    if recognized_fields == 0 {
        return Err("Input did not contain recognizable dsregcmd /status fields".to_string());
    }

    Ok(facts)
}

fn apply_field(facts: &mut DsregcmdFacts, key: &str, value: &str) -> bool {
    match key {
        "azureadjoined" => {
            facts.join_state.azure_ad_joined = parse_bool(value);
            true
        }
        "domainjoined" => {
            facts.join_state.domain_joined = parse_bool(value);
            true
        }
        "workplacejoined" => {
            facts.join_state.workplace_joined = parse_bool(value);
            true
        }
        "enterprisejoined" => {
            facts.join_state.enterprise_joined = parse_bool(value);
            true
        }
        "tenantid" => set_string(&mut facts.tenant_details.tenant_id, value),
        "tenantname" => set_string(&mut facts.tenant_details.tenant_name, value),
        "domainname" => set_string(&mut facts.tenant_details.domain_name, value),
        "deviceid" => set_string(&mut facts.device_details.device_id, value),
        "thumbprint" => set_string(&mut facts.device_details.thumbprint, value),
        "devicecertificatevalidity" => {
            set_string(&mut facts.device_details.device_certificate_validity, value)
        }
        "keycontainerid" => set_string(&mut facts.device_details.key_container_id, value),
        "keyprovider" => set_string(&mut facts.device_details.key_provider, value),
        "tpmprotected" => {
            facts.device_details.tpm_protected = parse_bool(value);
            true
        }
        "deviceauthstatus" => set_string(&mut facts.device_details.device_auth_status, value),
        "mdmurl" => set_string(&mut facts.management_details.mdm_url, value),
        "mdmcomplianceurl" | "dmcomplianceurl" => {
            set_string(&mut facts.management_details.mdm_compliance_url, value)
        }
        "mdmtouurl" => set_string(&mut facts.management_details.mdm_tou_url, value),
        "settingsurl" => set_string(&mut facts.management_details.settings_url, value),
        "devicemanagementsrvver" => set_string(
            &mut facts.management_details.device_management_srv_ver,
            value,
        ),
        "devicemanagementsrvurl" => set_string(
            &mut facts.management_details.device_management_srv_url,
            value,
        ),
        "devicemanagementsrvid" => set_string(
            &mut facts.management_details.device_management_srv_id,
            value,
        ),
        "idp" => set_string(&mut facts.tenant_details.idp, value),
        "authcodeurl" => set_string(&mut facts.service_endpoints.auth_code_url, value),
        "accesstokenurl" => set_string(&mut facts.service_endpoints.access_token_url, value),
        "joinsrvversion" => set_string(&mut facts.service_endpoints.join_srv_version, value),
        "joinsrvurl" => set_string(&mut facts.service_endpoints.join_srv_url, value),
        "joinsrvid" => set_string(&mut facts.service_endpoints.join_srv_id, value),
        "keysrvversion" => set_string(&mut facts.service_endpoints.key_srv_version, value),
        "keysrvurl" => set_string(&mut facts.service_endpoints.key_srv_url, value),
        "keysrvid" => set_string(&mut facts.service_endpoints.key_srv_id, value),
        "webauthnsrvversion" => {
            set_string(&mut facts.service_endpoints.web_authn_srv_version, value)
        }
        "webauthnsrvurl" => set_string(&mut facts.service_endpoints.web_authn_srv_url, value),
        "webauthnsrvid" => set_string(&mut facts.service_endpoints.web_authn_srv_id, value),
        "ngcset" => {
            facts.user_state.ngc_set = parse_bool(value);
            true
        }
        "ngckeyid" => set_string(&mut facts.user_state.ngc_key_id, value),
        "canreset" => set_string(&mut facts.user_state.can_reset, value),
        "wamdefaultset" => {
            facts.user_state.wam_default_set = parse_bool(value);
            true
        }
        "wamdefaultauthority" => set_string(&mut facts.user_state.wam_default_authority, value),
        "wamdefaultid" => set_string(&mut facts.user_state.wam_default_id, value),
        "wamdefaultguid" => set_string(&mut facts.user_state.wam_default_guid, value),
        "isdevicejoined" => {
            facts.user_state.is_device_joined = parse_bool(value);
            true
        }
        "isuserazuread" => {
            facts.user_state.is_user_azure_ad = parse_bool(value);
            true
        }
        "policyenabled" => {
            facts.user_state.policy_enabled = parse_bool(value);
            true
        }
        "postlogonenabled" => {
            facts.user_state.post_logon_enabled = parse_bool(value);
            true
        }
        "deviceeligible" => {
            facts.user_state.device_eligible = parse_bool(value);
            true
        }
        "sessionisnotremote" => {
            facts.user_state.session_is_not_remote = parse_bool(value);
            true
        }
        "azureadprt" => {
            facts.sso_state.azure_ad_prt = parse_bool(value);
            true
        }
        "azureadprtauthority" => set_string(&mut facts.sso_state.azure_ad_prt_authority, value),
        "azureadprtupdatetime" => set_string(&mut facts.sso_state.azure_ad_prt_update_time, value),
        "acquireprtdiagnostics" => set_string(&mut facts.sso_state.acquire_prt_diagnostics, value),
        "enterpriseprt" => {
            facts.sso_state.enterprise_prt = parse_bool(value);
            true
        }
        "enterpriseprtupdatetime" => {
            set_string(&mut facts.sso_state.enterprise_prt_update_time, value)
        }
        "enterpriseprtexpirytime" => {
            set_string(&mut facts.sso_state.enterprise_prt_expiry_time, value)
        }
        "enterpriseprtauthority" => {
            set_string(&mut facts.sso_state.enterprise_prt_authority, value)
        }
        "onpremtgt" => {
            facts.sso_state.on_prem_tgt = parse_bool(value);
            true
        }
        "cloudtgt" => {
            facts.sso_state.cloud_tgt = parse_bool(value);
            true
        }
        "adfsrefreshtoken" => {
            facts.sso_state.adfs_refresh_token = parse_bool(value);
            true
        }
        "adfsraisready" => {
            facts.sso_state.adfs_ra_is_ready = parse_bool(value);
            true
        }
        "kerbtoplevelnames" => set_string(&mut facts.sso_state.kerb_top_level_names, value),
        "previousprtattempt" => set_string(&mut facts.diagnostics.previous_prt_attempt, value),
        "attemptstatus" => set_string(&mut facts.diagnostics.attempt_status, value),
        "useridentity" => set_string(&mut facts.diagnostics.user_identity, value),
        "credentialtype" => set_string(&mut facts.diagnostics.credential_type, value),
        "correlationid" => set_string(&mut facts.diagnostics.correlation_id, value),
        "endpointuri" => set_string(&mut facts.diagnostics.endpoint_uri, value),
        "httpmethod" => set_string(&mut facts.diagnostics.http_method, value),
        "httperror" => set_string(&mut facts.diagnostics.http_error, value),
        "httpstatus" => {
            facts.diagnostics.http_status = parse_u16(value);
            true
        }
        "requestid" => set_string(&mut facts.diagnostics.request_id, value),
        "diagnosticsreference" => set_string(&mut facts.diagnostics.diagnostics_reference, value),
        "usercontext" => set_string(&mut facts.diagnostics.user_context, value),
        "clienttime" => set_string(&mut facts.diagnostics.client_time, value),
        "adconnectivitytest" => set_string(&mut facts.pre_join_tests.ad_connectivity_test, value),
        "adconfigurationtest" => set_string(&mut facts.pre_join_tests.ad_configuration_test, value),
        "drsdiscoverytest" => set_string(&mut facts.pre_join_tests.drs_discovery_test, value),
        "drsconnectivitytest" => set_string(&mut facts.pre_join_tests.drs_connectivity_test, value),
        "tokenacquisitiontest" => {
            set_string(&mut facts.pre_join_tests.token_acquisition_test, value)
        }
        "fallbacktosyncjoin" => set_string(&mut facts.pre_join_tests.fallback_to_sync_join, value),
        "previousregistration" => set_string(&mut facts.registration.previous_registration, value),
        "errorphase" => set_string(&mut facts.registration.error_phase, value),
        "certenrollment" => set_string(&mut facts.registration.cert_enrollment, value),
        "logoncerttemplateready" => {
            set_string(&mut facts.registration.logon_cert_template_ready, value)
        }
        "prereqresult" => set_string(&mut facts.registration.pre_req_result, value),
        "clienterrorcode" => set_string(&mut facts.registration.client_error_code, value),
        "servererrorcode" => set_string(&mut facts.registration.server_error_code, value),
        "servermessage" => set_string(&mut facts.registration.server_message, value),
        "servererrordescription" => {
            set_string(&mut facts.registration.server_error_description, value)
        }
        "aadrecoveryenabled" => {
            facts.post_join_diagnostics.aad_recovery_enabled = parse_bool(value);
            true
        }
        "keysigntest" => set_string(&mut facts.post_join_diagnostics.key_sign_test, value),
        _ => false,
    }
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn normalize_absent(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed == "-" || trimmed.eq_ignore_ascii_case("n/a") {
        return None;
    }

    Some(trimmed.to_string())
}

fn set_string(slot: &mut Option<String>, value: &str) -> bool {
    *slot = normalize_absent(value);
    true
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" => Some(true),
        "no" | "false" | "0" => Some(false),
        _ => None,
    }
}

fn parse_u16(value: &str) -> Option<u16> {
    value.trim().parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::parse_dsregcmd;

    const SAMPLE: &str = r#"
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+
 AzureAdJoined : YES
 DomainJoined = NO
 WorkplaceJoined : NO
 EnterpriseJoined : NO
 TenantId : 11111111-2222-3333-4444-555555555555
 DeviceId : abcdefab-1111-2222-3333-abcdefabcdef
 MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
 dmComplianceUrl : https://portal.manage.microsoft.com/Compliance
 AzureAdPrt : YES
 AzureAdPrtUpdateTime : 2025-03-10 10:00:00.000 UTC
 Previous Prt Attempt : 2025-03-10 09:55:00.000 UTC
 Attempt Status : 0xc000006d
 HTTP status : 401
 User Context : SYSTEM
 SessionIsNotRemote : NO
 AD Connectivity Test : PASS
 DRS Discovery Test : FAIL [0x801c0021]
 Client ErrorCode : 0x801c03f2
 KeySignTest : PASSED
 AadRecoveryEnabled : NO
 DeviceCertificateValidity : [ 2025-03-01 00:00:00.000 UTC -- 2025-03-20 00:00:00.000 UTC ]
"#;

    #[test]
    fn parses_high_value_fields_and_fallback_names() {
        let facts = parse_dsregcmd(SAMPLE).expect("parse sample dsregcmd");

        assert_eq!(facts.join_state.azure_ad_joined, Some(true));
        assert_eq!(facts.join_state.domain_joined, Some(false));
        assert_eq!(
            facts.management_details.mdm_compliance_url.as_deref(),
            Some("https://portal.manage.microsoft.com/Compliance")
        );
        assert_eq!(facts.diagnostics.http_status, Some(401));
        assert_eq!(facts.diagnostics.user_context.as_deref(), Some("SYSTEM"));
        assert_eq!(facts.user_state.session_is_not_remote, Some(false));
        assert_eq!(
            facts.pre_join_tests.drs_discovery_test.as_deref(),
            Some("FAIL [0x801c0021]")
        );
        assert_eq!(
            facts.registration.client_error_code.as_deref(),
            Some("0x801c03f2")
        );
        assert_eq!(
            facts.post_join_diagnostics.key_sign_test.as_deref(),
            Some("PASSED")
        );
        assert_eq!(facts.post_join_diagnostics.aad_recovery_enabled, Some(false));
    }

    #[test]
    fn rejects_non_dsregcmd_input() {
        let error = parse_dsregcmd("totally unrelated text").expect_err("expected parse error");
        assert!(error.to_string().contains("recognizable dsregcmd"));
    }

    #[test]
    fn treats_placeholder_values_as_absent() {
        let facts = parse_dsregcmd("MdmUrl : -\nTenantName : n/a\nAzureAdJoined : YES")
            .expect("parse placeholder sample");

        assert_eq!(facts.management_details.mdm_url, None);
        assert_eq!(facts.tenant_details.tenant_name, None);
        assert_eq!(facts.join_state.azure_ad_joined, Some(true));
    }
}
