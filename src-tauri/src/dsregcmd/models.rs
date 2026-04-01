use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::intune::models::{EventLogAnalysis, IntuneDiagnosticSeverity};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DsregcmdJoinType {
    HybridEntraIdJoined,
    EntraIdJoined,
    NotJoined,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DsregcmdDiagnosticPhase {
    Precheck,
    Discover,
    Auth,
    Join,
    PostJoin,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DsregcmdCaptureConfidence {
    High,
    #[default]
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DsregcmdEvidenceSource {
    Dsregcmd,
    PolicyManagerCurrent,
    PolicyManagerProvider,
    PolicyManagerComparison,
    WindowsPolicyMachine,
    WindowsPolicyUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdPolicyEvidenceValue {
    pub display_value: Option<bool>,
    pub current_value: Option<bool>,
    pub provider_value: Option<bool>,
    pub source: Option<DsregcmdEvidenceSource>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdWhfbPolicyEvidence {
    pub policy_enabled: DsregcmdPolicyEvidenceValue,
    pub post_logon_enabled: DsregcmdPolicyEvidenceValue,
    pub pin_recovery_enabled: DsregcmdPolicyEvidenceValue,
    pub require_security_device: DsregcmdPolicyEvidenceValue,
    pub use_certificate_for_on_prem_auth: DsregcmdPolicyEvidenceValue,
    pub use_cloud_trust_for_on_prem_auth: DsregcmdPolicyEvidenceValue,
    #[serde(default)]
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdJoinState {
    pub azure_ad_joined: Option<bool>,
    pub domain_joined: Option<bool>,
    pub workplace_joined: Option<bool>,
    pub enterprise_joined: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdDeviceDetails {
    pub device_id: Option<String>,
    pub thumbprint: Option<String>,
    pub device_certificate_validity: Option<String>,
    pub key_container_id: Option<String>,
    pub key_provider: Option<String>,
    pub tpm_protected: Option<bool>,
    pub device_auth_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdTenantDetails {
    pub tenant_id: Option<String>,
    pub tenant_name: Option<String>,
    pub domain_name: Option<String>,
    pub idp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdManagementDetails {
    pub mdm_url: Option<String>,
    pub mdm_compliance_url: Option<String>,
    pub mdm_tou_url: Option<String>,
    pub settings_url: Option<String>,
    pub device_management_srv_ver: Option<String>,
    pub device_management_srv_url: Option<String>,
    pub device_management_srv_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdServiceEndpoints {
    pub auth_code_url: Option<String>,
    pub access_token_url: Option<String>,
    pub join_srv_version: Option<String>,
    pub join_srv_url: Option<String>,
    pub join_srv_id: Option<String>,
    pub key_srv_version: Option<String>,
    pub key_srv_url: Option<String>,
    pub key_srv_id: Option<String>,
    pub web_authn_srv_version: Option<String>,
    pub web_authn_srv_url: Option<String>,
    pub web_authn_srv_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdUserState {
    pub ngc_set: Option<bool>,
    pub ngc_key_id: Option<String>,
    pub can_reset: Option<String>,
    pub wam_default_set: Option<bool>,
    pub wam_default_authority: Option<String>,
    pub wam_default_id: Option<String>,
    pub wam_default_guid: Option<String>,
    pub is_device_joined: Option<bool>,
    pub is_user_azure_ad: Option<bool>,
    pub policy_enabled: Option<bool>,
    pub post_logon_enabled: Option<bool>,
    pub device_eligible: Option<bool>,
    pub session_is_not_remote: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdSsoState {
    pub azure_ad_prt: Option<bool>,
    pub azure_ad_prt_authority: Option<String>,
    pub azure_ad_prt_update_time: Option<String>,
    pub acquire_prt_diagnostics: Option<String>,
    pub enterprise_prt: Option<bool>,
    pub enterprise_prt_update_time: Option<String>,
    pub enterprise_prt_expiry_time: Option<String>,
    pub enterprise_prt_authority: Option<String>,
    pub on_prem_tgt: Option<bool>,
    pub cloud_tgt: Option<bool>,
    pub adfs_refresh_token: Option<bool>,
    pub adfs_ra_is_ready: Option<bool>,
    pub kerb_top_level_names: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdDiagnosticFields {
    pub previous_prt_attempt: Option<String>,
    pub attempt_status: Option<String>,
    pub user_identity: Option<String>,
    pub credential_type: Option<String>,
    pub correlation_id: Option<String>,
    pub endpoint_uri: Option<String>,
    pub http_method: Option<String>,
    pub http_error: Option<String>,
    pub http_status: Option<u16>,
    pub request_id: Option<String>,
    pub diagnostics_reference: Option<String>,
    pub user_context: Option<String>,
    pub client_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdPreJoinTests {
    pub ad_connectivity_test: Option<String>,
    pub ad_configuration_test: Option<String>,
    pub drs_discovery_test: Option<String>,
    pub drs_connectivity_test: Option<String>,
    pub token_acquisition_test: Option<String>,
    pub fallback_to_sync_join: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdRegistrationState {
    pub previous_registration: Option<String>,
    pub error_phase: Option<String>,
    pub cert_enrollment: Option<String>,
    pub logon_cert_template_ready: Option<String>,
    pub pre_req_result: Option<String>,
    pub client_error_code: Option<String>,
    pub server_error_code: Option<String>,
    pub server_message: Option<String>,
    pub server_error_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdPostJoinDiagnostics {
    pub aad_recovery_enabled: Option<bool>,
    pub key_sign_test: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdFacts {
    pub join_state: DsregcmdJoinState,
    pub device_details: DsregcmdDeviceDetails,
    pub tenant_details: DsregcmdTenantDetails,
    pub management_details: DsregcmdManagementDetails,
    pub service_endpoints: DsregcmdServiceEndpoints,
    pub user_state: DsregcmdUserState,
    pub sso_state: DsregcmdSsoState,
    pub diagnostics: DsregcmdDiagnosticFields,
    pub pre_join_tests: DsregcmdPreJoinTests,
    pub registration: DsregcmdRegistrationState,
    pub post_join_diagnostics: DsregcmdPostJoinDiagnostics,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdDerived {
    pub join_type: DsregcmdJoinType,
    pub join_type_label: String,
    pub dominant_phase: DsregcmdDiagnosticPhase,
    pub phase_summary: String,
    pub capture_confidence: DsregcmdCaptureConfidence,
    pub capture_confidence_reason: String,
    pub mdm_enrolled: Option<bool>,
    pub missing_mdm: Option<bool>,
    pub compliance_url_present: Option<bool>,
    pub missing_compliance_url: Option<bool>,
    pub azure_ad_prt_present: Option<bool>,
    pub stale_prt: Option<bool>,
    pub prt_last_update: Option<DateTime<Utc>>,
    pub prt_reference_time: Option<DateTime<Utc>>,
    pub prt_age_hours: Option<f64>,
    pub tpm_protected: Option<bool>,
    pub certificate_valid_from: Option<DateTime<Utc>>,
    pub certificate_valid_to: Option<DateTime<Utc>>,
    pub certificate_expiring_soon: Option<bool>,
    pub certificate_days_remaining: Option<i64>,
    pub network_error_code: Option<String>,
    pub has_network_error: bool,
    pub remote_session_system: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdDiagnosticInsight {
    pub id: String,
    pub severity: IntuneDiagnosticSeverity,
    pub category: String,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<String>,
    pub next_checks: Vec<String>,
    #[serde(default)]
    pub suggested_fixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdOsVersionEvidence {
    pub current_build: Option<String>,
    pub display_version: Option<String>,
    pub product_name: Option<String>,
    pub ubr: Option<u32>,
    pub edition_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdProxyEvidence {
    pub proxy_enabled: Option<bool>,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
    pub auto_config_url: Option<String>,
    pub wpad_detected: bool,
    pub winhttp_proxy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdEnrollmentEntry {
    pub guid: Option<String>,
    pub upn: Option<String>,
    pub provider_id: Option<String>,
    pub enrollment_state: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdEnrollmentEvidence {
    pub enrollment_count: u32,
    #[serde(default)]
    pub enrollments: Vec<DsregcmdEnrollmentEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdConnectivityResult {
    pub endpoint: String,
    pub reachable: bool,
    pub status_code: Option<u16>,
    pub latency_ms: Option<u64>,
    pub error_message: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdScpQueryResult {
    pub scp_found: bool,
    pub tenant_domain: Option<String>,
    pub azuread_id: Option<String>,
    pub keywords: Vec<String>,
    pub domain_controller: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdActiveEvidence {
    pub connectivity_tests: Vec<DsregcmdConnectivityResult>,
    pub scp_query: Option<DsregcmdScpQueryResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdScheduledTaskEvidence {
    #[serde(default)]
    pub enterprise_mgmt_guids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DsregcmdAnalysisResult {
    pub facts: DsregcmdFacts,
    pub derived: DsregcmdDerived,
    #[serde(default)]
    pub diagnostics: Vec<DsregcmdDiagnosticInsight>,
    #[serde(default)]
    pub policy_evidence: DsregcmdWhfbPolicyEvidence,
    #[serde(default)]
    pub os_version: Option<DsregcmdOsVersionEvidence>,
    #[serde(default)]
    pub proxy_evidence: Option<DsregcmdProxyEvidence>,
    #[serde(default)]
    pub enrollment_evidence: Option<DsregcmdEnrollmentEvidence>,
    #[serde(default)]
    pub active_evidence: Option<DsregcmdActiveEvidence>,
    #[serde(default)]
    pub scheduled_task_evidence: Option<DsregcmdScheduledTaskEvidence>,
    #[serde(default)]
    pub event_log_analysis: Option<EventLogAnalysis>,
}

#[cfg(test)]
mod tests {
    use super::{
        DsregcmdCaptureConfidence, DsregcmdDiagnosticPhase, DsregcmdEvidenceSource,
        DsregcmdJoinType,
    };

    #[test]
    fn join_type_serializes_with_pascal_case_variants() {
        assert_eq!(
            serde_json::to_string(&DsregcmdJoinType::HybridEntraIdJoined).expect("serialize join type"),
            "\"HybridEntraIdJoined\""
        );
        assert_eq!(
            serde_json::to_string(&DsregcmdJoinType::EntraIdJoined).expect("serialize join type"),
            "\"EntraIdJoined\""
        );
        assert_eq!(
            serde_json::to_string(&DsregcmdJoinType::NotJoined).expect("serialize join type"),
            "\"NotJoined\""
        );
        assert_eq!(
            serde_json::to_string(&DsregcmdJoinType::Unknown).expect("serialize join type"),
            "\"Unknown\""
        );
    }

    #[test]
    fn phase_and_confidence_serialize_with_expected_strings() {
        assert_eq!(
            serde_json::to_string(&DsregcmdDiagnosticPhase::PostJoin)
                .expect("serialize diagnostic phase"),
            "\"post_join\""
        );
        assert_eq!(
            serde_json::to_string(&DsregcmdCaptureConfidence::High)
                .expect("serialize capture confidence"),
            "\"high\""
        );
        assert_eq!(
            serde_json::to_string(&DsregcmdEvidenceSource::PolicyManagerCurrent)
                .expect("serialize evidence source"),
            "\"policy_manager_current\""
        );
        assert_eq!(
            serde_json::to_string(&DsregcmdEvidenceSource::WindowsPolicyMachine)
                .expect("serialize evidence source"),
            "\"windows_policy_machine\""
        );
    }
}
