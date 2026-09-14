//! The dsregcmd export projection (issue #556).
//!
//! `dsregcmd /status` is dense with the identifiers the Intune lanes mask:
//! the tenant id, the tenant and on-premises domains, the device id, the
//! device certificate thumbprint, the signed-in user's principal name and the
//! user's SID. This module is where that lane classifies them and produces the
//! form callers may publish.
//!
//! # Where the boundary is
//!
//! ADR-004 revision 1, Ruling 1: the contract binds at the crate/library export
//! boundary, and the published analysis value reaching callers is projected.
//! [`analyze_text`](super::analyze_text) and
//! [`analyze_text_with_evidence`](super::analyze_text_with_evidence) therefore
//! apply [`redacted_analysis`] before returning; the unprojected analysis is
//! reachable only through
//! [`analyze_text_preserving_local_values`](super::analyze_text_preserving_local_values),
//! which is named for what it is. A caller that receives an analysis from this
//! crate has no unprojected value in hand to copy to a clipboard or a file, and
//! a workspace that finds itself holding one has found a defect here rather
//! than something to fix at the clipboard call site.
//!
//! # What is shared and what is local
//!
//! Ruling 5: the masking *grammar* is shared and the *projection* is
//! workload-local. Masking runs through
//! [`redact_text`](crate::intune::apps::windows::common::redaction::redact_text)
//! for text and
//! [`redact_field_value`](crate::intune::apps::windows::common::redaction::redact_field_value)
//! for a value that is sensitive only because of the field it sits in; this
//! module owns only the classification — which of this lane's fields carry
//! identity. It writes no rule and mints no token of its own.
//!
//! # How the classification is expressed
//!
//! Ruling 7: every function on the projection path constructs its result with a
//! full struct literal, at every depth. There is no `clone()`-then-mutate and
//! no struct-update syntax anywhere in this file, so a field added to any model
//! on this path is a compile error here, in the change that adds it, rather
//! than a field that ships raw.
//!
//! # Two classes of field, and the free-text gap
//!
//! A string field is either an *identity field* — masked whole, from its
//! meaning — or *text*, masked for anything the shared grammar recognizes and
//! then scrubbed of every literal this projection classified as identity. The
//! second pass is what closes the gap a shaped rule cannot: `DeviceId` and
//! `Thumbprint` have no shape and no label once they are a struct field, and
//! the tenant id also appears inside `Endpoint URI` and the PRT authority URL
//! where nothing labels it.
//!
//! # Equality scope
//!
//! Masking here preserves equality within one analysis: equal values produce
//! equal tokens, and a value masked as a typed field and mentioned in narrative
//! text reaches the same token, so an export still shows that two records name
//! one tenant, one device, one user. Ruling 2 requires that derivation to be
//! keyed per analysis and Ruling 4 forbids a scope the caller did not supply;
//! neither is implemented for any lane yet, and this lane adopts the one shared
//! derivation rather than minting a fifth (Ruling 5). A lane that forked the
//! derivation would keep the unkeyed one, and the fix would not reach it.

use std::collections::BTreeMap;

use crate::intune::apps::windows::common::{redact_field_value, redact_text};
use crate::intune::models::{
    EventLogAnalysis, EventLogChannelSummary, EventLogCorrelationLink, EventLogEntry,
    EventLogLiveQueryChannelResult, EventLogLiveQueryMetadata, IntuneTimestampBounds,
};

use super::models::{
    DsregcmdActiveEvidence, DsregcmdAnalysisResult, DsregcmdConnectivityResult,
    DsregcmdDerived, DsregcmdDeviceDetails, DsregcmdDiagnosticFields, DsregcmdDiagnosticInsight,
    DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence, DsregcmdFacts, DsregcmdJoinState,
    DsregcmdManagementDetails, DsregcmdOsVersionEvidence, DsregcmdPolicyEvidenceValue,
    DsregcmdPostJoinDiagnostics, DsregcmdPreJoinTests, DsregcmdProxyEvidence,
    DsregcmdRegistrationState, DsregcmdScheduledTaskEvidence, DsregcmdScpQueryResult,
    DsregcmdServiceEndpoints, DsregcmdSsoState, DsregcmdTenantDetails, DsregcmdUserState,
    DsregcmdWhfbPolicyEvidence,
};

/// The field vocabulary this lane masks with. The shared grammar already emits
/// `tenant`, `upn` and `host` for values it recognizes from shape, so an
/// identity field that carries one of those keeps the token a narrative mention
/// of the same value would get.
const KIND_TENANT: &str = "tenant";
const KIND_DEVICE: &str = "device";
const KIND_THUMBPRINT: &str = "thumbprint";
const KIND_UPN: &str = "upn";
const KIND_HOST: &str = "host";

/// Shortest classified value scrubbed out of free text.
///
/// A tenant display name can be a short ordinary word, and a value that short
/// cannot be told apart from prose once it sits unlabelled in a sentence.
/// Scrubbing it would mangle readable evidence without protecting anything the
/// typed field does not already cover. The floor stays below the shortest real
/// domain, device id and thumbprint, so every shaped identifier is still
/// covered.
const MIN_SCRUBBED_LITERAL_BYTES: usize = 6;

/// Every identity value this lane classified, paired with the token that
/// replaces it.
///
/// Built from the unprojected analysis and then applied to it, so a literal is
/// known before any free-text field is scrubbed. Keyed by the ASCII-lowercased
/// literal: case is the only way an identifier varies between two lines of one
/// capture, and unlike `to_lowercase` it cannot shift a byte offset out from
/// under the slicing in [`IdentityLiterals::scrub`].
#[derive(Default)]
struct IdentityLiterals {
    /// Literal (ASCII-lowercased) to token, longest literal first.
    tokens: BTreeMap<String, String>,
    /// Longest literal first, so a literal that sits inside a longer one can
    /// never cut the longer one in half.
    order: Vec<String>,
}

impl IdentityLiterals {
    /// Classify one identity value. Values too short to be told apart from
    /// prose are skipped rather than scrubbed out of narrative over-eagerly.
    fn push(&mut self, value: &str, kind: &str) {
        let literal = value.trim();
        if literal.len() < MIN_SCRUBBED_LITERAL_BYTES {
            return;
        }

        let key = literal.to_ascii_lowercase();
        if self.tokens.contains_key(&key) {
            return;
        }

        self.tokens.insert(key.clone(), identity_token(literal, kind));
        self.order.push(key);
        self.order
            .sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    }

    /// Replace every occurrence of a classified literal, whatever its case.
    ///
    /// Runs after the shared grammar in every free-text pipeline: the shaped
    /// rules must see the original text, or scrubbing a tenant domain on its
    /// own would break the mail-address match on a principal name that contains
    /// it and leak the local part.
    fn scrub(&self, value: &str) -> String {
        if self.order.is_empty() {
            return value.to_string();
        }

        // ASCII folding only, so byte offsets match the haystack's.
        let haystack = value.to_ascii_lowercase();
        let mut scrubbed = String::with_capacity(value.len());
        let mut cursor = 0;

        while let Some((start, end, token)) = self.leftmost_longest_match(&haystack, cursor) {
            scrubbed.push_str(&value[cursor..start]);
            scrubbed.push_str(token);
            cursor = end;
        }
        scrubbed.push_str(&value[cursor..]);
        scrubbed
    }

    fn leftmost_longest_match(
        &self,
        haystack: &str,
        cursor: usize,
    ) -> Option<(usize, usize, &str)> {
        self.order
            .iter()
            .filter_map(|literal| {
                haystack[cursor..]
                    .find(literal.as_str())
                    .map(|offset| (cursor + offset, cursor + offset + literal.len(), literal))
            })
            .min_by(|left, right| left.0.cmp(&right.0).then_with(|| right.1.cmp(&left.1)))
            .and_then(|(start, end, literal)| {
                self.tokens
                    .get(literal)
                    .map(|token| (start, end, token.as_str()))
            })
    }
}

/// The token an identity value reaches, wherever it is projected.
///
/// A value the shared grammar recognizes by shape keeps the grammar's token, so
/// a principal name masked as a typed field and the same principal name inside
/// a server message reach one token. Anything else — a device id, a thumbprint,
/// a bare domain — is minted through the shared minter.
fn identity_token(value: &str, kind: &str) -> String {
    let shaped = redact_text(value);
    if shaped == value {
        redact_field_value(kind, value)
    } else {
        shaped
    }
}

/// The projection: the classification above, applied to a whole analysis.
struct Projection {
    literals: IdentityLiterals,
}

impl Projection {
    /// A free-text field: the shared grammar first, then this lane's literal
    /// scrub.
    fn text(&self, value: &str) -> String {
        self.literals.scrub(&redact_text(value))
    }

    fn text_opt(&self, value: &Option<String>) -> Option<String> {
        value.as_deref().map(|value| self.text(value))
    }

    fn texts(&self, values: &[String]) -> Vec<String> {
        values.iter().map(|value| self.text(value)).collect()
    }

    /// An identity field: masked whole, because the field's meaning is what
    /// makes the value an identifier rather than anything in the value.
    fn identity(&self, value: &Option<String>, kind: &str) -> Option<String> {
        value
            .as_deref()
            .map(|value| identity_token(value.trim(), kind))
    }
}

/// Project a fully assembled analysis into the form callers may publish.
pub fn redacted_analysis(result: &DsregcmdAnalysisResult) -> DsregcmdAnalysisResult {
    let projection = Projection {
        literals: collect_identity_literals(result),
    };

    DsregcmdAnalysisResult {
        facts: projection.facts(&result.facts),
        derived: projection.derived(&result.derived),
        diagnostics: projection.diagnostics(&result.diagnostics),
        policy_evidence: projection.policy_evidence(&result.policy_evidence),
        os_version: result
            .os_version
            .as_ref()
            .map(|os_version| projection.os_version(os_version)),
        proxy_evidence: result
            .proxy_evidence
            .as_ref()
            .map(|proxy_evidence| projection.proxy_evidence(proxy_evidence)),
        enrollment_evidence: result
            .enrollment_evidence
            .as_ref()
            .map(|enrollment| projection.enrollment_evidence(enrollment)),
        active_evidence: result
            .active_evidence
            .as_ref()
            .map(|active| projection.active_evidence(active)),
        scheduled_task_evidence: result
            .scheduled_task_evidence
            .as_ref()
            .map(|scheduled| projection.scheduled_task_evidence(scheduled)),
        event_log_analysis: result
            .event_log_analysis
            .as_ref()
            .map(|events| projection.event_log_analysis(events)),
    }
}

/// Project raw `dsregcmd /status` text.
///
/// For callers that hold the capture itself rather than an analysis of it —
/// the workspace's "copy status text" path — this is the projection of the
/// input, and it is the same classification: the shared grammar over the whole
/// text, then the literals the parser read out of this same capture scrubbed
/// out of it. Text the parser does not recognize loses only what the grammar
/// recognizes by shape; nothing is invented for it.
///
/// This is the one form of the capture text that may be published. The capture
/// text itself stays a capture: it is the analyzer's input, and two analyzers
/// read it back from a bundle, so masking where it is *stored* would change what
/// they conclude rather than what they publish.
pub fn redacted_status_text(input: &str) -> String {
    Projection {
        literals: collect_literals(input, |_| {}),
    }
    .text(input)
}

impl Projection {
    fn facts(&self, facts: &DsregcmdFacts) -> DsregcmdFacts {
        DsregcmdFacts {
            join_state: DsregcmdJoinState {
                azure_ad_joined: facts.join_state.azure_ad_joined,
                domain_joined: facts.join_state.domain_joined,
                workplace_joined: facts.join_state.workplace_joined,
                enterprise_joined: facts.join_state.enterprise_joined,
            },
            device_details: DsregcmdDeviceDetails {
                device_id: self.identity(&facts.device_details.device_id, KIND_DEVICE),
                thumbprint: self.identity(&facts.device_details.thumbprint, KIND_THUMBPRINT),
                device_certificate_validity: self
                    .text_opt(&facts.device_details.device_certificate_validity),
                key_container_id: self.text_opt(&facts.device_details.key_container_id),
                key_provider: self.text_opt(&facts.device_details.key_provider),
                tpm_protected: facts.device_details.tpm_protected,
                device_auth_status: self.text_opt(&facts.device_details.device_auth_status),
            },
            tenant_details: self.tenant_details(&facts.tenant_details),
            management_details: DsregcmdManagementDetails {
                mdm_url: self.text_opt(&facts.management_details.mdm_url),
                mdm_compliance_url: self.text_opt(&facts.management_details.mdm_compliance_url),
                mdm_tou_url: self.text_opt(&facts.management_details.mdm_tou_url),
                settings_url: self.text_opt(&facts.management_details.settings_url),
                device_management_srv_ver: self
                    .text_opt(&facts.management_details.device_management_srv_ver),
                device_management_srv_url: self
                    .text_opt(&facts.management_details.device_management_srv_url),
                device_management_srv_id: self
                    .text_opt(&facts.management_details.device_management_srv_id),
            },
            service_endpoints: DsregcmdServiceEndpoints {
                auth_code_url: self.text_opt(&facts.service_endpoints.auth_code_url),
                access_token_url: self.text_opt(&facts.service_endpoints.access_token_url),
                join_srv_version: self.text_opt(&facts.service_endpoints.join_srv_version),
                join_srv_url: self.text_opt(&facts.service_endpoints.join_srv_url),
                join_srv_id: self.text_opt(&facts.service_endpoints.join_srv_id),
                key_srv_version: self.text_opt(&facts.service_endpoints.key_srv_version),
                key_srv_url: self.text_opt(&facts.service_endpoints.key_srv_url),
                key_srv_id: self.text_opt(&facts.service_endpoints.key_srv_id),
                web_authn_srv_version: self
                    .text_opt(&facts.service_endpoints.web_authn_srv_version),
                web_authn_srv_url: self.text_opt(&facts.service_endpoints.web_authn_srv_url),
                web_authn_srv_id: self.text_opt(&facts.service_endpoints.web_authn_srv_id),
            },
            user_state: DsregcmdUserState {
                ngc_set: facts.user_state.ngc_set,
                ngc_key_id: self.text_opt(&facts.user_state.ngc_key_id),
                can_reset: self.text_opt(&facts.user_state.can_reset),
                wam_default_set: facts.user_state.wam_default_set,
                wam_default_authority: self.text_opt(&facts.user_state.wam_default_authority),
                wam_default_id: self.text_opt(&facts.user_state.wam_default_id),
                wam_default_guid: self.text_opt(&facts.user_state.wam_default_guid),
                is_device_joined: facts.user_state.is_device_joined,
                is_user_azure_ad: facts.user_state.is_user_azure_ad,
                policy_enabled: facts.user_state.policy_enabled,
                post_logon_enabled: facts.user_state.post_logon_enabled,
                device_eligible: facts.user_state.device_eligible,
                session_is_not_remote: facts.user_state.session_is_not_remote,
            },
            sso_state: DsregcmdSsoState {
                azure_ad_prt: facts.sso_state.azure_ad_prt,
                // The PRT authority is tenant-scoped: for an Entra authority
                // its path is the tenant id, and for a hybrid authority its
                // host is the organization's STS. Scrubbing the classified
                // literals leaves the host readable and removes the identity
                // embedded in it.
                azure_ad_prt_authority: self.text_opt(&facts.sso_state.azure_ad_prt_authority),
                azure_ad_prt_update_time: self.text_opt(&facts.sso_state.azure_ad_prt_update_time),
                acquire_prt_diagnostics: self.text_opt(&facts.sso_state.acquire_prt_diagnostics),
                enterprise_prt: facts.sso_state.enterprise_prt,
                enterprise_prt_update_time: self
                    .text_opt(&facts.sso_state.enterprise_prt_update_time),
                enterprise_prt_expiry_time: self
                    .text_opt(&facts.sso_state.enterprise_prt_expiry_time),
                enterprise_prt_authority: self.text_opt(&facts.sso_state.enterprise_prt_authority),
                on_prem_tgt: facts.sso_state.on_prem_tgt,
                cloud_tgt: facts.sso_state.cloud_tgt,
                adfs_refresh_token: facts.sso_state.adfs_refresh_token,
                adfs_ra_is_ready: facts.sso_state.adfs_ra_is_ready,
                kerb_top_level_names: self.text_opt(&facts.sso_state.kerb_top_level_names),
            },
            diagnostics: DsregcmdDiagnosticFields {
                previous_prt_attempt: self.text_opt(&facts.diagnostics.previous_prt_attempt),
                attempt_status: self.text_opt(&facts.diagnostics.attempt_status),
                user_identity: self.identity(&facts.diagnostics.user_identity, KIND_UPN),
                credential_type: self.text_opt(&facts.diagnostics.credential_type),
                correlation_id: self.text_opt(&facts.diagnostics.correlation_id),
                endpoint_uri: self.text_opt(&facts.diagnostics.endpoint_uri),
                http_method: self.text_opt(&facts.diagnostics.http_method),
                http_error: self.text_opt(&facts.diagnostics.http_error),
                http_status: facts.diagnostics.http_status,
                request_id: self.text_opt(&facts.diagnostics.request_id),
                diagnostics_reference: self.text_opt(&facts.diagnostics.diagnostics_reference),
                user_context: self.text_opt(&facts.diagnostics.user_context),
                client_time: self.text_opt(&facts.diagnostics.client_time),
            },
            pre_join_tests: DsregcmdPreJoinTests {
                ad_connectivity_test: self.text_opt(&facts.pre_join_tests.ad_connectivity_test),
                ad_configuration_test: self.text_opt(&facts.pre_join_tests.ad_configuration_test),
                drs_discovery_test: self.text_opt(&facts.pre_join_tests.drs_discovery_test),
                drs_connectivity_test: self.text_opt(&facts.pre_join_tests.drs_connectivity_test),
                token_acquisition_test: self.text_opt(&facts.pre_join_tests.token_acquisition_test),
                fallback_to_sync_join: self.text_opt(&facts.pre_join_tests.fallback_to_sync_join),
            },
            registration: DsregcmdRegistrationState {
                previous_registration: self.text_opt(&facts.registration.previous_registration),
                error_phase: self.text_opt(&facts.registration.error_phase),
                cert_enrollment: self.text_opt(&facts.registration.cert_enrollment),
                logon_cert_template_ready: self
                    .text_opt(&facts.registration.logon_cert_template_ready),
                pre_req_result: self.text_opt(&facts.registration.pre_req_result),
                client_error_code: self.text_opt(&facts.registration.client_error_code),
                server_error_code: self.text_opt(&facts.registration.server_error_code),
                server_message: self.text_opt(&facts.registration.server_message),
                server_error_description: self
                    .text_opt(&facts.registration.server_error_description),
            },
            post_join_diagnostics: DsregcmdPostJoinDiagnostics {
                aad_recovery_enabled: facts.post_join_diagnostics.aad_recovery_enabled,
                key_sign_test: self.text_opt(&facts.post_join_diagnostics.key_sign_test),
            },
        }
    }

    fn tenant_details(&self, tenant: &DsregcmdTenantDetails) -> DsregcmdTenantDetails {
        DsregcmdTenantDetails {
            tenant_id: self.identity(&tenant.tenant_id, KIND_TENANT),
            tenant_name: self.identity(&tenant.tenant_name, KIND_TENANT),
            domain_name: self.identity(&tenant.domain_name, KIND_TENANT),
            idp: self.text_opt(&tenant.idp),
        }
    }

    fn derived(&self, derived: &DsregcmdDerived) -> DsregcmdDerived {
        DsregcmdDerived {
            join_type: derived.join_type,
            join_type_label: self.text(&derived.join_type_label),
            dominant_phase: derived.dominant_phase,
            phase_summary: self.text(&derived.phase_summary),
            capture_confidence: derived.capture_confidence,
            capture_confidence_reason: self.text(&derived.capture_confidence_reason),
            mdm_enrolled: derived.mdm_enrolled,
            missing_mdm: derived.missing_mdm,
            compliance_url_present: derived.compliance_url_present,
            missing_compliance_url: derived.missing_compliance_url,
            azure_ad_prt_present: derived.azure_ad_prt_present,
            stale_prt: derived.stale_prt,
            prt_last_update: derived.prt_last_update,
            prt_reference_time: derived.prt_reference_time,
            prt_age_hours: derived.prt_age_hours,
            tpm_protected: derived.tpm_protected,
            certificate_valid_from: derived.certificate_valid_from,
            certificate_valid_to: derived.certificate_valid_to,
            certificate_expiring_soon: derived.certificate_expiring_soon,
            certificate_days_remaining: derived.certificate_days_remaining,
            network_error_code: self.text_opt(&derived.network_error_code),
            has_network_error: derived.has_network_error,
            remote_session_system: derived.remote_session_system,
        }
    }

    fn diagnostics(
        &self,
        diagnostics: &[DsregcmdDiagnosticInsight],
    ) -> Vec<DsregcmdDiagnosticInsight> {
        diagnostics
            .iter()
            .map(|diagnostic| DsregcmdDiagnosticInsight {
                id: diagnostic.id.clone(),
                severity: diagnostic.severity.clone(),
                category: diagnostic.category.clone(),
                title: self.text(&diagnostic.title),
                summary: self.text(&diagnostic.summary),
                evidence: self.texts(&diagnostic.evidence),
                next_checks: self.texts(&diagnostic.next_checks),
                suggested_fixes: self.texts(&diagnostic.suggested_fixes),
            })
            .collect()
    }

    fn policy_evidence(&self, policy: &DsregcmdWhfbPolicyEvidence) -> DsregcmdWhfbPolicyEvidence {
        DsregcmdWhfbPolicyEvidence {
            policy_enabled: self.policy_value(&policy.policy_enabled),
            post_logon_enabled: self.policy_value(&policy.post_logon_enabled),
            pin_recovery_enabled: self.policy_value(&policy.pin_recovery_enabled),
            require_security_device: self.policy_value(&policy.require_security_device),
            use_certificate_for_on_prem_auth: self
                .policy_value(&policy.use_certificate_for_on_prem_auth),
            use_cloud_trust_for_on_prem_auth: self
                .policy_value(&policy.use_cloud_trust_for_on_prem_auth),
            artifact_paths: self.texts(&policy.artifact_paths),
        }
    }

    fn policy_value(&self, value: &DsregcmdPolicyEvidenceValue) -> DsregcmdPolicyEvidenceValue {
        DsregcmdPolicyEvidenceValue {
            display_value: value.display_value,
            current_value: value.current_value,
            provider_value: value.provider_value,
            source: value.source,
            note: self.text_opt(&value.note),
        }
    }

    fn os_version(&self, os: &DsregcmdOsVersionEvidence) -> DsregcmdOsVersionEvidence {
        DsregcmdOsVersionEvidence {
            current_build: self.text_opt(&os.current_build),
            display_version: self.text_opt(&os.display_version),
            product_name: self.text_opt(&os.product_name),
            ubr: os.ubr,
            edition_id: self.text_opt(&os.edition_id),
        }
    }

    fn proxy_evidence(&self, proxy: &DsregcmdProxyEvidence) -> DsregcmdProxyEvidence {
        DsregcmdProxyEvidence {
            proxy_enabled: proxy.proxy_enabled,
            proxy_server: self.text_opt(&proxy.proxy_server),
            proxy_override: self.text_opt(&proxy.proxy_override),
            auto_config_url: self.text_opt(&proxy.auto_config_url),
            wpad_detected: proxy.wpad_detected,
            winhttp_proxy: self.text_opt(&proxy.winhttp_proxy),
        }
    }

    fn enrollment_evidence(
        &self,
        enrollment: &DsregcmdEnrollmentEvidence,
    ) -> DsregcmdEnrollmentEvidence {
        DsregcmdEnrollmentEvidence {
            enrollment_count: enrollment.enrollment_count,
            enrollments: enrollment
                .enrollments
                .iter()
                .map(|entry| self.enrollment_entry(entry))
                .collect(),
        }
    }

    fn enrollment_entry(&self, entry: &DsregcmdEnrollmentEntry) -> DsregcmdEnrollmentEntry {
        DsregcmdEnrollmentEntry {
            // The enrollment GUID is an MDM correlation key, not an
            // organization identifier: it joins enrollment records inside one
            // export and the shared grammar documents correlation keys as
            // surviving.
            guid: self.text_opt(&entry.guid),
            upn: self.identity(&entry.upn, KIND_UPN),
            provider_id: self.text_opt(&entry.provider_id),
            enrollment_state: entry.enrollment_state,
        }
    }

    fn active_evidence(&self, active: &DsregcmdActiveEvidence) -> DsregcmdActiveEvidence {
        DsregcmdActiveEvidence {
            connectivity_tests: active
                .connectivity_tests
                .iter()
                .map(|test| self.connectivity_result(test))
                .collect(),
            scp_query: active.scp_query.as_ref().map(|scp| self.scp_query(scp)),
        }
    }

    fn connectivity_result(&self, test: &DsregcmdConnectivityResult) -> DsregcmdConnectivityResult {
        DsregcmdConnectivityResult {
            endpoint: self.text(&test.endpoint),
            reachable: test.reachable,
            status_code: test.status_code,
            latency_ms: test.latency_ms,
            error_message: self.text_opt(&test.error_message),
            timestamp: self.text(&test.timestamp),
        }
    }

    fn scp_query(&self, scp: &DsregcmdScpQueryResult) -> DsregcmdScpQueryResult {
        DsregcmdScpQueryResult {
            scp_found: scp.scp_found,
            tenant_domain: self.identity(&scp.tenant_domain, KIND_TENANT),
            azuread_id: self.identity(&scp.azuread_id, KIND_TENANT),
            keywords: self.texts(&scp.keywords),
            domain_controller: self.text_opt(&scp.domain_controller),
            error: self.text_opt(&scp.error),
        }
    }

    fn scheduled_task_evidence(
        &self,
        scheduled: &DsregcmdScheduledTaskEvidence,
    ) -> DsregcmdScheduledTaskEvidence {
        DsregcmdScheduledTaskEvidence {
            // EnterpriseMgmt task GUIDs are schedule identifiers; the shared
            // grammar documents GUIDs as correlation keys rather than
            // organization identifiers, and the event-log diagnostics match
            // enrollment records to them by value.
            enterprise_mgmt_guids: scheduled.enterprise_mgmt_guids.clone(),
        }
    }

    fn event_log_analysis(&self, analysis: &EventLogAnalysis) -> EventLogAnalysis {
        EventLogAnalysis {
            source_kind: analysis.source_kind,
            entries: analysis
                .entries
                .iter()
                .map(|entry| self.event_log_entry(entry))
                .collect(),
            channel_summaries: analysis
                .channel_summaries
                .iter()
                .map(|summary| self.event_log_channel_summary(summary))
                .collect(),
            correlation_links: analysis
                .correlation_links
                .iter()
                .map(|link| self.event_log_correlation_link(link))
                .collect(),
            parsed_file_count: analysis.parsed_file_count,
            total_entry_count: analysis.total_entry_count,
            error_entry_count: analysis.error_entry_count,
            warning_entry_count: analysis.warning_entry_count,
            timestamp_bounds: analysis
                .timestamp_bounds
                .as_ref()
                .map(|bounds| self.timestamp_bounds(bounds)),
            live_query: analysis
                .live_query
                .as_ref()
                .map(|live| self.event_log_live_query(live)),
        }
    }

    fn event_log_entry(&self, entry: &EventLogEntry) -> EventLogEntry {
        EventLogEntry {
            id: entry.id,
            channel: entry.channel.clone(),
            channel_display: self.text(&entry.channel_display),
            provider: self.text(&entry.provider),
            event_id: entry.event_id,
            severity: entry.severity,
            timestamp: self.text(&entry.timestamp),
            computer: self.identity(&entry.computer, KIND_HOST),
            message: self.text(&entry.message),
            // A correlation activity id is an event-log correlation key.
            correlation_activity_id: self.text_opt(&entry.correlation_activity_id),
            source_file: self.text(&entry.source_file),
        }
    }

    fn event_log_channel_summary(
        &self,
        summary: &EventLogChannelSummary,
    ) -> EventLogChannelSummary {
        EventLogChannelSummary {
            channel: summary.channel.clone(),
            channel_display: self.text(&summary.channel_display),
            entry_count: summary.entry_count,
            error_count: summary.error_count,
            warning_count: summary.warning_count,
            timestamp_bounds: summary
                .timestamp_bounds
                .as_ref()
                .map(|bounds| self.timestamp_bounds(bounds)),
            source_file: self.text(&summary.source_file),
        }
    }

    fn event_log_correlation_link(
        &self,
        link: &EventLogCorrelationLink,
    ) -> EventLogCorrelationLink {
        EventLogCorrelationLink {
            event_log_entry_id: link.event_log_entry_id,
            linked_intune_event_id: link.linked_intune_event_id,
            linked_diagnostic_id: link.linked_diagnostic_id.clone(),
            correlation_kind: link.correlation_kind,
            time_delta_secs: link.time_delta_secs,
        }
    }

    fn event_log_live_query(&self, live: &EventLogLiveQueryMetadata) -> EventLogLiveQueryMetadata {
        EventLogLiveQueryMetadata {
            attempted_channel_count: live.attempted_channel_count,
            successful_channel_count: live.successful_channel_count,
            channels_with_results_count: live.channels_with_results_count,
            failed_channel_count: live.failed_channel_count,
            per_channel_entry_limit: live.per_channel_entry_limit,
            channels: live
                .channels
                .iter()
                .map(|channel| self.event_log_live_query_channel(channel))
                .collect(),
        }
    }

    fn event_log_live_query_channel(
        &self,
        channel: &EventLogLiveQueryChannelResult,
    ) -> EventLogLiveQueryChannelResult {
        EventLogLiveQueryChannelResult {
            channel: channel.channel.clone(),
            channel_display: self.text(&channel.channel_display),
            channel_path: self.text(&channel.channel_path),
            source_file: self.text(&channel.source_file),
            status: channel.status,
            entry_count: channel.entry_count,
            error_message: self.text_opt(&channel.error_message),
        }
    }

    fn timestamp_bounds(&self, bounds: &IntuneTimestampBounds) -> IntuneTimestampBounds {
        IntuneTimestampBounds {
            first_timestamp: self.text_opt(&bounds.first_timestamp),
            last_timestamp: self.text_opt(&bounds.last_timestamp),
        }
    }
}

/// Read the identity values out of the fields this projection masks as typed
/// fields, so each literal is available for the free-text scrub.
///
/// One list, read twice: a value cannot be masked as a typed field without its
/// literal also being scrubbed out of narrative text.
fn collect_identity_literals(result: &DsregcmdAnalysisResult) -> IdentityLiterals {
    let mut literals = IdentityLiterals::default();
    collect_fact_literals(&result.facts, &mut literals);

    if let Some(enrollment) = &result.enrollment_evidence {
        for entry in &enrollment.enrollments {
            if let Some(upn) = entry.upn.as_deref() {
                literals.push(upn, KIND_UPN);
            }
        }
    }

    if let Some(active) = &result.active_evidence {
        collect_active_evidence_into(active, &mut literals);
    }

    if let Some(events) = &result.event_log_analysis {
        collect_event_log_into(events, &mut literals);
    }

    literals
}

/// The identity literals of one capture: what the parser reads out of the
/// command output, plus whatever the evidence captured alongside it carries.
///
/// Output that does not parse is not an error here — the classification simply
/// falls back to the evidence alone.
fn collect_literals(
    capture_output: &str,
    evidence: impl FnOnce(&mut IdentityLiterals),
) -> IdentityLiterals {
    let mut literals = IdentityLiterals::default();
    if let Ok(facts) = super::parser::parse_dsregcmd(capture_output) {
        collect_fact_literals(&facts, &mut literals);
    }
    evidence(&mut literals);
    literals
}

fn collect_fact_literals(facts: &DsregcmdFacts, literals: &mut IdentityLiterals) {
    for (value, kind) in [
        (facts.tenant_details.tenant_id.as_deref(), KIND_TENANT),
        (facts.tenant_details.tenant_name.as_deref(), KIND_TENANT),
        (facts.tenant_details.domain_name.as_deref(), KIND_TENANT),
        (facts.device_details.device_id.as_deref(), KIND_DEVICE),
        (facts.device_details.thumbprint.as_deref(), KIND_THUMBPRINT),
        (facts.diagnostics.user_identity.as_deref(), KIND_UPN),
    ] {
        if let Some(value) = value {
            literals.push(value, kind);
        }
    }
}

fn collect_active_evidence_into(
    evidence: &DsregcmdActiveEvidence,
    literals: &mut IdentityLiterals,
) {
    if let Some(scp) = &evidence.scp_query {
        if let Some(domain) = scp.tenant_domain.as_deref() {
            literals.push(domain, KIND_TENANT);
        }
        if let Some(azuread_id) = scp.azuread_id.as_deref() {
            literals.push(azuread_id, KIND_TENANT);
        }
    }
}

fn collect_event_log_into(analysis: &EventLogAnalysis, literals: &mut IdentityLiterals) {
    for entry in &analysis.entries {
        if let Some(computer) = entry.computer.as_deref() {
            literals.push(computer, KIND_HOST);
        }
    }
}
