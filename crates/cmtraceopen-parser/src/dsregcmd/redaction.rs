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
//! apply [`redacted_analysis`] before returning, and the unprojected analysis
//! stays crate-internal (`dsregcmd::analyze_text_preserving_local_values`), so
//! a consumer of this crate has no unprojected value in hand to copy to a
//! clipboard or a file, and a workspace that finds itself holding one has found
//! a defect here rather than something to fix at the clipboard call site.
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
//! one tenant, one device, one user. Identity values are canonicalized (trimmed
//! and folded, Unicode-aware) before a token is minted, so two spellings of one
//! identity cannot reach two tokens.
//!
//! One case escapes that, and it belongs to the shared grammar rather than to
//! this lane: the grammar's own principal-name rule hashes the spelling it sees
//! (`stable_token("upn", &caps[0])`), so a narrative mention spelled in a
//! different case than the classified field keeps the grammar's token. Masking
//! runs after the grammar deliberately — the shaped rules must see the original
//! text — and changing that derivation would change every lane's tokens, so it
//! is the grammar owner's call rather than something to fork here.
//!
//! Two spellings are one identity when the shared caseless comparison says so:
//! equal after lowercasing, or after uppercasing (which is what bridges `Σ` and
//! Greek's final `ς`), or one side writes out the other's case mapping (`İ`
//! against `i` plus U+0307). What that deliberately does not reach is a pair
//! whose case mapping changes length (`ß` against `SS`, the `ﬀ`-style
//! ligatures), or a difference that is normalization rather than case (`é`
//! against `e` plus U+0301). Those need a folding or normalization table, which
//! this crate does not depend on; the limit is pinned by a test rather than
//! left to be assumed.
//!
//! Ruling 2 requires the derivation to be keyed per analysis and Ruling 4
//! forbids a scope the caller did not supply; neither is implemented for any
//! lane yet, and this lane adopts the one shared derivation rather than minting
//! a fifth (Ruling 5). A lane that forked the derivation would keep the unkeyed
//! one, and the fix would not reach it.

use crate::intune::apps::windows::common::{
    caseless_equal, find_ignore_case, fold_with_offsets, redact_field_value, redact_text,
    FoldedChar,
};
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
/// known before any free-text field is scrubbed. The table is the single source
/// of tokens: a typed field asks it for the token of the identity it holds rather
/// than minting a second one, and membership is decided by the shared
/// caseless comparison, so the table can never hold two entries that the
/// scrubber would treat as one identity — including spellings that differ by
/// case in a way only one of the two folds bridges (`Σ` against final `ς`) or
/// that write a case mapping out (`İ` against `i` plus U+0307).
#[derive(Default)]
struct IdentityLiterals {
    /// Literal as classified, paired with its token, longest literal first.
    ///
    /// The scrub no longer depends on that order —
    /// [`IdentityLiterals::leftmost_longest_match`] takes the longest match at
    /// the leftmost position itself, so a literal that sits inside a longer one
    /// still cannot cut the longer one in half — but the table is left in the
    /// order it has always held rather than reshuffled for no observable
    /// difference.
    values: Vec<(String, String)>,
}

impl IdentityLiterals {
    /// Classify one identity value. Values too short to be told apart from
    /// prose are skipped rather than scrubbed out of narrative over-eagerly.
    fn push(&mut self, value: &str, kind: &str) {
        let literal = value.trim();
        if literal.len() < MIN_SCRUBBED_LITERAL_BYTES {
            return;
        }

        // The table is keyed by, holds, and mints from the canonical form, so a
        // second spelling of an identity already classified cannot reach a
        // second token.
        let canonical = canonical_identity(literal);
        if self
            .values
            .iter()
            .any(|(classified, _)| caseless_equal(classified, &canonical))
        {
            return;
        }

        self.values.push((canonical, identity_token(literal, kind)));
        self.values.sort_by(|left, right| {
            right
                .0
                .len()
                .cmp(&left.0.len())
                .then_with(|| left.0.cmp(&right.0))
        });
    }

    /// The token this identity already reached, when it is one of the classified
    /// ones. Caseless-equal spellings are one identity, so they all reach the
    /// token the table minted for the first of them.
    fn token_for(&self, value: &str) -> Option<&str> {
        let canonical = canonical_identity(value);
        self.values
            .iter()
            .find(|(classified, _)| caseless_equal(classified, &canonical))
            .map(|(_, token)| token.as_str())
    }

    /// Replace every occurrence of a classified literal, whatever its case.
    ///
    /// Runs after the shared grammar in every free-text pipeline: the shaped
    /// rules must see the original text, or scrubbing a tenant domain on its
    /// own would break the mail-address match on a principal name that contains
    /// it and leak the local part.
    fn scrub(&self, value: &str) -> String {
        if self.values.is_empty() {
            return value.to_string();
        }

        // One folded view of the text, shared by every literal. The fold is the
        // grammar's, not this lane's.
        let folded = fold_with_offsets(value);
        let mut scrubbed = String::with_capacity(value.len());
        let mut cursor = 0;

        while let Some((start, end, token)) = self.leftmost_longest_match(value, &folded, cursor) {
            scrubbed.push_str(&value[cursor..start]);
            scrubbed.push_str(token);
            cursor = end;
        }
        scrubbed.push_str(&value[cursor..]);
        scrubbed
    }

    /// The leftmost match, longest at that position, as `(start, end, token)`
    /// with byte offsets into `haystack` itself.
    ///
    /// Each literal asks the grammar's cursor search for its next occurrence at
    /// or after `cursor`; the leftmost of those answers wins, and a tie there
    /// goes to the longest match, so a literal that sits inside a longer one can
    /// never cut the longer one in half.
    fn leftmost_longest_match<'a>(
        &'a self,
        haystack: &str,
        folded: &[FoldedChar],
        cursor: usize,
    ) -> Option<(usize, usize, &'a str)> {
        let mut best: Option<(usize, usize, &'a str)> = None;
        for (literal, token) in &self.values {
            let Some((start, end)) = find_ignore_case(haystack, literal, folded, cursor) else {
                continue;
            };
            let replaces = best.is_none_or(|(best_start, best_end, _)| {
                start < best_start || (start == best_start && end > best_end)
            });
            if replaces {
                best = Some((start, end, token.as_str()));
            }
        }
        best
    }
}

/// The canonical form every classification keys on and mints from: trimmed and
/// case-folded.
///
/// Every identifier this lane masks is case-insensitive *as an identity*: a
/// tenant id and a device id are GUIDs, a certificate thumbprint is hex, a
/// tenant, on-premises and computer name is a DNS or NetBIOS name, a SID is
/// case-insensitive by definition, and a user principal name is matched
/// case-insensitively by Entra. None of them is case-significant, so folding
/// cannot conflate two distinct identities, and it is what keeps one identity
/// from reaching two tokens when two fields or a line of prose spell it
/// differently.
///
/// The fold is Unicode-aware (`to_lowercase`, not `to_ascii_lowercase`), because
/// a non-ASCII letter has to fold the same way here as it does in the scrub.
fn canonical_identity(value: &str) -> String {
    value.trim().to_lowercase()
}

/// The token an identity value reaches, wherever it is projected.
///
/// The value is canonicalized first, so a typed field and a narrative mention of
/// one identity reach one token. A canonical value the shared grammar recognizes
/// by shape keeps the grammar's token, which is already case-independent where
/// the grammar intends it to be (the SID rule hashes the uppercase form); a
/// value with no distinctive shape is minted through the shared minter.
fn identity_token(value: &str, kind: &str) -> String {
    let canonical = canonical_identity(value);
    let shaped = redact_text(&canonical);
    if shaped == canonical {
        redact_field_value(kind, &canonical)
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
    ///
    /// The table is asked first. It decided this identity's token when the
    /// classification was collected, and the narrative scrub will use that same
    /// token, so minting a second one here would be the one way left for a field
    /// and a prose mention of one identity to disagree. A value the table does
    /// not hold is one below the scrub floor, and it mints its own.
    fn identity(&self, value: &Option<String>, kind: &str) -> Option<String> {
        value.as_deref().map(|value| match self.literals.token_for(value) {
            Some(token) => token.to_string(),
            None => identity_token(value, kind),
        })
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
        literals: capture_literals(input),
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

/// The identity literals one capture's command output contributes.
///
/// Output that does not parse is not an error here; the classification simply
/// has nothing to read.
fn capture_literals(capture_output: &str) -> IdentityLiterals {
    let mut literals = IdentityLiterals::default();
    if let Ok(facts) = super::parser::parse_dsregcmd(capture_output) {
        collect_fact_literals(&facts, &mut literals);
    }
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

#[cfg(test)]
mod tests {
    use super::{
        super::{
            analyze_text, analyze_text_preserving_local_values, analyze_text_with_evidence,
            models::{DsregcmdAnalysisResult, DsregcmdBundleEvidence},
        },
        redacted_status_text,
    };
    use crate::intune::models::{
        EventLogAnalysis, EventLogAnalysisSource, EventLogChannel, EventLogEntry, EventLogSeverity,
    };

    /// A capture carrying one identifier of every class this projection masks.
    const IDENTITY_CAPTURE: &str = r#"
 AzureAdJoined : YES
 DomainJoined : YES
 TenantId : 8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90
 TenantName : contoso.onmicrosoft.com
 DomainName : corp.contoso.com
 DeviceId : 4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b
 Thumbprint : 8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D
 User Identity : adele.vance@contoso.onmicrosoft.com
 User Context : SYSTEM
"#;

    /// The same, with the identity shape the built-in-Administrator rule reads.
    const SID_CAPTURE: &str = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 TenantId : 8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90
 DeviceId : 4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b
 User Identity : S-1-5-21-3623811015-3361044348-30300820-500
"#;

    const USER_SID: &str = "S-1-5-21-3623811015-3361044348-30300820-500";

    const PLANTED_IDENTIFIERS: &[(&str, &str)] = &[
        ("tenant id", "8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90"),
        ("tenant domain", "contoso.onmicrosoft.com"),
        ("on-premises domain", "corp.contoso.com"),
        ("device id", "4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b"),
        ("certificate thumbprint", "8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D"),
        ("user principal name", "adele.vance@contoso.onmicrosoft.com"),
    ];

    /// The canary: the unprojected analysis is crate-internal, so proving that
    /// each planted value really does reach the analysis as that identifier —
    /// rather than the export assertion passing because the fixture stopped
    /// carrying it — can only be asserted from inside.
    #[test]
    fn the_unprojected_analysis_carries_every_identity_the_projection_masks() {
        let local = json(&analyze_text_preserving_local_values(IDENTITY_CAPTURE).expect("parses"));
        let published = json(&analyze_text(IDENTITY_CAPTURE).expect("parses"));

        for (label, marker) in PLANTED_IDENTIFIERS {
            assert!(
                local.contains(marker),
                "the fixture no longer reaches the analysis as the {label}; the export check is vacuous"
            );
            assert!(
                !published.contains(marker),
                "the published analysis leaks the {label} ({marker})"
            );
        }
    }

    /// Rules that read an identifier's shape rather than its presence run on the
    /// unprojected values, so masking a value must not cost the diagnosis it
    /// produced. This is why the assembly lives here instead of in a caller.
    #[test]
    fn a_sid_user_identity_is_masked_without_losing_the_diagnosis_it_produced() {
        let local = analyze_text_preserving_local_values(SID_CAPTURE).expect("parses");
        let published = analyze_text(SID_CAPTURE).expect("parses");

        assert!(
            local
                .diagnostics
                .iter()
                .any(|issue| issue.id == "builtin-admin-cannot-join"),
            "the SID no longer reaches the built-in-Administrator rule"
        );
        assert!(
            !json(&published).contains(USER_SID),
            "the published analysis leaks the user SID ({USER_SID})"
        );
        assert!(
            published
                .diagnostics
                .iter()
                .any(|issue| issue.id == "builtin-admin-cannot-join"),
            "the diagnosis the raw SID produced was lost when the value was masked"
        );
    }

    #[test]
    fn projecting_does_not_drop_or_rename_a_diagnostic() {
        let local = analyze_text_preserving_local_values(IDENTITY_CAPTURE).expect("parses");
        let published = analyze_text(IDENTITY_CAPTURE).expect("parses");

        let local_ids = diagnostic_ids(&local);
        let published_ids = diagnostic_ids(&published);

        assert!(!local_ids.is_empty(), "the fixture produced no diagnostics");
        assert_eq!(local_ids, published_ids);
    }

    /// The capture text is the analyzer's input and keeps its values, so the
    /// projection of it is a separate entry point with the same classification.
    #[test]
    fn the_projected_status_text_keeps_the_capture_and_loses_the_identities() {
        let projected = redacted_status_text(IDENTITY_CAPTURE);

        for (label, marker) in PLANTED_IDENTIFIERS {
            assert!(
                !projected.contains(marker),
                "the projected status text leaks the {label} ({marker})"
            );
        }
        assert!(
            projected.contains("AzureAdJoined : YES")
                && projected.contains("User Context : SYSTEM"),
            "over-masking: the capture's own content was lost: {projected}"
        );
    }

    /// A classified literal whose letters are not all ASCII must still match the
    /// narrative spelling of it that differs only in case, or the export carries
    /// the identifier after all — the shared grammar masks only shapes it
    /// recognizes, and a bare display name is not one.
    #[test]
    fn a_non_ascii_identity_is_scrubbed_whatever_its_case_in_the_narrative() {
        let capture = " TenantName : Ünïcode.Example\n \
                       Server Message : discovery failed for ünïcode.example\n";
        let projected = redacted_status_text(capture);

        assert!(
            !projected.contains("Ünïcode") && !projected.contains("ünïcode"),
            "a differently-cased spelling of a non-ASCII identity survived: {projected:?}"
        );
        assert!(
            projected.matches("[tenant:").count() == 2,
            "expected both spellings at the typed token: {projected:?}"
        );
        assert!(
            projected.contains("discovery failed for"),
            "over-masking: the narrative around the identity was lost: {projected:?}"
        );
    }

    /// One canonical identity reaches exactly one token, whichever spelling the
    /// capture used and wherever it appears. Two typed fields that spell the same
    /// identity differently, plus a narrative mention, must all carry the same
    /// token — otherwise the export shows one tenant as two.
    #[test]
    fn one_identity_reaches_one_token_whatever_its_case() {
        let capture = " TenantName : ÉLODIE.Example\n \
                       DomainName : élodie.example\n \
                       Server Message : retry against ÉLODIE.Example failed\n";
        let published = json(&analyze_text(capture).expect("parses"));

        let tokens = tokens_of_kind(&published, "tenant");
        assert_eq!(
            tokens.len(),
            3,
            "expected both typed fields and the narrative to be masked: {published}"
        );
        assert!(
            tokens.iter().all(|token| *token == tokens[0]),
            "one identity reached more than one token: {tokens:?}"
        );
    }

    /// A missing value is reported as missing, not as a masked identity.
    ///
    /// The evidence for the `missing-tenant` diagnostic is the analyzer's own
    /// render of an absent field. If the projection masks that render, the export
    /// contradicts itself — the rule says the capture held no `TenantId` while
    /// the evidence shows a tenant token — and it invents an identity the device
    /// never presented.
    #[test]
    fn a_missing_value_is_evidence_of_absence_not_a_masked_identity() {
        let published = analyze_text(" AzureAdJoined : NO\n DomainJoined : NO\n")
            .expect("a capture with no tenant or device id analyzes");

        let missing_tenant = published
            .diagnostics
            .iter()
            .find(|issue| issue.id == "missing-tenant")
            .expect("the missing tenant id is diagnosed");

        assert_eq!(missing_tenant.evidence, vec!["TenantId: (missing)"]);
        assert!(
            !json(&published).contains("[tenant:"),
            "the export claims a tenant identity the capture never held: {}",
            json(&published)
        );
    }

    /// `ΣΟΦΟΥΣ.Example` in capitals: `Σ` U+03A3, `Ο` U+039F, `Φ` U+03A6,
    /// `Υ` U+03A5, and a final `Σ` U+03A3 that the narrative renders as `ς`.
    const CAPITAL_SIGMA_IDENTITY: &str =
        "\u{3A3}\u{39F}\u{3A6}\u{39F}\u{3A5}\u{3A3}.Example";

    /// The same name written in lower case with Greek's final sigma: it ends in
    /// `ς` U+03C2, which lowercasing `Σ` never produces.
    const FINAL_SIGMA_NARRATIVE: &str =
        "\u{3C3}\u{3BF}\u{3C6}\u{3BF}\u{3C5}\u{3C2}.example";

    /// `Σ` and final `ς` are caseless-equal, but they are two different
    /// lowercase letters, so a comparison that only folds down keeps them apart
    /// and the narrative spelling of the identity survives.
    #[test]
    fn a_final_sigma_narrative_reaches_the_capital_sigma_token() {
        let capture = format!(
            " TenantName : {CAPITAL_SIGMA_IDENTITY}\n \
               Server Message : discovery failed for {FINAL_SIGMA_NARRATIVE}\n"
        );
        let projected = redacted_status_text(&capture);

        assert!(
            !projected.contains(CAPITAL_SIGMA_IDENTITY)
                && !projected.contains(FINAL_SIGMA_NARRATIVE),
            "a sigma spelling of one identity survived: {projected:?}"
        );
        let tokens = tokens_of_kind(&projected, "tenant");
        assert_eq!(
            tokens.len(),
            2,
            "expected both spellings at the typed token: {projected:?}"
        );
        assert!(
            tokens.iter().all(|token| *token == tokens[0]),
            "one identity reached more than one token: {tokens:?}"
        );
    }

    /// `İSTANBUL-PC` with the precomposed dotted capital I, which is U+0130.
    const DOTTED_CAPITAL_IDENTITY: &str = "\u{130}STANBUL-PC";

    /// The same name written with the capital I intact but lower case: `İ` then
    /// `stanbul-pc`. This is the spelling the identity's own lowercasing does not
    /// produce, so matching it needs the precomposed character understood as the
    /// sequence its case mapping stands for.
    const PRECOMPOSED_NARRATIVE: &str = "\u{130}stanbul-pc";

    /// The same name with that character's decomposition written out: `i`
    /// followed by U+0307, which is what lowercasing U+0130 produces.
    const DECOMPOSED_NARRATIVE: &str = "i\u{307}stanbul-pc";

    /// A character whose case mapping is a sequence must match the other side
    /// spelling that sequence out, in either direction, or the precomposed and
    /// decomposed spellings of one identity are two identities to this
    /// projection. A device name is where this lane meets a value like
    /// `İSTANBUL-PC`: the computer an event log record was written on, and the
    /// same name spelled inside the record's message.
    #[test]
    fn a_dotted_capital_i_reaches_one_token_whichever_way_it_is_spelled() {
        let events = EventLogAnalysis {
            source_kind: EventLogAnalysisSource::Live,
            entries: vec![EventLogEntry {
                id: 1,
                channel: EventLogChannel::AadOperational,
                channel_display: "AAD Operational".to_string(),
                provider: "Microsoft-Windows-AAD".to_string(),
                event_id: 1103,
                severity: EventLogSeverity::Error,
                timestamp: "2026-08-26T09:15:00Z".to_string(),
                computer: Some(DOTTED_CAPITAL_IDENTITY.to_string()),
                message: format!(
                    "registration failed on {PRECOMPOSED_NARRATIVE} and again on {DECOMPOSED_NARRATIVE}"
                ),
                correlation_activity_id: None,
                source_file: "AAD.evtx".to_string(),
            }],
            ..EventLogAnalysis::default()
        };
        let evidence = DsregcmdBundleEvidence {
            event_log_analysis: Some(events),
            ..DsregcmdBundleEvidence::default()
        };
        let published = {
            let analysis = analyze_text_with_evidence(IDENTITY_CAPTURE, evidence)
                .expect("the dsregcmd capture analyzes");
            serde_json::to_string(&analysis).expect("a dsregcmd analysis serializes")
        };

        assert!(
            !published.contains(DOTTED_CAPITAL_IDENTITY)
                && !published.contains(PRECOMPOSED_NARRATIVE)
                && !published.contains(DECOMPOSED_NARRATIVE),
            "a dotted-I spelling of one identity survived: {published}"
        );
        let tokens = tokens_of_kind(&published, "host");
        assert_eq!(
            tokens.len(),
            3,
            "expected the typed host and both message spellings masked: {published}"
        );
        assert!(
            tokens.iter().all(|token| *token == tokens[0]),
            "one identity reached more than one token: {tokens:?}"
        );
    }

    /// The boundary of the rule above, asserted rather than assumed.
    ///
    /// A pair only bridges when the case mapping of one side spells the other
    /// out. `ß` (U+00DF) and `SS` do not: one character cannot be matched
    /// against two, and `ß`'s uppercase is `SS` while `S`'s is `S`, so neither
    /// the character comparison nor the mapping consumption reaches it. The
    /// same holds for the `ﬀ`-style ligatures and for text that differs by
    /// normalization rather than by case (`é` written as `e` plus U+0301).
    /// Closing those needs a case folding or normalization table — a dependency
    /// this crate does not have and should not acquire for this — so the
    /// limitation is pinned here instead of being implied.
    #[test]
    fn a_length_changing_case_pair_stays_out_of_reach() {
        let capture = " TenantName : Straße.Example\n \
                       Server Message : retry against strasse.example failed\n";
        let projected = redacted_status_text(capture);

        assert!(
            !projected.contains("Straße.Example"),
            "the typed field itself must still be masked: {projected:?}"
        );
        assert!(
            projected.contains("strasse.example"),
            "this pair is covered after all; the limitation note and this test need updating: {projected:?}"
        );
    }

    /// Every `[kind:…]` token in a serialized analysis, in order.
    fn tokens_of_kind(published: &str, kind: &str) -> Vec<String> {
        let marker = format!("[{kind}:");
        published
            .split(marker.as_str())
            .skip(1)
            .filter_map(|rest| rest.split(']').next())
            .map(str::to_string)
            .collect()
    }

    fn diagnostic_ids(result: &DsregcmdAnalysisResult) -> Vec<&str> {
        result
            .diagnostics
            .iter()
            .map(|issue| issue.id.as_str())
            .collect()
    }

    fn json(result: &DsregcmdAnalysisResult) -> String {
        serde_json::to_string(result).expect("a dsregcmd analysis serializes")
    }
}
