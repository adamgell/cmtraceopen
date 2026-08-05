//! Deterministic privacy projection for compliance evidence.
//!
//! Compliance evidence names people. A setting display name can quote a UPN, a
//! custom-compliance script prints whatever the author decided to print, and the
//! device/tenant/user keys are identifiers for a real machine and a real person.
//!
//! The projection masks all of that while keeping the *shape* of the reduction
//! intact: setting grouping tokens, states, timestamps, error codes, and
//! evidence references survive, because those are what show whether two records
//! belong to the same local evaluation. Masking is a pure function of the masked
//! text, so the same identity produces the same token everywhere it appears and
//! a reader can still see that two records mention the same device.
//!
//! The projection is idempotent: a replacement token cannot itself match a rule.

use std::sync::OnceLock;

use regex::Regex;

use super::models::*;
use crate::intune::evidence::{IntuneFinding, IntuneNamedValue};

/// FNV-1a. Stable across runs, platforms, and processes, which the standard
/// library's `DefaultHasher` explicitly is not.
fn stable_token(kind: &str, value: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("[{kind}:{hash:016x}]")
}

/// A user principal name or email address.
fn upn_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("UPN regex must compile")
    })
}

/// A Windows security identifier.
fn sid_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"S-1-(?:\d+-){3,}\d+").expect("SID regex must compile"))
}

/// The profile segment of a user path, in either slash direction.
///
/// The segment is bounded by a separator, a quote, or a line break rather than
/// by whitespace, because Windows allows spaces in profile directory names. The
/// leading `[` exclusion is what makes the projection idempotent: an
/// already-masked `[user:…]` segment must not be masked a second time.
fn user_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)(?P<prefix>[\\/]Users[\\/])(?P<user>[^\\/\r\n\x22\[][^\\/\r\n\x22]*)")
            .expect("user path regex must compile")
    })
}

/// Mask the sensitive spans inside a free-text value.
pub fn redact_text(value: &str) -> String {
    let masked = upn_re().replace_all(value, |caps: &regex::Captures<'_>| {
        stable_token("upn", &caps[0])
    });
    let masked = sid_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        stable_token("sid", &caps[0])
    });
    user_path_re()
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            format!("{}{}", &caps["prefix"], stable_token("user", &caps["user"]))
        })
        .into_owned()
}

/// Replace an identifier with a stable token, leaving an already-masked value alone.
fn mask_key(kind: &str, value: &Option<String>) -> Option<String> {
    value.as_ref().map(|value| {
        if is_masked_token(kind, value) {
            value.clone()
        } else {
            stable_token(kind, value)
        }
    })
}

/// Whether a value is exactly a token this module produced for `kind`.
///
/// The shape must match `[kind:<16 hex digits>]` in full. Treating any bracketed
/// value as already masked would let a source-supplied identifier such as
/// `[contoso\alice]` skip redaction simply by wearing brackets.
fn is_masked_token(kind: &str, value: &str) -> bool {
    let prefix = format!("[{kind}:");
    let Some(rest) = value.strip_prefix(&prefix) else {
        return false;
    };
    let Some(digits) = rest.strip_suffix(']') else {
        return false;
    };
    digits.len() == 16 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn redact_opt_text(value: &Option<String>) -> Option<String> {
    value.as_deref().map(redact_text)
}

fn redact_named(values: &[IntuneNamedValue]) -> Vec<IntuneNamedValue> {
    values
        .iter()
        .map(|entry| IntuneNamedValue {
            name: entry.name.clone(),
            value: redact_text(&entry.value),
        })
        .collect()
}

/// Return a copy of the snapshot safe to export by default.
///
/// What survives: every state, count, timestamp, error code, coverage entry,
/// evidence reference, grouping token, and finding structure. What is masked:
/// device/tenant/user keys, enrollment id, display names, custom-compliance
/// output, access-resource details, and any UPN, SID, or user profile path
/// appearing in free text.
pub fn redacted_export_projection(snapshot: &ComplianceSnapshot) -> ComplianceSnapshot {
    let mut projected = snapshot.clone();

    projected.device_context = ComplianceDeviceContextView {
        device_key: mask_key("deviceKey", &snapshot.device_context.device_key),
        tenant_key: mask_key("tenantKey", &snapshot.device_context.tenant_key),
        enrollment_id: mask_key("enrollmentId", &snapshot.device_context.enrollment_id),
        // The build number is a fleet-level fact, not an identity, and it is
        // often the whole reason a setting is not applicable.
        windows_build: snapshot.device_context.windows_build.clone(),
        active_user_key: mask_key("userKey", &snapshot.device_context.active_user_key),
        user_evaluation_context: snapshot.device_context.user_evaluation_context,
        evidence: snapshot.device_context.evidence.clone(),
    };

    // Prerequisite detail is collector-supplied free text and routinely quotes
    // the user or path that blocked evaluation, so it goes through the same
    // masking as any other free-text field.
    for prerequisite in &mut projected.local_evaluation.prerequisites {
        prerequisite.name = redact_text(&prerequisite.name);
        prerequisite.detail = redact_opt_text(&prerequisite.detail);
    }

    for setting in &mut projected.local_evaluation.settings {
        setting.display_name = redact_opt_text(&setting.display_name);
        setting.named_data = redact_named(&setting.named_data);
    }

    for custom in &mut projected.local_evaluation.custom_compliance {
        custom.setting_name = redact_opt_text(&custom.setting_name);
        // Script output is arbitrary author-controlled text. It is replaced
        // wholesale rather than pattern-masked, because there is no vocabulary
        // to reason about and a partial mask would be a false assurance.
        // `mask_key` is what keeps this idempotent: re-projecting an already
        // masked snapshot must not hash the token again.
        custom.raw_output = mask_key("output", &custom.raw_output);
        custom.named_data = redact_named(&custom.named_data);
    }

    for result in &mut projected.reporting.service_results {
        result.device_key = mask_key("deviceKey", &result.device_key);
        result.user_key = mask_key("userKey", &result.user_key);
    }

    for decision in &mut projected.access_impact.decisions {
        decision.device_key = mask_key("deviceKey", &decision.device_key);
        decision.user_key = mask_key("userKey", &decision.user_key);
        decision.resource = mask_key("resource", &decision.resource);
    }

    projected.findings = projected
        .findings
        .iter()
        .map(|finding| IntuneFinding {
            title: redact_text(&finding.title),
            summary: redact_text(&finding.summary),
            recommended_checks: finding
                .recommended_checks
                .iter()
                .map(|check| redact_text(check))
                .collect(),
            ..finding.clone()
        })
        .collect();

    for entry in &mut projected.coverage {
        entry.detail = redact_opt_text(&entry.detail);
    }

    projected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::IntuneEvidenceRef;

    #[test]
    fn a_upn_is_masked_and_the_same_upn_yields_the_same_token() {
        let first = redact_text("evaluated for analyst@contoso.invalid");
        let second = redact_text("reported by analyst@contoso.invalid");
        assert!(!first.contains("analyst@contoso.invalid"));
        let token = |text: &str| {
            text.split('[')
                .nth(1)
                .and_then(|rest| rest.split(']').next())
                .map(str::to_owned)
        };
        assert_eq!(token(&first), token(&second));
    }

    #[test]
    fn a_sid_is_masked() {
        let masked = redact_text("owner S-1-5-21-1004336348-1177238915-682003330-512 evaluated");
        assert!(!masked.contains("S-1-5-21-"), "got {masked}");
        assert!(masked.contains("[sid:"));
    }

    #[test]
    fn a_user_profile_path_with_a_space_is_fully_masked() {
        let masked = redact_text(r"D:\Users\Jane Roe\policy.json");
        assert!(!masked.contains("Jane"), "got {masked}");
        assert!(!masked.contains("Roe"), "got {masked}");
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = redact_text(r"D:\Users\Jane Roe\p.json for analyst@contoso.invalid");
        assert_eq!(redact_text(&once), once);
    }

    #[test]
    fn script_output_is_replaced_wholesale() {
        let snapshot = ComplianceSnapshot {
            local_evaluation: ComplianceLocalPhase {
                custom_compliance: vec![ComplianceCustomEvaluation {
                    policy_id: Some("policy-1".to_owned()),
                    run_id: Some("run-1".to_owned()),
                    setting_name: Some("DiskEncryption".to_owned()),
                    state: ComplianceCustomState::DiscoveryNoncompliant,
                    error: None,
                    raw_output: Some("{\"BitLocker\":\"Off\",\"Owner\":\"jane\"}".to_owned()),
                    evidence: vec![IntuneEvidenceRef {
                        evidence_id: "c1".to_owned(),
                        source_artifact_id: "custom".to_owned(),
                    }],
                    named_data: Vec::new(),
                }],
                ..ComplianceLocalPhase::default()
            },
            ..ComplianceSnapshot::default()
        };
        let projected = redacted_export_projection(&snapshot);
        let output = projected.local_evaluation.custom_compliance[0]
            .raw_output
            .as_deref()
            .expect("output token");
        assert!(output.starts_with("[output:"), "got {output}");
        assert!(!output.contains("jane"));
    }

    #[test]
    fn the_projection_preserves_states_and_evidence() {
        let snapshot = ComplianceSnapshot {
            aggregate: ComplianceAggregatePhase {
                state: ComplianceAggregateState::Noncompliant,
                rationale: ComplianceAggregateRationale::LocalSettingNoncompliant,
                noncompliant_count: 1,
                ..ComplianceAggregatePhase::default()
            },
            ..ComplianceSnapshot::default()
        };
        let projected = redacted_export_projection(&snapshot);
        assert_eq!(projected.aggregate, snapshot.aggregate);
    }

    #[test]
    fn a_bracketed_identifier_is_still_masked() {
        let snapshot = ComplianceSnapshot {
            device_context: ComplianceDeviceContextView {
                device_key: Some("[deviceKey:not-a-real-token]".to_owned()),
                ..ComplianceDeviceContextView::default()
            },
            ..ComplianceSnapshot::default()
        };
        let projected = redacted_export_projection(&snapshot);
        let key = projected
            .device_context
            .device_key
            .as_deref()
            .expect("device key");
        assert_ne!(
            key, "[deviceKey:not-a-real-token]",
            "a value that merely wears brackets must not bypass masking"
        );
        assert!(is_masked_token("deviceKey", key), "got {key}");
    }

    #[test]
    fn masking_a_key_twice_is_stable() {
        let snapshot = ComplianceSnapshot {
            device_context: ComplianceDeviceContextView {
                device_key: Some("11111111-2222-3333-4444-555555555555".to_owned()),
                ..ComplianceDeviceContextView::default()
            },
            ..ComplianceSnapshot::default()
        };
        let once = redacted_export_projection(&snapshot);
        let twice = redacted_export_projection(&once);
        assert_eq!(
            once.device_context.device_key,
            twice.device_context.device_key
        );
        assert!(once
            .device_context
            .device_key
            .as_deref()
            .is_some_and(|key| key.starts_with("[deviceKey:")));
    }
}
