//! Deterministic privacy projection for the Autopilot snapshot.
//!
//! Autopilot evidence is unusually identity-dense: serial numbers, hardware
//! hashes, tenant domains, device names, and UPNs are the *subject* of the
//! analysis rather than incidental. A projection that simply dropped them would
//! destroy the diagnosis; one that dropped nothing would make the export
//! unshareable.
//!
//! So every masked value becomes a stable token derived only from the value
//! itself. Two records that named the same device still visibly name the same
//! device, and an explicit Autopilot-to-ESP correlation key still matches its
//! ESP counterpart after masking. Masking is idempotent: a token cannot itself
//! match a rule.
//!
//! # What survives, and why
//!
//! Tenant *object* identifiers survive in the clear: the Autopilot profile id,
//! the enrollment id, the correlation id, the activity id, and the ESP session
//! id. Those are the entire reason an export is shareable -- without them the
//! reader cannot line the export up against Intune or against the sibling ESP
//! analysis, and none of them describes a person or a machine.
//!
//! *Device and user* identity does not survive: serial number, hardware hash,
//! product key, ZTD id, Entra and managed device ids, tenant id and domain,
//! device name, user principal name, and the admin-authored profile name.
//! `entraDeviceId` is both device identity and a correlation key, which is
//! exactly why masking is deterministic rather than destructive.
//!
//! Every whole-value mask is computed over the trimmed, lowercased value under
//! a single token kind, so the same identifier masks identically no matter
//! which field or which casing it arrived in.
//!
//! The hash is deliberately non-cryptographic and unsalted. It exists to make
//! equal values look equal across an export, not to resist an attacker who
//! already knows the serial number they are looking for.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::evidence::{IntuneFinding, IntuneNamedValue};

use super::models::*;

/// Named-data and report-value keys whose values are masked in an export.
///
/// Deliberately excludes `profileId`, `enrollmentId`, `correlationId`,
/// `activityId`, and `espSessionId`; see the module docs.
const SENSITIVE_VALUE_KEYS: [&str; 12] = [
    "serialNumber",
    "hardwareHash",
    "productKeyId",
    "ztdRegistrationId",
    "entraDeviceId",
    "managedDeviceId",
    "tenantId",
    "tenantDomain",
    "deviceName",
    "userPrincipalName",
    "upn",
    "profileName",
];

/// The single token kind used for every whole-value mask.
///
/// One kind rather than one per field is what makes a masked `serialNumber`
/// visibly equal to the same serial masked inside a record's named data. The
/// field name already says what the value was, so a per-field kind bought
/// nothing and cost cross-field equality.
const VALUE_KIND: &str = "redacted";

/// FNV-1a, stable across runs, platforms, and process restarts, which
/// `DefaultHasher` explicitly is not.
fn stable_token(kind: &str, value: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("[{kind}:{hash:016x}]")
}

/// Mask one whole value, normalizing case and surrounding space first so the
/// same identifier always produces the same token.
fn mask_value(value: &str) -> String {
    if is_token(value) {
        return value.to_owned();
    }
    stable_token(VALUE_KIND, &value.trim().to_ascii_lowercase())
}

fn upn_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("upn regex must compile")
    })
}

/// The profile segment of a user path, in either slash direction.
///
/// The leading `[` exclusion is what keeps the projection idempotent: an
/// already-masked `[user:…]` segment must not be masked a second time.
fn user_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)(?P<prefix>[\\/]Users[\\/])(?P<user>[^\\/\r\n\x22\[][^\\/\r\n\x22]*)")
            .expect("user path regex must compile")
    })
}

/// A hardware hash or similar long opaque blob embedded in free text.
///
/// Bounded at 40 characters so a GUID (32 hex digits plus dashes, matched in
/// runs of at most 12) and an eight-digit HRESULT are both left readable; those
/// are diagnostic grammar, not identity.
fn opaque_blob_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9+/=]{40,}\b").expect("opaque blob regex must compile")
    })
}

/// Mask the sensitive spans inside a free-text value.
pub fn redact_text(value: &str) -> String {
    let masked = upn_re().replace_all(value, |captures: &regex::Captures<'_>| {
        stable_token("upn", &captures[0])
    });
    let masked = user_path_re().replace_all(&masked, |captures: &regex::Captures<'_>| {
        format!(
            "{}{}",
            &captures["prefix"],
            stable_token("user", &captures["user"])
        )
    });
    opaque_blob_re()
        .replace_all(&masked, |captures: &regex::Captures<'_>| {
            stable_token("blob", &captures[0])
        })
        .into_owned()
}

fn redact_opt(value: &Option<String>) -> Option<String> {
    value.as_ref().map(|value| mask_value(value))
}

/// Whether a value is already a mask, which is what makes the projection
/// idempotent for whole-value fields.
fn is_token(value: &str) -> bool {
    // Only the exact format `[redacted:<16 lowercase hex chars>]` produced by
    // stable_token() is considered already-masked.  Arbitrary `[foo:bar]`
    // values (e.g. event-log setting tokens) must still go through redaction.
    let Some(inner) = value.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return false;
    };
    let Some(hex) = inner.strip_prefix("redacted:") else {
        return false;
    };
    hex.len() == 16 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Return a copy of `snapshot` safe to export by default.
///
/// Idempotent: `redacted_export_projection(&redacted_export_projection(&s))`
/// serializes identically to `redacted_export_projection(&s)`.
pub fn redacted_export_projection(snapshot: &AutopilotSnapshot) -> AutopilotSnapshot {
    let mut projected = snapshot.clone();

    projected.identity = AutopilotDeviceIdentity {
        serial_number: redact_opt(&snapshot.identity.serial_number),
        hardware_hash: redact_opt(&snapshot.identity.hardware_hash),
        product_key_id: redact_opt(&snapshot.identity.product_key_id),
        ztd_registration_id: redact_opt(&snapshot.identity.ztd_registration_id),
        entra_device_id: redact_opt(&snapshot.identity.entra_device_id),
        managed_device_id: redact_opt(&snapshot.identity.managed_device_id),
        tenant_id: redact_opt(&snapshot.identity.tenant_id),
        tenant_domain: redact_opt(&snapshot.identity.tenant_domain),
        device_name: redact_opt(&snapshot.identity.device_name),
        registration_state: snapshot.identity.registration_state,
        evidence: snapshot.identity.evidence.clone(),
    };

    // `profile_id` survives: it is a tenant object identifier and the only way
    // to line an export up against the Intune profile it describes. The
    // admin-authored display name does not survive.
    projected.profile.profile_name = redact_opt(&snapshot.profile.profile_name);

    for observation in &mut projected.observations {
        observation.message = observation.message.as_deref().map(redact_text);
        observation.context.provenance.file_path =
            redact_opt(&observation.context.provenance.file_path);
        redact_named_values(&mut observation.named_data);
    }

    for conflict in &mut projected.conflicts {
        conflict.detail = redact_text(&conflict.detail);
        conflict.values = conflict
            .values
            .iter()
            .map(|value| redact_conflict_value(value))
            .collect();
    }

    // `mask_value` everywhere a whole value is masked: it performs the
    // trim/lowercase normalization the module contract promises, so the same
    // identifier masks identically whatever field or casing it arrived in.
    for key in &mut projected.esp_linkage.matched_keys {
        key.value = mask_value(&key.value);
    }

    for entry in &mut projected.coverage {
        entry.detail = entry.detail.as_deref().map(redact_text);
    }

    projected.next_evidence_requests = projected
        .next_evidence_requests
        .iter()
        .map(|request| redact_text(request))
        .collect();

    for finding in &mut projected.findings {
        redact_finding(finding);
    }

    projected
}

fn redact_named_values(values: &mut [IntuneNamedValue]) {
    for value in values {
        if SENSITIVE_VALUE_KEYS
            .iter()
            .any(|key| key.eq_ignore_ascii_case(&value.name))
        {
            value.value = mask_value(&value.value);
        } else {
            value.value = redact_text(&value.value);
        }
    }
}

/// Conflict values are written as `name=value` by the reducer for report
/// sections and as bare values for named-key conflicts, so both shapes are
/// handled rather than assuming one.
fn redact_conflict_value(value: &str) -> String {
    match value.split_once('=') {
        Some((name, raw))
            if SENSITIVE_VALUE_KEYS
                .iter()
                .any(|key| key.eq_ignore_ascii_case(name)) =>
        {
            format!("{name}={}", mask_value(raw))
        }
        _ => mask_value(value),
    }
}

fn redact_finding(finding: &mut IntuneFinding) {
    finding.summary = redact_text(&finding.summary);
    finding.recommended_checks = finding
        .recommended_checks
        .iter()
        .map(|check| redact_text(check))
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_values_mask_to_equal_tokens_so_correlation_survives() {
        let left = stable_token(VALUE_KIND, "5CD1234ABC");
        let right = stable_token(VALUE_KIND, "5CD1234ABC");
        assert_eq!(left, right);
        assert_ne!(left, stable_token(VALUE_KIND, "5CD1234ABD"));
    }

    #[test]
    fn masking_free_text_is_idempotent() {
        let once = redact_text("signed in as synthetic.user@example.invalid");
        let twice = redact_text(&once);
        assert_eq!(once, twice);
        assert!(!once.contains('@'));
    }

    #[test]
    fn a_user_profile_segment_with_a_space_is_masked_in_full() {
        let masked = redact_text(r"D:\Users\Synthetic Person\provisioning.log");
        assert!(!masked.contains("Synthetic"), "got {masked}");
        assert!(!masked.contains("Person"), "got {masked}");
        assert!(masked.contains(r"\Users\"), "the shape must survive");
    }

    #[test]
    fn a_guid_and_an_hresult_survive_because_they_are_diagnostic_grammar() {
        let text = "profile 11111111-2222-3333-4444-555555555555 failed HRESULT=0x801C03EA";
        assert_eq!(redact_text(text), text);
    }

    #[test]
    fn a_long_opaque_blob_is_masked() {
        let hash = "A".repeat(64);
        let masked = redact_text(&format!("hardware hash {hash}"));
        assert!(!masked.contains(&hash), "got {masked}");
    }

    #[test]
    fn an_already_masked_whole_value_is_left_alone() {
        let token = stable_token(VALUE_KIND, "abc");
        assert!(is_token(&token));
        assert_eq!(redact_conflict_value(&token), token);
        assert_eq!(
            redact_conflict_value(&format!("serialNumber={token}")),
            format!("serialNumber={token}")
        );
    }

    /// Every whole-value masking site must normalize case and surrounding
    /// space before hashing, or the same identifier arriving in two casings
    /// would mask to two different tokens and destroy the very correlation the
    /// projection exists to preserve.
    #[test]
    fn whole_value_masking_normalizes_case_and_space_at_every_site() {
        let canonical = mask_value("abcdabcd-1234-5678-9012-abcdabcdabcd");

        // Named-data values with a sensitive key.
        let mut values = vec![IntuneNamedValue {
            name: "entraDeviceId".to_owned(),
            value: "  ABCDABCD-1234-5678-9012-ABCDABCDABCD  ".to_owned(),
        }];
        redact_named_values(&mut values);
        assert_eq!(values[0].value, canonical);

        // Conflict values, both shapes.
        assert_eq!(
            redact_conflict_value("entraDeviceId= ABCDABCD-1234-5678-9012-ABCDABCDABCD "),
            format!("entraDeviceId={canonical}")
        );
        assert_eq!(
            redact_conflict_value(" ABCDABCD-1234-5678-9012-ABCDABCDABCD "),
            canonical
        );

        // The identity-field path already goes through mask_value; the token
        // must line up with all of the above.
        assert_eq!(
            redact_opt(&Some("Abcdabcd-1234-5678-9012-abcdabcdABCD".to_owned())),
            Some(canonical)
        );
    }

    #[test]
    fn a_non_sensitive_conflict_key_still_masks_its_value() {
        // Falling through to the bare-value branch is deliberate: a conflict
        // value the reducer could not attribute to a known key is more likely
        // to be identity than not.
        let masked = redact_conflict_value("someOtherKey=5CD1234ABC");
        assert!(!masked.contains("5CD1234ABC"), "got {masked}");
    }
}
