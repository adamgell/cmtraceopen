//! Deterministic redaction for the default export.
//!
//! Configuration values are arbitrary tenant data: a proxy URL, a certificate
//! subject, a wallpaper path, a user principal name. The default export must not
//! carry them, but simply deleting them destroys the one comparison that matters
//! most — whether two configuration sources are fighting over the *same* value or
//! two different ones.
//!
//! So a redacted value becomes `[redacted:<hash>]`, where the hash is FNV-1a over
//! the original bytes. Equal inputs produce equal tokens, so a conflict stays
//! legible after redaction, and the token is stable across runs and machines,
//! which is what makes it golden-testable.
//!
//! FNV is used rather than a cryptographic digest because this crate takes no new
//! dependencies and the token is a correlation aid, not an authentication tag.
//! It is not a defense against an attacker who can guess a value and confirm it;
//! nothing in this file claims to be.

use crate::intune::evidence::{IntuneNamedValue, IntuneSensitivity};

use super::models::{
    ConfigurationObservation, ConfigurationSetting, ConfigurationSnapshot,
    ConfigurationSourceStatement,
};

/// Named-value keys whose contents are redacted regardless of classification.
///
/// The value-bearing keys are here for the same reason the typed fields are
/// tokenized: a configuration value is arbitrary tenant data, and leaving the
/// `namedData` copy of it intact would have made the field-level redaction
/// pointless. The same applies to `EnrollmentId`, which is also tokenized in
/// [`ConfigurationObservation::enrollment_id`].
const SENSITIVE_NAMES: [&str; 24] = [
    "Value",
    "SettingValue",
    "PreviousValue",
    "Data",
    "EnrollmentId",
    "EnrollmentName",
    "User",
    "UserName",
    "CurrentUser",
    "Upn",
    "UserPrincipalName",
    "Sid",
    "Account",
    "Email",
    "Owner",
    "Token",
    "AccessToken",
    "Secret",
    "Password",
    "Path",
    "FilePath",
    "DeviceName",
    "SerialNumber",
    "TenantId",
];

/// Return a copy of the snapshot with every value-bearing field redacted.
///
/// The snapshot's structure, identities, states, findings, and coverage are
/// untouched: those are the diagnosis, and redacting them would defeat the
/// export. Only free-text values are replaced.
pub fn redacted_configuration_snapshot(snapshot: &ConfigurationSnapshot) -> ConfigurationSnapshot {
    let mut redacted = snapshot.clone();
    redacted.settings = snapshot.settings.iter().map(redact_setting).collect();
    redacted.unattributed = snapshot
        .unattributed
        .iter()
        .map(redact_observation)
        .collect();
    redacted.redacted = true;
    redacted
}

/// The deterministic replacement token for one value.
pub fn redaction_token(value: &str) -> String {
    format!("[redacted:{:016x}]", fnv1a64(value.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn redact_setting(setting: &ConfigurationSetting) -> ConfigurationSetting {
    let mut redacted = setting.clone();
    redacted.identity = redact_identity(&setting.identity);
    redacted.applied_value = setting.applied_value.as_deref().map(redaction_token);
    redacted.observations = setting
        .observations
        .iter()
        .map(redact_observation)
        .collect();
    redacted.sources = setting
        .sources
        .iter()
        .map(redact_source_statement)
        .collect();
    redacted
}

fn redact_source_statement(
    statement: &ConfigurationSourceStatement,
) -> ConfigurationSourceStatement {
    // A configuration source id is a policy identifier, not an identity, and the
    // whole point of the conflict findings is to name which policies collided.
    // It is left intact deliberately.
    statement.clone()
}

fn redact_observation(observation: &ConfigurationObservation) -> ConfigurationObservation {
    let mut redacted = observation.clone();
    redacted.identity = redact_identity(&observation.identity);
    redacted.value = observation.value.as_deref().map(redaction_token);
    // An enrollment id identifies this device's enrollment, so it is tokenized
    // rather than dropped: correlating two records to the same enrollment stays
    // possible without disclosing which enrollment it is.
    redacted.enrollment_id = observation.enrollment_id.as_deref().map(redaction_token);
    redacted.named_data = observation
        .named_data
        .iter()
        .map(|entry| redact_named_value(entry, &observation.sensitivity))
        .collect();
    redacted
}

fn redact_named_value(
    entry: &IntuneNamedValue,
    sensitivity: &IntuneSensitivity,
) -> IntuneNamedValue {
    let redact = matches!(sensitivity, IntuneSensitivity::Restricted)
        || SENSITIVE_NAMES
            .iter()
            .any(|name| entry.name.eq_ignore_ascii_case(name))
        || looks_like_identity(&entry.value);

    IntuneNamedValue {
        name: entry.name.clone(),
        value: if redact {
            redaction_token(&entry.value)
        } else {
            entry.value.clone()
        },
    }
}

/// Redact only the URI segments that carry identity, keeping the node path.
///
/// A CSP node path is the single most useful thing in the output and must
/// survive. Some nodes embed a SID or account name as a segment, and those
/// segments are tokenized. Because the dedupe key is derived from the same
/// string, it is scrubbed with the same function so a redacted snapshot stays
/// internally consistent.
fn redact_identity(
    identity: &super::identity::ConfigurationSettingIdentity,
) -> super::identity::ConfigurationSettingIdentity {
    let mut redacted = identity.clone();
    redacted.canonical_uri = identity.canonical_uri.as_deref().map(scrub_uri);
    redacted.raw_uri = identity.raw_uri.as_deref().map(scrub_uri);
    redacted.resource_path = identity.resource_path.as_deref().map(scrub_uri);
    redacted.key = scrub_uri(&identity.key);
    redacted
}

fn scrub_uri(uri: &str) -> String {
    uri.split('/')
        .map(|segment| {
            if looks_like_identity(segment) {
                redaction_token(segment)
            } else {
                segment.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Whether a free-text value carries identity, path, or credential material.
///
/// GUIDs are deliberately *not* matched: policy, configuration source, and
/// setting identifiers are GUIDs, and tokenizing them would remove the only
/// handle an administrator has for finding the offending policy in the portal.
pub fn looks_like_identity(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    if is_windows_sid(trimmed) {
        return true;
    }
    if is_mail_like(trimmed) {
        return true;
    }
    if trimmed.contains(":\\") || trimmed.starts_with("\\\\") || trimmed.contains("/Users/") {
        return true;
    }
    // JWTs and bearer tokens.
    trimmed.starts_with("eyJ") || trimmed.to_ascii_lowercase().contains("bearer ")
}

fn is_windows_sid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("S-1-") else {
        return false;
    };
    rest.matches('-').count() >= 2
        && rest
            .chars()
            .all(|character| character.is_ascii_digit() || character == '-')
}

fn is_mail_like(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.contains(' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_value_always_redacts_to_the_same_token() {
        assert_eq!(redaction_token("secret"), redaction_token("secret"));
        assert_ne!(redaction_token("secret"), redaction_token("other"));
    }

    #[test]
    fn the_token_is_a_fixed_width_stable_string() {
        // Pinned so a change to the hashing scheme cannot pass unnoticed: every
        // committed golden fixture depends on this exact value.
        assert_eq!(redaction_token("1"), "[redacted:af63ac4c86019afc]");
    }

    #[test]
    fn identity_detection_covers_sids_upns_and_paths_but_not_guids() {
        assert!(looks_like_identity("S-1-5-21-1-2-3-1001"));
        assert!(looks_like_identity("someone@example.invalid"));
        assert!(looks_like_identity("D:\\Data\\wallpaper.png"));
        assert!(looks_like_identity("\\\\server\\share"));
        assert!(looks_like_identity("eyJhbGciOiJIUzI1NiJ9.e30"));
        assert!(!looks_like_identity("11111111-1111-4111-8111-111111111111"));
        assert!(!looks_like_identity("Update/AllowAutoUpdate"));
    }

    #[test]
    fn scrubbing_a_uri_keeps_the_node_path_and_tokenizes_only_identity_segments() {
        let scrubbed = scrub_uri("Device/Vendor/MSFT/Policy/Config/S-1-5-21-1-2-3-1001/Setting");
        assert!(scrubbed.starts_with("Device/Vendor/MSFT/Policy/Config/[redacted:"));
        assert!(scrubbed.ends_with("/Setting"));
    }
}
