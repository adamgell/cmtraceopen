//! Canonical identity for one configuration setting transaction.
//!
//! # What is in the key, and what is deliberately not
//!
//! The key is `scope | resource`. The configuration source (policy id) is *not*
//! part of it, even though issue #363 lists source alongside scope. Including it
//! would put two policies targeting the same OMA-URI into two separate
//! transactions, and the conflict and supersedence states the same issue requires
//! could then never be observed: a conflict is by definition two sources arguing
//! over one resource. Sources are therefore recorded inside the transaction, and
//! the rules cite them.
//!
//! Display name is never part of the key. Two settings sharing a friendly name
//! with different CSP paths stay separate, which is the twelfth fixture in the
//! required matrix.

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Whether the setting targets the device or a user.
///
/// `Unspecified` is not a default-to-device: a device-scoped and a user-scoped
/// instance of the same CSP node are different settings, and collapsing an
/// unknown scope into either one invents a correlation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ConfigurationScope {
    /// The setting targets the machine: `./Device/Vendor/MSFT/…`.
    Device,
    /// The setting targets a signed-in user: `./User/Vendor/MSFT/…`.
    User,
    /// No source stated a scope. Never resolved to one of the others by
    /// inference; see the type-level note above.
    Unspecified,
}

impl ConfigurationScope {
    fn as_key(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::User => "user",
            Self::Unspecified => "unspecified",
        }
    }

    /// Parse a scope token as written in an OMA-URI segment or a report column.
    pub fn from_token(token: &str) -> Self {
        match token.trim().trim_matches('/').to_ascii_lowercase().as_str() {
            "device" => Self::Device,
            "user" => Self::User,
            _ => Self::Unspecified,
        }
    }
}

/// The canonical resource an observation is about.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationSettingIdentity {
    /// Deterministic dedupe key: `scope|resource`.
    pub key: String,
    /// The OMA-URI with `./` and duplicate or trailing separators removed.
    pub canonical_uri: Option<String>,
    /// The OMA-URI exactly as the source wrote it.
    pub raw_uri: Option<String>,
    /// The canonical URI with its leading scope segment removed, used to detect
    /// the same CSP node appearing under two scopes.
    pub resource_path: Option<String>,
    /// Source-stated setting identifier, used as the resource key when no URI was
    /// available. Never merged with a URI-keyed transaction.
    pub setting_id: Option<String>,
    /// Configuration source / policy identifier, when a record stated one.
    /// Descriptive only: it is deliberately not part of [`Self::key`], because two
    /// policies arguing over one node must land in one transaction for the
    /// conflict to be observable.
    pub policy_id: Option<String>,
    /// Friendly name as the portal shows it. Never part of the key: two settings
    /// can share a display name and resolve to different CSP nodes.
    pub display_name: Option<String>,
    /// Whether this transaction is the device-scoped or user-scoped instance of
    /// the node. Part of the key.
    pub scope: ConfigurationScope,
    /// CSP vendor node, e.g. `Policy` in `./Device/Vendor/MSFT/Policy/Config/...`.
    pub csp: Option<String>,
    /// True when no stable identifier was available and the key falls back to the
    /// originating evidence id. Such a transaction can never be high confidence.
    pub is_unidentified: bool,
}

/// Everything an observation offered about which setting it is about.
#[derive(Debug, Clone, Default)]
pub struct IdentityHints<'a> {
    /// OMA-URI exactly as the source wrote it, if it wrote one.
    pub uri: Option<&'a str>,
    /// Source-stated setting identifier, used only when no URI is present.
    pub setting_id: Option<&'a str>,
    /// Configuration source / policy identifier, recorded but never keyed on.
    pub policy_id: Option<&'a str>,
    /// Friendly name, recorded but never keyed on.
    pub display_name: Option<&'a str>,
    /// Explicit scope token from a report column or named value, used only when
    /// the URI does not carry one.
    pub scope_token: Option<&'a str>,
    /// Evidence id, used as the last-resort key so unidentified records never
    /// merge with one another.
    pub evidence_id: &'a str,
}

/// Build the canonical identity for one observation.
pub fn resolve_identity(hints: &IdentityHints<'_>) -> ConfigurationSettingIdentity {
    let raw_uri = hints
        .uri
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let canonical_uri = raw_uri.as_deref().map(canonicalize_uri);
    let uri_scope = canonical_uri.as_deref().map(scope_of_uri);

    let scope = match uri_scope {
        Some(ConfigurationScope::Unspecified) | None => hints
            .scope_token
            .map(ConfigurationScope::from_token)
            .unwrap_or(ConfigurationScope::Unspecified),
        Some(scope) => scope,
    };

    let resource_path = canonical_uri.as_deref().map(strip_scope_segment);
    let csp = canonical_uri.as_deref().and_then(csp_of_uri);

    let setting_id = normalize_opt(hints.setting_id);
    let policy_id = normalize_opt(hints.policy_id);
    let display_name = normalize_opt(hints.display_name);

    let (resource_key, is_unidentified) = match (&canonical_uri, &setting_id) {
        (Some(uri), _) => (format!("uri:{}", uri.to_ascii_lowercase()), false),
        (None, Some(id)) => (format!("settingId:{}", id.to_ascii_lowercase()), false),
        (None, None) => (format!("unidentified:{}", hints.evidence_id), true),
    };

    ConfigurationSettingIdentity {
        key: format!("{}|{resource_key}", scope.as_key()),
        canonical_uri,
        raw_uri,
        resource_path,
        setting_id,
        policy_id,
        display_name,
        scope,
        csp,
        is_unidentified,
    }
}

fn normalize_opt(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Strip `./`, normalize separators, collapse repeats, drop a trailing separator.
///
/// Case is preserved: CSP node names are documented with specific casing and a
/// lowercased URI is harder to match against Microsoft's documentation. Only the
/// dedupe key lowercases.
pub fn canonicalize_uri(uri: &str) -> String {
    let replaced = uri.trim().replace('\\', "/");
    let without_prefix = replaced.strip_prefix("./").unwrap_or(&replaced);
    without_prefix
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

/// Scope implied by the first segment of a canonical URI.
fn scope_of_uri(canonical: &str) -> ConfigurationScope {
    match canonical.split('/').next() {
        Some(first) => ConfigurationScope::from_token(first),
        None => ConfigurationScope::Unspecified,
    }
}

/// The canonical URI without its leading `Device`/`User` segment.
///
/// Two scopes of the same CSP node share this string, which is what lets the
/// scope-mismatch rule find them without merging their transactions.
fn strip_scope_segment(canonical: &str) -> String {
    let mut segments = canonical.split('/');
    match segments.next() {
        Some(first)
            if matches!(
                ConfigurationScope::from_token(first),
                ConfigurationScope::Device | ConfigurationScope::User
            ) =>
        {
            segments.collect::<Vec<_>>().join("/")
        }
        _ => canonical.to_owned(),
    }
}

/// The CSP vendor node named by a canonical URI, e.g. `Policy` or `BitLocker`.
fn csp_of_uri(canonical: &str) -> Option<String> {
    let segments = canonical.split('/').collect::<Vec<_>>();
    let vendor = segments
        .iter()
        .position(|segment| segment.eq_ignore_ascii_case("MSFT"))?;
    segments.get(vendor + 1).map(|node| (*node).to_owned())
}

// ── Message scraping ────────────────────────────────────────────────────────
//
// Rendered MDM Admin-channel messages carry the CSP URI, configuration source,
// and result code inline. Some adapters populate named data from the event XML
// and some can only supply the rendered message, so when named data is empty the
// message text is the only place the identity lives. Parenthesized values are the
// shape Microsoft's provider actually renders, so the patterns strip them.

fn csp_uri_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // The terminal alternation allows an optional sentence-ending period
        // before the boundary. Without it, `CSP URI: ./Device/…/Node.` captured
        // the period as part of the node path and `CSP URI: (./Device/…/Node).`
        // did not match at all — one produced a URI that correlates with nothing,
        // the other produced no identity.
        Regex::new(r"(?i)\bCSP\s+URI:\s*\(?([^,()\r\n]+?)\)?\s*(?:,|\.?(?:\s|$))")
            .expect("CSP URI pattern is valid")
    })
}

fn result_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bResult:?\s*\(?(0x[0-9A-Fa-f]+|-?\d+)\)?")
            .expect("result pattern is valid")
    })
}

fn policy_area_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\bPolicy:\s*\(?([^,()\r\n]+?)\)?\s*,\s*Area:\s*\(?([^,()\r\n]+?)\)?\s*(?:,|$)",
        )
        .expect("policy/area pattern is valid")
    })
}

fn source_id_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bConfiguration\s+Source\s+ID:\s*\(?([0-9A-Fa-f-]{8,})\)?")
            .expect("configuration source pattern is valid")
    })
}

/// Extract `CSP URI: …` from a rendered event message.
pub fn csp_uri_from_message(message: &str) -> Option<String> {
    csp_uri_regex()
        .captures(message)
        .map(|captures| captures[1].trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Extract `Result: …` from a rendered event message.
pub fn result_token_from_message(message: &str) -> Option<String> {
    result_regex()
        .captures(message)
        .map(|captures| captures[1].trim().to_owned())
}

/// Extract `Configuration Source ID: …` from a rendered event message.
pub fn source_id_from_message(message: &str) -> Option<String> {
    source_id_regex()
        .captures(message)
        .map(|captures| captures[1].trim().to_owned())
}

/// Rebuild a Policy CSP URI from a `Policy: X, Area: Y` message.
///
/// PolicyManager events name the area and policy rather than the node path, so
/// without this the set-policy events and the CSP failure events would key on
/// different resources and never correlate.
///
/// When the caller could not determine a scope, the rebuilt path carries **no**
/// scope segment. Defaulting to `Device` synthesized a joinable device-scoped
/// URI out of a record that never said it was device-scoped, which contradicts
/// this module's own contract that an unknown scope must not merge with a known
/// one. A scope-free path keys on `unspecified|…` and stays in its own
/// transaction; it still shares a `resource_path` with the scoped instances, so
/// nothing about the node is lost.
pub fn policy_uri_from_message(message: &str, scope: ConfigurationScope) -> Option<String> {
    let captures = policy_area_regex().captures(message)?;
    let policy = captures[1].trim();
    let area = captures[2].trim();
    if policy.is_empty() || area.is_empty() {
        return None;
    }
    let scope_segment = match scope {
        ConfigurationScope::User => "User/",
        ConfigurationScope::Device => "Device/",
        ConfigurationScope::Unspecified => "",
    };
    Some(format!(
        "{scope_segment}Vendor/MSFT/Policy/Config/{area}/{policy}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hints<'a>(uri: Option<&'a str>, evidence_id: &'a str) -> IdentityHints<'a> {
        IdentityHints {
            uri,
            evidence_id,
            ..IdentityHints::default()
        }
    }

    #[test]
    fn canonicalization_removes_prefix_duplicates_and_trailing_separator() {
        assert_eq!(
            canonicalize_uri(".//Device//Vendor/MSFT/Policy/Config/DeviceLock/"),
            "Device/Vendor/MSFT/Policy/Config/DeviceLock"
        );
    }

    #[test]
    fn scope_comes_from_the_uri_before_any_hint() {
        let identity = resolve_identity(&IdentityHints {
            uri: Some("./User/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate"),
            scope_token: Some("Device"),
            evidence_id: "e1",
            ..IdentityHints::default()
        });
        assert_eq!(identity.scope, ConfigurationScope::User);
    }

    #[test]
    fn the_same_node_under_two_scopes_produces_two_keys_but_one_resource_path() {
        let device = resolve_identity(&hints(
            Some("./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate"),
            "e1",
        ));
        let user = resolve_identity(&hints(
            Some("./User/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate"),
            "e2",
        ));
        assert_ne!(device.key, user.key);
        assert_eq!(device.resource_path, user.resource_path);
    }

    #[test]
    fn display_name_never_merges_two_csp_paths() {
        let first = resolve_identity(&IdentityHints {
            uri: Some("./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordEnabled"),
            display_name: Some("Require password"),
            evidence_id: "e1",
            ..IdentityHints::default()
        });
        let second = resolve_identity(&IdentityHints {
            uri: Some("./Device/Vendor/MSFT/PassportForWork/Policies/UsePassportForWork"),
            display_name: Some("Require password"),
            evidence_id: "e2",
            ..IdentityHints::default()
        });
        assert_ne!(first.key, second.key);
    }

    #[test]
    fn casing_differences_in_a_uri_do_not_split_a_transaction() {
        let upper = resolve_identity(&hints(
            Some("./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate"),
            "e1",
        ));
        let lower = resolve_identity(&hints(
            Some("./Device/Vendor/MSFT/Policy/Config/update/allowautoupdate"),
            "e2",
        ));
        assert_eq!(upper.key, lower.key);
    }

    #[test]
    fn an_unidentified_record_keys_on_its_own_evidence_id() {
        let first = resolve_identity(&hints(None, "e1"));
        let second = resolve_identity(&hints(None, "e2"));
        assert!(first.is_unidentified);
        assert_ne!(first.key, second.key);
    }

    #[test]
    fn setting_id_is_used_when_no_uri_is_present() {
        let identity = resolve_identity(&IdentityHints {
            setting_id: Some("Update_AllowAutoUpdate"),
            evidence_id: "e1",
            ..IdentityHints::default()
        });
        assert!(!identity.is_unidentified);
        assert_eq!(identity.key, "unspecified|settingId:update_allowautoupdate");
    }

    #[test]
    fn csp_node_is_taken_from_the_segment_after_msft() {
        let identity = resolve_identity(&hints(
            Some("./Device/Vendor/MSFT/BitLocker/RequireDeviceEncryption"),
            "e1",
        ));
        assert_eq!(identity.csp.as_deref(), Some("BitLocker"));
    }

    #[test]
    fn message_scraping_recovers_uri_result_and_source() {
        let message = "MDM ConfigurationManager: Command failure status. \
             Configuration Source ID: (11111111-1111-4111-8111-111111111111), \
             Enrollment Name: (MDMDeviceWithAAD), Provider Name: (Policy), \
             Command Type: (Add), CSP URI: (./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate), \
             Result: (0x82B00006).";
        assert_eq!(
            csp_uri_from_message(message).as_deref(),
            Some("./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate")
        );
        assert_eq!(
            result_token_from_message(message).as_deref(),
            Some("0x82B00006")
        );
        assert_eq!(
            source_id_from_message(message).as_deref(),
            Some("11111111-1111-4111-8111-111111111111")
        );
    }

    #[test]
    fn policy_manager_messages_rebuild_the_config_node_path() {
        let message = "MDM PolicyManager: Set policy int, Policy: (AllowAutoUpdate), \
             Area: (Update), EnrollmentID requesting merge: (E1), Value: (1)";
        assert_eq!(
            policy_uri_from_message(message, ConfigurationScope::Device).as_deref(),
            Some("Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate")
        );
    }

    #[test]
    fn a_sentence_ending_period_is_not_part_of_the_node_path() {
        let node = "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate";
        for message in [
            format!("Command failure status. CSP URI: {node}."),
            format!("Command failure status. CSP URI: ({node})."),
            format!("Command failure status. CSP URI: ({node}), Result: (0x1)."),
            format!("Command failure status. CSP URI: {node}"),
        ] {
            assert_eq!(
                csp_uri_from_message(&message).as_deref(),
                Some(node),
                "got {message}"
            );
        }
    }

    #[test]
    fn a_scopeless_policy_manager_message_does_not_become_device_scoped() {
        let message = "MDM PolicyManager: Set policy int, Policy: (AllowAutoUpdate), \
             Area: (Update), Value: (1)";
        let rebuilt = policy_uri_from_message(message, ConfigurationScope::Unspecified)
            .expect("the node path is still recoverable");
        assert_eq!(rebuilt, "Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate");

        let unspecified = resolve_identity(&hints(Some(&rebuilt), "e1"));
        let device = resolve_identity(&hints(
            Some("./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate"),
            "e2",
        ));
        assert_eq!(unspecified.scope, ConfigurationScope::Unspecified);
        assert_ne!(
            unspecified.key, device.key,
            "an unknown scope must not join a device-scoped transaction"
        );
        assert_eq!(
            unspecified.resource_path, device.resource_path,
            "the node itself is still comparable across scopes"
        );
    }
}
