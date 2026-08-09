//! Deterministic redaction for the configuration export.
//!
//! Configuration values are arbitrary tenant data: a proxy URL, a certificate
//! subject, a wallpaper path, a user principal name. The default export must not
//! carry them, but simply deleting them destroys the one comparison that matters
//! most — whether two configuration sources are fighting over the *same* value or
//! two different ones. A redacted value therefore becomes `[redacted:<hash>]`,
//! and equal inputs produce equal tokens.
//!
//! # One choke point
//!
//! Everything that leaves this module is produced by [`RedactionScope`]. There
//! are exactly three ways to emit a value — [`RedactionScope::token`] for a
//! classified value, [`RedactionScope::free_text`] for prose, and
//! [`RedactionScope::uri`] for a node path — and every field of the snapshot goes
//! through one of them. [`redacted_configuration_snapshot`] builds its result
//! with a struct literal rather than `clone()` + mutate, so a new snapshot field
//! is a compile error here rather than a silent leak. That is what closes the
//! previous gap where findings and coverage bypassed redaction entirely and
//! exported the un-scrubbed node path embedded in a finding summary.
//!
//! # Token scope (ADR-004)
//!
//! ADR-004 accepts the redaction *boundary* but records the token algorithm,
//! caller-supplied key, and equality scope as **provisional**, and forbids a new
//! reducer from introducing a stable identifier token intended for cross-artifact,
//! cross-session, or cross-export correlation. This module therefore scopes token
//! equality to **one analysis**: the hash is salted with the snapshot's
//! `generatedAtUtc`, so two settings inside one export that carry the same value
//! still show the same token — which is the equality the conflict diagnosis needs
//! — while two separate exports of the same device produce different tokens and
//! cannot be joined.
//!
//! No keyed-token API is invented here. Defining one (a caller-supplied secret,
//! a documented equality scope, and the tests that pin it) is the Store pilot's
//! decision under ADR-004, and this module adopts it when it lands. Until then
//! the honest statement of what the token defends is: it prevents casual
//! disclosure and cross-export correlation. It is not a defense against an
//! attacker who can enumerate candidate values and confirm a match *within a
//! single export*, because the salt travels with the export.
//!
//! Free-text spans are masked by the family-owned
//! [`crate::intune::apps::windows::common::redact_text`], which is where
//! user-profile-path and inline-credential masking is maintained for every
//! Windows Intune analyzer, rather than by a second whole-value predicate here.
//! The two shapes that also occur as CSP *node segments* — a SID and a UPN — are
//! masked locally first, with this analysis's token, so the same identity reads
//! identically whether it reached the export through `canonicalUri`, through the
//! lowercased dedupe key, or through a finding summary built from either.
//!
//! # Idempotence
//!
//! Re-projecting an already redacted snapshot returns it unchanged. A value that
//! is exactly a token this module produced is passed through rather than hashed
//! again, using the same full-shape check the compliance sibling settled on: a
//! source-supplied value that merely wears brackets does not get to skip
//! redaction.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::apps::windows::common::redact_text;
use crate::intune::evidence::{
    IntuneArtifactCoverage, IntuneFinding, IntuneNamedValue, IntuneSensitivity,
};

use super::identity::ConfigurationSettingIdentity;
use super::models::{
    ConfigurationObservation, ConfigurationSetting, ConfigurationSnapshot,
    ConfigurationSourceStatement,
};

/// Named-value keys whose contents are tokenized regardless of classification.
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

/// Named-value keys whose contents are a CSP node path.
///
/// These are scrubbed segment by segment rather than replaced wholesale: the node
/// path is the single most useful thing in the export, and a whole-value token
/// would have hidden a SID segment *and* the node it belongs to. Some nodes embed
/// a SID or an account name as a segment, and only those segments are tokenized.
const URI_NAMES: [&str; 6] = ["NodeUri", "CspUri", "CSPURI", "SettingUri", "Uri", "OmaUri"];

/// Named-value keys the reducer itself keys on to reach a diagnosis.
///
/// A record classified [`IntuneSensitivity::Sensitive`] is one the adapter has
/// told us carries identity, so its free text is replaced wholesale — except for
/// these, which are policy identifiers, status codes, and command verbs. Dropping
/// them would leave a redacted export that can no longer state *why* it concluded
/// what it concluded, which ADR-004 forbids just as firmly as leaking the value.
/// The list mirrors the lookup keys in [`super::sources`].
const DIAGNOSTIC_NAMES: [&str; 15] = [
    "ConfigurationSourceId",
    "PolicyId",
    "SourceId",
    "ConfigSourceId",
    "SettingId",
    "CommandType",
    "Command",
    "Result",
    "ResultCode",
    "ErrorCode",
    "Hresult",
    "Scope",
    "TargetScope",
    "Area",
    "SchemaVersion",
];

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// The redaction scope of one analysis.
///
/// Constructed from the snapshot's own `generatedAtUtc`, which is the only
/// identifier of "this analysis" the pure crate is given. Every token in one
/// export shares this scope; no two exports share it.
struct RedactionScope {
    salt: u64,
}

impl RedactionScope {
    fn new(analysis_id: &str) -> Self {
        Self {
            salt: fnv1a64(FNV_OFFSET_BASIS, analysis_id.as_bytes()),
        }
    }

    /// The replacement token for one whole value.
    fn token(&self, value: &str) -> String {
        if is_redaction_token(value) {
            return value.to_owned();
        }
        format!("[redacted:{:016x}]", fnv1a64(self.salt, value.as_bytes()))
    }

    fn token_opt(&self, value: Option<&str>) -> Option<String> {
        value.map(|value| self.token(value))
    }

    /// The replacement token for an identity that is being *matched*, not stated.
    ///
    /// Case is folded first. The dedupe key is lowercased at build time while the
    /// canonical URI keeps the documented CSP casing, so hashing the bytes as
    /// written would give the same SID two different tokens in one snapshot and
    /// destroy exactly the equality redaction exists to preserve.
    fn identity_token(&self, value: &str) -> String {
        self.token(&value.to_ascii_lowercase())
    }

    /// Mask the identity-bearing spans inside free text, keeping the rest.
    ///
    /// Whole-value replacement is not enough for prose: `"user a@b could not
    /// apply"` is not itself an identity by any whole-value predicate, and used to
    /// export intact.
    /// The two shapes that also appear as CSP node segments — a SID and a UPN —
    /// are masked here first, with this analysis's token, so the same identity
    /// reads identically whether it reached the export through `canonicalUri` or
    /// through a finding summary built from it. Whatever is left goes to the
    /// family-owned helper, which owns user-profile paths and inline credentials.
    fn free_text(&self, value: &str) -> String {
        let masked = sid_regex().replace_all(value, |captures: &regex::Captures<'_>| {
            self.identity_token(&captures[0])
        });
        let masked = upn_regex().replace_all(&masked, |captures: &regex::Captures<'_>| {
            self.identity_token(&captures[0])
        });
        redact_text(&masked)
    }

    fn free_text_opt(&self, value: Option<&str>) -> Option<String> {
        value.map(|value| self.free_text(value))
    }

    /// Scrub the identity segments out of a node path, keeping the path.
    fn uri(&self, uri: &str) -> String {
        uri.split('/')
            .map(|segment| {
                if looks_like_identity(segment) {
                    self.identity_token(segment)
                } else {
                    self.free_text(segment)
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    fn uri_opt(&self, uri: Option<&str>) -> Option<String> {
        uri.map(|uri| self.uri(uri))
    }
}

fn fnv1a64(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Whether a value is exactly a token this module produced.
///
/// The shape must match `[redacted:<16 hex digits>]` in full. Treating any
/// bracketed value as already masked would let a source-supplied value such as
/// `[redacted:pick-me]` skip redaction simply by wearing brackets.
fn is_redaction_token(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("[redacted:") else {
        return false;
    };
    let Some(digits) = rest.strip_suffix(']') else {
        return false;
    };
    digits.len() == 16 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// A Windows security identifier appearing anywhere inside a longer string.
fn sid_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)S-1-(?:\d+-){2,}\d+").expect("SID pattern is valid"))
}

/// A user principal name or address appearing anywhere inside a longer string.
///
/// Deliberately the same shape the shared helper uses, because this module needs
/// the span tokenized in *its* scope and must therefore win the race.
fn upn_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("UPN pattern is valid")
    })
}

/// Return a copy of the snapshot with every value-bearing field redacted.
///
/// The states, resolutions, source identifiers, evidence references, finding
/// identifiers, severities, and confidences are untouched: those are the
/// diagnosis, and ADR-004 requires redaction to leave non-sensitive conclusions
/// alone. Only free text is replaced.
pub fn redacted_configuration_snapshot(snapshot: &ConfigurationSnapshot) -> ConfigurationSnapshot {
    let scope = RedactionScope::new(&snapshot.generated_at_utc);

    // Written as a struct literal on purpose: adding a field to the snapshot must
    // not silently inherit an un-redacted value from a `clone()`.
    ConfigurationSnapshot {
        schema_version: snapshot.schema_version,
        generated_at_utc: snapshot.generated_at_utc.clone(),
        settings: snapshot
            .settings
            .iter()
            .map(|setting| redact_setting(setting, &scope))
            .collect(),
        unattributed: snapshot
            .unattributed
            .iter()
            .map(|observation| redact_observation(observation, &scope))
            .collect(),
        coverage: snapshot
            .coverage
            .iter()
            .map(|entry| redact_coverage(entry, &scope))
            .collect(),
        findings: snapshot
            .findings
            .iter()
            .map(|finding| redact_finding(finding, &scope))
            .collect(),
        redacted: true,
    }
}

fn redact_setting(setting: &ConfigurationSetting, scope: &RedactionScope) -> ConfigurationSetting {
    ConfigurationSetting {
        identity: redact_identity(&setting.identity, scope),
        receipt: setting.receipt,
        local: setting.local,
        service: setting.service,
        resolution: setting.resolution,
        sources: setting
            .sources
            .iter()
            .map(redact_source_statement)
            .collect(),
        local_error: setting.local_error.clone(),
        service_error: setting.service_error.clone(),
        applied_value: scope.token_opt(setting.applied_value.as_deref()),
        time_is_reliable: setting.time_is_reliable,
        ordering_is_contradictory: setting.ordering_is_contradictory,
        has_uninterpretable_evidence: setting.has_uninterpretable_evidence,
        has_unassessable_failure: setting.has_unassessable_failure,
        observations: setting
            .observations
            .iter()
            .map(|observation| redact_observation(observation, scope))
            .collect(),
        evidence: setting.evidence.clone(),
    }
}

fn redact_source_statement(
    statement: &ConfigurationSourceStatement,
) -> ConfigurationSourceStatement {
    // A configuration source id is a policy identifier, not an identity, and the
    // whole point of the conflict findings is to name which policies collided.
    // It is left intact deliberately.
    statement.clone()
}

fn redact_observation(
    observation: &ConfigurationObservation,
    scope: &RedactionScope,
) -> ConfigurationObservation {
    ConfigurationObservation {
        evidence_ref: observation.evidence_ref.clone(),
        side: observation.side,
        source_kind: observation.source_kind.clone(),
        sensitivity: observation.sensitivity.clone(),
        identity: redact_identity(&observation.identity, scope),
        disposition: observation.disposition,
        event_kind: observation.event_kind,
        event_id: observation.event_id,
        source_id: observation.source_id.clone(),
        // An enrollment id identifies this device's enrollment, so it is
        // tokenized rather than dropped: correlating two records to the same
        // enrollment stays possible without disclosing which enrollment it is.
        enrollment_id: scope.token_opt(observation.enrollment_id.as_deref()),
        command_type: observation.command_type.clone(),
        value: scope.token_opt(observation.value.as_deref()),
        error: observation.error.clone(),
        winning_source_id: observation.winning_source_id.clone(),
        superseded_by_source_id: observation.superseded_by_source_id.clone(),
        occurred_at_utc: observation.occurred_at_utc.clone(),
        time_is_reliable: observation.time_is_reliable,
        record_id: observation.record_id,
        is_uninterpretable: observation.is_uninterpretable,
        named_data: observation
            .named_data
            .iter()
            .map(|entry| redact_named_value(entry, &observation.sensitivity, scope))
            .collect(),
    }
}

fn redact_named_value(
    entry: &IntuneNamedValue,
    sensitivity: &IntuneSensitivity,
    scope: &RedactionScope,
) -> IntuneNamedValue {
    let value = if matches!(sensitivity, IntuneSensitivity::Restricted) {
        // Restricted means the record may not contribute free text at all, and
        // that outranks keeping the node path legible.
        scope.token(&entry.value)
    } else if matches_name(&entry.name, &URI_NAMES) {
        scope.uri(&entry.value)
    } else if matches_name(&entry.name, &SENSITIVE_NAMES)
        || looks_like_identity(&entry.value)
        || (matches!(sensitivity, IntuneSensitivity::Sensitive)
            && !matches_name(&entry.name, &DIAGNOSTIC_NAMES))
    {
        scope.token(&entry.value)
    } else {
        scope.free_text(&entry.value)
    };

    IntuneNamedValue {
        name: entry.name.clone(),
        value,
    }
}

fn matches_name(name: &str, names: &[&str]) -> bool {
    names
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

/// Scrub the identity segments out of every URI-shaped identity field.
///
/// Because the dedupe key is derived from the same string, it is scrubbed with
/// the same function so a redacted snapshot stays internally consistent. The key
/// is lowercased at build time, which is why every detector below is
/// case-insensitive: a case-sensitive detector matched the `canonicalUri` copy of
/// a SID and missed the lowercased `key` copy sitting beside it.
fn redact_identity(
    identity: &ConfigurationSettingIdentity,
    scope: &RedactionScope,
) -> ConfigurationSettingIdentity {
    ConfigurationSettingIdentity {
        key: scope.uri(&identity.key),
        canonical_uri: scope.uri_opt(identity.canonical_uri.as_deref()),
        raw_uri: scope.uri_opt(identity.raw_uri.as_deref()),
        resource_path: scope.uri_opt(identity.resource_path.as_deref()),
        setting_id: identity.setting_id.clone(),
        policy_id: identity.policy_id.clone(),
        display_name: scope.free_text_opt(identity.display_name.as_deref()),
        scope: identity.scope,
        csp: identity.csp.clone(),
        is_unidentified: identity.is_unidentified,
    }
}

/// Scrub a coverage entry's collector-supplied detail.
fn redact_coverage(
    entry: &IntuneArtifactCoverage,
    scope: &RedactionScope,
) -> IntuneArtifactCoverage {
    IntuneArtifactCoverage {
        artifact_id: entry.artifact_id.clone(),
        family: entry.family.clone(),
        status: entry.status.clone(),
        detail: scope.free_text_opt(entry.detail.as_deref()),
        observed_at_utc: entry.observed_at_utc.clone(),
        evidence: entry.evidence.clone(),
    }
}

/// Scrub a finding's prose, leaving the conclusion it states untouched.
///
/// The identifier, severity, confidence, citations, and coverage-gap references
/// are the diagnosis and must survive byte-for-byte; ADR-004's invariant is that
/// redaction does not alter non-sensitive conclusions. The title, summary, and
/// recommended checks are prose built from setting labels, and a label is a node
/// path that can embed a SID.
fn redact_finding(finding: &IntuneFinding, scope: &RedactionScope) -> IntuneFinding {
    IntuneFinding {
        finding_id: finding.finding_id.clone(),
        severity: finding.severity.clone(),
        confidence: finding.confidence.clone(),
        title: scope.free_text(&finding.title),
        summary: scope.free_text(&finding.summary),
        recommended_checks: finding
            .recommended_checks
            .iter()
            .map(|check| scope.free_text(check))
            .collect(),
        evidence: finding.evidence.clone(),
        coverage_gap_ids: finding.coverage_gap_ids.clone(),
    }
}

/// Whether a value is *entirely* identity, path, or credential material.
///
/// Used for whole-value replacement, where a partial mask would be a false
/// assurance. Free text goes through [`RedactionScope::free_text`] instead.
///
/// Every check is case-insensitive because the dedupe key is lowercased and is
/// scrubbed by the same code path as the mixed-case URI it was derived from.
///
/// GUIDs are deliberately *not* matched: policy, configuration source, and
/// setting identifiers are GUIDs, and tokenizing them would remove the only
/// handle an administrator has for finding the offending policy in the portal.
fn looks_like_identity(value: &str) -> bool {
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
    let lowercased = trimmed.to_ascii_lowercase();
    if lowercased.contains(":\\")
        || lowercased.starts_with("\\\\")
        || lowercased.contains("/users/")
    {
        return true;
    }
    // JWTs and bearer tokens.
    lowercased.starts_with("eyj") || lowercased.contains("bearer ")
}

fn is_windows_sid(value: &str) -> bool {
    let Some(rest) = value
        .get(..4)
        .filter(|head| head.eq_ignore_ascii_case("S-1-"))
    else {
        return false;
    };
    let rest = &value[rest.len()..];
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

    fn scope() -> RedactionScope {
        RedactionScope::new("2026-07-31T10:00:00Z")
    }

    #[test]
    fn the_same_value_always_redacts_to_the_same_token_within_one_analysis() {
        let scope = scope();
        assert_eq!(scope.token("secret"), scope.token("secret"));
        assert_ne!(scope.token("secret"), scope.token("other"));
    }

    #[test]
    fn two_analyses_do_not_share_a_token_for_the_same_value() {
        // ADR-004: a new reducer must not introduce a token that joins two
        // exports. Pinning the *inequality* is what stops a future refactor from
        // quietly restoring a globally stable dictionary of low-entropy values.
        let first = RedactionScope::new("2026-07-31T10:00:00Z");
        let second = RedactionScope::new("2026-08-01T10:00:00Z");
        assert_ne!(first.token("1"), second.token("1"));
    }

    #[test]
    fn the_token_is_a_fixed_width_stable_string_within_its_scope() {
        // Pinned so a change to the hashing scheme cannot pass unnoticed. The
        // scope is named explicitly: the value alone no longer determines the
        // token, which is the point.
        assert_eq!(scope().token("1"), "[redacted:187c4fa5b79764ea]");
    }

    #[test]
    fn redacting_a_token_again_returns_it_unchanged() {
        let scope = scope();
        let once = scope.token("D:\\Data\\wallpaper.png");
        assert_eq!(scope.token(&once), once);
        assert_eq!(scope.free_text(&once), once);
        assert_eq!(scope.uri(&once), once);
    }

    #[test]
    fn a_value_that_merely_wears_brackets_is_still_redacted() {
        let scope = scope();
        assert_ne!(
            scope.token("[redacted:pick-me]"),
            "[redacted:pick-me]",
            "a source-supplied bracketed value must not bypass redaction"
        );
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
    fn identity_detection_is_case_insensitive_because_the_dedupe_key_is_lowercased() {
        // The regression this pins: `key` is built lowercased while the detectors
        // were case-sensitive, so a SID was tokenized in `canonicalUri` and
        // shipped verbatim in `key` right beside it.
        assert!(looks_like_identity("s-1-5-21-1-2-3-1001"));
        assert!(looks_like_identity("d:\\data\\wallpaper.png"));
        assert!(looks_like_identity("eyjhbgcioijiuzi1nij9.e30"));
    }

    #[test]
    fn scrubbing_a_uri_keeps_the_node_path_and_tokenizes_only_identity_segments() {
        let scrubbed = scope().uri("Device/Vendor/MSFT/Policy/Config/S-1-5-21-1-2-3-1001/Setting");
        assert!(scrubbed.starts_with("Device/Vendor/MSFT/Policy/Config/[redacted:"));
        assert!(scrubbed.ends_with("/Setting"));
    }

    #[test]
    fn a_lowercased_dedupe_key_is_scrubbed_the_same_way_as_its_uri() {
        let scope = scope();
        let uri = scope.uri("Device/Vendor/MSFT/Policy/Config/S-1-5-21-1-2-3-1001/Setting");
        let key =
            scope.uri("device|uri:device/vendor/msft/policy/config/s-1-5-21-1-2-3-1001/setting");
        let token = uri
            .split('/')
            .find(|segment| segment.starts_with("[redacted:"))
            .expect("the URI carries a token");
        assert!(key.contains(token), "key {key} must reuse the URI's token");
        assert!(!key.contains("s-1-5-21"), "got {key}");
    }

    #[test]
    fn an_identity_embedded_in_prose_is_masked_without_destroying_the_sentence() {
        let masked = scope().free_text("user a@b.invalid could not apply S-1-5-21-1-2-3-1001");
        assert!(!masked.contains("a@b.invalid"), "got {masked}");
        assert!(!masked.contains("S-1-5-21"), "got {masked}");
        assert!(masked.contains("could not apply"), "got {masked}");
    }

    #[test]
    fn free_text_masking_is_idempotent() {
        let scope = scope();
        let once = scope.free_text("owner S-1-5-21-1-2-3-1001 at a@b.invalid");
        assert_eq!(scope.free_text(&once), once);
    }

    #[test]
    fn a_sensitive_record_keeps_the_identifiers_the_diagnosis_is_built_from() {
        let scope = scope();
        let source = redact_named_value(
            &IntuneNamedValue {
                name: "ConfigurationSourceId".to_owned(),
                value: "11111111-1111-4111-8111-111111111111".to_owned(),
            },
            &IntuneSensitivity::Sensitive,
            &scope,
        );
        assert_eq!(source.value, "11111111-1111-4111-8111-111111111111");

        let other = redact_named_value(
            &IntuneNamedValue {
                name: "Comment".to_owned(),
                value: "set by the helpdesk".to_owned(),
            },
            &IntuneSensitivity::Sensitive,
            &scope,
        );
        assert!(
            other.value.starts_with("[redacted:"),
            "a sensitive record's free text is replaced wholesale, got {}",
            other.value
        );
    }

    #[test]
    fn a_uri_valued_named_entry_is_scrubbed_rather_than_replaced() {
        let entry = redact_named_value(
            &IntuneNamedValue {
                name: "NodeUri".to_owned(),
                value: "./Device/Vendor/MSFT/Policy/Config/S-1-5-21-1-2-3-1001/Setting".to_owned(),
            },
            &IntuneSensitivity::Public,
            &scope(),
        );
        assert!(
            entry.value.contains("Vendor/MSFT/Policy"),
            "got {}",
            entry.value
        );
        assert!(!entry.value.contains("S-1-5-21"), "got {}", entry.value);
    }

    #[test]
    fn a_restricted_record_contributes_no_free_text_at_all() {
        let entry = redact_named_value(
            &IntuneNamedValue {
                name: "NodeUri".to_owned(),
                value: "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate".to_owned(),
            },
            &IntuneSensitivity::Restricted,
            &scope(),
        );
        assert!(entry.value.starts_with("[redacted:"), "got {}", entry.value);
    }
}
