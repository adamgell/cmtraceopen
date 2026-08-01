//! Deterministic redacted export projection.
//!
//! This is a projection, never a mutation: the caller keeps its fully detailed
//! snapshot and gets back a parallel value safe to attach to a support case.
//!
//! Two properties are load-bearing and are asserted by the corpus tests.
//!
//! *Determinism* — the same snapshot always produces byte-identical output.
//! Pseudonyms are numbered from a sorted set of the distinct values, not from the
//! order the records happened to arrive in, so re-ordering the input cannot
//! renumber anything.
//!
//! *Idempotence* — redacting an already-redacted snapshot is a no-op. A
//! redaction marker is terminal: it is matched before every other pattern and
//! returned unchanged, so a second pass cannot pseudonymize a pseudonym and
//! renumber the export.
//!
//! What survives is deliberate. Severity, subsystem, category, activity id, app
//! version, thread, and timestamps are correlation keys with no identity in
//! them; destroying them would leave an export that proves nothing, which is the
//! over-redaction failure mode this module exists to avoid. A pseudonymized
//! identifier still correlates: the same value reads the same way everywhere in
//! one export.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::{Captures, Regex};

use crate::intune::evidence::IntuneSensitivity;

use super::models::{CompanyPortalClassifiedString, CompanyPortalLogSnapshot};

/// Replacement for a value that carries no reusable correlation.
const REDACTED: &str = "[redacted]";

/// Categories that receive a numbered pseudonym, in the order they are matched.
const IDENTITY: &str = "identity";
const URL: &str = "url";
const GUID: &str = "guid";
const THUMBPRINT: &str = "thumbprint";

/// Return a redacted copy of `snapshot`, leaving the input untouched.
pub fn redacted_company_portal_log_export(
    snapshot: &CompanyPortalLogSnapshot,
) -> CompanyPortalLogSnapshot {
    let mut safe = snapshot.clone();

    // Pass one collects every distinct value that needs a pseudonym, from the
    // original text. Numbering from a sorted set is what makes the result
    // independent of record order.
    let mut discovered: BTreeSet<(&'static str, String)> = BTreeSet::new();
    for record in &safe.records {
        for text in classified_texts(record) {
            collect(text, &mut discovered);
        }
    }

    let mut counters: BTreeMap<&'static str, usize> = BTreeMap::new();
    let pseudonyms: BTreeMap<(&'static str, String), String> = discovered
        .into_iter()
        .map(|(category, value)| {
            let counter = counters.entry(category).or_insert(0);
            *counter += 1;
            let pseudonym = format!("[redacted-{category}-{counter}]");
            ((category, value), pseudonym)
        })
        .collect();

    // Pass two rewrites. Only values a producer classified as non-public are
    // touched; masking on presence alone would delete the diagnostic content the
    // export exists to carry.
    for record in &mut safe.records {
        mask(&mut record.message, &pseudonyms);
        mask(&mut record.raw, &pseudonyms);
        if let Some(path) = record.context.provenance.file_path.as_mut() {
            *path = REDACTED.to_owned();
        }
        for attribute in &mut record.attributes {
            attribute.value = apply(&attribute.value, &pseudonyms);
        }
        record.category = record.category.as_deref().map(|v| apply(v, &pseudonyms));
        record.activity_id = record.activity_id.as_deref().map(|v| apply(v, &pseudonyms));
        record.app_version = record.app_version.as_deref().map(|v| apply(v, &pseudonyms));
    }

    for artifact in &mut safe.artifacts {
        if let Some(path) = artifact.file_path.as_mut() {
            if path.sensitivity != IntuneSensitivity::Public {
                path.value = REDACTED.to_owned();
            }
        }
    }

    safe
}

fn classified_texts(
    record: &super::models::CompanyPortalLogRecord,
) -> impl Iterator<Item = &str> {
    [&record.message, &record.raw]
        .into_iter()
        .filter(|text| text.sensitivity != IntuneSensitivity::Public)
        .map(|text| text.value.as_str())
        .chain(
            record
                .attributes
                .iter()
                .map(|attribute| attribute.value.as_str()),
        )
}

fn mask(
    text: &mut CompanyPortalClassifiedString,
    pseudonyms: &BTreeMap<(&'static str, String), String>,
) {
    if text.sensitivity == IntuneSensitivity::Public {
        return;
    }
    text.value = apply(&text.value, pseudonyms);
}

/// Everything the projection recognizes, in priority order.
///
/// One combined pattern rather than a sequence of passes: leftmost-first
/// alternation means the marker alternative wins at any position where a
/// previously redacted value starts, which is what makes the projection
/// idempotent. Sequential passes would each have to re-check for markers, and a
/// missed check would silently renumber.
fn redaction_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(concat!(
            r"(?P<marker>\[redacted(?:-[a-z]+-\d+)?\])",
            r"|(?i:bearer)\s+(?P<bearer>[A-Za-z0-9._~+/-]+=*)",
            r"|(?P<secretkey>(?i:authorization|access_token|refresh_token|id_token|client_secret|token|password|pwd|secret))\s*[=:]\s*(?P<secretval>[^\s,;\|]+)",
            r"|(?P<identity>[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)",
            r#"|(?P<url>[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>\|]+)"#,
            r"|CN\s*=\s*(?P<cn>[^,;\|\r\n]+)",
            r"|(?P<guid>\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b)",
            r"|(?P<thumbprint>\b[0-9A-Fa-f]{32,}\b)",
            r#"|(?P<path>(?:~|/Users|/home|/private/var/folders)/[^\s"'\|]*)"#,
        ))
        .expect("Company Portal redaction pattern must compile")
    })
}

/// Record every value in `text` that needs a numbered pseudonym.
fn collect(text: &str, discovered: &mut BTreeSet<(&'static str, String)>) {
    for captures in redaction_re().captures_iter(text) {
        if captures.name("marker").is_some() {
            continue;
        }
        if let Some((category, value)) = pseudonymized(&captures) {
            discovered.insert((category, value));
        }
    }
}

/// Which pseudonym category, if any, this match belongs to.
fn pseudonymized(captures: &Captures<'_>) -> Option<(&'static str, String)> {
    for category in [IDENTITY, URL, GUID, THUMBPRINT] {
        if let Some(matched) = captures.name(category) {
            return Some((category, matched.as_str().to_owned()));
        }
    }
    None
}

/// Rewrite `text` using the assigned pseudonyms.
fn apply(text: &str, pseudonyms: &BTreeMap<(&'static str, String), String>) -> String {
    redaction_re()
        .replace_all(text, |captures: &Captures<'_>| {
            if let Some(marker) = captures.name("marker") {
                return marker.as_str().to_owned();
            }
            if captures.name("bearer").is_some() {
                return format!("Bearer {REDACTED}");
            }
            if let Some(key) = captures.name("secretkey") {
                return format!("{}={REDACTED}", key.as_str());
            }
            if captures.name("cn").is_some() {
                return format!("CN={REDACTED}");
            }
            if captures.name("path").is_some() {
                return REDACTED.to_owned();
            }
            match pseudonymized(captures) {
                Some(key) => pseudonyms
                    .get(&key)
                    .cloned()
                    // A value discovered in one pass but absent from the map can
                    // only mean it was never classified for pseudonymization.
                    // Masking outright is the safe direction.
                    .unwrap_or_else(|| REDACTED.to_owned()),
                None => REDACTED.to_owned(),
            }
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::portal::macos::company_portal::logs::{
        analyze_company_portal_logs, CompanyPortalLogSource,
    };

    const ADVANCED: &str = concat!(
        "2026-03-12 09:14:22:301-0700 | CompanyPortal | I | 8412 | SSO | category=Auth | activity=0x1a2b | signed in synthetic.user@example.invalid device 11111111-2222-4333-8444-555555555555\n",
        "2026-03-12 09:14:23:000-0700 | CompanyPortal | E | 8412 | Network | category=Http | activity=0x3c4d | GET https://portal.manage.invalid/api/devices?deviceId=abc failed; server cert CN=Synthetic Issuing CA, thumbprint 0123456789ABCDEF0123456789ABCDEF01234567\n",
        "2026-03-12 09:14:24:000-0700 | CompanyPortal | I | 8412 | SSO | category=Auth | activity=0x1a2b | refreshing for synthetic.user@example.invalid\n",
    );

    fn snapshot() -> super::CompanyPortalLogSnapshot {
        let mut source = CompanyPortalLogSource::captured(
            "cp",
            "CompanyPortal.log",
            ADVANCED,
            "2026-07-31T00:00:00Z",
        );
        source.sanitized_file_path =
            Some("SYNTHETIC://Library/Logs/CompanyPortal/CompanyPortal.log".to_owned());
        analyze_company_portal_logs(&[source])
    }

    #[test]
    fn identities_urls_certificates_and_guids_do_not_survive() {
        let redacted = redacted_company_portal_log_export(&snapshot());
        let text = serde_json::to_string(&redacted).expect("snapshot must serialize");
        for needle in [
            "synthetic.user@example.invalid",
            "portal.manage.invalid",
            "11111111-2222-4333-8444-555555555555",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            "Synthetic Issuing CA",
        ] {
            assert!(!text.contains(needle), "redacted export still contains {needle:?}");
        }
    }

    #[test]
    fn correlation_keys_survive() {
        let redacted = redacted_company_portal_log_export(&snapshot());
        let text = serde_json::to_string(&redacted).expect("snapshot must serialize");
        for needle in ["0x1a2b", "0x3c4d", "Auth", "Http", "SSO", "Network"] {
            assert!(text.contains(needle), "redacted export dropped {needle:?}");
        }
    }

    #[test]
    fn the_same_identity_reads_the_same_way_everywhere() {
        let redacted = redacted_company_portal_log_export(&snapshot());
        let first = &redacted.records[0].message.value;
        let third = &redacted.records[2].message.value;
        let pseudonym = first
            .split_whitespace()
            .find(|token| token.starts_with("[redacted-identity-"))
            .expect("the first record must carry an identity pseudonym");
        assert!(
            third.contains(pseudonym),
            "the same identity must pseudonymize identically; got {third:?}"
        );
    }

    #[test]
    fn the_projection_is_deterministic() {
        let snapshot = snapshot();
        let first = serde_json::to_string(&redacted_company_portal_log_export(&snapshot)).unwrap();
        let second = serde_json::to_string(&redacted_company_portal_log_export(&snapshot)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn the_projection_is_idempotent() {
        let once = redacted_company_portal_log_export(&snapshot());
        let twice = redacted_company_portal_log_export(&once);
        assert_eq!(
            serde_json::to_value(&once).unwrap(),
            serde_json::to_value(&twice).unwrap()
        );
    }

    #[test]
    fn record_order_does_not_change_the_numbering() {
        // Determinism has to survive the input arriving in a different order,
        // which is the case a per-record counter would silently get wrong.
        let forward = snapshot();
        let mut reversed = forward.clone();
        reversed.records.reverse();
        let a = redacted_company_portal_log_export(&forward);
        let b = redacted_company_portal_log_export(&reversed);
        assert_eq!(a.records[0].message.value, b.records[2].message.value);
    }

    #[test]
    fn the_sanitized_file_path_is_masked_everywhere_it_appears() {
        let redacted = redacted_company_portal_log_export(&snapshot());
        let text = serde_json::to_string(&redacted).unwrap();
        assert!(!text.contains("SYNTHETIC://Library/Logs/CompanyPortal"));
        assert_eq!(
            redacted.artifacts[0].file_path.as_ref().unwrap().value,
            REDACTED
        );
    }

    #[test]
    fn secrets_are_masked_without_pseudonymizing_them() {
        let pseudonyms = BTreeMap::new();
        assert_eq!(
            apply("access_token=abc.def.ghi and done", &pseudonyms),
            "access_token=[redacted] and done"
        );
        assert_eq!(
            apply("header Bearer abc.def", &pseudonyms),
            "header Bearer [redacted]"
        );
    }

    #[test]
    fn a_home_relative_path_in_a_message_is_masked() {
        let pseudonyms = BTreeMap::new();
        assert_eq!(
            apply("wrote ~/Library/Logs/CompanyPortal/x.log ok", &pseudonyms),
            "wrote [redacted] ok"
        );
    }
}
