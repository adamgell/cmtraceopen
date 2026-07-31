//! Company Portal Windows log record grammar, version `V1`.
//!
//! # Evidence basis
//!
//! Exactly one verbatim Company Portal `Log_<n>.log` record has ever been
//! published, from app version `12-0-0`:
//!
//! ```text
//! 2024-11-15T16:50:07.2850341Z  INFO  Event        None                      0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Configuration Manager Trace Listener] 15/11/2024 16:50:07: SCClient Information: 1: Getting all instances of CCM_Application    (Microsoft.SoftwareCenter.Client.Data.Shared.WmiDataConnectorShared at GetAllApplicationsWithType)
//! ```
//!
//! Fields are column-aligned and separated by runs of two or more spaces; the
//! message is the remainder of the line and keeps its own internal spacing.
//!
//! | # | Field | Sample | Rule |
//! |---|---|---|---|
//! | 1 | timestamp | `2024-11-15T16:50:07.2850341Z` | .NET round-trip (`"O"`) UTC instant: `T` separator, exactly 7 fractional digits, trailing `Z` |
//! | 2 | severity | `INFO` | Dedicated severity token |
//! | 3 | category | `Event` | Record category/kind |
//! | 4 | scenario | `None` | Scenario name; `None` is .NET's null rendering, not a missing field |
//! | 5 | sequence | `0` | Unsigned integer, semantics unproven |
//! | 6 | activity id | `1487dc30-…` | Hyphenated GUID |
//! | 7 | app version | `12-0-0` | Dash-separated version triple |
//! | 8 | message | `[Configuration Manager Trace Listener] …` | Remainder of the line, verbatim |
//!
//! # What this grammar deliberately does not do
//!
//! The published message embeds a nested legacy ConfigMgr trace line with its
//! own **day-first** date (`15/11/2024`), a `SCClient Information: 1:` prefix,
//! and a trailing `(Type at Method)`. None of that is stripped or
//! reinterpreted — it is message text. Only the leading `[...]` is *surfaced*
//! as a component, and even then it is left in the message because the exact
//! spacing after `]` cannot be reconstructed.

use chrono::{DateTime, SecondsFormat, Utc};

use super::models::{
    CompanyPortalAppVersion, CompanyPortalGrammarSupport, CompanyPortalSeverity,
    CompanyPortalSeverityLevel, CompanyPortalTimestamp, CompanyPortalTimestampKind,
    CompanyPortalVersionTriple,
};

/// Number of fixed fields that precede the free-text message.
const LEADING_FIELD_COUNT: usize = 7;

/// Length of a hyphenated GUID in its canonical 8-4-4-4-12 form.
const GUID_LEN: usize = 36;

/// Fractional-second digits emitted by .NET's round-trip (`"O"`) format. This
/// is fixed-width, so requiring it exactly costs nothing and is a large part of
/// what keeps the matcher off arbitrary ISO-timestamped logs.
const FRACTIONAL_DIGITS: usize = 7;

/// App versions whose record layout has actually been observed.
///
/// Only `12-0-0` has a published verbatim record. Anything else still parses
/// with the `V1` grammar — it is the only grammar there is — but is reported as
/// [`CompanyPortalGrammarSupport::Experimental`] instead of being presented as
/// a validated read.
const VALIDATED_APP_VERSIONS: &[CompanyPortalVersionTriple] = &[CompanyPortalVersionTriple {
    major: 12,
    minor: 0,
    patch: 0,
}];

/// A record header that validated against the `V1` field grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyPortalRecordFields {
    pub timestamp: CompanyPortalTimestamp,
    pub severity: CompanyPortalSeverity,
    pub category: String,
    pub scenario: String,
    pub sequence: u64,
    pub activity_id: String,
    pub app_version: CompanyPortalAppVersion,
    pub component: Option<String>,
    pub message: String,
}

/// Cheap test for "this line is trying to start a record".
///
/// Used to decide whether a line that fails full validation is a *malformed
/// record* (flush the pending record, report a parse error) or a *continuation*
/// of the record above it. Deliberately looser than [`parse_record_fields`]:
/// only the leading `YYYY-MM-DDT` shape is required.
pub fn looks_like_record_start(line: &str) -> bool {
    let bytes = line.as_bytes();
    if bytes.len() < 11 {
        return false;
    }
    bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[10] == b'T'
}

/// Parse a single physical line against the `V1` grammar.
///
/// Returns `None` unless every one of fields 1-7 validates. Callers treat
/// `None` as "preserve this line verbatim", never as "drop it".
pub fn parse_record_fields(line: &str) -> Option<CompanyPortalRecordFields> {
    // Cheap reject first: this runs on every sampled line of every file the app
    // opens, and the split below walks the whole line.
    if !looks_like_record_start(line) {
        return None;
    }

    let (fields, message) = split_leading_fields(line)?;

    let timestamp = parse_utc_instant(fields[0])?;
    let activity_id = parse_activity_id(fields[5])?;
    let triple = parse_version_triple(fields[6])?;
    let sequence: u64 = fields[4].parse().ok()?;

    // Fields 3 and 4 carry no validatable shape, but an empty column would mean
    // the split landed somewhere other than a real record boundary.
    if fields[1].is_empty() || fields[2].is_empty() || fields[3].is_empty() {
        return None;
    }

    let support = if VALIDATED_APP_VERSIONS.contains(&triple) {
        CompanyPortalGrammarSupport::Validated
    } else {
        CompanyPortalGrammarSupport::Experimental
    };

    Some(CompanyPortalRecordFields {
        timestamp,
        severity: CompanyPortalSeverity {
            raw_text: fields[1].to_string(),
            level: severity_level(fields[1]),
        },
        category: fields[2].to_string(),
        scenario: fields[3].to_string(),
        sequence,
        activity_id,
        app_version: CompanyPortalAppVersion {
            raw_text: fields[6].to_string(),
            triple,
            support,
        },
        component: leading_component(message).map(str::to_string),
        message: message.to_string(),
    })
}

/// Split a record into its seven leading fields plus the message remainder.
///
/// Fields are separated by runs of two or more spaces. A single space stays
/// inside a field, so multi-word categories and scenarios survive, and once the
/// seventh field is closed everything left is the message — including the runs
/// of spaces the published sample has in front of `(Type at Method)`.
///
/// Hand-rolled rather than a regex: this is linear with no backtracking, and it
/// runs on every sampled line of every file opened.
fn split_leading_fields(line: &str) -> Option<([&str; LEADING_FIELD_COUNT], &str)> {
    let mut fields = [""; LEADING_FIELD_COUNT];
    let mut filled = 0usize;
    let mut field_start = 0usize;
    let mut index = 0usize;
    let bytes = line.as_bytes();

    while index < bytes.len() {
        if bytes[index] != b' ' {
            index += 1;
            continue;
        }
        let run_start = index;
        while index < bytes.len() && bytes[index] == b' ' {
            index += 1;
        }
        if index - run_start < 2 {
            continue;
        }
        fields[filled] = &line[field_start..run_start];
        filled += 1;
        field_start = index;
        if filled == LEADING_FIELD_COUNT {
            return Some((fields, &line[field_start..]));
        }
    }

    // A record whose message is empty ends immediately after field 7.
    if filled == LEADING_FIELD_COUNT - 1 && field_start < line.len() {
        fields[filled] = &line[field_start..];
        return Some((fields, ""));
    }

    None
}

/// Parse field 1 as a .NET round-trip UTC instant.
fn parse_utc_instant(raw: &str) -> Option<CompanyPortalTimestamp> {
    if !has_round_trip_shape(raw) {
        return None;
    }
    // Shape alone does not make an instant real; 2024-13-45T99:99:99.0000000Z
    // has to be rejected here rather than resolved to something plausible.
    let parsed = DateTime::parse_from_rfc3339(raw).ok()?.with_timezone(&Utc);
    Some(CompanyPortalTimestamp {
        raw_text: raw.to_string(),
        // Same canonical serialization the ESP pipeline uses, so equal instants
        // render byte-identically across modules.
        normalized_utc: Some(parsed.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
        kind: CompanyPortalTimestampKind::Utc,
    })
}

/// `YYYY-MM-DDTHH:MM:SS.fffffffZ` — exactly seven fractional digits, mandatory
/// `Z`.
fn has_round_trip_shape(raw: &str) -> bool {
    // `d` marks a digit; every other byte must match literally.
    const HEAD: &str = "dddd-dd-ddTdd:dd:dd.";
    if raw.len() != HEAD.len() + FRACTIONAL_DIGITS + 1 {
        return false;
    }
    let bytes = raw.as_bytes();
    bytes[..HEAD.len()]
        .iter()
        .zip(HEAD.bytes())
        .all(|(actual, expected)| match expected {
            b'd' => actual.is_ascii_digit(),
            _ => *actual == expected,
        })
        && bytes[HEAD.len()..HEAD.len() + FRACTIONAL_DIGITS]
            .iter()
            .all(u8::is_ascii_digit)
        && bytes[raw.len() - 1] == b'Z'
}

/// Parse field 6 as a hyphenated GUID.
///
/// Every published sample is lowercase, but hex case carries no meaning, so
/// both cases are accepted; the raw text is returned unchanged either way.
fn parse_activity_id(raw: &str) -> Option<String> {
    const SHAPE: &str = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
    debug_assert_eq!(SHAPE.len(), GUID_LEN);
    if raw.len() != GUID_LEN {
        return None;
    }
    let valid = raw
        .bytes()
        .zip(SHAPE.bytes())
        .all(|(actual, expected)| match expected {
            b'x' => actual.is_ascii_hexdigit(),
            _ => actual == expected,
        });
    valid.then(|| raw.to_string())
}

/// Parse field 7 as a `<major>-<minor>-<patch>` triple.
fn parse_version_triple(raw: &str) -> Option<CompanyPortalVersionTriple> {
    let mut parts = raw.split('-');
    let major = parse_version_component(parts.next()?)?;
    let minor = parse_version_component(parts.next()?)?;
    let patch = parse_version_component(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some(CompanyPortalVersionTriple {
        major,
        minor,
        patch,
    })
}

fn parse_version_component(raw: &str) -> Option<u32> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

/// Map field 2 onto a level. Tokens outside the known vocabulary map to
/// [`CompanyPortalSeverityLevel::Unknown`] and keep their raw text, so a future
/// level never silently becomes `Information`.
fn severity_level(token: &str) -> CompanyPortalSeverityLevel {
    match token.to_ascii_uppercase().as_str() {
        "INFO" => CompanyPortalSeverityLevel::Information,
        "WARN" | "WARNING" => CompanyPortalSeverityLevel::Warning,
        "ERROR" => CompanyPortalSeverityLevel::Error,
        "VERBOSE" | "DEBUG" => CompanyPortalSeverityLevel::Verbose,
        "CRITICAL" | "FATAL" => CompanyPortalSeverityLevel::Critical,
        _ => CompanyPortalSeverityLevel::Unknown,
    }
}

/// Return the leading `[Component Name]` of a message, when the message opens
/// with a balanced bracket that contains no nested bracket.
pub fn leading_component(message: &str) -> Option<&str> {
    let rest = message.strip_prefix('[')?;
    let end = rest.find(']')?;
    let name = &rest[..end];
    if name.is_empty() || name.contains('[') {
        return None;
    }
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The only publicly published Company Portal record.
    const PUBLISHED_RECORD: &str = "2024-11-15T16:50:07.2850341Z  INFO  Event        None                      0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Configuration Manager Trace Listener] 15/11/2024 16:50:07: SCClient Information: 1: Getting all instances of CCM_Application    (Microsoft.SoftwareCenter.Client.Data.Shared.WmiDataConnectorShared at GetAllApplicationsWithType)";

    #[test]
    fn published_record_maps_to_every_documented_field() {
        let fields = parse_record_fields(PUBLISHED_RECORD).expect("published record must parse");

        assert_eq!(fields.timestamp.raw_text, "2024-11-15T16:50:07.2850341Z");
        assert_eq!(fields.timestamp.kind, CompanyPortalTimestampKind::Utc);
        assert_eq!(
            fields.timestamp.normalized_utc.as_deref(),
            Some("2024-11-15T16:50:07.285034100Z")
        );
        assert_eq!(fields.severity.raw_text, "INFO");
        assert_eq!(
            fields.severity.level,
            CompanyPortalSeverityLevel::Information
        );
        assert_eq!(fields.category, "Event");
        assert_eq!(fields.scenario, "None");
        assert_eq!(fields.sequence, 0);
        assert_eq!(fields.activity_id, "1487dc30-3bb0-46bf-98ee-76771bd9953e");
        assert_eq!(fields.app_version.raw_text, "12-0-0");
        assert_eq!(
            fields.app_version.support,
            CompanyPortalGrammarSupport::Validated
        );
        assert_eq!(
            fields.component.as_deref(),
            Some("Configuration Manager Trace Listener")
        );
    }

    #[test]
    fn message_keeps_nested_configmgr_trace_text_verbatim() {
        let fields = parse_record_fields(PUBLISHED_RECORD).expect("published record must parse");

        // The nested day-first date, the SCClient prefix, the internal run of
        // spaces, and the trailing (Type at Method) all survive untouched.
        assert_eq!(
            fields.message,
            "[Configuration Manager Trace Listener] 15/11/2024 16:50:07: SCClient Information: 1: Getting all instances of CCM_Application    (Microsoft.SoftwareCenter.Client.Data.Shared.WmiDataConnectorShared at GetAllApplicationsWithType)"
        );
        assert!(PUBLISHED_RECORD.ends_with(&fields.message));
    }

    #[test]
    fn multi_word_category_and_scenario_survive_the_split() {
        let line = "2024-11-15T16:50:07.2850341Z  INFO  App Install  Device Sync  17  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  ready";
        let fields = parse_record_fields(line).expect("multi-word columns must parse");

        assert_eq!(fields.category, "App Install");
        assert_eq!(fields.scenario, "Device Sync");
        assert_eq!(fields.sequence, 17);
        assert_eq!(fields.message, "ready");
    }

    #[test]
    fn record_with_empty_message_parses() {
        let line = "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0";
        let fields = parse_record_fields(line).expect("empty message must still parse");

        assert_eq!(fields.message, "");
        assert_eq!(fields.component, None);
    }

    #[test]
    fn unknown_app_version_is_experimental_not_rejected() {
        let line = "2026-02-03T09:15:00.1230000Z  WARNING  Event  None  4  1487dc30-3bb0-46bf-98ee-76771bd9953e  13-4-2  catalog refresh deferred";
        let fields = parse_record_fields(line).expect("unknown app version must still parse");

        assert_eq!(
            fields.app_version.support,
            CompanyPortalGrammarSupport::Experimental
        );
        assert_eq!(fields.app_version.triple.major, 13);
    }

    #[test]
    fn unknown_severity_token_is_preserved_rather_than_defaulted() {
        let line = "2024-11-15T16:50:07.2850341Z  NOTICE  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  something happened";
        let fields = parse_record_fields(line).expect("unknown severity must not fail the record");

        assert_eq!(fields.severity.raw_text, "NOTICE");
        assert_eq!(fields.severity.level, CompanyPortalSeverityLevel::Unknown);
    }

    #[test]
    fn invalid_timestamp_does_not_parse_as_a_record() {
        let line = "2024-13-45T99:99:99.0000000Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  impossible instant";
        assert_eq!(parse_record_fields(line), None);
        // It still *looks* like a record start, so the caller reports it as a
        // malformed record rather than folding it into the record above.
        assert!(looks_like_record_start(line));
    }

    #[test]
    fn missing_fractional_digits_or_zone_does_not_parse() {
        assert!(!has_round_trip_shape("2024-11-15T16:50:07Z"));
        assert!(!has_round_trip_shape("2024-11-15T16:50:07.285Z"));
        assert!(!has_round_trip_shape("2024-11-15T16:50:07.2850341"));
        assert!(!has_round_trip_shape("2024-11-15T16:50:07.2850341+00:00"));
        assert!(has_round_trip_shape("2024-11-15T16:50:07.2850341Z"));
    }

    #[test]
    fn non_guid_activity_field_does_not_parse() {
        let line = "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  not-a-guid-at-all-not-a-guid-at-all  12-0-0  message";
        assert_eq!(parse_record_fields(line), None);
    }

    #[test]
    fn dotted_version_field_does_not_parse() {
        let line = "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12.0.0  message";
        assert_eq!(parse_record_fields(line), None);
    }

    #[test]
    fn single_spaced_line_does_not_parse() {
        // Fields are column-aligned; a single-spaced line is a different format.
        let line = "2024-11-15T16:50:07.2850341Z INFO Event None 0 1487dc30-3bb0-46bf-98ee-76771bd9953e 12-0-0 message";
        assert_eq!(parse_record_fields(line), None);
    }

    #[test]
    fn leading_component_requires_a_balanced_first_bracket() {
        assert_eq!(leading_component("[Sync] started"), Some("Sync"));
        assert_eq!(leading_component("[Sync]"), Some("Sync"));
        assert_eq!(leading_component("started [Sync]"), None);
        assert_eq!(leading_component("[unterminated"), None);
        assert_eq!(leading_component("[] empty"), None);
        assert_eq!(leading_component("[[nested]] value"), None);
    }

    #[test]
    fn record_start_shape_rejects_other_timestamp_styles() {
        assert!(looks_like_record_start(
            "2024-11-15T16:50:07.2850341Z  INFO"
        ));
        assert!(!looks_like_record_start("2024-11-15 16:50:07 message"));
        assert!(!looks_like_record_start("   at Microsoft.Foo.Bar()"));
        assert!(!looks_like_record_start(""));
    }
}
