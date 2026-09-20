//! Rendering event descriptions from captured provider metadata.
//!
//! An event on disk carries values, not sentences. The sentence lives in the provider's message
//! table, which is why opening someone else's `.evtx` on your own machine shows raw `EventData`
//! and no description: the provider is not registered there. On macOS or Linux there is no
//! provider registry at all, so the problem is total rather than partial.
//!
//! EventLogExpert solves this by capturing provider metadata into a portable database. This module
//! is the rendering half of that: it takes already-deserialized metadata plus an event's insertion
//! strings and produces the description. It is pure, so it works identically on every platform,
//! which is the entire point. Reading the database file is the host layer's job.
//!
//! The format was reverse engineered from a real database built on Windows 11; the full spec is in
//! issue #539.

use std::collections::{BTreeMap, BTreeSet};

use serde::ser::{Error as _, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Reinterprets a signed integer as unsigned, preserving the bit pattern.
///
/// The metadata is serialized by a .NET tool, which writes `long` and `int`. A keyword mask with
/// the top bit set therefore appears as a negative number: the reserved keyword
/// `0x8000000000000000` is written as `-9223372036854775808`. Deserializing straight into `u64`
/// rejects those, which in practice meant the Microsoft-Windows-DeviceManagement provider, among
/// many others, failed to load at all.
fn signed_as_u64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    Ok(i64::deserialize(deserializer)? as u64)
}

fn signed_as_u64_vec<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u64>, D::Error> {
    Ok(Vec::<i64>::deserialize(deserializer)?
        .into_iter()
        .map(|value| value as u64)
        .collect())
}

/// Writes an unsigned value back in the signed form the source used.
///
/// Needed because these types are public and derive `Serialize`. Without it a value round-trips
/// asymmetrically: `-9223372036854775808` deserializes to `0x8000000000000000`, serializes as
/// `9223372036854775808`, and then fails to deserialize again because the reader expects `i64`.
/// Anything that persisted or forwarded this metadata could not read its own output back.
fn u64_as_signed<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_i64(*value as i64)
}

fn u64_vec_as_signed<S: Serializer>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error> {
    let mut sequence = serializer.serialize_seq(Some(values.len()))?;
    for value in values {
        sequence.serialize_element(&(*value as i64))?;
    }
    sequence.end()
}

/// EventLogExpert stores the low message identifier as a signed Int16 even though the in-memory
/// model keeps the complete low-word value as `u32`.
fn short_id_as_signed<S: Serializer>(value: &u32, serializer: S) -> Result<S::Ok, S::Error> {
    if *value > u16::MAX as u32 {
        return Err(S::Error::custom(
            "ShortId must fit an unsigned 16-bit low word",
        ));
    }
    serializer.serialize_i64((*value as u16 as i16) as i64)
}

fn signed_as_short_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let value = i64::deserialize(deserializer)?;
    if !(-32768..=32767).contains(&value) {
        return Err(serde::de::Error::custom(
            "ShortId must be a signed Int16 value",
        ));
    }
    Ok((value as i16 as u16) as u32)
}

/// One event definition from a provider's manifest.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ProviderEvent {
    /// Message template with `%1`-style insertion points.
    #[serde(default)]
    pub description: Option<String>,
    /// Event ID.
    pub id: u32,
    /// Version of this event's definition. Providers can define several versions of one ID.
    #[serde(default)]
    pub version: u32,
    /// Channel the event belongs to.
    #[serde(default)]
    pub log_name: Option<String>,
    /// Level value.
    #[serde(default)]
    pub level: Option<u32>,
    /// Task value.
    #[serde(default)]
    pub task: Option<u32>,
    /// Opcode value.
    #[serde(default)]
    pub opcode: Option<u32>,
    /// Keyword bitmask values.
    #[serde(
        default,
        deserialize_with = "signed_as_u64_vec",
        serialize_with = "u64_vec_as_signed"
    )]
    pub keywords: Vec<u64>,
    /// The manifest template, which declares each field's name and type.
    #[serde(default)]
    pub template: Option<String>,
}

/// An entry from the provider's message table.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ProviderMessage {
    /// Full message identifier as the provider declares it.
    #[serde(
        default,
        deserialize_with = "signed_as_u64",
        serialize_with = "u64_as_signed"
    )]
    pub raw_id: u64,
    /// Low bits of `raw_id`, which is what most references use.
    #[serde(
        default,
        deserialize_with = "signed_as_short_id",
        serialize_with = "short_id_as_signed"
    )]
    pub short_id: u32,
    /// Provider name owning this message row, when persisted by EventLogExpert.
    #[serde(default)]
    pub provider_name: Option<String>,
    /// Manifest template associated with this message, when present.
    #[serde(default)]
    pub template: Option<String>,
    /// EventLogExpert message tag, when present.
    #[serde(default)]
    pub tag: Option<String>,
    /// EventLogExpert log-link metadata, when present.
    #[serde(default)]
    pub log_link: Option<String>,
    /// The message text.
    #[serde(default)]
    pub text: Option<String>,
}

/// Everything captured about one provider.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ProviderMetadata {
    /// Provider name, matching `System/Provider/@Name`.
    #[serde(default)]
    pub provider_name: String,
    /// Event definitions.
    #[serde(default)]
    pub events: Vec<ProviderEvent>,
    /// Message table.
    #[serde(default)]
    pub messages: Vec<ProviderMessage>,
    /// Level value to name.
    #[serde(default)]
    pub levels: BTreeMap<String, String>,
    /// Task value to name.
    #[serde(default)]
    pub tasks: BTreeMap<String, String>,
    /// Keyword bit to name.
    #[serde(default)]
    pub keywords: BTreeMap<String, String>,
    /// Opcode value to name.
    #[serde(default)]
    pub opcodes: BTreeMap<String, String>,
    /// Categories that were unavailable in the source publisher metadata.
    ///
    /// An absent category is distinct from a present category with zero entries.
    #[serde(default)]
    pub unavailable_categories: BTreeSet<String>,
    /// Windows build the metadata was captured from, so a mismatch is visible rather than assumed.
    #[serde(default)]
    pub source_os_build: Option<u32>,
}

fn compare_event_stable(left: &ProviderEvent, right: &ProviderEvent) -> std::cmp::Ordering {
    left.description
        .as_deref()
        .cmp(&right.description.as_deref())
        .then_with(|| left.log_name.as_deref().cmp(&right.log_name.as_deref()))
        .then_with(|| left.template.as_deref().cmp(&right.template.as_deref()))
        .then_with(|| left.level.cmp(&right.level))
        .then_with(|| left.task.cmp(&right.task))
        .then_with(|| left.opcode.cmp(&right.opcode))
        .then_with(|| left.keywords.cmp(&right.keywords))
}

impl ProviderMetadata {
    /// Finds the definition for `event_id`, preferring an exact `version` match and channel match.
    ///
    /// Providers legitimately define several versions of one ID and can reuse that ID on
    /// different channels. Picking a definition from a sibling channel renders a description whose
    /// insertion points do not line up with the event's fields, which reads as plausible but wrong
    /// text, so channel and exact version matches win and the highest known version is only a
    /// fallback.
    pub fn event(
        &self,
        event_id: u32,
        version: Option<u32>,
        log_name: Option<&str>,
    ) -> Option<&ProviderEvent> {
        let exact_channel_available = log_name.is_some_and(|actual| {
            self.events.iter().any(|event| {
                event.id == event_id
                    && event
                        .log_name
                        .as_deref()
                        .is_some_and(|expected| expected.eq_ignore_ascii_case(actual))
            })
        });
        let candidates = self.events.iter().filter(|event| {
            event.id == event_id
                && match (event.log_name.as_deref(), log_name, exact_channel_available) {
                    (Some(expected), Some(actual), true) => expected.eq_ignore_ascii_case(actual),
                    (None, Some(_), false) => true,
                    (None, None, _) => true,
                    _ => false,
                }
        });
        if let Some(version) = version {
            if let Some(exact) = candidates
                .clone()
                .filter(|event| event.version == version)
                .max_by(|left, right| compare_event_stable(left, right))
            {
                return Some(exact);
            }
        }
        candidates.max_by(|left, right| {
            left.version
                .cmp(&right.version)
                .then_with(|| compare_event_stable(left, right))
        })
    }
    /// Renders the selected event definition without consulting a Windows registry.
    ///
    /// Captured provider metadata is portable; callers can use this on macOS, Linux, and wasm
    /// builds exactly as on Windows.
    pub fn render_event_description(
        &self,
        event_id: u32,
        version: Option<u32>,
        log_name: Option<&str>,
        insertions: &[String],
    ) -> Option<RenderedDescription> {
        let template = self
            .event(event_id, version, log_name)?
            .description
            .as_deref()?;
        Some(render_description(template, insertions))
    }

    /// Resolves a task value to its name.
    pub fn task_name(&self, task: u32) -> Option<&str> {
        self.tasks.get(&task.to_string()).map(String::as_str)
    }

    /// Resolves an opcode value to its name.
    pub fn opcode_name(&self, opcode: u32) -> Option<&str> {
        self.opcodes.get(&opcode.to_string()).map(String::as_str)
    }

    /// Resolves a keyword bitmask to the names of the bits that are set.
    ///
    /// Only bits the provider declares are named. Undeclared bits are ignored rather than reported
    /// as unknown keywords, because the reserved high bits are set by the system on most events.
    pub fn keyword_names(&self, mask: u64) -> Vec<&str> {
        // Sorted by bit value, not by key. The map is keyed by the decimal bit as a string, so its
        // own order is lexicographic: "1", "16", "2", "32", "4". Returning that would put the names
        // in an order matching neither the mask nor the provider's manifest, which reads as
        // meaningful when it is an artefact of string comparison.
        let mut matched: Vec<(u64, &str)> = self
            .keywords
            .iter()
            .filter_map(|(raw_bit, name)| {
                let bit = raw_bit.parse::<u64>().ok()?;
                (bit != 0 && mask & bit == bit).then_some((bit, name.as_str()))
            })
            .collect();
        matched.sort_by_key(|(bit, _)| *bit);
        matched.into_iter().map(|(_, name)| name).collect()
    }
}

/// The outcome of rendering a description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedDescription {
    /// The rendered text.
    pub text: String,
    /// Insertion numbers the template referenced but the event did not supply.
    ///
    /// Non-empty means `text` still contains those `%n` markers. They are left visible rather than
    /// blanked, so a partially rendered description cannot be mistaken for a complete one.
    pub missing_insertions: Vec<u32>,
}

impl RenderedDescription {
    /// True when every insertion point was filled.
    pub fn is_complete(&self) -> bool {
        self.missing_insertions.is_empty()
    }
}

/// Renders a provider message template against an event's insertion strings.
///
/// `insertions` are the event's `EventData` values in document order, so `%1` is the first.
///
/// Windows message syntax is much larger than this; only the parts that appear in captured event
/// descriptions are handled. `%%` is a literal percent and `%n` selects an insertion. Anything else
/// is passed through untouched rather than guessed at, because inventing a rendering is worse than
/// showing the provider's raw text.
pub fn render_description(template: &str, insertions: &[String]) -> RenderedDescription {
    let mut text = String::with_capacity(template.len());
    let mut missing = Vec::new();
    let mut chars = template.char_indices().peekable();

    while let Some((_, character)) = chars.next() {
        if character != '%' {
            text.push(character);
            continue;
        }

        match chars.peek().map(|(_, c)| *c) {
            // "%%" is an escaped percent sign.
            Some('%') => {
                chars.next();
                text.push('%');
            }
            Some(digit) if digit.is_ascii_digit() => {
                let mut number = String::new();
                while let Some((_, c)) = chars.peek() {
                    if c.is_ascii_digit() {
                        number.push(*c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let index: u32 = number.parse().unwrap_or(0);
                match index
                    .checked_sub(1)
                    .and_then(|zero_based| insertions.get(zero_based as usize))
                {
                    Some(value) => text.push_str(value),
                    None => {
                        text.push('%');
                        text.push_str(&number);
                        if !missing.contains(&index) {
                            missing.push(index);
                        }
                    }
                }
            }
            // Not an insertion point, so the percent is literal content.
            _ => text.push('%'),
        }
    }

    RenderedDescription {
        text,
        missing_insertions: missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insertions(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn renders_a_real_mdm_description() {
        // Verbatim from the DeviceManagement-Enterprise-Diagnostics-Provider metadata captured on
        // Windows 11, event id 2.
        let template = "MDM Enroll: Certificate policy create message failed. Result: (%1).";
        let rendered = render_description(template, &insertions(&["0x80180005"]));
        assert_eq!(
            rendered.text,
            "MDM Enroll: Certificate policy create message failed. Result: (0x80180005)."
        );
        assert!(rendered.is_complete());
    }

    #[test]
    fn insertions_are_one_based_and_ordered() {
        let rendered = render_description("%1 then %2 then %3", &insertions(&["a", "b", "c"]));
        assert_eq!(rendered.text, "a then b then c");
    }

    #[test]
    fn a_two_digit_insertion_is_not_read_as_two_single_digit_ones() {
        // "%10" must select the tenth value, not the first followed by a literal zero.
        let values = insertions(&["1", "2", "3", "4", "5", "6", "7", "8", "9", "TENTH"]);
        assert_eq!(render_description("%10", &values).text, "TENTH");
    }

    #[test]
    fn a_double_percent_is_a_literal_percent() {
        let rendered = render_description("100%% complete", &[]);
        assert_eq!(rendered.text, "100% complete");
        assert!(rendered.is_complete());
    }

    #[test]
    fn a_missing_insertion_stays_visible_and_is_reported() {
        let rendered = render_description("value is %1 and %2", &insertions(&["only-one"]));
        assert_eq!(rendered.text, "value is only-one and %2");
        assert_eq!(rendered.missing_insertions, vec![2]);
        assert!(!rendered.is_complete());
    }

    #[test]
    fn a_percent_that_is_not_an_insertion_is_left_alone() {
        let rendered = render_description("50% of %1", &insertions(&["disk"]));
        assert_eq!(rendered.text, "50% of disk");
        assert!(rendered.is_complete());
    }

    #[test]
    fn a_trailing_percent_does_not_panic() {
        assert_eq!(render_description("done %", &[]).text, "done %");
    }

    #[test]
    fn insertion_zero_is_reported_rather_than_wrapping() {
        // %0 has no meaning as an insertion; treating it as index -1 would panic or wrap.
        let rendered = render_description("%0", &insertions(&["a"]));
        assert_eq!(rendered.text, "%0");
        assert_eq!(rendered.missing_insertions, vec![0]);
    }

    fn metadata() -> ProviderMetadata {
        ProviderMetadata {
            provider_name: "Test-Provider".into(),
            events: vec![
                ProviderEvent {
                    id: 100,
                    version: 0,
                    description: Some("v0 %1".into()),
                    ..Default::default()
                },
                ProviderEvent {
                    id: 100,
                    version: 1,
                    description: Some("v1 %1".into()),
                    ..Default::default()
                },
            ],
            tasks: BTreeMap::from([("1".into(), "Enrollment".into())]),
            opcodes: BTreeMap::from([("11".into(), "Start".into())]),
            keywords: BTreeMap::from([
                ("1".into(), "Error".into()),
                ("2".into(), "Debug".into()),
                ("4".into(), "Trace".into()),
            ]),
            ..Default::default()
        }
    }
    #[test]
    fn captured_metadata_renders_the_requested_event_version_without_registry() {
        let rendered = metadata()
            .render_event_description(100, Some(0), None, &insertions(&["portable"]))
            .expect("event description");
        assert_eq!(rendered.text, "v0 portable");
        assert!(rendered.is_complete());
    }

    #[test]
    fn an_exact_version_match_wins() {
        let meta = metadata();
        assert_eq!(
            meta.event(100, Some(0), None)
                .and_then(|e| e.description.as_deref()),
            Some("v0 %1")
        );
    }

    #[test]
    fn an_unknown_version_falls_back_to_the_highest_known() {
        // Better a definition from a newer manifest than none, but never a silently wrong one when
        // the exact version is available.
        let meta = metadata();
        assert_eq!(
            meta.event(100, Some(7), None)
                .and_then(|e| e.description.as_deref()),
            Some("v1 %1")
        );
        assert_eq!(
            meta.event(100, None, None)
                .and_then(|e| e.description.as_deref()),
            Some("v1 %1")
        );
    }

    #[test]
    fn an_unknown_event_id_resolves_to_nothing() {
        assert!(metadata().event(999, None, None).is_none());
    }

    #[test]
    fn exact_channel_match_beats_wildcard_at_the_same_version() {
        let metadata = ProviderMetadata {
            events: vec![
                ProviderEvent {
                    id: 42,
                    version: 3,
                    description: Some("wildcard".into()),
                    ..Default::default()
                },
                ProviderEvent {
                    id: 42,
                    version: 3,
                    log_name: Some("Provider/Admin".into()),
                    description: Some("admin".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            metadata
                .event(42, Some(3), Some("provider/admin"))
                .and_then(|event| event.description.as_deref()),
            Some("admin")
        );
    }

    #[test]
    fn channel_tier_precedes_version_fallback() {
        let metadata = ProviderMetadata {
            events: vec![
                ProviderEvent {
                    id: 43,
                    version: 9,
                    description: Some("wildcard-newer".into()),
                    ..Default::default()
                },
                ProviderEvent {
                    id: 43,
                    version: 2,
                    log_name: Some("Provider/Admin".into()),
                    description: Some("admin-older".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            metadata
                .event(43, Some(7), Some("Provider/Admin"))
                .and_then(|event| event.description.as_deref()),
            Some("admin-older")
        );
    }

    #[test]
    fn event_lookup_requires_the_captured_channel() {
        let metadata = ProviderMetadata {
            events: vec![
                ProviderEvent {
                    id: 42,
                    version: 0,
                    log_name: Some("Provider/Admin".into()),
                    description: Some("admin".into()),
                    ..Default::default()
                },
                ProviderEvent {
                    id: 42,
                    version: 0,
                    log_name: Some("Provider/Operational".into()),
                    description: Some("operational".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            metadata
                .event(42, Some(0), Some("Provider/Admin"))
                .and_then(|event| event.description.as_deref()),
            Some("admin")
        );
        assert_eq!(
            metadata
                .event(42, Some(0), Some("Provider/Operational"))
                .and_then(|event| event.description.as_deref()),
            Some("operational")
        );
        assert!(metadata
            .event(42, Some(0), Some("Provider/Debug"))
            .is_none());
    }

    #[test]
    fn task_and_opcode_names_resolve() {
        let meta = metadata();
        assert_eq!(meta.task_name(1), Some("Enrollment"));
        assert_eq!(meta.task_name(2), None);
        assert_eq!(meta.opcode_name(11), Some("Start"));
    }

    #[test]
    fn keyword_names_report_only_declared_bits_that_are_set() {
        let meta = metadata();
        assert_eq!(meta.keyword_names(0b101), vec!["Error", "Trace"]);
        assert_eq!(meta.keyword_names(0), Vec::<&str>::new());
    }

    #[test]
    fn undeclared_keyword_bits_are_ignored_rather_than_reported_as_unknown() {
        // Windows sets reserved high bits on most events; surfacing those as unknown keywords
        // would make almost every event look anomalous.
        let meta = metadata();
        assert_eq!(meta.keyword_names(0x8000_0000_0000_0001), vec!["Error"]);
    }

    #[test]
    fn a_high_bit_keyword_written_as_a_negative_number_round_trips() {
        // The metadata is written by a .NET tool, so 0x8000000000000000 appears as
        // -9223372036854775808. Rejecting that made whole providers fail to load.
        let json = r#"{"Id":1,"Keywords":[-9223372036854775808,576460752303423488]}"#;
        let event: ProviderEvent = serde_json::from_str(json).expect("deserializes");
        assert_eq!(event.keywords[0], 0x8000_0000_0000_0000);
        assert_eq!(event.keywords[1], 576_460_752_303_423_488);
    }

    #[test]
    fn short_message_ids_use_signed_int16_wire_values() {
        let json = r#"{"RawId":-2147221478,"ShortId":-32768,"Text":"x"}"#;
        let message: ProviderMessage = serde_json::from_str(json).expect("deserializes");
        assert_eq!(message.raw_id, (-2_147_221_478_i64) as u64);
        assert_eq!(message.short_id, 0x8000);
        let encoded = serde_json::to_string(&message).expect("serializes");
        assert!(encoded.contains(r#""ShortId":-32768"#));

        let all_bits = ProviderMessage {
            short_id: 0xffff,
            ..ProviderMessage::default()
        };
        let encoded = serde_json::to_string(&all_bits).expect("serializes");
        assert!(encoded.contains(r#""ShortId":-1"#));
        let decoded: ProviderMessage = serde_json::from_str(&encoded).expect("round-trips");
        assert_eq!(decoded.short_id, 0xffff);
    }
    #[test]
    fn short_message_ids_accept_signed_int16_boundaries() {
        for (wire_value, expected_short_id) in [(-32768, 0x8000), (32767, 0x7fff)] {
            let json = format!(r#"{{"RawId":1,"ShortId":{wire_value},"Text":"x"}}"#);
            let message: ProviderMessage = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(message.short_id, expected_short_id);
        }
    }

    #[test]
    fn short_message_ids_reject_values_outside_signed_int16() {
        for wire_value in [32768, -32769] {
            let json = format!(r#"{{"RawId":1,"ShortId":{wire_value},"Text":"x"}}"#);
            assert!(
                serde_json::from_str::<ProviderMessage>(&json).is_err(),
                "out-of-range ShortId should be rejected: {wire_value}"
            );
        }
    }

    #[test]
    fn short_message_ids_reject_in_memory_values_wider_than_a_low_word() {
        let message = ProviderMessage {
            short_id: u16::MAX as u32 + 1,
            ..ProviderMessage::default()
        };

        let error = serde_json::to_string(&message)
            .expect_err("serializing a ShortId wider than 16 bits must fail");
        assert!(error.to_string().contains("ShortId"));
    }

    #[test]
    fn ordinary_positive_values_are_unaffected() {
        let json = r#"{"RawId":1342177282,"ShortId":2,"Text":"Error"}"#;
        let message: ProviderMessage = serde_json::from_str(json).expect("deserializes");
        assert_eq!(message.raw_id, 1_342_177_282);
        assert_eq!(message.short_id, 2);
    }

    #[test]
    fn a_keyword_mask_with_the_reserved_high_bit_still_resolves_declared_names() {
        let meta = metadata();
        assert_eq!(
            meta.keyword_names(0x8000_0000_0000_0000_u64 | 1),
            vec!["Error"]
        );
    }

    #[test]
    fn metadata_deserializes_from_the_captured_shape() {
        // Field names as they appear in a real provider database row.
        let json = r#"{
            "ProviderName": "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
            "Events": [{
                "Description": "MDM Enroll: failed. Result: (%1).",
                "Id": 2, "Version": 0, "Level": 2, "Task": 0, "Opcode": 0,
                "Keywords": [576460752303423488],
                "LogName": "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Enrollment",
                "Template": "<template><data name=\"HRESULT\" inType=\"win:HexInt32\"/></template>"
            }],
            "Tasks": {"1": "None"},
            "Keywords": {"1": "Error"},
            "SourceOsBuild": 26200
        }"#;
        let meta: ProviderMetadata = serde_json::from_str(json).expect("deserializes");
        assert_eq!(meta.events.len(), 1);
        assert_eq!(meta.events[0].id, 2);
        assert_eq!(meta.events[0].keywords, vec![576_460_752_303_423_488]);
        assert_eq!(meta.source_os_build, Some(26200));
        assert_eq!(meta.task_name(1), Some("None"));
    }

    #[test]
    fn keyword_names_come_back_in_bit_order_not_key_order() {
        // The map is keyed by the decimal bit as a string, so its own order is "1", "16", "2",
        // "32", "4". Returning that reads as meaningful when it is an artefact of string sorting.
        let mut keywords = std::collections::BTreeMap::new();
        for (bit, name) in [
            ("1", "Startup"),
            ("2", "Shutdown"),
            ("4", "Network"),
            ("16", "Disk"),
            ("32", "Memory"),
        ] {
            keywords.insert(bit.to_string(), name.to_string());
        }
        let metadata = ProviderMetadata {
            keywords,
            ..Default::default()
        };

        assert_eq!(
            metadata.keyword_names(0b11_0111),
            vec!["Startup", "Shutdown", "Network", "Disk", "Memory"]
        );
    }

    #[test]
    fn only_the_bits_present_in_the_mask_are_named() {
        let mut keywords = std::collections::BTreeMap::new();
        keywords.insert("1".to_string(), "Startup".to_string());
        keywords.insert("16".to_string(), "Disk".to_string());
        keywords.insert("32".to_string(), "Memory".to_string());
        let metadata = ProviderMetadata {
            keywords,
            ..Default::default()
        };

        assert_eq!(metadata.keyword_names(0b10_0001), vec!["Startup", "Memory"]);
        assert!(metadata.keyword_names(0).is_empty());
    }

    #[test]
    fn a_top_bit_keyword_survives_a_serialization_round_trip() {
        // The .NET source writes these signed. Deserializing accepted that and serializing wrote
        // the unsigned form, so the type could not read its own output back: anything that
        // persisted or forwarded provider metadata broke on the reserved keyword alone.
        let json = r#"{"Id":1,"Version":0,"Keywords":[-9223372036854775808]}"#;
        let event: ProviderEvent = serde_json::from_str(json).expect("deserializes");
        assert_eq!(event.keywords, vec![0x8000_0000_0000_0000]);

        let written = serde_json::to_string(&event).expect("serializes");
        assert!(
            written.contains("-9223372036854775808"),
            "the signed form the source used must be preserved: {written}"
        );

        let again: ProviderEvent = serde_json::from_str(&written).expect("re-reads its own output");
        assert_eq!(again, event);
    }

    #[test]
    fn an_ordinary_keyword_is_unchanged_by_the_round_trip() {
        let json = r#"{"Id":1,"Version":0,"Keywords":[16]}"#;
        let event: ProviderEvent = serde_json::from_str(json).expect("deserializes");
        let written = serde_json::to_string(&event).expect("serializes");
        assert!(written.contains("[16]"), "{written}");
        let again: ProviderEvent = serde_json::from_str(&written).expect("re-reads");
        assert_eq!(again.keywords, vec![16]);
    }
}
