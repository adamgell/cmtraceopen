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

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

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

/// Reinterprets a signed integer as an unsigned 32-bit value.
///
/// Message identifiers above `0x7FFFFFFF` are written negative for the same reason.
fn signed_as_u32<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    Ok(i64::deserialize(deserializer)? as u32)
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
    #[serde(default, deserialize_with = "signed_as_u64_vec")]
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
    #[serde(default, deserialize_with = "signed_as_u64")]
    pub raw_id: u64,
    /// Low bits of `raw_id`, which is what most references use.
    #[serde(default, deserialize_with = "signed_as_u32")]
    pub short_id: u32,
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
    /// Task value to name.
    #[serde(default)]
    pub tasks: BTreeMap<String, String>,
    /// Keyword bit to name.
    #[serde(default)]
    pub keywords: BTreeMap<String, String>,
    /// Opcode value to name.
    #[serde(default)]
    pub opcodes: BTreeMap<String, String>,
    /// Windows build the metadata was captured from, so a mismatch is visible rather than assumed.
    #[serde(default)]
    pub source_os_build: Option<u32>,
}

impl ProviderMetadata {
    /// Finds the definition for `event_id`, preferring an exact `version` match.
    ///
    /// Providers legitimately define several versions of one ID. Picking the wrong one renders a
    /// description whose insertion points do not line up with the event's fields, which reads as
    /// plausible but wrong text, so the exact version wins and the highest known version is only a
    /// fallback.
    pub fn event(&self, event_id: u32, version: Option<u32>) -> Option<&ProviderEvent> {
        let candidates = self.events.iter().filter(|event| event.id == event_id);
        if let Some(version) = version {
            if let Some(exact) = candidates.clone().find(|event| event.version == version) {
                return Some(exact);
            }
        }
        candidates.max_by_key(|event| event.version)
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
    fn an_exact_version_match_wins() {
        let meta = metadata();
        assert_eq!(
            meta.event(100, Some(0))
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
            meta.event(100, Some(7))
                .and_then(|e| e.description.as_deref()),
            Some("v1 %1")
        );
        assert_eq!(
            meta.event(100, None).and_then(|e| e.description.as_deref()),
            Some("v1 %1")
        );
    }

    #[test]
    fn an_unknown_event_id_resolves_to_nothing() {
        assert!(metadata().event(999, None).is_none());
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
    fn a_negative_message_id_is_reinterpreted_rather_than_rejected() {
        let json = r#"{"RawId":-2147221478,"ShortId":-2147221478,"Text":"x"}"#;
        let message: ProviderMessage = serde_json::from_str(json).expect("deserializes");
        assert_eq!(message.raw_id, (-2_147_221_478_i64) as u64);
        assert_eq!(message.short_id, (-2_147_221_478_i64) as u32);
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
}
