//! Applying a map to an event.
//!
//! Resolution is deliberately non-fatal. Maps are written against a provider's superset of
//! fields, so an individual event legitimately omits some of them. A missing field is a coverage
//! state, reported on [`MappedValue::unresolved`], never an error and never silently blank.

use std::collections::BTreeMap;

use super::model::{EventMap, MapEntry, MapProperty};
use super::node::EventNode;

/// One normalized column produced from an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedValue {
    /// The column this fills.
    pub property: MapProperty,
    /// The rendered text, with every resolved placeholder substituted.
    pub text: String,
    /// Variables whose paths matched nothing, in template order.
    ///
    /// Non-empty means `text` still contains their raw `%Name%` placeholders. Callers decide
    /// whether to show the column, hide it, or flag it; the engine refuses to guess by blanking
    /// the placeholder, which would present a partial value as a complete one.
    pub unresolved: Vec<String>,
}

impl MappedValue {
    /// True when every placeholder in the template resolved.
    pub fn is_complete(&self) -> bool {
        self.unresolved.is_empty()
    }
}

/// The full result of applying a map to one event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MappedEvent {
    /// Columns in map order.
    pub values: Vec<MappedValue>,
    /// Path expressions that failed to parse, as `(variable, expression)`.
    ///
    /// A malformed expression is a defect in the map file rather than in the event, so it is
    /// surfaced separately instead of being reported as a missing field.
    pub invalid_paths: Vec<(String, String)>,
}

impl MappedEvent {
    /// Returns the text written to `property`, if the map produced it.
    pub fn value_for(&self, property: &MapProperty) -> Option<&str> {
        self.values
            .iter()
            .find(|value| &value.property == property)
            .map(|value| value.text.as_str())
    }
}

/// Applies every entry of `map` to `event`, which must be the `Event` element.
pub fn apply_map(map: &EventMap, event: &EventNode) -> MappedEvent {
    let mut result = MappedEvent::default();
    for entry in &map.maps {
        result
            .values
            .push(apply_entry(map, entry, event, &mut result.invalid_paths));
    }
    result
}

fn apply_entry(
    map: &EventMap,
    entry: &MapEntry,
    event: &EventNode,
    invalid_paths: &mut Vec<(String, String)>,
) -> MappedValue {
    let template = entry.property_value.as_str();
    let mut resolved: BTreeMap<&str, String> = BTreeMap::new();

    // Paths and placeholders are parsed once per map, not once per record. This runs for every
    // event on a channel, so re-parsing an expression that cannot change was the dominant cost.
    for (binding, compiled) in entry.values.iter().zip(entry.compiled()) {
        // Checked against the original template, never against partially rendered output.
        if !template.contains(&compiled.placeholder) {
            continue;
        }

        let value = match &compiled.path {
            Some(path) => path.evaluate(event).map(|value| value.into_owned()),
            None => {
                let defect = (binding.name.clone(), binding.value.clone());
                if !invalid_paths.contains(&defect) {
                    invalid_paths.push(defect);
                }
                None
            }
        };

        let translated = value.and_then(|raw| match map.lookup_for(&binding.name) {
            Some(lookup) => lookup.translate(&raw),
            None => Some(raw),
        });

        if let Some(translated) = translated {
            resolved.insert(binding.name.as_str(), translated);
        }
    }

    // A binding that failed to resolve is simply absent from the map, so the renderer reports it
    // alongside placeholders the map never bound at all. Both are the same thing to a reader.
    let (text, unresolved) = render(template, &resolved);

    MappedValue {
        property: entry.property.clone(),
        text,
        unresolved,
    }
}

/// Renders `template` in one left-to-right pass, returning the text and any unfilled placeholders.
///
/// Single-pass matters for correctness, not just speed. Event field content is untrusted: a field
/// whose value is literally `%user%` must not become a substitution target for a later binding,
/// which is exactly what repeated `str::replace` over accumulating output would do.
fn render(template: &str, values: &BTreeMap<&str, String>) -> (String, Vec<String>) {
    let mut out = String::with_capacity(template.len());
    let mut unresolved: Vec<String> = Vec::new();
    let mut rest = template;

    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];

        let Some(end) = after.find('%') else {
            // Unpaired '%': the remainder is literal text.
            out.push_str(&rest[start..]);
            return (out, unresolved);
        };

        let name = &after[..end];
        if name.is_empty() || name.contains(char::is_whitespace) {
            // Not a placeholder. Emit the opening '%' and resume at the character after it, so the
            // closing '%' stays available as the opening delimiter of a real placeholder that
            // follows, as in "50% off %Cost%".
            out.push('%');
            rest = after;
            continue;
        }

        match values.get(name) {
            // The substituted value is appended to `out` and never revisited.
            Some(value) => out.push_str(value),
            None => {
                out.push('%');
                out.push_str(name);
                out.push('%');
                if !unresolved.iter().any(|existing| existing == name) {
                    unresolved.push(name.to_string());
                }
            }
        }
        rest = &after[end + 1..];
    }

    out.push_str(rest);
    (out, unresolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventmap::model::{Lookup, MapEntry, ValueBinding};
    use std::collections::BTreeMap;

    fn event() -> EventNode {
        EventNode::new("Event").with_child(
            EventNode::new("EventData")
                .with_child(
                    EventNode::new("Data")
                        .with_attribute("Name", "SubjectUserName")
                        .with_text("adam"),
                )
                .with_child(
                    EventNode::new("Data")
                        .with_attribute("Name", "SubjectDomainName")
                        .with_text("TEST"),
                )
                .with_child(
                    EventNode::new("Data")
                        .with_attribute("Name", "BusType")
                        .with_text("7"),
                ),
        )
    }

    fn binding(name: &str, field: &str) -> ValueBinding {
        ValueBinding {
            name: name.to_string(),
            value: format!(r#"/Event/EventData/Data[@Name="{field}"]"#),
        }
    }

    fn map_with(entries: Vec<MapEntry>, lookups: Vec<Lookup>) -> EventMap {
        EventMap {
            author: None,
            description: None,
            event_id: 4624,
            channel: "Security".to_string(),
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            maps: entries,
            lookups,
        }
    }

    #[test]
    fn substitutes_multiple_placeholders_in_one_template() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::UserName,
                "%domain%\\%user%".to_string(),
                vec![
                    binding("domain", "SubjectDomainName"),
                    binding("user", "SubjectUserName"),
                ],
            )],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(mapped.value_for(&MapProperty::UserName), Some("TEST\\adam"));
        assert!(mapped.values[0].is_complete());
    }

    #[test]
    fn missing_field_is_reported_and_leaves_the_placeholder_visible() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::PayloadData(1),
                "LogonType %LogonType%".to_string(),
                vec![binding("LogonType", "LogonType")],
            )],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        let value = &mapped.values[0];
        assert_eq!(value.unresolved, vec!["LogonType".to_string()]);
        assert!(!value.is_complete());
        assert_eq!(value.text, "LogonType %LogonType%");
    }

    #[test]
    fn lookup_translates_a_bound_variable() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::PayloadData(1),
                "Bus: %BusType%".to_string(),
                vec![binding("BusType", "BusType")],
            )],
            vec![Lookup {
                name: "BusType".to_string(),
                default: Some("Unknown code".to_string()),
                values: BTreeMap::from([("7".to_string(), "USB".to_string())]),
            }],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(
            mapped.value_for(&MapProperty::PayloadData(1)),
            Some("Bus: USB")
        );
    }

    #[test]
    fn lookup_default_applies_to_an_unknown_code() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::PayloadData(1),
                "Bus: %BusType%".to_string(),
                vec![binding("BusType", "BusType")],
            )],
            vec![Lookup {
                name: "BusType".to_string(),
                default: Some("Unknown code".to_string()),
                values: BTreeMap::new(),
            }],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(
            mapped.value_for(&MapProperty::PayloadData(1)),
            Some("Bus: Unknown code")
        );
    }

    #[test]
    fn a_template_with_no_placeholders_is_emitted_verbatim() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::PayloadData(1),
                "Screen saver invoked".to_string(),
                vec![],
            )],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(
            mapped.value_for(&MapProperty::PayloadData(1)),
            Some("Screen saver invoked")
        );
        assert!(mapped.values[0].is_complete());
    }

    #[test]
    fn a_placeholder_with_no_binding_is_reported_unresolved() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::PayloadData(1),
                "Value %NeverBound%".to_string(),
                vec![],
            )],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(mapped.values[0].unresolved, vec!["NeverBound".to_string()]);
    }

    #[test]
    fn a_malformed_path_is_a_map_defect_not_a_missing_field() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::PayloadData(1),
                "%broken%".to_string(),
                vec![ValueBinding {
                    name: "broken".to_string(),
                    value: "EventData/Data".to_string(),
                }],
            )],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(
            mapped.invalid_paths,
            vec![("broken".to_string(), "EventData/Data".to_string())]
        );
        assert_eq!(mapped.values[0].unresolved, vec!["broken".to_string()]);
    }

    #[test]
    fn a_field_value_containing_a_placeholder_is_not_re_substituted() {
        // Event content is untrusted. If rendering re-scanned its own output, a field whose text
        // happens to be "%user%" would be replaced by a later binding.
        let event = EventNode::new("Event").with_child(
            EventNode::new("EventData")
                .with_child(
                    EventNode::new("Data")
                        .with_attribute("Name", "SubjectDomainName")
                        .with_text("%user%"),
                )
                .with_child(
                    EventNode::new("Data")
                        .with_attribute("Name", "SubjectUserName")
                        .with_text("adam"),
                ),
        );
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::UserName,
                "%domain%\\%user%".to_string(),
                vec![
                    binding("domain", "SubjectDomainName"),
                    binding("user", "SubjectUserName"),
                ],
            )],
            vec![],
        );

        let mapped = apply_map(&map, &event);
        assert_eq!(
            mapped.value_for(&MapProperty::UserName),
            Some("%user%\\adam")
        );
    }

    #[test]
    fn a_literal_percent_does_not_hide_the_placeholder_that_follows_it() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::PayloadData(1),
                "50% off %Cost%".to_string(),
                vec![],
            )],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        let value = &mapped.values[0];
        assert_eq!(value.unresolved, vec!["Cost".to_string()]);
        assert!(!value.is_complete());
        assert_eq!(value.text, "50% off %Cost%");
    }

    #[test]
    fn a_literal_percent_survives_when_a_later_placeholder_resolves() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::PayloadData(1),
                "50% off for %user%".to_string(),
                vec![binding("user", "SubjectUserName")],
            )],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(
            mapped.value_for(&MapProperty::PayloadData(1)),
            Some("50% off for adam")
        );
        assert!(mapped.values[0].is_complete());
    }

    #[test]
    fn an_unpaired_trailing_percent_is_preserved_verbatim() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::PayloadData(1),
                "complete: 100%".to_string(),
                vec![],
            )],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(
            mapped.value_for(&MapProperty::PayloadData(1)),
            Some("complete: 100%")
        );
        assert!(mapped.values[0].is_complete());
    }

    #[test]
    fn an_unused_binding_does_not_affect_the_result() {
        let map = map_with(
            vec![MapEntry::new(
                MapProperty::PayloadData(1),
                "User %user%".to_string(),
                vec![
                    binding("user", "SubjectUserName"),
                    binding("unused", "DoesNotExist"),
                ],
            )],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(
            mapped.value_for(&MapProperty::PayloadData(1)),
            Some("User adam")
        );
        assert!(mapped.values[0].is_complete());
    }
}
