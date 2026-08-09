//! Applying a map to an event.
//!
//! Resolution is deliberately non-fatal. Maps are written against a provider's superset of
//! fields, so an individual event legitimately omits some of them. A missing field is a coverage
//! state, reported on [`MappedValue::unresolved`], never an error and never silently blank.

use super::model::{EventMap, MapEntry, MapProperty};
use super::node::EventNode;
use super::path::ValuePath;

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
    let mut text = entry.property_value.clone();
    let mut unresolved = Vec::new();

    for binding in &entry.values {
        let placeholder = format!("%{}%", binding.name);
        if !text.contains(&placeholder) {
            continue;
        }

        let resolved = match ValuePath::parse(&binding.value) {
            Ok(path) => path.evaluate(event).map(|value| value.into_owned()),
            Err(_) => {
                let defect = (binding.name.clone(), binding.value.clone());
                if !invalid_paths.contains(&defect) {
                    invalid_paths.push(defect);
                }
                None
            }
        };

        let translated = resolved.and_then(|raw| match map.lookup_for(&binding.name) {
            Some(lookup) => lookup.translate(&raw),
            None => Some(raw),
        });

        match translated {
            Some(value) => text = text.replace(&placeholder, &value),
            None => unresolved.push(binding.name.clone()),
        }
    }

    // A template may reference a variable the map never binds. That is still an unresolved
    // placeholder from the reader's point of view, so report it the same way.
    for name in remaining_placeholders(&text) {
        if !unresolved.contains(&name) {
            unresolved.push(name);
        }
    }

    MappedValue {
        property: entry.property.clone(),
        text,
        unresolved,
    }
}

fn remaining_placeholders(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else { break };
        let name = &after[..end];
        if !name.is_empty() && !name.contains(char::is_whitespace) {
            names.push(name.to_string());
        }
        rest = &after[end + 1..];
    }
    names
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
            vec![MapEntry {
                property: MapProperty::UserName,
                property_value: "%domain%\\%user%".to_string(),
                values: vec![
                    binding("domain", "SubjectDomainName"),
                    binding("user", "SubjectUserName"),
                ],
            }],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(mapped.value_for(&MapProperty::UserName), Some("TEST\\adam"));
        assert!(mapped.values[0].is_complete());
    }

    #[test]
    fn missing_field_is_reported_and_leaves_the_placeholder_visible() {
        let map = map_with(
            vec![MapEntry {
                property: MapProperty::PayloadData(1),
                property_value: "LogonType %LogonType%".to_string(),
                values: vec![binding("LogonType", "LogonType")],
            }],
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
            vec![MapEntry {
                property: MapProperty::PayloadData(1),
                property_value: "Bus: %BusType%".to_string(),
                values: vec![binding("BusType", "BusType")],
            }],
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
            vec![MapEntry {
                property: MapProperty::PayloadData(1),
                property_value: "Bus: %BusType%".to_string(),
                values: vec![binding("BusType", "BusType")],
            }],
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
            vec![MapEntry {
                property: MapProperty::PayloadData(1),
                property_value: "Screen saver invoked".to_string(),
                values: vec![],
            }],
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
            vec![MapEntry {
                property: MapProperty::PayloadData(1),
                property_value: "Value %NeverBound%".to_string(),
                values: vec![],
            }],
            vec![],
        );

        let mapped = apply_map(&map, &event());
        assert_eq!(mapped.values[0].unresolved, vec!["NeverBound".to_string()]);
    }

    #[test]
    fn a_malformed_path_is_a_map_defect_not_a_missing_field() {
        let map = map_with(
            vec![MapEntry {
                property: MapProperty::PayloadData(1),
                property_value: "%broken%".to_string(),
                values: vec![ValueBinding {
                    name: "broken".to_string(),
                    value: "EventData/Data".to_string(),
                }],
            }],
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
    fn an_unused_binding_does_not_affect_the_result() {
        let map = map_with(
            vec![MapEntry {
                property: MapProperty::PayloadData(1),
                property_value: "User %user%".to_string(),
                values: vec![
                    binding("user", "SubjectUserName"),
                    binding("unused", "DoesNotExist"),
                ],
            }],
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
