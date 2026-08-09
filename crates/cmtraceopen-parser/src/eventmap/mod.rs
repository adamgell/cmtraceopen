//! Normalizing Windows event data into stable columns.
//!
//! Every event ID carries a different `EventData` shape, which is why event logs resist tabular
//! display. EvtxECmd solved this with community "maps" that project each event's fields into a
//! fixed set of columns. This module implements that schema so the existing corpus of upstream
//! maps works unmodified, and so maps written here work in EvtxECmd and Timeline Explorer.
//!
//! Two boundaries keep this crate pure and wasm32-compatible:
//!
//! - **No XML dependency.** Callers convert whatever they hold into [`EventNode`].
//! - **No YAML dependency.** The schema derives `serde::Deserialize`, so the host layer picks the
//!   format. Upstream maps are YAML; the fixtures here are the same maps as JSON.
//!
//! ```
//! use cmtraceopen_parser::eventmap::{apply_map, EventMap, EventNode, MapProperty};
//!
//! let map: EventMap = serde_json::from_str(r#"{
//!     "EventId": 9701,
//!     "Channel": "Microsoft-Windows-Shell-Core/Operational",
//!     "Provider": "Microsoft-Windows-Shell-Core",
//!     "Maps": [{
//!         "Property": "PayloadData1",
//!         "PropertyValue": "%PayloadData1%",
//!         "Values": [{ "Name": "PayloadData1", "Value": "/Event/EventData/Data" }]
//!     }]
//! }"#).unwrap();
//!
//! let event = EventNode::new("Event").with_child(
//!     EventNode::new("EventData").with_child(EventNode::new("Data").with_text("RunOnceEx")),
//! );
//!
//! let mapped = apply_map(&map, &event);
//! assert_eq!(mapped.value_for(&MapProperty::PayloadData(1)), Some("RunOnceEx"));
//! ```

mod apply;
mod model;
mod node;
mod path;

pub use apply::{apply_map, MappedEvent, MappedValue};
pub use model::{EventMap, Lookup, MapEntry, MapProperty, ValueBinding};
pub use node::EventNode;
pub use path::{PathError, Predicate, Step, ValuePath};

use std::collections::HashMap;

/// Identity of a map: channel, provider, and event ID.
///
/// The file name is not part of identity upstream, and neither is it here. Channel and provider
/// are compared ASCII case-insensitively, because a case mismatch would silently drop the mapping
/// for every event of that type rather than fail loudly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MapKey {
    channel: String,
    provider: String,
    event_id: u32,
}

impl MapKey {
    fn new(channel: &str, provider: &str, event_id: u32) -> Self {
        Self {
            channel: channel.trim().to_ascii_lowercase(),
            provider: provider.trim().to_ascii_lowercase(),
            event_id,
        }
    }
}

/// A set of maps, resolved by channel, provider, and event ID.
#[derive(Debug, Clone, Default)]
pub struct MapRegistry {
    maps: HashMap<MapKey, EventMap>,
}

impl MapRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `map`, returning any map it replaced.
    ///
    /// Upstream loads maps in alphabetical file order so that a `1_`-prefixed copy overrides the
    /// original. Load order is the caller's concern; last insert wins here.
    pub fn insert(&mut self, map: EventMap) -> Option<EventMap> {
        let key = MapKey::new(&map.channel, &map.provider, map.event_id);
        self.maps.insert(key, map)
    }

    /// Finds the map for an event, if one exists.
    pub fn find(&self, channel: &str, provider: &str, event_id: u32) -> Option<&EventMap> {
        self.maps.get(&MapKey::new(channel, provider, event_id))
    }

    /// Number of maps held.
    pub fn len(&self) -> usize {
        self.maps.len()
    }

    /// True when no maps are held.
    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
    }

    /// Applies the matching map to `event`, if one is registered.
    pub fn apply(
        &self,
        channel: &str,
        provider: &str,
        event_id: u32,
        event: &EventNode,
    ) -> Option<MappedEvent> {
        self.find(channel, provider, event_id)
            .map(|map| apply_map(map, event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(channel: &str, provider: &str, event_id: u32) -> EventMap {
        EventMap {
            author: None,
            description: None,
            event_id,
            channel: channel.to_string(),
            provider: provider.to_string(),
            maps: Vec::new(),
            lookups: Vec::new(),
        }
    }

    #[test]
    fn resolves_by_channel_provider_and_event_id() {
        let mut registry = MapRegistry::new();
        registry.insert(map("Security", "Microsoft-Windows-Security-Auditing", 4624));

        assert!(registry
            .find("Security", "Microsoft-Windows-Security-Auditing", 4624)
            .is_some());
        assert!(registry
            .find("Security", "Microsoft-Windows-Security-Auditing", 4625)
            .is_none());
        assert!(registry
            .find("System", "Microsoft-Windows-Security-Auditing", 4624)
            .is_none());
    }

    #[test]
    fn channel_and_provider_matching_is_case_insensitive() {
        let mut registry = MapRegistry::new();
        registry.insert(map(
            "Microsoft-Windows-Shell-Core/Operational",
            "Microsoft-Windows-Shell-Core",
            9701,
        ));

        assert!(registry
            .find(
                "microsoft-windows-shell-core/operational",
                "MICROSOFT-WINDOWS-SHELL-CORE",
                9701
            )
            .is_some());
    }

    #[test]
    fn the_same_event_id_on_different_channels_stays_distinct() {
        let mut registry = MapRegistry::new();
        registry.insert(map("Security", "Provider-A", 4624));
        registry.insert(map("System", "Provider-A", 4624));

        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn reinserting_the_same_identity_replaces_and_returns_the_previous_map() {
        let mut registry = MapRegistry::new();
        let mut first = map("Security", "Provider-A", 4624);
        first.description = Some("original".to_string());
        registry.insert(first);

        let mut override_map = map("Security", "Provider-A", 4624);
        override_map.description = Some("override".to_string());
        let replaced = registry.insert(override_map);

        assert_eq!(
            replaced.and_then(|m| m.description).as_deref(),
            Some("original")
        );
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry
                .find("Security", "Provider-A", 4624)
                .and_then(|m| m.description.as_deref()),
            Some("override")
        );
    }

    #[test]
    fn an_empty_registry_maps_nothing() {
        let registry = MapRegistry::new();
        assert!(registry.is_empty());
        assert!(registry
            .apply("Security", "Provider-A", 4624, &EventNode::new("Event"))
            .is_none());
    }
}
