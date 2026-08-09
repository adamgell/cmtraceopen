//! The EvtxECmd map schema.
//!
//! Deliberately derives `serde::Deserialize` rather than depending on a YAML crate. Upstream maps
//! are YAML, but this crate is pure and wasm32-compatible, so format-specific loading belongs in
//! the host layer. Any serde format that produces these field names works, which keeps YAML out
//! of the parser crate and lets tests drive the real corpus through `serde_json`.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};

/// A normalized output column that a map entry writes into.
///
/// The upstream corpus is not perfectly consistent: four maps spell the target `Username` rather
/// than `UserName`, so parsing is ASCII case-insensitive.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MapProperty {
    /// The acting or target account.
    UserName,
    /// The remote host, typically a workstation name and address.
    RemoteHost,
    /// Process, command line, service, or scheduled-task detail.
    ExecutableInfo,
    /// One of the six generic overflow slots, numbered 1 through 6.
    PayloadData(u8),
    /// A target this build does not know, preserved rather than dropped so a community map
    /// contributed against a newer schema is not silently discarded.
    Other(String),
}

impl MapProperty {
    /// Parses a `Property` value, ASCII case-insensitively.
    pub fn parse(raw: &str) -> Self {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("username") {
            return Self::UserName;
        }
        if trimmed.eq_ignore_ascii_case("remotehost") {
            return Self::RemoteHost;
        }
        if trimmed.eq_ignore_ascii_case("executableinfo") {
            return Self::ExecutableInfo;
        }
        if let Some(suffix) = trimmed
            .get(..11)
            .filter(|prefix| prefix.eq_ignore_ascii_case("payloaddata"))
            .and_then(|_| trimmed.get(11..))
        {
            if let Ok(slot @ 1..=6) = suffix.parse::<u8>() {
                return Self::PayloadData(slot);
            }
        }
        Self::Other(trimmed.to_string())
    }
}

impl<'de> Deserialize<'de> for MapProperty {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::parse(&raw))
    }
}

/// Binds a template variable to a location in the event.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ValueBinding {
    /// Variable name, referenced as `%Name%` in the owning entry's `PropertyValue`.
    pub name: String,
    /// The path expression locating the value.
    pub value: String,
}

/// A translation table turning raw codes into readable text.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Lookup {
    /// Matches the [`ValueBinding::name`] this table applies to.
    pub name: String,
    /// Text used when the raw value is absent from `values`.
    #[serde(default)]
    pub default: Option<String>,
    /// Raw value to readable text.
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

impl Lookup {
    /// Translates `raw`, falling back to [`Lookup::default`] when it is not in the table.
    pub fn translate(&self, raw: &str) -> Option<String> {
        self.values
            .get(raw)
            .cloned()
            .or_else(|| self.default.clone())
    }
}

/// One output column produced from an event.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct MapEntry {
    /// Which normalized column this writes.
    pub property: MapProperty,
    /// Template containing `%Name%` placeholders.
    pub property_value: String,
    /// Variables available to the template.
    #[serde(default)]
    pub values: Vec<ValueBinding>,
}

/// A parsed EvtxECmd map file.
///
/// Identity is `(channel, provider, event_id)`, not the file name, matching upstream.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct EventMap {
    /// Map author, carried through for attribution.
    #[serde(default)]
    pub author: Option<String>,
    /// What the mapped event means.
    #[serde(default)]
    pub description: Option<String>,
    /// The event ID this map applies to.
    pub event_id: u32,
    /// The channel this map applies to, for example `Security`.
    pub channel: String,
    /// The provider this map applies to.
    pub provider: String,
    /// Output columns, evaluated in order.
    #[serde(default)]
    pub maps: Vec<MapEntry>,
    /// Translation tables referenced by variable name.
    #[serde(default)]
    pub lookups: Vec<Lookup>,
}

impl EventMap {
    /// Returns the lookup table bound to `variable`, if any.
    pub fn lookup_for(&self, variable: &str) -> Option<&Lookup> {
        self.lookups
            .iter()
            .find(|lookup| lookup.name.eq_ignore_ascii_case(variable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_property_targets() {
        assert_eq!(MapProperty::parse("UserName"), MapProperty::UserName);
        assert_eq!(MapProperty::parse("RemoteHost"), MapProperty::RemoteHost);
        assert_eq!(
            MapProperty::parse("ExecutableInfo"),
            MapProperty::ExecutableInfo
        );
        assert_eq!(
            MapProperty::parse("PayloadData4"),
            MapProperty::PayloadData(4)
        );
    }

    #[test]
    fn property_parsing_tolerates_the_corpus_case_inconsistency() {
        // Four upstream maps spell this "Username"; treating that as unknown would silently drop
        // the account column for those events.
        assert_eq!(MapProperty::parse("Username"), MapProperty::UserName);
        assert_eq!(
            MapProperty::parse("payloaddata2"),
            MapProperty::PayloadData(2)
        );
    }

    #[test]
    fn unknown_and_out_of_range_targets_are_preserved() {
        assert_eq!(
            MapProperty::parse("PayloadData7"),
            MapProperty::Other("PayloadData7".to_string())
        );
        assert_eq!(
            MapProperty::parse("SomethingNew"),
            MapProperty::Other("SomethingNew".to_string())
        );
    }

    #[test]
    fn property_parsing_does_not_panic_on_short_input() {
        assert_eq!(MapProperty::parse(""), MapProperty::Other(String::new()));
        assert_eq!(
            MapProperty::parse("Pay"),
            MapProperty::Other("Pay".to_string())
        );
    }

    #[test]
    fn lookup_falls_back_to_default() {
        let lookup = Lookup {
            name: "BusType".to_string(),
            default: Some("Unknown code".to_string()),
            values: BTreeMap::from([("7".to_string(), "USB".to_string())]),
        };
        assert_eq!(lookup.translate("7").as_deref(), Some("USB"));
        assert_eq!(lookup.translate("99").as_deref(), Some("Unknown code"));
    }

    #[test]
    fn lookup_without_default_returns_none_for_unknown_codes() {
        let lookup = Lookup {
            name: "BusType".to_string(),
            default: None,
            values: BTreeMap::new(),
        };
        assert_eq!(lookup.translate("7"), None);
    }
}
