//! Loading EvtxECmd `.map` files from disk.
//!
//! The schema and the engine live in `cmtraceopen-parser`, which stays pure and
//! wasm32-compatible and therefore has no YAML dependency. This module is the host-side adapter:
//! it reads `.map` files, deserializes the YAML, and builds a
//! [`MapRegistry`](cmtraceopen_parser::eventmap::MapRegistry).
//!
//! Two behaviours were verified against EvtxECmd 1.5.2 on a Windows 11 host rather than inferred
//! from its documentation:
//!
//! - **First loaded wins.** Files load in alphabetical order and a later file with the same
//!   identity is rejected, which is what makes the documented `1_` prefix override work. EvtxECmd
//!   reports this as `An item with the same key has already been added. Key: 326-APPLICATION-ESENT`
//!   and continues with the first map.
//! - **Identity is case-insensitive.** That same key is uppercased channel and provider, matching
//!   how `MapRegistry` compares them.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

use cmtraceopen_parser::eventmap::{apply_map, EventMap, EventNode, MapProperty, MapRegistry};
use serde::{Deserialize, Serialize};

/// Why a `.map` file could not be used.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MapLoadFailure {
    /// The file that failed.
    pub path: String,
    /// The reason, suitable for showing to an operator.
    pub reason: String,
}

/// A map that parsed but lost to an earlier file claiming the same identity.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SupersededMap {
    /// The file that was skipped.
    pub path: String,
    /// The file that already owned this identity.
    pub superseded_by: String,
    /// `channel/provider/eventId` of the contested identity.
    pub identity: String,
}

/// The result of loading a directory of maps.
///
/// Failures and supersessions are reported rather than silently dropped: a map that did not load
/// means events of that type render unmapped, which is a coverage gap an operator needs to see.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MapLoadOutcome {
    /// Files that loaded and won their identity.
    pub loaded: Vec<String>,
    /// Files skipped because an earlier file already owned the identity.
    pub superseded: Vec<SupersededMap>,
    /// Files that could not be read or parsed.
    pub failures: Vec<MapLoadFailure>,
}

impl MapLoadOutcome {
    /// Number of maps actually registered.
    pub fn loaded_count(&self) -> usize {
        self.loaded.len()
    }

    /// True when nothing failed and nothing was skipped.
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty() && self.superseded.is_empty()
    }
}

/// Parses one `.map` file's contents.
///
/// Upstream maps are UTF-8 with a byte order mark, which YAML parsers reject as an unexpected
/// character, so the BOM is stripped first.
pub fn parse_map(contents: &str) -> Result<EventMap, String> {
    let without_bom = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    serde_norway::from_str::<EventMap>(without_bom).map_err(|error| error.to_string())
}

fn identity_of(map: &EventMap) -> String {
    format!("{}/{}/{}", map.channel, map.provider, map.event_id)
}

/// Loads every `.map` file directly inside `directory`.
///
/// Files are processed in case-insensitive alphabetical order so a `1_`-prefixed copy wins, which
/// is how upstream lets a local customization survive a map-corpus update.
pub fn load_maps_from_dir(directory: &Path) -> Result<(MapRegistry, MapLoadOutcome), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read map directory {}: {error}", directory.display()))?;

    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("map"))
        })
        .collect();
    files.sort_by_key(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
    });

    let mut registry = MapRegistry::new();
    let mut outcome = MapLoadOutcome::default();
    // identity (lowercased, matching MapRegistry's comparison) -> the file that claimed it
    let mut owners: HashMap<String, String> = HashMap::new();

    for path in files {
        let display = path.display().to_string();
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) => {
                outcome.failures.push(MapLoadFailure {
                    path: display,
                    reason: format!("cannot read file: {error}"),
                });
                continue;
            }
        };

        let map = match parse_map(&contents) {
            Ok(map) => map,
            Err(reason) => {
                outcome.failures.push(MapLoadFailure {
                    path: display,
                    reason,
                });
                continue;
            }
        };

        // First loaded wins, matching EvtxECmd. Checking before inserting is deliberate:
        // MapRegistry::insert is last-wins, which is the opposite of what upstream does.
        let identity = identity_of(&map);
        let owner_key = identity.to_ascii_lowercase();
        if let Some(owner) = owners.get(&owner_key) {
            outcome.superseded.push(SupersededMap {
                path: display,
                superseded_by: owner.clone(),
                identity,
            });
            continue;
        }

        owners.insert(owner_key, display.clone());
        registry.insert(map);
        outcome.loaded.push(display);
    }

    Ok((registry, outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmtraceopen_parser::eventmap::{apply_map, EventNode, MapProperty};
    use std::fs;

    /// A real upstream map, byte for byte, including the leading comment style and quoting.
    pub(super) const SHELL_CORE_9701: &str = r#"Author: Troy Larson
Description: RunOnceEx commands started
EventId: 9701
Channel: Microsoft-Windows-Shell-Core/Operational
Provider: Microsoft-Windows-Shell-Core
Maps:
  -
    Property: PayloadData1
    PropertyValue: "%PayloadData1%"
    Values:
      -
        Name: PayloadData1
        Value: "/Event/EventData/Data"

# Documentation:
# https://www.geoffchappell.com/notes/windows/shell/events/core.htm
"#;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cmtraceopen-maps-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write(dir: &Path, name: &str, contents: &str) {
        fs::write(dir.join(name), contents).expect("write map");
    }

    #[test]
    fn parses_a_real_upstream_map_including_trailing_comments() {
        let map = parse_map(SHELL_CORE_9701).expect("parses");
        assert_eq!(map.event_id, 9701);
        assert_eq!(map.provider, "Microsoft-Windows-Shell-Core");
        assert_eq!(map.author.as_deref(), Some("Troy Larson"));
        assert_eq!(map.maps.len(), 1);
        assert_eq!(map.maps[0].property, MapProperty::PayloadData(1));
    }

    #[test]
    fn strips_the_utf8_byte_order_mark_upstream_files_carry() {
        let with_bom = format!("\u{feff}{SHELL_CORE_9701}");
        let map = parse_map(&with_bom).expect("BOM-prefixed map parses");
        assert_eq!(map.event_id, 9701);
    }

    #[test]
    fn reports_a_malformed_map_as_a_failure_rather_than_aborting_the_load() {
        let dir = temp_dir("malformed");
        write(&dir, "good.map", SHELL_CORE_9701);
        write(&dir, "bad.map", "EventId: [this is not a scalar\nChannel:");

        let (registry, outcome) = load_maps_from_dir(&dir).expect("directory reads");

        assert_eq!(registry.len(), 1);
        assert_eq!(outcome.loaded_count(), 1);
        assert_eq!(outcome.failures.len(), 1);
        assert!(outcome.failures[0].path.ends_with("bad.map"));
        assert!(!outcome.is_clean());
    }

    #[test]
    fn first_loaded_wins_so_a_numeric_prefix_overrides() {
        let dir = temp_dir("override");
        let original = SHELL_CORE_9701.replace("%PayloadData1%", "ORIGINAL %PayloadData1%");
        let custom = SHELL_CORE_9701.replace("%PayloadData1%", "CUSTOM %PayloadData1%");
        write(&dir, "Shell-Core_9701.map", &original);
        write(&dir, "1_Shell-Core_9701.map", &custom);

        let (registry, outcome) = load_maps_from_dir(&dir).expect("directory reads");

        assert_eq!(registry.len(), 1);
        assert_eq!(outcome.superseded.len(), 1);
        assert!(outcome.superseded[0].path.ends_with("Shell-Core_9701.map"));
        assert!(outcome.superseded[0].superseded_by.contains("1_"));

        let event = EventNode::new("Event").with_child(
            EventNode::new("EventData").with_child(EventNode::new("Data").with_text("cmd.exe")),
        );
        let map = registry
            .find(
                "Microsoft-Windows-Shell-Core/Operational",
                "Microsoft-Windows-Shell-Core",
                9701,
            )
            .expect("map registered");
        assert_eq!(
            apply_map(map, &event).value_for(&MapProperty::PayloadData(1)),
            Some("CUSTOM cmd.exe"),
            "the 1_-prefixed file loads first and must win"
        );
    }

    #[test]
    fn ignores_files_that_are_not_maps() {
        let dir = temp_dir("filter");
        write(&dir, "real.map", SHELL_CORE_9701);
        write(&dir, "notes.txt", "ignore me");
        write(&dir, "README.md", "ignore me too");

        let (registry, outcome) = load_maps_from_dir(&dir).expect("directory reads");

        assert_eq!(registry.len(), 1);
        assert!(outcome.is_clean());
    }

    #[test]
    fn accepts_an_uppercase_extension() {
        let dir = temp_dir("uppercase");
        write(&dir, "real.MAP", SHELL_CORE_9701);

        let (registry, _) = load_maps_from_dir(&dir).expect("directory reads");
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn an_empty_directory_loads_cleanly_rather_than_erroring() {
        let dir = temp_dir("empty");
        let (registry, outcome) = load_maps_from_dir(&dir).expect("directory reads");
        assert!(registry.is_empty());
        assert!(outcome.is_clean());
        assert_eq!(outcome.loaded_count(), 0);
    }

    #[test]
    fn a_missing_directory_is_an_error_not_an_empty_result() {
        let missing = std::env::temp_dir().join("cmtraceopen-maps-does-not-exist");
        let _ = fs::remove_dir_all(&missing);
        assert!(load_maps_from_dir(&missing).is_err());
    }
}

// ── Process-wide registry ───────────────────────────────────────────────────

/// The maps in effect for this process.
///
/// Held globally rather than threaded through every call site because both the live and file
/// record paths already parse the event once and applying maps there avoids a second parse. An
/// empty registry is the normal state until maps are loaded, and it simply yields no columns.
fn global() -> &'static RwLock<MapRegistry> {
    static REGISTRY: OnceLock<RwLock<MapRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(MapRegistry::new()))
}

/// One normalized column produced by a map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MappedColumn {
    /// Column name, for example `UserName` or `PayloadData1`.
    pub property: String,
    /// The rendered text.
    pub text: String,
    /// False when the map referenced a field this event did not carry, in which case `text` still
    /// contains the unresolved `%placeholder%`.
    pub complete: bool,
}

fn property_name(property: &MapProperty) -> String {
    match property {
        MapProperty::UserName => "UserName".to_string(),
        MapProperty::RemoteHost => "RemoteHost".to_string(),
        MapProperty::ExecutableInfo => "ExecutableInfo".to_string(),
        MapProperty::PayloadData(slot) => format!("PayloadData{slot}"),
        MapProperty::Other(name) => name.clone(),
    }
}

/// Replaces the process registry with the maps in `directory`.
pub fn load_global(directory: &Path) -> Result<MapLoadOutcome, String> {
    let (registry, outcome) = load_maps_from_dir(directory)?;
    *global()
        .write()
        .map_err(|_| "map registry lock was poisoned".to_string())? = registry;
    Ok(outcome)
}

/// Number of maps currently loaded.
pub fn loaded_count() -> usize {
    global().read().map(|registry| registry.len()).unwrap_or(0)
}

/// Applies the registered map for this event, if one exists.
///
/// Returns an empty vector when no map matches, which is the common case: the upstream corpus
/// covers a few hundred event types out of many thousands.
pub fn apply_global(
    channel: &str,
    provider: &str,
    event_id: u32,
    event: &EventNode,
) -> Vec<MappedColumn> {
    let Ok(registry) = global().read() else {
        return Vec::new();
    };
    let Some(map) = registry.find(channel, provider, event_id) else {
        return Vec::new();
    };
    apply_map(map, event)
        .values
        .into_iter()
        .map(|value| MappedColumn {
            property: property_name(&value.property),
            complete: value.unresolved.is_empty(),
            text: value.text,
        })
        .collect()
}

#[cfg(test)]
mod global_tests {
    use super::tests::SHELL_CORE_9701;
    use super::*;

    #[test]
    fn an_unloaded_registry_yields_no_columns_rather_than_failing() {
        let event = EventNode::new("Event");
        // Whatever other tests have loaded, an event with no matching map must map to nothing.
        assert!(apply_global("No-Such-Channel", "No-Such-Provider", 1, &event).is_empty());
    }

    #[test]
    fn a_loaded_map_produces_columns_for_a_matching_event_end_to_end() {
        // Proves the whole chain: YAML on disk, into the process registry, applied to XML parsed
        // by the host adapter, out as columns the UI can render.
        let dir = std::env::temp_dir().join("cmtraceopen-maps-global-e2e");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        fs::write(dir.join("shell-core-9701.map"), SHELL_CORE_9701).expect("write map");

        let outcome = load_global(&dir).expect("loads");
        assert_eq!(outcome.loaded_count(), 1);
        assert!(loaded_count() >= 1);

        let event = crate::event_log::event_node::parse_event_xml(
            "<Event><EventData><Data>RunOnceEx started</Data></EventData></Event>",
        )
        .expect("parses");

        let columns = apply_global(
            "Microsoft-Windows-Shell-Core/Operational",
            "Microsoft-Windows-Shell-Core",
            9701,
            &event,
        );
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].property, "PayloadData1");
        assert_eq!(columns[0].text, "RunOnceEx started");
        assert!(columns[0].complete);

        // A different event id on the same channel has no map and must map to nothing.
        assert!(apply_global(
            "Microsoft-Windows-Shell-Core/Operational",
            "Microsoft-Windows-Shell-Core",
            9702,
            &event
        )
        .is_empty());
    }

    #[test]
    fn property_names_match_the_upstream_column_names() {
        assert_eq!(property_name(&MapProperty::UserName), "UserName");
        assert_eq!(property_name(&MapProperty::PayloadData(3)), "PayloadData3");
        assert_eq!(
            property_name(&MapProperty::Other("Custom".into())),
            "Custom"
        );
    }
}
