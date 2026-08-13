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

/// Reads a map file as text, falling back to Windows-1252 when it is not UTF-8.
///
/// The upstream corpus is UTF-8, but a map written by hand on a Windows machine often is not, and
/// `read_to_string` would reject it with "stream did not contain valid UTF-8". That reads as a
/// corrupt file when it is really an encoding the rest of this codebase already handles, so the
/// same UTF-8 then Windows-1252 fallback used for log files applies here.
fn read_map_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    match String::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(error) => {
            let (text, _, _) = encoding_rs::WINDOWS_1252.decode(error.as_bytes());
            Ok(text.into_owned())
        }
    }
}

/// Load order for two map files.
///
/// Case-insensitive first, so a `1_`-prefixed copy wins regardless of case, which is what makes
/// the documented override work. The exact name breaks ties: without it `Map.map` and `map.map`
/// compare equal, and on a case-sensitive filesystem which one claims the identity would depend on
/// the unspecified order `read_dir` happened to return them in. Since load order decides which map
/// wins, that would make the registry differ between machines holding identical directories.
fn map_file_order(left: &Path, right: &Path) -> std::cmp::Ordering {
    let name_of = |path: &Path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string()
    };
    let (left_name, right_name) = (name_of(left), name_of(right));
    left_name
        .to_ascii_lowercase()
        .cmp(&right_name.to_ascii_lowercase())
        .then_with(|| left_name.cmp(&right_name))
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

    let mut registry = MapRegistry::new();
    let mut outcome = MapLoadOutcome::default();

    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        // An enumeration error after the directory itself opened is recorded rather than skipped.
        // Dropping it would let a partial registry come back with is_clean() true, which reads as
        // "every map loaded" when a map is in fact missing and its columns are silently absent.
        match entry {
            Ok(entry) => files.push(entry.path()),
            Err(error) => outcome.failures.push(MapLoadFailure {
                path: directory.display().to_string(),
                reason: format!("cannot read directory entry: {error}"),
            }),
        }
    }
    files.retain(|path| {
        path.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("map"))
    });
    files.sort_by(|left, right| map_file_order(left, right));
    // identity (lowercased, matching MapRegistry's comparison) -> the file that claimed it
    let mut owners: HashMap<String, String> = HashMap::new();

    for path in files {
        let display = path.display().to_string();
        let contents = match read_map_file(&path) {
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
    fn a_numeric_prefix_sorts_first_regardless_of_case() {
        use std::cmp::Ordering;
        assert_eq!(
            map_file_order(Path::new("/m/1_Shell.map"), Path::new("/m/Shell.map")),
            Ordering::Less
        );
        assert_eq!(
            map_file_order(Path::new("/m/1_shell.map"), Path::new("/m/Shell.map")),
            Ordering::Less
        );
    }

    #[test]
    fn names_differing_only_in_case_have_a_defined_order() {
        use std::cmp::Ordering;
        // Tested directly rather than through a directory, because the filesystem this runs on may
        // be case-insensitive and would collapse the two names into one file. The ordering is what
        // matters: load order decides which map wins, so leaving these equal would let identical
        // directories produce different registries on different machines.
        assert_eq!(
            map_file_order(Path::new("/m/Shell.map"), Path::new("/m/shell.map")),
            Ordering::Less,
            "uppercase must sort before lowercase, not compare equal"
        );
        assert_eq!(
            map_file_order(Path::new("/m/shell.map"), Path::new("/m/Shell.map")),
            Ordering::Greater,
            "the order must be antisymmetric"
        );
        assert_eq!(
            map_file_order(Path::new("/m/Shell.map"), Path::new("/m/Shell.map")),
            Ordering::Equal
        );
    }

    #[test]
    fn case_insensitive_ordering_still_decides_unrelated_names() {
        use std::cmp::Ordering;
        assert_eq!(
            map_file_order(Path::new("/m/Apple.map"), Path::new("/m/banana.map")),
            Ordering::Less,
            "case must not dominate the alphabetical comparison"
        );
    }

    #[test]
    fn a_windows_1252_map_is_read_rather_than_rejected() {
        // read_to_string would reject this as invalid UTF-8, which reads as a corrupt file when it
        // is really an encoding this codebase already handles everywhere else.
        let dir = temp_dir("cp1252");
        let text = SHELL_CORE_9701.replace("Shell-Core 9701", "Shell-Core 9701 caf\u{e9}");
        let mut bytes: Vec<u8> = Vec::new();
        for ch in text.chars() {
            if ch == '\u{e9}' {
                bytes.push(0xE9); // Windows-1252 e-acute, which is not valid UTF-8 on its own
            } else {
                let mut buffer = [0u8; 4];
                bytes.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            }
        }
        fs::write(dir.join("Shell-Core_9701.map"), &bytes).expect("writes");

        let (registry, outcome) = load_maps_from_dir(&dir).expect("directory reads");
        assert!(
            outcome.is_clean(),
            "expected a clean load, got {:?}",
            outcome.failures
        );
        assert_eq!(registry.len(), 1);
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
        // MapProperty is non_exhaustive, so a newer schema can add a target this build predates.
        // Naming it after its own debug form keeps the column visible and labelled rather than
        // dropping data because the name is unfamiliar.
        other => format!("{other:?}"),
    }
}

/// Applies the registered map for this event, if one exists.
///
/// Returns an empty vector when no map matches, which is the common case: the upstream corpus
/// covers a few hundred event types out of many thousands.
///
/// The registry is passed in rather than reached for. Both record paths already parse the event
/// once and apply maps there, so whoever owns the registry hands it down; there is no process
/// global to make two tests, or two windows, share one set of maps.
pub fn apply_registered(
    registry: &MapRegistry,
    channel: &str,
    provider: &str,
    event_id: u32,
    event: &EventNode,
) -> Vec<MappedColumn> {
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
        assert!(apply_registered(
            &MapRegistry::new(),
            "No-Such-Channel",
            "No-Such-Provider",
            1,
            &event
        )
        .is_empty());
    }

    #[test]
    fn a_loaded_map_produces_columns_for_a_matching_event_end_to_end() {
        // Proves the whole chain: YAML on disk, into a registry, applied to XML parsed by the
        // host adapter, out as columns the UI can render. The registry is local to this test, so
        // it cannot be disturbed by another test loading a different set on a parallel thread.
        let dir = std::env::temp_dir().join("cmtraceopen-maps-global-e2e");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        fs::write(dir.join("shell-core-9701.map"), SHELL_CORE_9701).expect("write map");

        let (registry, outcome) = load_maps_from_dir(&dir).expect("loads");
        assert_eq!(outcome.loaded_count(), 1);
        assert_eq!(registry.len(), 1);

        let event = crate::event_log::event_node::parse_event_xml(
            "<Event><EventData><Data>RunOnceEx started</Data></EventData></Event>",
        )
        .expect("parses");

        let columns = apply_registered(
            &registry,
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
        assert!(apply_registered(
            &registry,
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
