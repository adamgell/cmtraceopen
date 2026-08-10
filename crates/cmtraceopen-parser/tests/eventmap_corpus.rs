//! The map engine driven by unmodified upstream EvtxECmd maps.
//!
//! These fixtures are real corpus (see `tests/fixtures/eventmap/README.md`), converted from YAML
//! to JSON without touching keys or values. The point is to prove the schema is implemented as
//! shipped rather than as imagined, so a regression here means the engine has drifted from the
//! community format.

use cmtraceopen_parser::eventmap::{
    apply_map, EventMap, EventNode, MapProperty, MapRegistry, ValuePath,
};

const SHELL_CORE_9701: &str = include_str!("fixtures/eventmap/shell-core-9701.json");
const SECURITY_4624: &str = include_str!("fixtures/eventmap/security-4624.json");
const NTFS_146: &str = include_str!("fixtures/eventmap/ntfs-146-lookups.json");

fn load(raw: &str) -> EventMap {
    serde_json::from_str(raw).expect("upstream map deserializes")
}

/// Builds an `Event` whose `EventData` holds the given named `Data` elements.
fn event_with_named_data(fields: &[(&str, &str)]) -> EventNode {
    let event_data =
        fields
            .iter()
            .fold(EventNode::new("EventData"), |event_data, (name, value)| {
                event_data.with_child(
                    EventNode::new("Data")
                        .with_attribute("Name", *name)
                        .with_text(*value),
                )
            });
    EventNode::new("Event").with_child(event_data)
}

#[test]
fn shell_core_9701_maps_unnamed_event_data() {
    let map = load(SHELL_CORE_9701);
    assert_eq!(map.event_id, 9701);
    assert_eq!(map.channel, "Microsoft-Windows-Shell-Core/Operational");
    assert_eq!(map.author.as_deref(), Some("Troy Larson"));

    let event = EventNode::new("Event").with_child(
        EventNode::new("EventData")
            .with_child(EventNode::new("Data").with_text("RunOnceEx commands started")),
    );

    let mapped = apply_map(&map, &event);
    assert_eq!(
        mapped.value_for(&MapProperty::PayloadData(1)),
        Some("RunOnceEx commands started")
    );
    assert!(mapped.invalid_paths.is_empty());
    assert!(mapped.values.iter().all(|value| value.is_complete()));
}

#[test]
fn security_4624_fills_every_column_from_a_complete_event() {
    let map = load(SECURITY_4624);
    assert_eq!(map.maps.len(), 8);

    let event = event_with_named_data(&[
        ("SubjectDomainName", "TEST"),
        ("SubjectUserName", "adam"),
        ("IpAddress", "192.168.16.103"),
        ("WorkstationName", "RING0IVY24-01"),
        ("TargetDomainName", "TEST"),
        ("TargetUserName", "svc-collector"),
        ("LogonType", "10"),
        ("TargetLogonId", "0x3e7"),
        ("AuthenticationPackageName", "Negotiate"),
        ("LogonProcessName", "Advapi"),
        ("ProcessName", "C:\\Windows\\System32\\svchost.exe"),
    ]);

    let mapped = apply_map(&map, &event);

    assert_eq!(mapped.value_for(&MapProperty::UserName), Some("TEST\\adam"));
    assert_eq!(
        mapped.value_for(&MapProperty::RemoteHost),
        Some("RING0IVY24-01 (192.168.16.103)")
    );
    assert_eq!(
        mapped.value_for(&MapProperty::PayloadData(1)),
        Some("Target: TEST\\svc-collector")
    );
    assert_eq!(
        mapped.value_for(&MapProperty::PayloadData(2)),
        Some("LogonType 10")
    );
    assert_eq!(
        mapped.value_for(&MapProperty::ExecutableInfo),
        Some("C:\\Windows\\System32\\svchost.exe")
    );
    assert!(
        mapped.values.iter().all(|value| value.is_complete()),
        "every column should resolve from a complete event"
    );
}

#[test]
fn security_4624_reports_absent_fields_instead_of_blanking_them() {
    let map = load(SECURITY_4624);

    // A real 4624 from a network logon carries no WorkstationName.
    let event = event_with_named_data(&[
        ("SubjectDomainName", "TEST"),
        ("SubjectUserName", "adam"),
        ("IpAddress", "192.168.16.103"),
    ]);

    let mapped = apply_map(&map, &event);

    assert_eq!(mapped.value_for(&MapProperty::UserName), Some("TEST\\adam"));

    let remote_host = mapped
        .values
        .iter()
        .find(|value| value.property == MapProperty::RemoteHost)
        .expect("RemoteHost column exists");
    assert_eq!(remote_host.unresolved, vec!["workstation".to_string()]);
    assert!(!remote_host.is_complete());
    assert!(
        remote_host.text.contains("192.168.16.103"),
        "the field that did resolve is still shown: {}",
        remote_host.text
    );
    assert!(
        remote_host.text.contains("%workstation%"),
        "the missing field stays visibly unresolved rather than rendering as blank: {}",
        remote_host.text
    );
}

#[test]
fn ntfs_146_applies_its_lookup_table_and_default() {
    let map = load(NTFS_146);
    let lookup = map.lookup_for("BusType").expect("BusType lookup present");
    assert_eq!(lookup.default.as_deref(), Some("Unknown code"));

    let usb = apply_map(
        &map,
        &event_with_named_data(&[("VolumeName", "C:"), ("BusType", "7")]),
    );
    assert!(
        usb.values
            .iter()
            .any(|value| value.text.contains("USB") && !value.text.contains(": 7")),
        "raw BusType 7 should render as USB: {:?}",
        usb.values.iter().map(|v| &v.text).collect::<Vec<_>>()
    );

    let unknown = apply_map(
        &map,
        &event_with_named_data(&[("VolumeName", "C:"), ("BusType", "255")]),
    );
    assert!(
        unknown
            .values
            .iter()
            .any(|value| value.text.contains("Unknown code")),
        "an out-of-table code should fall back to the lookup default"
    );
}

#[test]
fn a_registry_resolves_each_fixture_by_its_own_identity() {
    let mut registry = MapRegistry::new();
    for raw in [SHELL_CORE_9701, SECURITY_4624, NTFS_146] {
        registry.insert(load(raw));
    }
    assert_eq!(registry.len(), 3);

    let mapped = registry
        .apply(
            "Microsoft-Windows-Shell-Core/Operational",
            "Microsoft-Windows-Shell-Core",
            9701,
            &EventNode::new("Event").with_child(
                EventNode::new("EventData").with_child(EventNode::new("Data").with_text("cmd.exe")),
            ),
        )
        .expect("registered map is found");
    assert_eq!(
        mapped.value_for(&MapProperty::PayloadData(1)),
        Some("cmd.exe")
    );

    // Right channel and provider, wrong event: no map, and no guessing.
    assert!(registry
        .apply(
            "Microsoft-Windows-Shell-Core/Operational",
            "Microsoft-Windows-Shell-Core",
            9702,
            &EventNode::new("Event")
        )
        .is_none());
}

#[test]
fn every_fixture_parses_with_no_malformed_paths() {
    // Every expression is parsed directly rather than inferred from apply_map. Applying a map
    // skips any binding whose %Name% is absent from its template, and a skipped binding never
    // reaches the parser, so a malformed expression on one would leave invalid_paths empty and
    // this test would pass while proving nothing about that binding.
    let mut checked = 0usize;
    for raw in [SHELL_CORE_9701, SECURITY_4624, NTFS_146] {
        let map = load(raw);
        for entry in &map.maps {
            for binding in &entry.values {
                assert!(
                    ValuePath::parse(&binding.value).is_ok(),
                    "upstream map {} binding {} has an expression this engine cannot parse: {}",
                    map.event_id,
                    binding.name,
                    binding.value
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 3,
        "the fixtures should contribute several bindings, saw {checked}"
    );
}
