use std::path::{Path, PathBuf};

use serde_json::Value;

const MAX_EXPORT_BYTES: usize = 1_048_576;
const FORBIDDEN_RAW_MARKERS: [&str; 10] = [
    "select ",
    "from ",
    "password",
    "connectionstring",
    "server=",
    "uid=",
    "resourceid",
    "deviceid",
    "username",
    "packageid",
];

fn fixture_root(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/site_database_export/v1")
        .join(scenario)
}

fn assert_no_raw_identifier_markers(bytes: &[u8]) {
    let document = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for marker in FORBIDDEN_RAW_MARKERS {
        assert!(
            !document.contains(marker),
            "fixture must not contain raw sensitive marker {marker}"
        );
    }
    assert!(!document.contains("sitecode"));
}

#[test]
fn schema_and_fixture_contract() {
    for scenario in ["captured", "partial", "denied"] {
        let bytes = std::fs::read(fixture_root(scenario).join("export.json"))
            .expect("fixture is readable");
        assert!(bytes.len() <= MAX_EXPORT_BYTES);
        assert_no_raw_identifier_markers(&bytes);

        let document: Value = serde_json::from_slice(&bytes).expect("fixture is valid JSON");
        let fields = document
            .as_object()
            .expect("fixture root is an object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            fields,
            std::collections::BTreeSet::from([
                "authorization",
                "captureState",
                "contractId",
                "integrity",
                "intent",
                "provenance",
                "schemaVersion",
                "snapshot",
            ])
        );
    }
}
