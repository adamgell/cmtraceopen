use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    assess_sccm_site_database_export, SccmSiteDatabaseExportCoverageState,
    SccmSiteDatabaseExportError, SccmSiteDatabaseExportEvidenceDisposition,
};
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
        let bytes =
            std::fs::read(fixture_root(scenario).join("export.json")).expect("fixture is readable");
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

#[test]
fn captured_export_is_coverage_only() {
    let captured = std::fs::read(fixture_root("captured").join("export.json"))
        .expect("captured fixture is readable");
    let assessment =
        assess_sccm_site_database_export(&captured).expect("captured v1 export is assessable");

    assert_eq!(
        assessment.coverage().state(),
        SccmSiteDatabaseExportCoverageState::Captured
    );
    assert_eq!(
        assessment.evidence_disposition(),
        SccmSiteDatabaseExportEvidenceDisposition::CoverageOnly
    );

    let public = serde_json::to_value(&assessment).expect("assessment serializes");
    assert_eq!(
        public,
        serde_json::from_slice::<Value>(
            &std::fs::read(fixture_root("captured").join("expected.json"))
                .expect("captured oracle is readable")
        )
        .expect("captured oracle is JSON")
    );
    let serialized = serde_json::to_string(&assessment).expect("assessment serializes");
    for forbidden in [
        "cmtraceopen.site.sha256.v1:",
        "findings",
        "transactions",
        "evidence",
        "authorization",
        "provenance",
        "snapshot",
        "integrity",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "public assessment must not expose {forbidden}"
        );
    }
}

fn fixture_bytes(scenario: &str) -> Vec<u8> {
    std::fs::read(fixture_root(scenario).join("export.json")).expect("fixture is readable")
}

fn fixture_value(scenario: &str) -> Value {
    serde_json::from_slice(&fixture_bytes(scenario)).expect("fixture is JSON")
}

#[test]
fn rejects_or_preserves_only_coverage_for_failed_gates() {
    let partial = assess_sccm_site_database_export(&fixture_bytes("partial"))
        .expect("partial export remains a coverage result");
    assert_eq!(
        partial.coverage().state(),
        SccmSiteDatabaseExportCoverageState::Partial
    );
    assert_eq!(
        partial.evidence_disposition(),
        SccmSiteDatabaseExportEvidenceDisposition::CoverageOnly
    );

    let denied = assess_sccm_site_database_export(&fixture_bytes("denied"))
        .expect("denied export remains a coverage result");
    assert_eq!(
        denied.coverage().state(),
        SccmSiteDatabaseExportCoverageState::AccessDenied
    );
    assert_eq!(
        denied.evidence_disposition(),
        SccmSiteDatabaseExportEvidenceDisposition::CoverageOnly
    );

    let mut denied_without_snapshot = fixture_value("denied");
    denied_without_snapshot
        .as_object_mut()
        .expect("denied fixture root is an object")
        .remove("snapshot");
    assert_eq!(
        assess_sccm_site_database_export(
            &serde_json::to_vec(&denied_without_snapshot).expect("mutation serializes")
        ),
        Err(SccmSiteDatabaseExportError::SnapshotContractViolation),
        "an access-denied envelope must contain an explicit null snapshot member"
    );

    assert_eq!(
        assess_sccm_site_database_export(&fixture_bytes("malformed")),
        Err(SccmSiteDatabaseExportError::MalformedDocument)
    );
    assert_eq!(
        assess_sccm_site_database_export(&fixture_bytes("unknown-version")),
        Err(SccmSiteDatabaseExportError::UnsupportedSchemaVersion { found: 2 })
    );
    assert_eq!(
        assess_sccm_site_database_export(&fixture_bytes("duplicate")),
        Err(SccmSiteDatabaseExportError::DuplicateJsonKey)
    );
    assert_eq!(
        assess_sccm_site_database_export(&fixture_bytes("oversized")),
        Err(SccmSiteDatabaseExportError::InputLimitExceeded)
    );

    let mut bad_integrity = fixture_value("captured");
    bad_integrity["integrity"]["canonicalPayloadSha256"] = Value::String("0".repeat(64));
    assert_eq!(
        assess_sccm_site_database_export(
            &serde_json::to_vec(&bad_integrity).expect("mutation serializes")
        ),
        Err(SccmSiteDatabaseExportError::IntegrityMismatch)
    );

    for field in [
        "queryText",
        "databaseName",
        "deviceId",
        "packageId",
        "userName",
        "siteCode",
    ] {
        let mut document = fixture_value("captured");
        document[field] = Value::String("not-admitted".to_owned());
        assert_eq!(
            assess_sccm_site_database_export(
                &serde_json::to_vec(&document).expect("mutation serializes")
            ),
            Err(SccmSiteDatabaseExportError::UnexpectedField),
            "{field} must not be admitted"
        );
    }

    let mut second_snapshot = fixture_value("captured");
    second_snapshot["snapshots"] = Value::Array(vec![second_snapshot["snapshot"].clone()]);
    assert_eq!(
        assess_sccm_site_database_export(
            &serde_json::to_vec(&second_snapshot).expect("mutation serializes")
        ),
        Err(SccmSiteDatabaseExportError::SnapshotContractViolation)
    );
}
