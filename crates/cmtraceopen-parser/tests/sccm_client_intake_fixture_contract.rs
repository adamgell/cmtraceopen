use cmtraceopen_parser::{
    models::log_entry::LogFormat,
    parser::{parse_content_with_selection, ResolvedParser},
};
use serde_json::Value;

const CAPPED_CONTENT: &[u8] = include_bytes!(
    "fixtures/sccm/client/intake/capped/evidence/client-content/current/DataTransferService.log"
);
const EXPECTED_CAPPED_CONTENT: &[u8] = b"<![LOG[SYNTHETIC FIXTURE capped: error-looking 0x80000001; coverage only]LOG]!><time=\"00:02:59.000+000\" date=\"7-30-2026\" compon\n";
const EXPECTED_CAPPED_SHA256: &str =
    "3253f6c4bc7d74bd2dbdadbe2f6543ff61a57161f85f650869b1292556270114";
const EXPECTED_ROLLOVER_RELATIVE_PATH: &str = "evidence/client-app-enforce/lo/AppEnforce.lo_";
const EXPECTED_ROLLOVER_SANITIZED_PATH: &str = "SYNTHETIC://root-a/CCM/Logs/AppEnforce.lo_";
const EXPECTED_ROLLOVER_BYTES: u64 = 176;

fn site_code_is_canonical(site_code: &str) -> bool {
    site_code == "LAB"
}

#[test]
fn client_intake_rejects_non_lab_three_character_site_codes() {
    assert!(!site_code_is_canonical("ABC"));
}

#[test]
fn capped_client_content_is_an_exact_incomplete_ccm_prefix() {
    assert_eq!(CAPPED_CONTENT.len(), 128);
    assert_eq!(
        CAPPED_CONTENT, EXPECTED_CAPPED_CONTENT,
        "fixture bytes must retain SHA-256 {EXPECTED_CAPPED_SHA256}"
    );

    let content = std::str::from_utf8(CAPPED_CONTENT).expect("fixture is declared UTF-8");
    assert!(content.starts_with("<![LOG[SYNTHETIC FIXTURE"));
    assert!(content.contains("error-looking 0x80000001"));
    assert!(!content.contains("[cut]"));

    let parsed =
        parse_content_with_selection(content, "DataTransferService.log", &ResolvedParser::ccm());

    assert_eq!(parsed.total_lines, 1);
    assert_eq!(parsed.parse_errors, 1);
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].format, LogFormat::Plain);
}

#[test]
fn client_intake_uses_canonical_site_and_rotation_contracts() {
    let manifests = [
        (
            "access-denied",
            include_str!("fixtures/sccm/client/intake/access-denied/manifest.json"),
        ),
        (
            "capped",
            include_str!("fixtures/sccm/client/intake/capped/manifest.json"),
        ),
        (
            "collision",
            include_str!("fixtures/sccm/client/intake/collision/manifest.json"),
        ),
        (
            "complete",
            include_str!("fixtures/sccm/client/intake/complete/manifest.json"),
        ),
        (
            "missing-root",
            include_str!("fixtures/sccm/client/intake/missing-root/manifest.json"),
        ),
        (
            "rotations",
            include_str!("fixtures/sccm/client/intake/rotations/manifest.json"),
        ),
    ];

    let mut failures = Vec::new();
    for (scenario, contents) in manifests {
        let manifest: Value = serde_json::from_str(contents).expect("fixture manifest is JSON");
        let site_code = manifest["bundle"]["siteCode"]
            .as_str()
            .expect("client intake bundle has a site code");
        if !site_code_is_canonical(site_code) {
            failures.push(format!("{scenario}: siteCode must be LAB, got {site_code}"));
        }
    }

    let rotations: Value = serde_json::from_str(include_str!(
        "fixtures/sccm/client/intake/rotations/manifest.json"
    ))
    .expect("rotation manifest is JSON");
    let rollovers: Vec<&Value> = rotations["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array")
        .iter()
        .filter(|artifact| artifact["rotation"]["kind"] == "lo")
        .collect();
    if rollovers.len() != 1 {
        failures.push(format!(
            "rotations: expected exactly one .lo_ artifact, got {}",
            rollovers.len()
        ));
    }
    let Some(rollover) = rollovers.first() else {
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        return;
    };
    let basename = rollover["originalBasename"]
        .as_str()
        .expect("rollover artifact has an original basename");
    if basename != "AppEnforce.lo_" {
        failures.push(format!(
            "rotations: standard ConfigMgr rollover basename must be AppEnforce.lo_, got {basename}"
        ));
    }

    let relative_path = rollover["relativePath"]
        .as_str()
        .expect("captured rollover has a relative path");
    if relative_path != EXPECTED_ROLLOVER_RELATIVE_PATH {
        failures.push(format!(
            "rotations: rollover relativePath must be {EXPECTED_ROLLOVER_RELATIVE_PATH}, got {relative_path}"
        ));
    }
    let sanitized_path = rollover["sanitizedSourcePath"]
        .as_str()
        .expect("rollover artifact has sanitized provenance");
    if sanitized_path != EXPECTED_ROLLOVER_SANITIZED_PATH {
        failures.push(format!(
            "rotations: rollover sanitizedSourcePath must be {EXPECTED_ROLLOVER_SANITIZED_PATH}, got {sanitized_path}"
        ));
    }
    let bytes_copied = rollover["bytesCopied"]
        .as_u64()
        .expect("captured rollover records bytesCopied");
    if bytes_copied != EXPECTED_ROLLOVER_BYTES {
        failures.push(format!(
            "rotations: bytesCopied must be the committed {EXPECTED_ROLLOVER_BYTES}, got {bytes_copied}"
        ));
    }
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/client/intake/rotations")
        .join(relative_path);
    if !fixture_path.is_file() {
        failures.push(format!(
            "rotations: manifest relativePath does not resolve to a fixture: {}",
            fixture_path.display()
        ));
    } else {
        let actual_bytes = std::fs::metadata(&fixture_path)
            .expect("rollover fixture metadata is readable")
            .len();
        if bytes_copied != actual_bytes {
            failures.push(format!(
                "rotations: bytesCopied {bytes_copied} does not match fixture length {actual_bytes}"
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
