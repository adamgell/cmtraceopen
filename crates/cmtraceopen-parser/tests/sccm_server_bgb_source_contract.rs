//! Source contract for server-side `BgbServer.log` (#479).
//!
//! The fixtures are sanitized windows of a lab site server's real `BgbServer.log`
//! and `BgbServer.lo_`. They pin framing, rotation, and privacy behavior only: no
//! notification request or terminal outcome was observed, so nothing here admits
//! notification semantics.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::models::log_entry::{LogFormat, ParserKind};
use cmtraceopen_parser::parser::parse_content;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

const COMPONENT: &str = "SMS_NOTIFICATION_SERVER";
const TIMEZONE_BIAS_MINUTES: i32 = 240;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected {
    fixture_id: String,
    evidence: String,
    files: Vec<ExpectedFile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedFile {
    name: String,
    rotation: String,
    lines: u32,
    framed_records: usize,
    unframed_lines: Vec<u32>,
}

fn advanced_roles_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/advanced_roles")
}

fn fixture_root() -> PathBuf {
    advanced_roles_root().join("client-notification-bgb")
}

fn card() -> Value {
    let path = advanced_roles_root().join("source-cards/client-notification-bgb.json");
    serde_json::from_str(&fs::read_to_string(&path).expect("BGB card is readable"))
        .expect("BGB card is valid JSON")
}

fn fixture_dirs() -> BTreeSet<String> {
    fs::read_dir(fixture_root())
        .expect("BGB fixture root exists")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

fn expected(id: &str) -> Expected {
    let path = fixture_root().join(id).join("expected.json");
    serde_json::from_str(&fs::read_to_string(&path).expect("expected.json is readable"))
        .unwrap_or_else(|error| panic!("{id}/expected.json: {error}"))
}

fn read_fixture(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn bgb_card_is_observed_with_simple_framing_and_scoped_version() {
    let card = card();
    // The capture contract (basename, roles, paths, rotation, limits) is unchanged,
    // so the version that capture manifests and intake attest stays 1.0.0.
    assert_eq!(card["cardVersion"], "1.0.0");
    assert_eq!(card["rawParserFamily"], "simple");
    assert_eq!(card["promotion"]["state"], "observed");
    assert!(!card["promotion"]["observedEvidenceIds"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(card["sourceVersionScope"]["state"], "scoped");
    assert_eq!(
        card["sourceVersionScope"]["allowedPrefixes"],
        serde_json::json!(["5.00.9141"])
    );
    assert_eq!(card["correlationPolicy"]["keyState"], "unvalidated");
    assert_eq!(card["semanticPolicy"]["captureGuidanceOnly"], true);
    assert_eq!(card["semanticPolicy"]["canCreateTransactions"], false);
    assert_eq!(card["semanticPolicy"]["canCreateFailureFindings"], false);
}

#[test]
fn bgb_fixture_inventory_matches_the_card() {
    let card_ids = card()["fixtureIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let dirs = fixture_dirs();
    assert!(!dirs.is_empty());
    assert_eq!(card_ids, dirs.iter().cloned().collect::<Vec<_>>());
    for id in &dirs {
        let expected = expected(id);
        assert_eq!(&expected.fixture_id, id);
        assert!(expected.evidence.trim().len() >= 30, "{id}: evidence note");
        let names = expected
            .files
            .iter()
            .map(|file| file.name.as_str())
            .chain(["expected.json"])
            .collect::<BTreeSet<_>>();
        let present = fs::read_dir(fixture_root().join(id))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            present,
            names.into_iter().map(str::to_owned).collect(),
            "{id}"
        );
    }
}

#[test]
fn bgb_fixtures_detect_as_simple_and_frame_every_trailer_line() {
    for id in fixture_dirs() {
        for file in expected(&id).files {
            let path = fixture_root().join(&id).join(&file.name);
            let content = read_fixture(&path);
            let (result, selection) = parse_content(&content, &file.name, content.len() as u64);

            assert_eq!(selection.parser, ParserKind::Simple, "{id}/{}", file.name);
            assert_eq!(
                result.format_detected,
                LogFormat::Simple,
                "{id}/{}",
                file.name
            );
            assert_eq!(
                content.lines().count() as u32,
                file.lines,
                "{id}/{}",
                file.name
            );
            // Every physical line stays a record; unframed lines are kept, not dropped.
            assert_eq!(
                result.entries.len() as u32,
                file.lines,
                "{id}/{}",
                file.name
            );

            let (framed, unframed): (Vec<_>, Vec<_>) = result
                .entries
                .iter()
                .partition(|entry| entry.component.is_some());
            assert_eq!(framed.len(), file.framed_records, "{id}/{}", file.name);
            assert_eq!(
                unframed
                    .iter()
                    .map(|entry| entry.line_number)
                    .collect::<Vec<_>>(),
                file.unframed_lines,
                "{id}/{}",
                file.name
            );

            for entry in &framed {
                assert_eq!(entry.component.as_deref(), Some(COMPONENT));
                assert_eq!(entry.timezone_offset, Some(TIMEZONE_BIAS_MINUTES));
                assert!(entry.thread.is_some(), "{id}/{}", file.name);
                assert!(entry.timestamp.is_some(), "{id}/{}", file.name);
            }
            for entry in &unframed {
                assert_eq!(entry.timestamp, None, "{id}/{}", file.name);
            }
            let timestamps = result
                .entries
                .iter()
                .filter_map(|entry| entry.timestamp)
                .collect::<Vec<_>>();
            assert!(
                timestamps.windows(2).all(|pair| pair[0] <= pair[1]),
                "{id}/{}: records stay in time order",
                file.name
            );
        }
    }
}

#[test]
fn rotated_file_ends_with_the_rename_marker_and_precedes_the_current_file() {
    let expected = expected("rotation-boundary");
    let rotated = expected
        .files
        .iter()
        .find(|file| file.rotation == "lo_")
        .expect("rotation fixture has an lo_ file");
    let current = expected
        .files
        .iter()
        .find(|file| file.rotation == "current")
        .expect("rotation fixture has a current file");
    assert_eq!(rotated.unframed_lines, [rotated.lines]);
    assert!(current.unframed_lines.is_empty());

    let rotated_content =
        read_fixture(&fixture_root().join("rotation-boundary").join(&rotated.name));
    assert_eq!(
        rotated_content.lines().last(),
        Some("<MAXIMUM LOG FILE SIZE REACHED - FILE RENAMED>")
    );

    let last_rotated = parse_content(&rotated_content, &rotated.name, 0)
        .0
        .entries
        .iter()
        .filter_map(|entry| entry.timestamp)
        .max()
        .unwrap();
    let current_content =
        read_fixture(&fixture_root().join("rotation-boundary").join(&current.name));
    let first_current = parse_content(&current_content, &current.name, 0)
        .0
        .entries
        .iter()
        .filter_map(|entry| entry.timestamp)
        .min()
        .unwrap();
    assert!(last_rotated <= first_current);
}

#[test]
fn bgb_fixtures_carry_only_sanitized_identity() {
    let guid =
        Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
    let placeholder_guid = Regex::new(r"^00000000-0000-0000-0000-[0-9]{12}$").unwrap();
    let thumbprint = Regex::new(r"(?i)\b[0-9a-f]{40}\b").unwrap();
    let fqdn = Regex::new(r"(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\.[a-z]{2,}\b").unwrap();
    let site_code = Regex::new(r#"SITE=(\w+)|P1='(\w+)'|"CM_(\w+)""#).unwrap();
    let allowed_dotted = [
        "SITESERVER.example.invalid",
        "dllhost.exe",
        "bgb.box",
        "statesys.box",
        "statmgr.box",
    ];

    for id in fixture_dirs() {
        for file in expected(&id).files {
            let content = read_fixture(&fixture_root().join(&id).join(&file.name));
            let label = format!("{id}/{}", file.name);
            for found in guid.find_iter(&content) {
                assert!(placeholder_guid.is_match(found.as_str()), "{label}: GUID");
            }
            for found in thumbprint.find_iter(&content) {
                assert!(
                    found.as_str().bytes().all(|byte| byte == b'0'),
                    "{label}: thumbprint"
                );
            }
            for found in fqdn.find_iter(&content) {
                let value = found.as_str();
                assert!(
                    allowed_dotted
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(value))
                        || value.ends_with(".example.invalid"),
                    "{label}: unexpected dotted name"
                );
            }
            for captures in site_code.captures_iter(&content) {
                let code = captures.iter().skip(1).flatten().next().unwrap().as_str();
                assert_eq!(code, "PS1", "{label}: site code");
            }
            assert!(!content.contains("Program Files"), "{label}: install path");
        }
    }
}
