//! Source contract for server-side `BgbServer.log` (#479).
//!
//! The fixtures are sanitized windows of a lab site server's real `BgbServer.log`
//! and `BgbServer.lo_`. They pin framing, rotation, and privacy behavior only: no
//! notification request or terminal outcome was observed, so nothing here admits
//! notification semantics.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::models::log_entry::{LogFormat, ParserKind, Severity};
use cmtraceopen_parser::parser::parse_content;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

const COMPONENT: &str = "SMS_NOTIFICATION_SERVER";
const CLIENT_COMPONENT: &str = "BgbAgent";
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
    /// `server` for `BgbServer.*`, `client` for the paired client-side log.
    side: String,
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
fn bgb_fixtures_detect_their_framing_and_keep_every_line() {
    for id in fixture_dirs() {
        for file in expected(&id).files {
            let path = fixture_root().join(&id).join(&file.name);
            let content = read_fixture(&path);
            let (result, selection) = parse_content(&content, &file.name, content.len() as u64);
            // BgbServer.log is SMS trace (Simple); the client notification log is CCM.
            let (parser, format, component) = match file.side.as_str() {
                "server" => (ParserKind::Simple, LogFormat::Simple, COMPONENT),
                "client" => (ParserKind::Ccm, LogFormat::Ccm, CLIENT_COMPONENT),
                other => panic!("{id}/{}: unknown side {other}", file.name),
            };

            assert_eq!(selection.parser, parser, "{id}/{}", file.name);
            assert_eq!(result.format_detected, format, "{id}/{}", file.name);
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
                assert_eq!(entry.component.as_deref(), Some(component));
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

fn record_timestamps(id: &str, file: &ExpectedFile) -> Vec<i64> {
    let content = read_fixture(&fixture_root().join(id).join(&file.name));
    parse_content(&content, &file.name, 0)
        .0
        .entries
        .iter()
        .filter_map(|entry| entry.timestamp)
        .collect()
}

#[test]
fn every_fixture_file_is_labeled_with_the_rotation_it_came_from() {
    let boundary = expected("rotation-boundary");
    let rotated_end = boundary
        .files
        .iter()
        .filter(|file| file.rotation == "lo_")
        .flat_map(|file| record_timestamps("rotation-boundary", file))
        .max()
        .unwrap();
    let current_start = boundary
        .files
        .iter()
        .filter(|file| file.rotation == "current")
        .flat_map(|file| record_timestamps("rotation-boundary", file))
        .min()
        .unwrap();

    for id in fixture_dirs() {
        for file in expected(&id).files {
            let label = format!("{id}/{}", file.name);
            let expected_name = match (file.side.as_str(), file.rotation.as_str()) {
                ("server", "current") => "BgbServer.log",
                ("server", "lo_") => "BgbServer.lo_",
                ("client", "current") => "CcmNotificationAgent.log",
                (side, rotation) => panic!("{label}: unknown {side}/{rotation}"),
            };
            assert_eq!(file.name, expected_name, "{label}");
            // The observed rename belongs to BgbServer; the client log rotates on its own.
            if file.side != "server" {
                continue;
            }
            let timestamps = record_timestamps(&id, &file);
            if file.rotation == "current" {
                assert!(
                    timestamps.iter().all(|time| *time >= current_start),
                    "{label}: a current-file record predates the observed rename"
                );
            } else {
                assert!(
                    timestamps.iter().all(|time| *time <= rotated_end),
                    "{label}: a rotated-file record follows the observed rename"
                );
            }
        }
    }
}

#[test]
fn firewall_warning_is_the_only_warning_type() {
    let mut warnings = Vec::new();
    for id in fixture_dirs() {
        for file in expected(&id).files {
            let content = read_fixture(&fixture_root().join(&id).join(&file.name));
            let (result, _) = parse_content(&content, &file.name, 0);
            warnings.extend(
                result
                    .entries
                    .into_iter()
                    .filter(|entry| entry.severity == Severity::Warning)
                    .map(|entry| (id.clone(), entry.message)),
            );
        }
    }
    assert!(warnings
        .iter()
        .any(|(id, _)| id == "firewall-warning-state-message"));
    for (id, message) in &warnings {
        assert!(
            message.starts_with("WARNING: Notification Server"),
            "{id}: unexpected warning {message:?}"
        );
    }
}

#[test]
fn bgb_fixtures_carry_only_sanitized_identity() {
    let guid =
        Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
    let placeholder_guid = Regex::new(r"^00000000-0000-0000-0000-[0-9]{12}$").unwrap();
    let thumbprint = Regex::new(r"(?i)\b[0-9a-f]{40}\b").unwrap();
    // Any dotted name of two or more labels that starts with a letter.
    let dotted = Regex::new(r"(?i)\b[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+\b").unwrap();
    let generated_name = Regex::new(r"^(?:Bgb|msg)[0-9]{5}\.(?:BLD|BOS|BTS|SMX)$").unwrap();
    let generated_file = Regex::new(r"\\([A-Za-z0-9]+\.(?:BLD|BOS|BTS|SMX))\b").unwrap();
    let drive_path = Regex::new(r"(?i)\b[a-z]:\\").unwrap();
    let host_field = Regex::new(r#"SYS=(\S+)|local on (\S+)"#).unwrap();
    let insertion_string = Regex::new(r#"ISTR[0-9]="([^"]*)""#).unwrap();
    let site_code = Regex::new(r"SITE=(\w+)|P1='(\w+)'|CM_(\w+)").unwrap();
    let allowed_dotted = [
        "SITESERVER.example.invalid",
        // Product source file named by the CCM `file=` attribute, not identity.
        "bgbconnector.cpp",
        "dllhost.exe",
        "bgb.box",
        "statesys.box",
        "statmgr.box",
    ];
    let allowed_hosts = ["SITESERVER", "SITESERVER.example.invalid"];

    let mut all_content = String::new();
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
            for found in dotted.find_iter(&content) {
                let value = found.as_str();
                assert!(
                    allowed_dotted
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(value))
                        || generated_name.is_match(value),
                    "{label}: unexpected dotted name {value:?}"
                );
            }
            for captures in generated_file.captures_iter(&content) {
                assert!(
                    generated_name.is_match(&captures[1]),
                    "{label}: generated file name"
                );
            }
            assert!(!drive_path.is_match(&content), "{label}: drive-letter path");
            for captures in host_field.captures_iter(&content) {
                let host = captures.iter().skip(1).flatten().next().unwrap().as_str();
                assert!(allowed_hosts.contains(&host), "{label}: host {host:?}");
            }
            for captures in insertion_string.captures_iter(&content) {
                let value = &captures[1];
                assert!(
                    value.is_empty()
                        || value.bytes().all(|byte| byte.is_ascii_digit())
                        || allowed_hosts.contains(&value)
                        || value == "CM_PS1",
                    "{label}: insertion string {value:?}"
                );
            }
            for captures in site_code.captures_iter(&content) {
                let code = captures.iter().skip(1).flatten().next().unwrap().as_str();
                assert_eq!(code, "PS1", "{label}: site code");
            }
            all_content.push_str(&content);
        }
    }

    // The placeholders must actually be exercised, so the checks above are not vacuous.
    for placeholder in [
        "SYS=SITESERVER.example.invalid",
        "local on SITESERVER",
        "SITE=PS1",
        r"<siteInstallRoot>\inboxes",
        "hash 0000000000000000000000000000000000000000",
        "00000000-0000-0000-0000-000000000001",
    ] {
        assert!(all_content.contains(placeholder), "missing {placeholder:?}");
    }
    assert!(generated_file.is_match(&all_content));
}

#[derive(Debug, PartialEq)]
struct PushKey {
    push_id: u32,
    task_id: u32,
    task_guid: String,
}

fn parsed_messages(id: &str, name: &str) -> Vec<(String, i64)> {
    let content = read_fixture(&fixture_root().join(id).join(name));
    parse_content(&content, name, 0)
        .0
        .entries
        .into_iter()
        .map(|entry| (entry.message, entry.timestamp.expect("framed record")))
        .collect()
}

#[test]
fn push_task_delivery_links_server_and_client_by_exact_task_key() {
    let server = parsed_messages("push-task-delivered", "BgbServer.log");
    let client = parsed_messages("push-task-delivered", "CcmNotificationAgent.log");

    let start = Regex::new(
        r"^Starting to send push task \(PushID: (\d+) TaskID: (\d+) TaskGUID: ([0-9a-f-]{36}) TaskType: (\d+) TaskParam: \) to (\d+) clients",
    )
    .unwrap();
    let finished =
        Regex::new(r"^Finished sending push task \(PushID: (\d+) TaskID: (\d+)\) to (\d+) clients")
            .unwrap();
    let status = Regex::new(
        r"^Generated BGB task status report .* \(PushID: (\d+) ReportedClients: (\d+) FailedClients: (\d+)\)",
    )
    .unwrap();
    let receive = Regex::new(
        r"^Receive task from server with pushid=(\d+), taskid=(\d+), taskguid=([0-9a-f-]{36}), tasktype=(\d+)",
    )
    .unwrap();

    fn only<'a>(records: &'a [(String, i64)], pattern: &Regex) -> (regex::Captures<'a>, i64) {
        let mut matches = records
            .iter()
            .filter_map(|(message, time)| pattern.captures(message).map(|caps| (caps, *time)))
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "{pattern}");
        matches.remove(0)
    }
    let (sent, sent_at) = only(&server, &start);
    let (done, _) = only(&server, &finished);
    let (report, _) = only(&server, &status);
    let (received, received_at) = only(&client, &receive);

    let server_key = PushKey {
        push_id: sent[1].parse().unwrap(),
        task_id: sent[2].parse().unwrap(),
        task_guid: sent[3].to_owned(),
    };
    let client_key = PushKey {
        push_id: received[1].parse().unwrap(),
        task_id: received[2].parse().unwrap(),
        task_guid: received[3].to_owned(),
    };
    // The correlation is the exact key; time only corroborates the order.
    assert_eq!(client_key, server_key);
    assert_eq!(&received[4], &sent[4], "task type");
    assert!(received_at >= sent_at);

    // Server-side request and terminal outcome close the same push.
    assert_eq!(done[1].parse::<u32>().unwrap(), server_key.push_id);
    assert_eq!(done[2].parse::<u32>().unwrap(), server_key.task_id);
    assert_eq!(&done[3], &sent[5], "clients targeted");
    assert_eq!(report[1].parse::<u32>().unwrap(), server_key.push_id);
    assert_eq!(
        (&report[2], &report[3]),
        (&"1".to_owned()[..], &"0".to_owned()[..])
    );
}
