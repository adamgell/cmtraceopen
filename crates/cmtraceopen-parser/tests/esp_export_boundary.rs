//! End-to-end guard for the ESP session export boundary (issue #549).
//!
//! These tests do not exercise `redacted_export_projection` directly. They
//! serialize a session the way the application's "Export session" button
//! writes it, through [`exported_session_json`], and assert that no local
//! identifier survives into the bytes that reach the user-chosen file.
//!
//! Two independent guards run against the same serialized text:
//!
//! 1. Named markers. Every sensitive value planted in the snapshot is asserted
//!    absent, and a canary asserts the same markers ARE present when the raw
//!    snapshot is serialized, so the test can never pass vacuously.
//! 2. Shape scan. Every string in the exported JSON is matched against
//!    identifier shapes (mail address, SID, MAC, IPv4). A field that starts
//!    carrying an identifier fails here even if no named marker was updated.
//!
//! What this does NOT cover: a bare device serial or DNS domain sitting in
//! narrative text. Those are masked where they are typed fields but carry no
//! label and no distinctive shape in free text, so the redaction rules leave
//! them. `bare_identifiers_in_free_text_are_a_known_residual_gap` pins that
//! limitation so it stays visible.

use cmtraceopen_parser::esp::*;
use regex::Regex;
use serde_json::Value;

const CAPTURED_AT: &str = "2026-08-11T09:15:00Z";

// Synthetic values. Nothing here belongs to a real tenant or device.
const UPN: &str = "adele.vance@contoso.onmicrosoft.com";
const PROFILE_USER: &str = "adele.vance";
const TENANT_DOMAIN: &str = "contoso.onmicrosoft.com";
const TENANT_ID: &str = "8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90";
const SERIAL: &str = "5CD9SYNTH01";
const ENTDM_ID: &str = "ENTDM-SYNTH-0001";
const USER_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const INSTALL_SECRET: &str = "Sup3rSyntheticSecret";
const BEARER_TOKEN: &str = "eyJzeW50aGV0aWMtdG9rZW4";
const CLIENT_IPV4: &str = "192.0.2.77";
const NIC_MAC: &str = "00:1A:2B:3C:4D:5E";

/// Every planted value that must not reach an exported file.
const PLANTED_IDENTIFIERS: &[(&str, &str)] = &[
    ("user principal name", UPN),
    ("user profile name", PROFILE_USER),
    ("tenant domain", TENANT_DOMAIN),
    ("tenant id", TENANT_ID),
    ("device serial number", SERIAL),
    ("EntDMID", ENTDM_ID),
    ("user SID", USER_SID),
    ("installer secret", INSTALL_SECRET),
    ("bearer token", BEARER_TOKEN),
    ("client IPv4 address", CLIENT_IPV4),
    ("NIC MAC address", NIC_MAC),
];

/// Serialize a session exactly the way the "Export session" button writes it.
///
/// This is the seam the whole test file turns on: it must stay the real export
/// path, never a direct call to the redaction module, or these tests stop
/// proving anything about what lands on disk.
///
/// That path is the `export_esp_session` command, which builds an
/// [`EspSessionCapture`] and writes its JSON to the user-chosen file. The
/// capture type is the boundary: its snapshot field is private and its only
/// constructor applies the export projection.
fn exported_session_json(snapshot: &EspDiagnosticsSnapshot) -> String {
    EspSessionCapture::from_snapshot(
        snapshot,
        EspSessionCaptureMeta {
            captured_at_utc: CAPTURED_AT.to_string(),
            app_version: None,
            app_commit: None,
        },
    )
    .to_json()
    .expect("an ESP session capture must serialize")
}

#[test]
fn the_exported_session_carries_no_planted_identifier() {
    let snapshot = snapshot_with_planted_identifiers();
    let raw = serde_json::to_string(&snapshot).expect("snapshot serializes");
    let exported = exported_session_json(&snapshot);

    for (label, marker) in PLANTED_IDENTIFIERS {
        // Canary: the marker really is reachable from the snapshot, so a
        // passing assertion below means redaction removed it rather than the
        // fixture never carrying it.
        assert!(
            raw.contains(marker),
            "test fixture no longer plants the {label}; the export assertion below would be vacuous"
        );
        assert!(
            !exported.contains(marker),
            "the exported session leaks the {label} ({marker})"
        );
    }
}

#[test]
fn the_exported_session_carries_no_identifier_shaped_string() {
    let snapshot = snapshot_with_planted_identifiers();
    let exported: Value =
        serde_json::from_str(&exported_session_json(&snapshot)).expect("export is JSON");

    let shapes = [
        ("mail address", Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap()),
        ("security identifier", Regex::new(r"(?i)\bS-1-\d+(?:-\d+){3,}\b").unwrap()),
        ("MAC address", Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b").unwrap()),
        // A dotted quad and a four-part version string are the same shape, so
        // this fixture keeps version strings to three parts on purpose.
        ("IPv4 address", Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap()),
    ];

    let mut strings = Vec::new();
    collect_strings(&exported, String::from("$"), &mut strings);
    assert!(
        strings.len() > 50,
        "the walker found only {} strings, so it is not reaching the whole export",
        strings.len()
    );

    for (path, value) in &strings {
        for (label, shape) in &shapes {
            assert!(
                !shape.is_match(value),
                "the exported session leaks a {label} at {path}: {value}"
            );
        }
    }
}

#[test]
fn the_exported_session_states_that_it_was_redacted() {
    // An export that cannot say whether it was redacted is not auditable.
    let snapshot = snapshot_with_planted_identifiers();
    let exported: Value =
        serde_json::from_str(&exported_session_json(&snapshot)).expect("export is JSON");

    assert_eq!(
        exported.get("redacted"),
        Some(&Value::Bool(true)),
        "the export envelope must record that it is a redacted projection"
    );
}

#[test]
fn the_exported_session_still_loads_as_a_session() {
    // The export format is also the replay format: "Open session" must be able
    // to read what "Export session" wrote, redaction included.
    let exported: Value =
        serde_json::from_str(&exported_session_json(&snapshot_with_planted_identifiers()))
            .expect("export is JSON");
    let reloaded: EspDiagnosticsSnapshot =
        serde_json::from_value(exported["snapshot"].clone()).expect("export reloads as a session");

    assert_eq!(reloaded.schema_version, ESP_DIAGNOSTICS_SCHEMA_VERSION);
    assert_eq!(reloaded.workloads.len(), 1);
}

#[test]
fn exporting_does_not_mutate_the_local_session() {
    // The local snapshot keeps its real values: this is an export projection,
    // not an in-place scrub of what the workspace renders.
    let snapshot = snapshot_with_planted_identifiers();
    let before = serde_json::to_string(&snapshot).expect("snapshot serializes");
    let _ = exported_session_json(&snapshot);
    let after = serde_json::to_string(&snapshot).expect("snapshot serializes");

    assert_eq!(before, after);
}

#[test]
fn bare_identifiers_in_free_text_are_a_known_residual_gap() {
    // Not an endorsement: a characterization of what this boundary does NOT
    // do, so the gap is visible instead of assumed closed. A device serial and
    // a DNS tenant domain are masked where they are typed fields, but in
    // narrative text they carry no label and no distinctive shape, so the
    // free-text rules leave them alone. Whoever closes that gap should delete
    // this test along with the note in the module docs.
    let mut snapshot = snapshot_with_planted_identifiers();
    snapshot.activity[0].detail = Some(format!("device {SERIAL} joined {TENANT_DOMAIN}"));

    let exported = exported_session_json(&snapshot);

    assert!(exported.contains(SERIAL), "the free-text serial gap closed");
    assert!(
        exported.contains(TENANT_DOMAIN),
        "the free-text tenant-domain gap closed"
    );
}

fn collect_strings(value: &Value, path: String, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(text) => out.push((path, text.clone())),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_strings(item, format!("{path}[{index}]"), out);
            }
        }
        Value::Object(members) => {
            for (key, member) in members {
                collect_strings(member, format!("{path}.{key}"), out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// A session shaped like a real device's, with a planted identifier in every
/// field family an export could carry one in.
fn snapshot_with_planted_identifiers() -> EspDiagnosticsSnapshot {
    EspDiagnosticsSnapshot {
        schema_version: ESP_DIAGNOSTICS_SCHEMA_VERSION,
        scenario: EspScenario::AutopilotV1,
        phase: EspPhase::DeviceSetup,
        generated_at_utc: CAPTURED_AT.to_string(),
        elevation: EspElevationState {
            is_elevated: true,
            restart_supported: true,
            restricted_sources: vec![format!("C:\\Users\\{PROFILE_USER}\\AppData\\Local\\Temp")],
        },
        identity: EspIdentityEvidence {
            device_name: Some("DESKTOP-SYNTH1".to_string()),
            managed_device_id: Some("11111111-2222-3333-4444-555555555555".to_string()),
            entra_device_id: Some("66666666-7777-8888-9999-aaaaaaaaaaaa".to_string()),
            entdm_id: Some(sensitive(ENTDM_ID)),
            tenant_id: Some(sensitive(TENANT_ID)),
            tenant_domain: Some(sensitive(TENANT_DOMAIN)),
            user_principal_name: Some(sensitive(UPN)),
            serial_number: Some(sensitive(SERIAL)),
            evidence: vec![evidence_ref("identity")],
        },
        profile: Some(EspProfileEvidence {
            profile_name: Some(format!("Autopilot profile owned by {UPN}")),
            deployment_profile_id: Some("profile-1".to_string()),
            correlation_id: Some("correlation-1".to_string()),
            tenant_domain: Some(sensitive(TENANT_DOMAIN)),
            tenant_id: Some(sensitive(TENANT_ID)),
            oobe_config: None,
            profile_download_time: Some(timestamp("2026-08-11T09:00:00Z")),
            join_mode: Some(EspJoinMode::Entra),
            odj_applied: Some(false),
            skip_domain_connectivity_check: Some(false),
            device_preparation: None,
            evidence: vec![evidence_ref("profile")],
        }),
        enrollments: vec![EspEnrollmentEvidence {
            enrollment_id: "enrollment-1".to_string(),
            provider_id: Some("MS DM Server".to_string()),
            tenant_id: Some(sensitive(TENANT_ID)),
            user_principal_name: Some(sensitive(UPN)),
            entdm_id: Some(sensitive(ENTDM_ID)),
            settings: EspEnrollmentSettings {
                device_esp_enabled: Some(true),
                user_esp_enabled: Some(true),
                timeout_seconds: Some(3600),
                blocking: Some(true),
                allow_reset: Some(false),
                allow_retry: Some(true),
                continue_anyway: Some(false),
            },
            evidence: vec![evidence_ref("enrollment")],
        }],
        sessions: vec![EspSession {
            session_id: "session-user".to_string(),
            kind: EspSessionKind::Classic,
            scope: EspScope::User,
            user_sid: Some(sensitive(USER_SID)),
            started_at: Some(timestamp("2026-08-11T09:01:00Z")),
            ended_at: None,
            phase: EspPhase::AccountSetup,
            is_latest: true,
            workload_ids: vec!["workload-app".to_string()],
            evidence: vec![evidence_ref("session")],
        }],
        workloads: vec![EspWorkload {
            workload_id: "workload-app".to_string(),
            session_id: "session-user".to_string(),
            kind: EspTrackedKind::Win32App,
            scope: EspScope::User,
            raw_identifier: "app-1".to_string(),
            display_name: Some(format!("Contoso VPN assigned to {UPN}")),
            status: status_text(&format!("Installing for {USER_SID}")),
            timestamps: EspWorkloadTimestamps {
                first_observed: timestamp("2026-08-11T09:02:00Z"),
                started: Some(timestamp("2026-08-11T09:03:00Z")),
                ended: None,
                last_updated: Some(timestamp("2026-08-11T09:04:00Z")),
            },
            exit_code: None,
            enforcement_error_code: None,
            blocking: Some(true),
            evidence: vec![evidence_ref("workload")],
        }],
        installer_correlations: vec![EspInstallerCorrelation {
            correlation_id: "correlation-1".to_string(),
            workload_id: Some("workload-app".to_string()),
            confidence: EspCorrelationConfidence::Strong,
            reason: format!("msiexec started by {UPN} from {CLIENT_IPV4}"),
            candidate_workload_ids: vec!["workload-app".to_string()],
            process_observations: vec![EspProcessObservation {
                context: observation_context("process"),
                pid: 4242,
                process_start_time: timestamp("2026-08-11T09:03:30Z"),
                parent_pid: Some(1234),
                executable_name: "msiexec.exe".to_string(),
                sanitized_command_line: Some(format!(
                    "msiexec.exe /i vpn.msi /qn PASSWORD={INSTALL_SECRET}"
                )),
                referenced_log_path: Some(format!(
                    "C:\\Users\\{PROFILE_USER}\\AppData\\Local\\Temp\\vpn.log"
                )),
                app_id: Some("app-1".to_string()),
                product_code: Some("{00000000-0000-0000-0000-000000000001}".to_string()),
            }],
            evidence: vec![evidence_ref("correlation")],
        }],
        node_cache: vec![EspNodeCacheEntry {
            index: 1,
            node_uri: "./Vendor/MSFT/DeviceEnroller/Enrollment".to_string(),
            expected_value: Some(ENTDM_ID.to_string()),
            sensitivity: EspSensitivity::Sensitive,
            evidence: vec![evidence_ref("node-cache")],
        }],
        registration_events: vec![EspRegistrationEvent {
            event_id: 76,
            record_id: Some(9001),
            status: status_text("Registered"),
            message: format!("Registered {UPN} ({USER_SID}) from {CLIENT_IPV4}"),
            timestamp: timestamp("2026-08-11T09:05:00Z"),
            named_data: vec![
                EspNamedValue {
                    name: "UserPrincipalName".to_string(),
                    value: UPN.to_string(),
                },
                EspNamedValue {
                    name: "Detail".to_string(),
                    // The serial deliberately does not appear here: an
                    // unlabelled serial in narrative text is a documented gap,
                    // characterized by
                    // `bare_identifiers_in_free_text_are_a_known_residual_gap`.
                    value: format!("device registered on nic {NIC_MAC}"),
                },
            ],
            evidence: vec![evidence_ref("registration")],
        }],
        delivery_optimization: None,
        hardware: Some(EspHardwareEvidence {
            // Kept to three parts: a four-part version string is the same shape
            // as a dotted quad and would trip the IPv4 scan on a safe value.
            os_version: Some("10.0.22631".to_string()),
            os_build: Some("22631".to_string()),
            manufacturer: Some("Contoso".to_string()),
            model: Some("Synth Book 3".to_string()),
            serial_number: Some(sensitive(SERIAL)),
            tpm_version: Some("2.0".to_string()),
            evidence: vec![evidence_ref("hardware")],
        }),
        activity: vec![EspTimelineEntry {
            entry_id: "activity-1".to_string(),
            timestamp: timestamp("2026-08-11T09:06:00Z"),
            kind: EspTimelineKind::Registration,
            title: format!("Account setup started for {UPN}"),
            detail: Some(format!("client {CLIENT_IPV4} nic {NIC_MAC}")),
            status: Some(status_text("Running")),
            evidence: vec![evidence_ref("activity")],
        }],
        findings: vec![],
        coverage: vec![EspArtifactCoverage {
            artifact_id: "artifact-registry".to_string(),
            family: "registry".to_string(),
            status: EspArtifactStatus::Available,
            detail: Some(format!("read under {USER_SID}")),
            observed_at_utc: CAPTURED_AT.to_string(),
            evidence: vec![evidence_ref("coverage")],
        }],
        raw_evidence: vec![
            raw_record(
                "raw-token",
                format!("Authorization: Bearer {BEARER_TOKEN}"),
            ),
            raw_record(
                "raw-network",
                // Same gap as above: the tenant domain is masked where it is a
                // typed field, not where it sits unlabelled in narrative.
                format!("client {CLIENT_IPV4} nic {NIC_MAC} joined the assigned tenant"),
            ),
            raw_record(
                "raw-profile-path",
                format!("wrote C:\\Users\\{PROFILE_USER}\\AppData\\Local\\ime.log"),
            ),
        ],
        graph: Some(graph_overlay_with_matched_device()),
    }
}

fn sensitive(value: &str) -> EspClassifiedString {
    EspClassifiedString {
        value: value.to_string(),
        sensitivity: EspSensitivity::Sensitive,
    }
}

fn evidence_ref(id: &str) -> EspEvidenceRef {
    EspEvidenceRef {
        evidence_id: format!("evidence-{id}"),
        source_artifact_id: "artifact-registry".to_string(),
    }
}

fn timestamp(raw: &str) -> EspTimestamp {
    EspTimestamp {
        raw_text: raw.to_string(),
        original_offset: Some("Z".to_string()),
        normalized_utc: Some(raw.to_string()),
        kind: EspTimestampKind::Utc,
    }
}

fn status_text(display: &str) -> EspStatus {
    EspStatus {
        raw: EspRawStatus::Text(display.to_string()),
        normalized: EspNormalizedStatus::Installing,
        display: display.to_string(),
        detail: None,
    }
}

fn provenance() -> EspEvidenceProvenance {
    EspEvidenceProvenance {
        source_kind: EspSourceKind::Registry,
        source_artifact_id: "artifact-registry".to_string(),
        file_path: Some(format!("C:\\Users\\{PROFILE_USER}\\AppData\\Local\\ime.log")),
        line_number: Some(12),
        record_number: None,
        registry: Some(EspRegistryProvenance {
            hive: "HKLM".to_string(),
            key: r"SOFTWARE\Microsoft\Provisioning".to_string(),
            value_name: Some("CloudAssignedOobeConfig".to_string()),
        }),
        event: None,
    }
}

fn observation_context(id: &str) -> EspObservationContext {
    EspObservationContext {
        evidence_ref: evidence_ref(id),
        provenance: provenance(),
        source_timestamp: Some(timestamp("2026-08-11T09:03:00Z")),
        observed_at_utc: "2026-08-11T09:03:01Z".to_string(),
        sensitivity: EspSensitivity::Public,
        parse_state: EspParseState::Parsed,
        access_state: EspSourceAccessState::Available,
    }
}

fn raw_record(id: &str, value: String) -> EspRawEvidenceRecord {
    EspRawEvidenceRecord {
        record_id: id.to_string(),
        provenance: provenance(),
        source_timestamp: Some(timestamp("2026-08-11T09:03:00Z")),
        observed_at_utc: "2026-08-11T09:03:01Z".to_string(),
        raw_value: EspObservationValue::Text(value),
        sensitivity: EspSensitivity::Public,
        parse_state: EspParseState::Parsed,
        access_state: EspSourceAccessState::Available,
        evidence: vec![evidence_ref(id)],
    }
}

fn graph_overlay_with_matched_device() -> EspGraphOverlay {
    EspGraphOverlay {
        request_id: "graph-request-1".to_string(),
        requested_at_utc: CAPTURED_AT.to_string(),
        device_match: GraphSection {
            status: GraphSectionStatus::Available,
            required_scope: Some("DeviceManagementManagedDevices.Read.All".to_string()),
            api_version: GraphApiVersion::V1_0,
            data: Some(EspGraphDeviceMatch {
                selected: Some(EspGraphManagedDevice {
                    managed_device_id: "11111111-2222-3333-4444-555555555555".to_string(),
                    entra_device_id: Some("66666666-7777-8888-9999-aaaaaaaaaaaa".to_string()),
                    serial_number: Some(sensitive(SERIAL)),
                    device_name: Some("DESKTOP-SYNTH1".to_string()),
                    user_id: Some("user-1".to_string()),
                    user_principal_name: Some(sensitive(UPN)),
                    tenant_id: Some(sensitive(TENANT_ID)),
                    evidence: vec![evidence_ref("graph-device")],
                }),
                candidates: vec![],
                match_basis: Some("serialNumber".to_string()),
                confidence: EspCorrelationConfidence::Strong,
                evidence: vec![evidence_ref("graph-match")],
            }),
            error: None,
        },
        autopilot_identity: skipped_section(),
        deployment_profile: skipped_section(),
        intended_deployment_profile: skipped_section(),
        profile_assignments: skipped_section(),
        autopilot_events: skipped_section(),
        enrollment_configuration: skipped_section(),
        apps: skipped_section(),
        policies: skipped_section(),
        scripts: skipped_section(),
    }
}

fn skipped_section<T>() -> GraphSection<T> {
    GraphSection {
        status: GraphSectionStatus::Skipped,
        required_scope: None,
        api_version: GraphApiVersion::NotRequested,
        data: None,
        error: None,
    }
}
