use std::collections::BTreeSet;

use cmtraceopen_parser::esp::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn assert_unit_variants<T: Serialize>(variants: &[T], expected: Value) {
    assert_eq!(serde_json::to_value(variants).unwrap(), expected);
}

fn evidence_ref(id: &str) -> EspEvidenceRef {
    evidence_ref_from(id, "artifact-registry")
}

fn evidence_ref_from(id: &str, source_artifact_id: &str) -> EspEvidenceRef {
    EspEvidenceRef {
        evidence_id: id.to_string(),
        source_artifact_id: source_artifact_id.to_string(),
    }
}

fn sensitive(value: &str) -> EspClassifiedString {
    EspClassifiedString {
        value: value.to_string(),
        sensitivity: EspSensitivity::Sensitive,
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

fn timestamp_parts(
    raw: &str,
    normalized_utc: Option<&str>,
    kind: EspTimestampKind,
) -> EspTimestamp {
    EspTimestamp {
        raw_text: raw.to_string(),
        original_offset: None,
        normalized_utc: normalized_utc.map(str::to_string),
        kind,
    }
}

fn provenance() -> EspEvidenceProvenance {
    EspEvidenceProvenance {
        source_kind: EspSourceKind::Registry,
        source_artifact_id: "artifact-registry".to_string(),
        file_path: None,
        line_number: None,
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
        source_timestamp: Some(timestamp("2026-07-15T12:00:00Z")),
        observed_at_utc: "2026-07-15T12:00:01Z".to_string(),
        sensitivity: EspSensitivity::Public,
        parse_state: EspParseState::Parsed,
        access_state: EspSourceAccessState::Available,
    }
}

fn status(raw: EspRawStatus, normalized: EspNormalizedStatus) -> EspStatus {
    EspStatus {
        raw,
        normalized,
        display: "status".to_string(),
        detail: None,
    }
}

fn graph_section<T>(
    status: GraphSectionStatus,
    required_scope: &str,
    api_version: GraphApiVersion,
    data: Option<T>,
    error: Option<GraphSectionError>,
) -> GraphSection<T> {
    GraphSection {
        status,
        required_scope: Some(required_scope.to_string()),
        api_version,
        data,
        error,
    }
}

fn not_requested_intent_state() -> GraphSection<EspStatus> {
    graph_section(
        GraphSectionStatus::Skipped,
        "DeviceManagementConfiguration.Read.All",
        GraphApiVersion::NotRequested,
        None,
        None,
    )
}

fn graph_error(code: &str) -> GraphSectionError {
    GraphSectionError {
        code: code.to_string(),
        message: "sanitized failure".to_string(),
        request_id: Some("request-1".to_string()),
        blocked_by: None,
        retry_after_seconds: Some(5),
    }
}

fn assignment(id: &str) -> EspGraphAssignment {
    EspGraphAssignment {
        assignment_id: id.to_string(),
        target_id: Some("group-1".to_string()),
        filter_id: Some("filter-1".to_string()),
        intent: EspGraphAssignmentIntent::Required,
        target_kind: EspGraphTargetKind::Group,
        targeting: EspGraphTargeting::Declared,
        evidence: vec![evidence_ref("graph-assignment")],
    }
}

#[test]
fn models_serialize_camel_case() {
    assert_unit_variants(
        &[
            EspScenario::Unknown,
            EspScenario::AutopilotV1,
            EspScenario::ExistingDeviceJson,
            EspScenario::EspOnly,
            EspScenario::AutopilotDevicePreparationV2,
        ],
        json!([
            "unknown",
            "autopilotV1",
            "existingDeviceJson",
            "espOnly",
            "autopilotDevicePreparationV2"
        ]),
    );
    assert_unit_variants(
        &[
            EspPhase::NotStarted,
            EspPhase::DevicePreparation,
            EspPhase::DeviceSetup,
            EspPhase::AccountSetup,
            EspPhase::Completed,
            EspPhase::Failed,
            EspPhase::Unknown,
        ],
        json!([
            "notStarted",
            "devicePreparation",
            "deviceSetup",
            "accountSetup",
            "completed",
            "failed",
            "unknown"
        ]),
    );
    assert_unit_variants(
        &[
            EspTrackedKind::Msi,
            EspTrackedKind::Office,
            EspTrackedKind::ModernApp,
            EspTrackedKind::Win32App,
            EspTrackedKind::Policy,
            EspTrackedKind::ScepCertificate,
            EspTrackedKind::PlatformScript,
            EspTrackedKind::DevicePreparationWorkload,
        ],
        json!([
            "msi",
            "office",
            "modernApp",
            "win32App",
            "policy",
            "scepCertificate",
            "platformScript",
            "devicePreparationWorkload"
        ]),
    );
    assert_unit_variants(
        &[
            EspNormalizedStatus::NotStarted,
            EspNormalizedStatus::NotInstalled,
            EspNormalizedStatus::Initialized,
            EspNormalizedStatus::Pending,
            EspNormalizedStatus::Downloading,
            EspNormalizedStatus::Downloaded,
            EspNormalizedStatus::Installing,
            EspNormalizedStatus::InProgress,
            EspNormalizedStatus::Processed,
            EspNormalizedStatus::Succeeded,
            EspNormalizedStatus::Failed,
            EspNormalizedStatus::Skipped,
            EspNormalizedStatus::Uninstalled,
            EspNormalizedStatus::RebootRequired,
            EspNormalizedStatus::Cancelled,
            EspNormalizedStatus::Unknown,
        ],
        json!([
            "notStarted",
            "notInstalled",
            "initialized",
            "pending",
            "downloading",
            "downloaded",
            "installing",
            "inProgress",
            "processed",
            "succeeded",
            "failed",
            "skipped",
            "uninstalled",
            "rebootRequired",
            "cancelled",
            "unknown"
        ]),
    );
    assert_unit_variants(
        &[
            EspArtifactStatus::Available,
            EspArtifactStatus::Missing,
            EspArtifactStatus::PermissionDenied,
            EspArtifactStatus::ParseFailed,
            EspArtifactStatus::Unsupported,
        ],
        json!([
            "available",
            "missing",
            "permissionDenied",
            "parseFailed",
            "unsupported"
        ]),
    );
    assert_unit_variants(
        &[
            EspCorrelationConfidence::Exact,
            EspCorrelationConfidence::Strong,
            EspCorrelationConfidence::Temporal,
            EspCorrelationConfidence::Uncorrelated,
        ],
        json!(["exact", "strong", "temporal", "uncorrelated"]),
    );
    assert_unit_variants(
        &[
            EspTimestampKind::Utc,
            EspTimestampKind::Offset,
            EspTimestampKind::Local,
            EspTimestampKind::Unspecified,
            EspTimestampKind::Invalid,
        ],
        json!(["utc", "offset", "local", "unspecified", "invalid"]),
    );
    assert_unit_variants(
        &[
            EspSourceKind::Registry,
            EspSourceKind::Json,
            EspSourceKind::EventLog,
            EspSourceKind::ImeLog,
            EspSourceKind::DeploymentLog,
            EspSourceKind::Process,
            EspSourceKind::System,
            EspSourceKind::DeliveryOptimization,
            EspSourceKind::Graph,
            EspSourceKind::Coverage,
        ],
        json!([
            "registry",
            "json",
            "eventLog",
            "imeLog",
            "deploymentLog",
            "process",
            "system",
            "deliveryOptimization",
            "graph",
            "coverage"
        ]),
    );
    assert_unit_variants(
        &[
            EspSensitivity::Public,
            EspSensitivity::Sensitive,
            EspSensitivity::Restricted,
        ],
        json!(["public", "sensitive", "restricted"]),
    );
    assert_unit_variants(
        &[
            EspParseState::Parsed,
            EspParseState::Raw,
            EspParseState::Malformed,
            EspParseState::Unsupported,
        ],
        json!(["parsed", "raw", "malformed", "unsupported"]),
    );
    assert_unit_variants(
        &[
            EspSourceAccessState::Available,
            EspSourceAccessState::Missing,
            EspSourceAccessState::PermissionDenied,
            EspSourceAccessState::Failed,
            EspSourceAccessState::Unsupported,
        ],
        json!([
            "available",
            "missing",
            "permissionDenied",
            "failed",
            "unsupported"
        ]),
    );
    assert_unit_variants(
        &[EspScope::Device, EspScope::User],
        json!(["device", "user"]),
    );
    assert_unit_variants(
        &[EspSessionKind::Classic, EspSessionKind::DevicePreparationV2],
        json!(["classic", "devicePreparationV2"]),
    );
    assert_unit_variants(
        &[
            EspJoinMode::Entra,
            EspJoinMode::HybridEntra,
            EspJoinMode::Unknown("unknown".to_string()),
        ],
        json!(["entra", "hybridEntra", "unknown"]),
    );
    assert_unit_variants(
        &[
            EspFindingSeverity::Info,
            EspFindingSeverity::Warning,
            EspFindingSeverity::Error,
            EspFindingSeverity::Blocker,
        ],
        json!(["info", "warning", "error", "blocker"]),
    );
    assert_unit_variants(
        &[
            EspFindingConfidence::Low,
            EspFindingConfidence::Medium,
            EspFindingConfidence::High,
        ],
        json!(["low", "medium", "high"]),
    );
    assert_unit_variants(
        &[
            EspTimelineKind::ProfileDownload,
            EspTimelineKind::OfflineDomainJoin,
            EspTimelineKind::Registration,
            EspTimelineKind::Workload,
            EspTimelineKind::DeliveryOptimization,
            EspTimelineKind::Coverage,
            EspTimelineKind::Process,
            EspTimelineKind::Other,
        ],
        json!([
            "profileDownload",
            "offlineDomainJoin",
            "registration",
            "workload",
            "deliveryOptimization",
            "coverage",
            "process",
            "other"
        ]),
    );
    assert_unit_variants(
        &[
            EspGraphAssignmentIntent::Required,
            EspGraphAssignmentIntent::Available,
            EspGraphAssignmentIntent::Uninstall,
            EspGraphAssignmentIntent::Unknown("unknown".to_string()),
        ],
        json!(["required", "available", "uninstall", "unknown"]),
    );
    assert_unit_variants(
        &[
            EspGraphTargetKind::AllDevices,
            EspGraphTargetKind::AllUsers,
            EspGraphTargetKind::Group,
            EspGraphTargetKind::Filter,
            EspGraphTargetKind::Unknown("unknown".to_string()),
        ],
        json!(["allDevices", "allUsers", "group", "filter", "unknown"]),
    );
    assert_unit_variants(
        &[EspGraphTargeting::Declared, EspGraphTargeting::Effective],
        json!(["declared", "effective"]),
    );
    assert_unit_variants(
        &[
            EspGraphPolicyKind::DeviceConfiguration,
            EspGraphPolicyKind::Compliance,
            EspGraphPolicyKind::ConfigurationPolicy,
            EspGraphPolicyKind::ScepCertificate,
            EspGraphPolicyKind::Unknown("unknown".to_string()),
        ],
        json!([
            "deviceConfiguration",
            "compliance",
            "configurationPolicy",
            "scepCertificate",
            "unknown"
        ]),
    );
    assert_unit_variants(
        &[
            EspGraphScriptKind::PlatformScript,
            EspGraphScriptKind::Remediation,
        ],
        json!(["platformScript", "remediation"]),
    );
    assert_unit_variants(
        &[
            EspGraphObservationSection::ManagedDevice,
            EspGraphObservationSection::AutopilotIdentity,
            EspGraphObservationSection::DeploymentProfile,
            EspGraphObservationSection::EnrollmentConfiguration,
            EspGraphObservationSection::App,
            EspGraphObservationSection::Policy,
            EspGraphObservationSection::Script,
        ],
        json!([
            "managedDevice",
            "autopilotIdentity",
            "deploymentProfile",
            "enrollmentConfiguration",
            "app",
            "policy",
            "script"
        ]),
    );
    assert_unit_variants(
        &[
            EspDeliveryOptimizationEventKind::DownloadStarted,
            EspDeliveryOptimizationEventKind::DownloadCompleted,
        ],
        json!(["downloadStarted", "downloadCompleted"]),
    );
    assert_unit_variants(
        &[
            GraphSectionStatus::Available,
            GraphSectionStatus::NotFound,
            GraphSectionStatus::PermissionDenied,
            GraphSectionStatus::Failed,
            GraphSectionStatus::Skipped,
            GraphSectionStatus::Cancelled,
        ],
        json!([
            "available",
            "notFound",
            "permissionDenied",
            "failed",
            "skipped",
            "cancelled"
        ]),
    );
    assert_unit_variants(
        &[
            GraphApiVersion::V1_0,
            GraphApiVersion::Beta,
            GraphApiVersion::NotRequested,
        ],
        json!(["v1.0", "beta", "notRequested"]),
    );

    let section = GraphSection::<EspGraphDeviceMatch> {
        status: GraphSectionStatus::Skipped,
        required_scope: Some("DeviceManagementManagedDevices.Read.All".to_string()),
        api_version: GraphApiVersion::NotRequested,
        data: None,
        error: Some(GraphSectionError {
            code: "blocked".to_string(),
            message: "Device selection is required".to_string(),
            request_id: Some("request-1".to_string()),
            blocked_by: Some("deviceMatch".to_string()),
            retry_after_seconds: None,
        }),
    };
    assert_eq!(
        serde_json::to_value(section).unwrap(),
        json!({
            "status": "skipped",
            "requiredScope": "DeviceManagementManagedDevices.Read.All",
            "apiVersion": "notRequested",
            "data": null,
            "error": {
                "code": "blocked",
                "message": "Device selection is required",
                "requestId": "request-1",
                "blockedBy": "deviceMatch",
                "retryAfterSeconds": null
            }
        }),
    );
}

#[test]
fn models_preserve_raw_status_provenance_sensitivity_and_coverage() {
    let record = EspRawEvidenceRecord {
        record_id: "raw-1".to_string(),
        provenance: provenance(),
        source_timestamp: Some(timestamp("2026-07-15T12:00:00Z")),
        observed_at_utc: "2026-07-15T12:00:01Z".to_string(),
        raw_value: EspObservationValue::Text("future-state".to_string()),
        sensitivity: EspSensitivity::Sensitive,
        parse_state: EspParseState::Malformed,
        access_state: EspSourceAccessState::PermissionDenied,
        evidence: vec![evidence_ref("raw-parent")],
    };
    let workload = EspWorkload {
        workload_id: "workload-1".to_string(),
        session_id: "session-1".to_string(),
        kind: EspTrackedKind::Win32App,
        scope: EspScope::Device,
        raw_identifier: "app-guid".to_string(),
        display_name: None,
        status: EspStatus {
            raw: EspRawStatus::Text("FutureState".to_string()),
            normalized: EspNormalizedStatus::Unknown,
            display: "FutureState".to_string(),
            detail: Some(EspStatusDetail {
                raw: EspRawStatus::Number(999),
                normalized: EspNormalizedStatus::Unknown,
                display: "999".to_string(),
            }),
        },
        timestamps: EspWorkloadTimestamps {
            first_observed: timestamp("2026-07-15T12:00:00Z"),
            started: None,
            ended: None,
            last_updated: None,
        },
        exit_code: Some(EspErrorCode {
            raw: "0x87D30067".to_string(),
            decimal: None,
            hex: Some("0x87D30067".to_string()),
        }),
        enforcement_error_code: Some(EspErrorCode {
            raw: "-2016346009".to_string(),
            decimal: Some(-2016346009),
            hex: Some("0x87D30067".to_string()),
        }),
        blocking: Some(true),
        evidence: vec![evidence_ref("raw-1")],
    };
    let coverage = EspArtifactCoverage {
        artifact_id: "registry-first-sync".to_string(),
        family: "registry".to_string(),
        status: EspArtifactStatus::PermissionDenied,
        detail: Some("Elevation is required".to_string()),
        observed_at_utc: "2026-07-15T12:00:01Z".to_string(),
        evidence: vec![evidence_ref("coverage-1")],
    };

    let value = serde_json::to_value((&record, &workload, &coverage)).unwrap();
    assert_eq!(value[0]["sensitivity"], "sensitive");
    assert_eq!(value[0]["parseState"], "malformed");
    assert_eq!(value[0]["accessState"], "permissionDenied");
    assert_eq!(value[1]["status"]["raw"], "FutureState");
    assert_eq!(value[1]["status"]["normalized"], "unknown");
    assert_eq!(value[1]["status"]["detail"]["raw"], 999);
    assert_eq!(value[1]["evidence"][0]["evidenceId"], "raw-1");
    assert_eq!(value[2]["status"], "permissionDenied");
}

#[test]
fn models_snapshot_schema_version_and_ordered_collections_are_stable() {
    let first = EspTimelineEntry {
        entry_id: "event-2".to_string(),
        timestamp: timestamp("2026-07-15T12:00:02Z"),
        kind: EspTimelineKind::Workload,
        title: "Retry 2".to_string(),
        detail: None,
        status: Some(status(
            EspRawStatus::Number(2),
            EspNormalizedStatus::InProgress,
        )),
        evidence: vec![evidence_ref("event-2")],
    };
    let second = EspTimelineEntry {
        entry_id: "event-1".to_string(),
        timestamp: timestamp("2026-07-15T12:00:01Z"),
        kind: EspTimelineKind::Workload,
        title: "Retry 1".to_string(),
        detail: None,
        status: Some(status(
            EspRawStatus::Number(2),
            EspNormalizedStatus::InProgress,
        )),
        evidence: vec![evidence_ref("event-1")],
    };
    let snapshot = EspDiagnosticsSnapshot {
        schema_version: ESP_DIAGNOSTICS_SCHEMA_VERSION,
        scenario: EspScenario::EspOnly,
        phase: EspPhase::DeviceSetup,
        generated_at_utc: "2026-07-15T12:00:03Z".to_string(),
        elevation: EspElevationState {
            is_elevated: false,
            restart_supported: true,
            restricted_sources: vec!["protectedRegistry".to_string()],
        },
        identity: EspIdentityEvidence {
            device_name: Some("DEVICE-1".to_string()),
            managed_device_id: None,
            entra_device_id: None,
            entdm_id: None,
            tenant_id: None,
            tenant_domain: None,
            user_principal_name: None,
            serial_number: None,
            evidence: vec![evidence_ref("identity-1")],
        },
        profile: None,
        enrollments: vec![],
        sessions: vec![],
        workloads: vec![],
        installer_correlations: vec![],
        node_cache: vec![
            EspNodeCacheEntry {
                index: 2,
                node_uri: "./node/2".to_string(),
                expected_value: Some("two".to_string()),
                sensitivity: EspSensitivity::Sensitive,
                evidence: vec![evidence_ref("node-2")],
            },
            EspNodeCacheEntry {
                index: 10,
                node_uri: "./node/10".to_string(),
                expected_value: Some("ten".to_string()),
                sensitivity: EspSensitivity::Sensitive,
                evidence: vec![evidence_ref("node-10")],
            },
        ],
        registration_events: vec![],
        delivery_optimization: None,
        hardware: None,
        activity: vec![first, second],
        findings: vec![],
        coverage: vec![],
        raw_evidence: vec![],
        graph: None,
    };

    let value = serde_json::to_value(snapshot).unwrap();
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["nodeCache"][0]["index"], 2);
    assert_eq!(value["nodeCache"][1]["index"], 10);
    assert_eq!(value["activity"][0]["entryId"], "event-2");
    assert_eq!(value["activity"][1]["entryId"], "event-1");
}

#[test]
fn models_graph_overlay_freezes_typed_correlated_sections() {
    let managed_device = EspGraphManagedDevice {
        managed_device_id: "managed-1".to_string(),
        entra_device_id: Some("entra-1".to_string()),
        serial_number: Some(sensitive("serial-1")),
        device_name: Some("DEVICE-1".to_string()),
        user_id: Some("user-1".to_string()),
        user_principal_name: Some(sensitive("user@example.test")),
        tenant_id: Some(sensitive("tenant-1")),
        evidence: vec![evidence_ref("managed-1")],
    };
    let overlay = EspGraphOverlay {
        request_id: "request-1".to_string(),
        requested_at_utc: "2026-07-15T12:00:00Z".to_string(),
        device_match: graph_section(
            GraphSectionStatus::Available,
            "DeviceManagementManagedDevices.Read.All",
            GraphApiVersion::V1_0,
            Some(EspGraphDeviceMatch {
                selected: Some(managed_device.clone()),
                candidates: vec![managed_device],
                match_basis: Some("managedDeviceId".to_string()),
                confidence: EspCorrelationConfidence::Exact,
                evidence: vec![evidence_ref("device-match")],
            }),
            None,
        ),
        autopilot_identity: graph_section(
            GraphSectionStatus::NotFound,
            "DeviceManagementServiceConfig.Read.All",
            GraphApiVersion::V1_0,
            None,
            None,
        ),
        deployment_profile: graph_section(
            GraphSectionStatus::PermissionDenied,
            "DeviceManagementServiceConfig.Read.All",
            GraphApiVersion::Beta,
            None,
            Some(graph_error("permissionDenied")),
        ),
        intended_deployment_profile: graph_section(
            GraphSectionStatus::Available,
            "DeviceManagementServiceConfig.Read.All",
            GraphApiVersion::Beta,
            Some(EspGraphDeploymentProfile {
                profile_id: "intended-profile-1".to_string(),
                display_name: Some("Intended Profile".to_string()),
                join_mode: Some(EspJoinMode::Entra),
                selected_mobile_app_ids: vec![],
                evidence: vec![evidence_ref("intended-profile-1")],
            }),
            None,
        ),
        profile_assignments: graph_section(
            GraphSectionStatus::Failed,
            "DeviceManagementServiceConfig.Read.All",
            GraphApiVersion::Beta,
            None,
            Some(graph_error("transportFailure")),
        ),
        autopilot_events: graph_section(
            GraphSectionStatus::Skipped,
            "DeviceManagementManagedDevices.Read.All",
            GraphApiVersion::Beta,
            None,
            Some(GraphSectionError {
                blocked_by: Some("deviceMatch".to_string()),
                ..graph_error("blocked")
            }),
        ),
        enrollment_configuration: graph_section(
            GraphSectionStatus::Cancelled,
            "DeviceManagementServiceConfig.Read.All",
            GraphApiVersion::V1_0,
            None,
            Some(graph_error("cancelled")),
        ),
        apps: graph_section(
            GraphSectionStatus::Available,
            "DeviceManagementApps.Read.All",
            GraphApiVersion::V1_0,
            Some(vec![EspGraphAppRecord {
                app_id: "app-1".to_string(),
                display_name: Some("App One".to_string()),
                tracked_on_enrollment_status: Some(true),
                status: Some(status(
                    EspRawStatus::Text("installed".to_string()),
                    EspNormalizedStatus::Succeeded,
                )),
                intent_state: graph_section(
                    GraphSectionStatus::NotFound,
                    "DeviceManagementConfiguration.Read.All",
                    GraphApiVersion::Beta,
                    None,
                    None,
                ),
                assignments: vec![assignment("app-assignment")],
                evidence: vec![evidence_ref("app-1")],
            }]),
            None,
        ),
        policies: graph_section(
            GraphSectionStatus::Available,
            "DeviceManagementConfiguration.Read.All",
            GraphApiVersion::V1_0,
            Some(vec![EspGraphPolicyRecord {
                policy_id: "policy-1".to_string(),
                display_name: Some("Policy One".to_string()),
                kind: EspGraphPolicyKind::DeviceConfiguration,
                status: None,
                assignments: vec![assignment("policy-assignment")],
                evidence: vec![evidence_ref("policy-1")],
            }]),
            None,
        ),
        scripts: graph_section(
            GraphSectionStatus::Available,
            "DeviceManagementScripts.Read.All",
            GraphApiVersion::Beta,
            Some(vec![EspGraphScriptRecord {
                script_id: "script-1".to_string(),
                display_name: Some("Script One".to_string()),
                kind: EspGraphScriptKind::PlatformScript,
                status: None,
                assignments: vec![assignment("script-assignment")],
                evidence: vec![evidence_ref("script-1")],
            }]),
            None,
        ),
    };

    let value = serde_json::to_value(overlay).unwrap();
    assert_eq!(value["deviceMatch"]["status"], "available");
    assert_eq!(value["autopilotIdentity"]["status"], "notFound");
    assert_eq!(value["deploymentProfile"]["status"], "permissionDenied");
    assert_eq!(
        value["intendedDeploymentProfile"]["data"]["profileId"],
        "intended-profile-1"
    );
    assert_eq!(value["profileAssignments"]["status"], "failed");
    assert_eq!(value["autopilotEvents"]["status"], "skipped");
    assert_eq!(value["autopilotEvents"]["apiVersion"], "beta");
    assert_eq!(value["enrollmentConfiguration"]["status"], "cancelled");
    assert_eq!(value["deploymentProfile"]["apiVersion"], "beta");
    assert_eq!(
        value["apps"]["data"][0]["evidence"][0]["evidenceId"],
        "app-1"
    );
    assert_eq!(
        value["apps"]["data"][0]["intentState"]["status"],
        "notFound"
    );
    assert_eq!(
        value["apps"]["data"][0]["intentState"]["apiVersion"],
        "beta"
    );
    assert_eq!(
        value["profileAssignments"]["error"]["requestId"],
        "request-1"
    );
    assert_eq!(
        value["deviceMatch"]["requiredScope"],
        "DeviceManagementManagedDevices.Read.All"
    );
    for section in [
        "autopilotIdentity",
        "deploymentProfile",
        "intendedDeploymentProfile",
        "profileAssignments",
        "enrollmentConfiguration",
    ] {
        assert_eq!(
            value[section]["requiredScope"], "DeviceManagementServiceConfig.Read.All",
            "wrong scope for {section}"
        );
    }
    assert_eq!(
        value["autopilotEvents"]["requiredScope"],
        "DeviceManagementManagedDevices.Read.All"
    );
    assert_eq!(
        value["apps"]["requiredScope"],
        "DeviceManagementApps.Read.All"
    );
    assert_eq!(
        value["policies"]["requiredScope"],
        "DeviceManagementConfiguration.Read.All"
    );
    assert_eq!(
        value["scripts"]["requiredScope"],
        "DeviceManagementScripts.Read.All"
    );
}

fn assert_unknown_string_round_trip<T>(raw: &str, expected: T)
where
    T: DeserializeOwned + Serialize + std::fmt::Debug + PartialEq,
{
    let encoded = serde_json::to_string(raw).unwrap();
    let decoded: T = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
}

#[test]
fn models_graph_unknown_enum_values_round_trip_without_loss() {
    assert_unknown_string_round_trip("vNext", GraphApiVersion::Unknown("vNext".to_string()));
    assert_unknown_string_round_trip(
        "retrying",
        GraphSectionStatus::Unknown("retrying".to_string()),
    );
    assert_unknown_string_round_trip(
        "federatedJoin",
        EspJoinMode::Unknown("federatedJoin".to_string()),
    );
    assert_unknown_string_round_trip(
        "futureIntent",
        EspGraphAssignmentIntent::Unknown("futureIntent".to_string()),
    );
    assert_unknown_string_round_trip(
        "dynamicTarget",
        EspGraphTargetKind::Unknown("dynamicTarget".to_string()),
    );
    assert_unknown_string_round_trip(
        "settingsCatalogV3",
        EspGraphPolicyKind::Unknown("settingsCatalogV3".to_string()),
    );
    assert_unknown_string_round_trip(
        "shellScript",
        EspGraphScriptKind::Unknown("shellScript".to_string()),
    );
    assert_unknown_string_round_trip(
        "deviceAction",
        EspGraphObservationSection::Unknown("deviceAction".to_string()),
    );

    assert_eq!(
        serde_json::to_string(&EspGraphPolicyStatusDetailKind::App).unwrap(),
        "\"app\""
    );
    assert_eq!(
        serde_json::to_string(&EspGraphPolicyStatusDetailKind::Policy).unwrap(),
        "\"policy\""
    );
    assert_unknown_string_round_trip(
        "futureStatusDetail",
        EspGraphPolicyStatusDetailKind::Unknown("futureStatusDetail".to_string()),
    );
}

#[test]
fn models_raw_status_preserves_future_json_shapes_without_loss() {
    for raw in [
        json!(true),
        Value::Null,
        json!({ "future": 1 }),
        json!([1, "x"]),
    ] {
        let decoded: EspRawStatus = serde_json::from_value(raw.clone()).unwrap();

        assert_eq!(decoded, EspRawStatus::Other(raw.clone()));
        assert_eq!(serde_json::to_value(decoded).unwrap(), raw);
    }
}

#[test]
fn models_sensitive_identifiers_carry_explicit_classification_metadata() {
    let identity = EspIdentityEvidence {
        device_name: Some("DEVICE-1".to_string()),
        managed_device_id: None,
        entra_device_id: None,
        entdm_id: Some(sensitive("entdm-1")),
        tenant_id: Some(sensitive("tenant-1")),
        tenant_domain: Some(sensitive("example.test")),
        user_principal_name: Some(sensitive("user@example.test")),
        serial_number: Some(sensitive("SERIAL-1")),
        evidence: vec![evidence_ref("identity-sensitive")],
    };
    let profile = EspProfileEvidence {
        profile_name: None,
        deployment_profile_id: None,
        correlation_id: None,
        tenant_domain: Some(sensitive("example.test")),
        tenant_id: Some(sensitive("tenant-1")),
        oobe_config: None,
        profile_download_time: None,
        join_mode: None,
        odj_applied: None,
        skip_domain_connectivity_check: None,
        device_preparation: None,
        evidence: vec![evidence_ref("profile-sensitive")],
    };
    let enrollment = EspEnrollmentEvidence {
        enrollment_id: "enrollment-1".to_string(),
        provider_id: None,
        tenant_id: Some(sensitive("tenant-1")),
        user_principal_name: Some(sensitive("user@example.test")),
        entdm_id: Some(sensitive("entdm-1")),
        settings: EspEnrollmentSettings {
            device_esp_enabled: None,
            user_esp_enabled: None,
            timeout_seconds: None,
            blocking: None,
            allow_reset: None,
            allow_retry: None,
            continue_anyway: None,
        },
        evidence: vec![evidence_ref("enrollment-sensitive")],
    };
    let session = EspSession {
        session_id: "session-1".to_string(),
        kind: EspSessionKind::Classic,
        scope: EspScope::User,
        user_sid: Some(sensitive("S-1-5-21-1")),
        started_at: None,
        ended_at: None,
        phase: EspPhase::AccountSetup,
        is_latest: true,
        workload_ids: vec![],
        evidence: vec![evidence_ref("session-sensitive")],
    };
    let hardware = EspHardwareEvidence {
        os_version: None,
        os_build: None,
        manufacturer: None,
        model: None,
        serial_number: Some(sensitive("SERIAL-1")),
        tpm_version: None,
        evidence: vec![evidence_ref("hardware-sensitive")],
    };
    let managed_device = EspGraphManagedDevice {
        managed_device_id: "managed-1".to_string(),
        entra_device_id: None,
        serial_number: Some(sensitive("SERIAL-1")),
        device_name: None,
        user_id: None,
        user_principal_name: Some(sensitive("user@example.test")),
        tenant_id: Some(sensitive("tenant-1")),
        evidence: vec![evidence_ref("managed-sensitive")],
    };
    let autopilot_identity = EspGraphAutopilotIdentity {
        autopilot_device_id: "autopilot-1".to_string(),
        entra_device_id: None,
        serial_number: Some(sensitive("SERIAL-1")),
        deployment_profile_id: None,
        group_tag: None,
        evidence: vec![evidence_ref("autopilot-sensitive")],
    };

    let value = serde_json::to_value((
        identity,
        profile,
        enrollment,
        session,
        hardware,
        managed_device,
        autopilot_identity,
    ))
    .unwrap();
    assert_eq!(value[0]["userPrincipalName"]["sensitivity"], "sensitive");
    assert_eq!(value[0]["serialNumber"]["value"], "SERIAL-1");
    assert_eq!(value[1]["tenantId"]["sensitivity"], "sensitive");
    assert_eq!(value[2]["entdmId"]["sensitivity"], "sensitive");
    assert_eq!(value[3]["userSid"]["sensitivity"], "sensitive");
    assert_eq!(value[4]["serialNumber"]["sensitivity"], "sensitive");
    assert_eq!(value[5]["tenantId"]["sensitivity"], "sensitive");
    assert_eq!(value[6]["serialNumber"]["sensitivity"], "sensitive");
}

#[test]
fn models_graph_correlated_record_shapes_keep_provenance() {
    let profile = EspGraphDeploymentProfile {
        profile_id: "profile-1".to_string(),
        display_name: Some("Profile One".to_string()),
        join_mode: Some(EspJoinMode::Entra),
        selected_mobile_app_ids: vec!["app-1".to_string()],
        evidence: vec![evidence_ref("profile-1")],
    };
    let autopilot = EspGraphAutopilotIdentity {
        autopilot_device_id: "autopilot-1".to_string(),
        entra_device_id: Some("entra-1".to_string()),
        serial_number: Some(sensitive("serial-1")),
        deployment_profile_id: Some("profile-1".to_string()),
        group_tag: Some("group-tag".to_string()),
        evidence: vec![evidence_ref("autopilot-1")],
    };
    let detail = EspGraphPolicyStatusDetail {
        status_detail_id: "detail-object-1".to_string(),
        related_object_id: None,
        display_name: Some("Policy detail".to_string()),
        kind: EspGraphPolicyStatusDetailKind::Unknown("unknown".to_string()),
        status: status(
            EspRawStatus::Text("futureState".to_string()),
            EspNormalizedStatus::Unknown,
        ),
        tracked_on_enrollment_status: Some(true),
        correlation_confidence: EspCorrelationConfidence::Uncorrelated,
        evidence: vec![evidence_ref("detail-1")],
    };
    let event = EspGraphAutopilotEvent {
        event_id: "event-1".to_string(),
        managed_device_id: Some("managed-1".to_string()),
        enrollment_configuration_id: Some("enrollment-1".to_string()),
        event_time: Some(timestamp("2026-07-15T12:00:00Z")),
        deployment_state: status(
            EspRawStatus::Text("futureState".to_string()),
            EspNormalizedStatus::Unknown,
        ),
        policy_status_details: vec![detail],
        evidence: vec![evidence_ref("event-1")],
    };
    let enrollment = EspGraphEnrollmentConfiguration {
        configuration_id: "esp-config-1".to_string(),
        display_name: Some("All users and devices".to_string()),
        show_installation_progress: Some(true),
        device_esp_enabled: Some(true),
        user_esp_enabled: Some(true),
        disable_user_status_tracking_after_first_user: Some(false),
        timeout_minutes: Some(60),
        selected_mobile_app_ids: vec!["app-1".to_string()],
        assignments: vec![assignment("enrollment-assignment")],
        evidence: vec![evidence_ref("enrollment-1")],
    };

    let value = serde_json::to_value((profile, autopilot, event, enrollment)).unwrap();
    assert_eq!(value[0]["evidence"][0]["evidenceId"], "profile-1");
    assert_eq!(value[1]["evidence"][0]["evidenceId"], "autopilot-1");
    assert_eq!(
        value[2]["policyStatusDetails"][0]["relatedObjectId"],
        Value::Null
    );
    assert_eq!(value[3]["assignments"][0]["targeting"], "declared");
    assert_eq!(value[3]["showInstallationProgress"], true);
    assert_eq!(value[3]["disableUserStatusTrackingAfterFirstUser"], false);
}

#[test]
fn models_installer_correlations_embed_process_observations() {
    let process = EspProcessObservation {
        context: observation_context("process-1"),
        pid: 4242,
        process_start_time: timestamp("2026-07-15T12:00:00Z"),
        parent_pid: Some(1000),
        executable_name: "msiexec.exe".to_string(),
        sanitized_command_line: Some(
            r#"msiexec /i {AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE} /L*v C:\Logs\app.log"#.to_string(),
        ),
        referenced_log_path: Some(r"C:\Logs\app.log".to_string()),
        app_id: Some("app-1".to_string()),
        product_code: Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".to_string()),
    };
    let correlation = EspInstallerCorrelation {
        correlation_id: "correlation-1".to_string(),
        workload_id: Some("workload-1".to_string()),
        confidence: EspCorrelationConfidence::Exact,
        reason: "canonicalLogPath".to_string(),
        candidate_workload_ids: vec!["workload-1".to_string()],
        process_observations: vec![process],
        evidence: vec![evidence_ref("process-1"), evidence_ref("workload-1")],
    };

    let value = serde_json::to_value(correlation).unwrap();
    assert_eq!(value["processObservations"][0]["pid"], 4242);
    assert_eq!(
        value["processObservations"][0]["processStartTime"]["normalizedUtc"],
        "2026-07-15T12:00:00Z"
    );
    assert_eq!(value["evidence"].as_array().unwrap().len(), 2);
}

fn correlation_workload(
    workload_id: &str,
    raw_identifier: &str,
    first_observed: &str,
    last_updated: &str,
) -> EspWorkload {
    EspWorkload {
        workload_id: workload_id.to_string(),
        session_id: "session-device".to_string(),
        kind: EspTrackedKind::Msi,
        scope: EspScope::Device,
        raw_identifier: raw_identifier.to_string(),
        display_name: None,
        status: status(EspRawStatus::Number(2), EspNormalizedStatus::Installing),
        timestamps: EspWorkloadTimestamps {
            first_observed: timestamp(first_observed),
            started: Some(timestamp(first_observed)),
            ended: None,
            last_updated: Some(timestamp(last_updated)),
        },
        exit_code: None,
        enforcement_error_code: None,
        blocking: Some(true),
        evidence: vec![evidence_ref_from(
            &format!("evidence-{workload_id}"),
            "esp-workloads",
        )],
    }
}

fn correlation_process(
    evidence_id: &str,
    pid: u32,
    parent_pid: Option<u32>,
    executable_name: &str,
    started_at: &str,
) -> EspProcessObservation {
    EspProcessObservation {
        context: fixture_context(
            EspSourceKind::Process,
            "process-snapshot",
            evidence_id,
            started_at,
        ),
        pid,
        process_start_time: timestamp(started_at),
        parent_pid,
        executable_name: executable_name.to_string(),
        sanitized_command_line: None,
        referenced_log_path: None,
        app_id: None,
        product_code: None,
    }
}

#[test]
fn correlation_extracts_quoted_unquoted_and_mixed_case_installer_log_switches() {
    assert_eq!(
        extract_installer_log_path(
            r#"msiexec.exe /i {AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE} /L*V "C:\Temp\Setup Log.log""#,
        )
        .as_deref(),
        Some(r"C:\Temp\Setup Log.log")
    );
    assert_eq!(
        extract_installer_log_path(r"MSIEXEC /I package.msi /l c:\temp\plain.log").as_deref(),
        Some(r"c:\temp\plain.log")
    );
    assert_eq!(
        extract_installer_log_path(r"installer.exe /LoG=c:\temp\custom.log").as_deref(),
        Some(r"c:\temp\custom.log")
    );
    assert_eq!(
        canonical_installer_log_path(r"\\?\C:/Temp/.\APP.log"),
        canonical_installer_log_path(r"c:\temp\app.log")
    );
    assert_eq!(
        canonical_installer_log_path(r"\\?\UNC\server\share\Temp\APP.log"),
        canonical_installer_log_path(r"\\server\share\temp\app.log")
    );
    assert_eq!(canonical_installer_log_path(r"C:\..\escape.log"), None);
}

#[test]
fn correlation_recognizes_full_path_and_extensionless_msiexec_images() {
    let workload = correlation_workload(
        "workload-a",
        "app-a",
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let full_path = correlation_process(
        "process-full-path",
        710,
        None,
        r"C:\Windows\System32\MSIEXEC.EXE",
        "2026-07-15T12:02:00Z",
    );
    let extensionless = correlation_process(
        "process-extensionless",
        711,
        None,
        "msiexec",
        "2026-07-15T12:03:00Z",
    );

    let correlations =
        correlate_installer_processes(&[workload], &[full_path, extensionless], &[], &[]);

    assert_eq!(correlations.len(), 2);
    assert!(correlations.iter().all(|correlation| {
        correlation.workload_id.as_deref() == Some("workload-a")
            && correlation.confidence == EspCorrelationConfidence::Temporal
    }));
}

#[test]
fn correlation_never_promotes_full_path_ime_agents_to_installer_roots() {
    let mut agent = correlation_process(
        "process-agent-only",
        712,
        None,
        r"C:\Program Files (x86)\Microsoft Intune Management Extension\AgentExecutor.exe",
        "2026-07-15T12:02:00Z",
    );
    agent.referenced_log_path = Some(r"C:\Windows\Temp\agent.log".to_string());
    agent.product_code = Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string());

    let correlations = correlate_installer_processes(&[], &[agent], &[], &[]);

    assert!(correlations.is_empty());
}

#[test]
fn correlation_ignores_blank_exact_identifiers_and_empty_path_metadata() {
    let workload = correlation_workload(
        "workload-a",
        "app-a",
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut msi = correlation_process(
        "process-msi-blank-id",
        713,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    msi.app_id = Some("   ".to_string());
    msi.product_code = Some("".to_string());
    let mut unrelated = correlation_process(
        "process-unrelated-empty-metadata",
        714,
        None,
        "notepad.exe",
        "2026-07-15T12:02:00Z",
    );
    unrelated.product_code = Some("  ".to_string());
    unrelated.referenced_log_path = Some("".to_string());

    let correlations = correlate_installer_processes(&[workload], &[unrelated, msi], &[], &[]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert_eq!(correlations[0].reason, "singleTemporalCandidate");
}

#[test]
fn correlation_prefers_consistent_exact_app_product_and_canonical_log_evidence() {
    let app_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let app_b = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-a",
            app_a,
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        ),
        correlation_workload(
            "workload-b",
            app_b,
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut process = correlation_process(
        "process-msi-a",
        4242,
        None,
        "msiexec.exe",
        "2026-07-15T12:03:00Z",
    );
    process.app_id = Some(format!("{{{}}}", app_a.to_ascii_uppercase()));
    process.product_code = Some(app_a.to_string());
    process.referenced_log_path = Some(r"C:\Temp\App.log".to_string());
    process.sanitized_command_line = Some(format!(
        r#"msiexec /i {{{}}} /L*V "c:/temp/./APP.log" --token [REDACTED]"#,
        app_a.to_ascii_uppercase()
    ));
    let deployment = EspDeploymentLogObservation {
        context: fixture_context(
            EspSourceKind::DeploymentLog,
            "msi-log",
            "deployment-a",
            "2026-07-15T12:03:01Z",
        ),
        component: Some("MsiInstaller".to_string()),
        message: "Installation started".to_string(),
        product_code: Some(format!("{{{}}}", app_a.to_ascii_uppercase())),
        log_path: Some(r"c:\temp\app.log".to_string()),
        status: None,
    };

    let correlations = correlate_installer_processes(&workloads, &[process], &[deployment], &[]);

    assert_eq!(correlations.len(), 1);
    let correlation = &correlations[0];
    assert_eq!(correlation.workload_id.as_deref(), Some("workload-a"));
    assert_eq!(correlation.confidence, EspCorrelationConfidence::Exact);
    assert_eq!(correlation.candidate_workload_ids, vec!["workload-a"]);
    assert!(correlation.reason.contains("appId"));
    assert!(correlation.reason.contains("productCode"));
    assert!(correlation.reason.contains("canonicalLogPath"));
    assert_eq!(
        correlation.process_observations[0]
            .sanitized_command_line
            .as_deref(),
        Some(
            format!(
                r#"msiexec /i {{{}}} /L*V "c:/temp/./APP.log" --token [REDACTED]"#,
                app_a.to_ascii_uppercase()
            )
            .as_str()
        )
    );
    assert!(!serde_json::to_string(correlation)
        .unwrap()
        .contains("secret-sentinel"));
}

#[test]
fn correlation_preserves_conflict_instead_of_overriding_exact_identifiers_with_time() {
    let app_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let app_b = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-a",
            app_a,
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        ),
        correlation_workload(
            "workload-b",
            app_b,
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut process = correlation_process(
        "process-conflict",
        4300,
        None,
        "msiexec.exe",
        "2026-07-15T12:03:00Z",
    );
    process.app_id = Some(app_a.to_string());
    process.product_code = Some(app_b.to_string());

    let correlations = correlate_installer_processes(&workloads, &[process], &[], &[]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].workload_id, None);
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Uncorrelated
    );
    assert_eq!(
        correlations[0].candidate_workload_ids,
        vec!["workload-a", "workload-b"]
    );
    assert_eq!(correlations[0].reason, "contradictoryExactIdentifiers");
}

#[test]
fn correlation_parent_chain_is_guarded_by_process_start_identity() {
    let app_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let app_b = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-a",
            app_a,
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        ),
        correlation_workload(
            "workload-b",
            app_b,
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut ime = correlation_process(
        "process-ime",
        100,
        None,
        "IntuneManagementExtension.exe",
        "2026-07-15T12:00:00Z",
    );
    ime.app_id = Some(app_a.to_string());
    let mut reused_future = correlation_process(
        "process-reused-future",
        100,
        None,
        "IntuneManagementExtension.exe",
        "2026-07-15T13:00:00Z",
    );
    reused_future.app_id = Some(app_b.to_string());
    let agent = correlation_process(
        "process-agent",
        200,
        Some(100),
        "AgentExecutor.exe",
        "2026-07-15T12:01:00Z",
    );
    let msi = correlation_process(
        "process-msi",
        300,
        Some(200),
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );

    let correlations =
        correlate_installer_processes(&workloads, &[reused_future, msi, agent, ime], &[], &[]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(correlations[0].confidence, EspCorrelationConfidence::Exact);
    assert!(correlations[0].reason.contains("parentAppId"));
    assert_eq!(
        correlations[0]
            .process_observations
            .iter()
            .map(|process| process.context.evidence_ref.evidence_id.as_str())
            .collect::<Vec<_>>(),
        vec!["process-msi", "process-agent", "process-ime"]
    );
}

#[test]
fn correlation_parent_chain_rejects_a_stale_sample_with_a_reused_parent_pid() {
    let stale_app = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let current_app = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let stale_workload = correlation_workload(
        "workload-stale",
        stale_app,
        "2026-07-15T09:55:00Z",
        "2026-07-15T10:10:00Z",
    );
    let current_workload = correlation_workload(
        "workload-current",
        current_app,
        "2026-07-15T11:58:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut stale_parent = correlation_process(
        "process-stale-parent",
        100,
        None,
        "AgentExecutor.exe",
        "2026-07-15T10:00:00Z",
    );
    stale_parent.app_id = Some(stale_app.to_string());
    stale_parent.context.source_timestamp = None;
    stale_parent.context.observed_at_utc = "2026-07-15T10:05:00Z".to_string();
    let child = correlation_process(
        "process-current-child",
        701,
        Some(100),
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );

    let correlations = correlate_installer_processes(
        &[stale_workload, current_workload],
        &[stale_parent, child],
        &[],
        &[],
    );

    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert_eq!(correlations[0].process_observations.len(), 1);
}

#[test]
fn correlation_deduplicates_repeated_samples_by_pid_and_start_time() {
    let app_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        app_a,
        "2026-07-15T11:58:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut informative = correlation_process(
        "process-sample-informative",
        701,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    informative.app_id = Some(app_a.to_string());
    informative.context.source_timestamp = None;
    informative.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut later_sparse = correlation_process(
        "process-sample-later",
        701,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    later_sparse.context.source_timestamp = None;
    later_sparse.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();

    let correlations =
        correlate_installer_processes(&[workload], &[later_sparse, informative], &[], &[]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(correlations[0].confidence, EspCorrelationConfidence::Exact);
    assert_eq!(correlations[0].process_observations.len(), 1);
    assert_eq!(
        correlations[0].correlation_id,
        "installer|701|2026-07-15T12:02:00Z"
    );
}

#[test]
fn correlation_repair_keeps_distinct_tracked_cross_field_ids_ambiguous() {
    let app_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let app_b = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-a",
            app_a,
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        ),
        correlation_workload(
            "workload-b",
            app_b,
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut app_sample = correlation_process(
        "process-sample-app-a",
        720,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    app_sample.app_id = Some(app_a.to_string());
    app_sample.context.source_timestamp = None;
    app_sample.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut product_sample = correlation_process(
        "process-sample-product-b",
        720,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    product_sample.product_code = Some(app_b.to_string());
    product_sample.context.source_timestamp = None;
    product_sample.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();

    let forward = correlate_installer_processes(
        &workloads,
        &[app_sample.clone(), product_sample.clone()],
        &[],
        &[],
    );
    let reverse =
        correlate_installer_processes(&workloads, &[product_sample, app_sample], &[], &[]);

    assert_eq!(forward, reverse);
    let correlations = forward;

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].workload_id, None);
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Uncorrelated
    );
    assert_eq!(correlations[0].reason, "contradictoryExactIdentifiers");
    assert_eq!(
        correlations[0].candidate_workload_ids,
        vec!["workload-a", "workload-b"]
    );
    assert_eq!(correlations[0].process_observations.len(), 2);
    assert!(correlations[0].process_observations.iter().any(|process| {
        process.app_id.as_deref() == Some(app_a) && process.product_code.is_none()
    }));
    assert!(correlations[0].process_observations.iter().any(|process| {
        process.app_id.is_none() && process.product_code.as_deref() == Some(app_b)
    }));
    assert!(correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-sample-app-a"));
    assert!(correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-sample-product-b"));
}

#[test]
fn correlation_repair_treats_tracked_app_and_untracked_product_as_complementary() {
    let app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let product_code = "11111111-2222-3333-4444-555555555555";
    let workload = correlation_workload(
        "workload-a",
        app_id,
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut app_sample = correlation_process(
        "process-complementary-app",
        7201,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    app_sample.app_id = Some(app_id.to_string());
    app_sample.context.source_timestamp = None;
    app_sample.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut product_sample = correlation_process(
        "process-complementary-product",
        7201,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    product_sample.product_code = Some(product_code.to_string());
    product_sample.context.source_timestamp = None;
    product_sample.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();

    let forward = correlate_installer_processes(
        std::slice::from_ref(&workload),
        &[app_sample.clone(), product_sample.clone()],
        &[],
        &[],
    );
    let reverse =
        correlate_installer_processes(&[workload], &[product_sample, app_sample], &[], &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(forward[0].confidence, EspCorrelationConfidence::Exact);
    assert_eq!(forward[0].reason, "appId");
    assert_eq!(forward[0].candidate_workload_ids, vec!["workload-a"]);
    assert_eq!(forward[0].process_observations.len(), 1);
    assert_eq!(
        forward[0].process_observations[0].app_id.as_deref(),
        Some(app_id)
    );
    assert_eq!(
        forward[0].process_observations[0].product_code.as_deref(),
        Some(product_code)
    );
}

#[test]
fn correlation_duplicate_blank_metadata_never_outranks_exact_identifier() {
    let app_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        app_a,
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut exact = correlation_process(
        "process-sample-exact",
        721,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    exact.app_id = Some(app_a.to_string());
    exact.context.source_timestamp = None;
    exact.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut blank = correlation_process(
        "process-sample-blank",
        721,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    blank.app_id = Some(String::new());
    blank.product_code = Some("   ".to_string());
    blank.referenced_log_path = Some(String::new());
    blank.sanitized_command_line = Some(String::new());
    blank.context.source_timestamp = None;
    blank.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();

    let correlations = correlate_installer_processes(&[workload], &[exact, blank], &[], &[]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(correlations[0].confidence, EspCorrelationConfidence::Exact);
    assert_eq!(correlations[0].reason, "appId");
    assert!(correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-sample-exact"));
    assert!(correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-sample-blank"));
}

#[test]
fn correlation_duplicate_later_sample_extends_proven_lifetime() {
    let product = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        product,
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:12:00Z",
    );
    let mut early = correlation_process(
        "process-sample-early-path",
        722,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    early.referenced_log_path = Some(r"C:\Windows\Temp\install.log".to_string());
    early.context.source_timestamp = None;
    early.context.observed_at_utc = "2026-07-15T12:01:00Z".to_string();
    let mut later = correlation_process(
        "process-sample-later-sparse",
        722,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    later.context.source_timestamp = None;
    later.context.observed_at_utc = "2026-07-15T12:10:00Z".to_string();
    let mut deployment = EspDeploymentLogObservation {
        context: fixture_context(
            EspSourceKind::DeploymentLog,
            "msi-log",
            "deployment-current-late",
            "2026-07-15T12:09:00Z",
        ),
        component: Some("MsiInstaller".to_string()),
        message: "Installation is still running".to_string(),
        product_code: Some(product.to_string()),
        log_path: Some(r"c:\windows\temp\INSTALL.log".to_string()),
        status: None,
    };
    deployment.context.source_timestamp = None;
    deployment.context.observed_at_utc = "2026-07-15T12:09:00Z".to_string();

    let correlations =
        correlate_installer_processes(&[workload], &[early, later], &[deployment], &[]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(correlations[0].confidence, EspCorrelationConfidence::Exact);
    assert_eq!(correlations[0].reason, "canonicalLogPath");
    assert!(correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "deployment-current-late"));
}

#[test]
fn correlation_merges_complementary_duplicate_samples_with_latest_liveness() {
    let app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        app_id,
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:12:00Z",
    );
    let mut identifier = correlation_process(
        "process-merge-identifier",
        729,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    identifier.app_id = Some(app_id.to_string());
    identifier.context.source_timestamp = None;
    identifier.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut log_path = correlation_process(
        "process-merge-log-path",
        729,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    log_path.product_code = Some(app_id.to_string());
    log_path.referenced_log_path = Some(r"C:\Windows\Temp\install.log".to_string());
    log_path.context.source_timestamp = None;
    log_path.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();
    let mut latest = correlation_process(
        "process-merge-latest",
        729,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    latest.context.source_timestamp = None;
    latest.context.observed_at_utc = "2026-07-15T12:10:00Z".to_string();
    let mut deployment = EspDeploymentLogObservation {
        context: fixture_context(
            EspSourceKind::DeploymentLog,
            "msi-log",
            "deployment-merge-late",
            "2026-07-15T12:09:00Z",
        ),
        component: Some("MsiInstaller".to_string()),
        message: "Installation is still running".to_string(),
        product_code: Some(app_id.to_string()),
        log_path: Some(r"c:\windows\temp\INSTALL.log".to_string()),
        status: None,
    };
    deployment.context.source_timestamp = None;
    deployment.context.observed_at_utc = "2026-07-15T12:09:00Z".to_string();

    let forward = correlate_installer_processes(
        std::slice::from_ref(&workload),
        &[identifier.clone(), log_path.clone(), latest.clone()],
        std::slice::from_ref(&deployment),
        &[],
    );
    let reverse = correlate_installer_processes(
        &[workload],
        &[latest, log_path, identifier],
        &[deployment],
        &[],
    );

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(
        forward[0].correlation_id,
        "installer|729|2026-07-15T12:02:00Z"
    );
    assert_eq!(forward[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(forward[0].confidence, EspCorrelationConfidence::Exact);
    assert_eq!(forward[0].process_observations.len(), 1);
    let process = &forward[0].process_observations[0];
    assert_eq!(process.app_id.as_deref(), Some(app_id));
    assert_eq!(process.product_code.as_deref(), Some(app_id));
    assert_eq!(
        process.referenced_log_path.as_deref(),
        Some(r"C:\Windows\Temp\install.log")
    );
    assert_eq!(process.context.observed_at_utc, "2026-07-15T12:10:00Z");
    assert!(forward[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-merge-identifier"));
    assert!(forward[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-merge-log-path"));
    assert!(forward[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-merge-latest"));
    assert!(forward[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "deployment-merge-late"));
}

#[test]
fn correlation_filters_pre_start_root_metadata_before_exact_matching() {
    let stale_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let current_id = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-stale",
            stale_id,
            "2026-07-15T09:55:00Z",
            "2026-07-15T10:05:00Z",
        ),
        correlation_workload(
            "workload-current",
            current_id,
            "2026-07-15T11:59:00Z",
            "2026-07-15T12:05:00Z",
        ),
    ];
    let mut stale = correlation_process(
        "process-root-before-start",
        730,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    stale.app_id = Some(stale_id.to_string());
    stale.referenced_log_path = Some(r"C:\Windows\Temp\stale.log".to_string());
    stale.context.source_timestamp = None;
    stale.context.observed_at_utc = "2026-07-15T10:00:00Z".to_string();
    let mut current = correlation_process(
        "process-root-current",
        730,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    current.context.source_timestamp = None;
    current.context.observed_at_utc = "2026-07-15T12:01:00Z".to_string();
    let mut deployment = EspDeploymentLogObservation {
        context: fixture_context(
            EspSourceKind::DeploymentLog,
            "stale-log",
            "deployment-via-stale-root-path",
            "2026-07-15T12:00:30Z",
        ),
        component: Some("MsiInstaller".to_string()),
        message: "A reused path names stale product evidence".to_string(),
        product_code: Some(stale_id.to_string()),
        log_path: Some(r"c:\windows\temp\STALE.log".to_string()),
        status: None,
    };
    deployment.context.source_timestamp = None;
    deployment.context.observed_at_utc = "2026-07-15T12:00:30Z".to_string();

    let correlations =
        correlate_installer_processes(&workloads, &[stale, current], &[deployment], &[]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert_eq!(correlations[0].reason, "singleTemporalCandidate");
    assert_eq!(correlations[0].process_observations.len(), 1);
    assert_eq!(
        correlations[0].process_observations[0]
            .context
            .evidence_ref
            .evidence_id,
        "process-root-current"
    );
    assert!(correlations[0].evidence.iter().all(|evidence| {
        evidence.evidence_id != "process-root-before-start"
            && evidence.evidence_id != "deployment-via-stale-root-path"
    }));
}

#[test]
fn correlation_rejects_process_sample_without_a_valid_observation_time() {
    let app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        app_id,
        "2026-07-15T11:59:00Z",
        "2026-07-15T12:05:00Z",
    );
    let mut process = correlation_process(
        "process-invalid-sample-time",
        731,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    process.app_id = Some(app_id.to_string());
    process.context.source_timestamp = None;
    process.context.observed_at_utc = "not-an-observation-time".to_string();

    let correlations = correlate_installer_processes(&[workload], &[process], &[], &[]);

    assert!(correlations.is_empty());
}

#[test]
fn correlation_rejects_processes_without_a_valid_start_identity() {
    let app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        app_id,
        "2026-07-15T11:59:00Z",
        "2026-07-15T12:05:00Z",
    );
    for (evidence_id, start) in [
        (
            "process-missing-start",
            timestamp_parts("", None, EspTimestampKind::Unspecified),
        ),
        (
            "process-invalid-start",
            timestamp_parts("not-a-process-start", None, EspTimestampKind::Invalid),
        ),
    ] {
        let mut process = correlation_process(
            evidence_id,
            732,
            None,
            "msiexec.exe",
            "2026-07-15T12:00:00Z",
        );
        process.process_start_time = start;
        process.app_id = Some(app_id.to_string());
        process.context.source_timestamp = None;
        process.context.observed_at_utc = "2026-07-15T12:01:00Z".to_string();

        let correlations =
            correlate_installer_processes(std::slice::from_ref(&workload), &[process], &[], &[]);

        assert!(correlations.is_empty(), "accepted {evidence_id}");
    }
}

#[test]
fn correlation_repair_rejects_malformed_or_inconsistent_raw_start_identity() {
    let mut accepted = Vec::new();
    for (label, start) in [
        (
            "invalid-rfc-date",
            timestamp_parts(
                "2026-02-30T12:00:00Z",
                Some("2026-07-15T12:00:00Z"),
                EspTimestampKind::Utc,
            ),
        ),
        (
            "invalid-rfc-offset",
            timestamp_parts(
                "2026-07-15T12:00:00+24:00",
                Some("2026-07-15T12:00:00Z"),
                EspTimestampKind::Offset,
            ),
        ),
        (
            "invalid-dmtf-date",
            timestamp_parts(
                "20260229120000.000000+000",
                Some("2026-07-15T12:00:00Z"),
                EspTimestampKind::Offset,
            ),
        ),
        (
            "wildcard-dmtf-date",
            timestamp_parts(
                "2026**15120000.000000+000",
                Some("2026-07-15T12:00:00Z"),
                EspTimestampKind::Offset,
            ),
        ),
        (
            "invalid-dmtf-sign",
            timestamp_parts(
                "20260715120000.000000*000",
                Some("2026-07-15T12:00:00Z"),
                EspTimestampKind::Offset,
            ),
        ),
        (
            "invalid-dmtf-second",
            timestamp_parts(
                "20260715120061.000000+000",
                Some("2026-07-15T12:00:00Z"),
                EspTimestampKind::Offset,
            ),
        ),
        (
            "rfc-kind-mismatch",
            timestamp_parts(
                "2026-07-15T12:00:00Z",
                Some("2026-07-15T12:00:00Z"),
                EspTimestampKind::Offset,
            ),
        ),
        (
            "unsupported-local-kind",
            timestamp_parts(
                "2026-07-15T12:00:00Z",
                Some("2026-07-15T12:00:00Z"),
                EspTimestampKind::Local,
            ),
        ),
        (
            "invalid-kind-with-valid-raw",
            timestamp_parts(
                "2026-07-15T12:00:00Z",
                Some("2026-07-15T12:00:00Z"),
                EspTimestampKind::Invalid,
            ),
        ),
        (
            "unspecified-kind-with-valid-raw",
            timestamp_parts(
                "2026-07-15T12:00:00Z",
                Some("2026-07-15T12:00:00Z"),
                EspTimestampKind::Unspecified,
            ),
        ),
        (
            "missing-raw-with-normalized",
            timestamp_parts("", Some("2026-07-15T12:00:00Z"), EspTimestampKind::Utc),
        ),
    ] {
        let mut process =
            correlation_process(label, 7321, None, "msiexec.exe", "2026-07-15T12:00:00Z");
        process.process_start_time = start;
        process.context.source_timestamp = None;
        process.context.observed_at_utc = "2026-07-15T12:01:00Z".to_string();

        let control = correlation_process(
            "valid-process-start-control",
            7321,
            None,
            "msiexec.exe",
            "2026-07-15T12:00:00Z",
        );
        let forward =
            correlate_installer_processes(&[], &[process.clone(), control.clone()], &[], &[]);
        let reverse = correlate_installer_processes(&[], &[control, process.clone()], &[], &[]);

        if forward != reverse
            || forward.len() != 1
            || forward[0].process_observations.len() != 1
            || forward[0].evidence.contains(&process.context.evidence_ref)
        {
            accepted.push(label);
        }
    }

    assert!(accepted.is_empty(), "accepted invalid starts: {accepted:?}");
}

#[test]
fn correlation_keeps_fractional_process_starts_as_lossless_identities() {
    let mut first = correlation_process(
        "process-fractional-first",
        733,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    first.process_start_time = timestamp_parts(
        "2026-07-15T12:00:00.100Z",
        Some("2026-07-15T12:00:00Z"),
        EspTimestampKind::Utc,
    );
    first.context.source_timestamp = None;
    first.context.observed_at_utc = "2026-07-15T12:00:01Z".to_string();
    let mut second = correlation_process(
        "process-fractional-second",
        733,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    second.process_start_time = timestamp_parts(
        "2026-07-15T12:00:00.900Z",
        Some("2026-07-15T12:00:00Z"),
        EspTimestampKind::Utc,
    );
    second.context.source_timestamp = None;
    second.context.observed_at_utc = "2026-07-15T12:00:02Z".to_string();

    let correlations = correlate_installer_processes(&[], &[first, second], &[], &[]);
    let correlation_ids = correlations
        .iter()
        .map(|correlation| correlation.correlation_id.as_str())
        .collect::<BTreeSet<_>>();

    assert_eq!(correlations.len(), 2);
    assert_eq!(
        correlation_ids,
        BTreeSet::from([
            "installer|733|2026-07-15T12:00:00.100Z",
            "installer|733|2026-07-15T12:00:00.900Z",
        ])
    );
}

#[test]
fn correlation_keeps_wmi_fractional_process_starts_as_lossless_identities() {
    let mut first = correlation_process(
        "process-wmi-fractional-first",
        735,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    first.process_start_time = timestamp_parts(
        "20260715120000.100000+000",
        Some("2026-07-15T12:00:00Z"),
        EspTimestampKind::Offset,
    );
    first.context.source_timestamp = None;
    first.context.observed_at_utc = "2026-07-15T12:00:01Z".to_string();
    let mut second = correlation_process(
        "process-wmi-fractional-second",
        735,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    second.process_start_time = timestamp_parts(
        "20260715120000.900000+000",
        Some("2026-07-15T12:00:00Z"),
        EspTimestampKind::Offset,
    );
    second.context.source_timestamp = None;
    second.context.observed_at_utc = "2026-07-15T12:00:02Z".to_string();

    let correlations = correlate_installer_processes(&[], &[first, second], &[], &[]);
    let correlation_ids = correlations
        .iter()
        .map(|correlation| correlation.correlation_id.as_str())
        .collect::<BTreeSet<_>>();

    assert_eq!(correlations.len(), 2);
    assert_eq!(
        correlation_ids,
        BTreeSet::from([
            "installer|735|2026-07-15T12:00:00.100Z",
            "installer|735|2026-07-15T12:00:00.900Z",
        ])
    );
}

#[test]
fn correlation_repair_rejects_nonzero_rfc3339_precision_beyond_nanoseconds() {
    let mut utc = correlation_process(
        "process-excess-fraction-utc",
        7352,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    utc.process_start_time = timestamp_parts(
        "2026-07-15T12:00:00.0000000001Z",
        Some("2026-07-15T12:00:00Z"),
        EspTimestampKind::Utc,
    );
    utc.sanitized_command_line = Some("msiexec.exe /i invalid-utc.msi".to_string());
    utc.context.source_timestamp = None;
    utc.context.observed_at_utc = "2026-07-15T12:00:01Z".to_string();
    let mut offset = correlation_process(
        "process-excess-fraction-offset",
        7352,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    offset.process_start_time = timestamp_parts(
        "2026-07-15T08:00:00.0000000002-04:00",
        Some("2026-07-15T12:00:00Z"),
        EspTimestampKind::Offset,
    );
    offset.sanitized_command_line = Some("msiexec.exe /i invalid-offset.msi".to_string());
    offset.context.source_timestamp = None;
    offset.context.observed_at_utc = "2026-07-15T12:00:02Z".to_string();
    let mut control = correlation_process(
        "process-excess-fraction-dmtf-control",
        7352,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    control.process_start_time = timestamp_parts(
        "20260715120000.000000+000",
        Some("2026-07-15T12:00:00Z"),
        EspTimestampKind::Offset,
    );
    control.sanitized_command_line = Some("msiexec.exe /i control.msi".to_string());
    control.context.source_timestamp = None;
    control.context.observed_at_utc = "2026-07-15T12:00:03Z".to_string();

    let forward = correlate_installer_processes(
        &[],
        &[utc.clone(), offset.clone(), control.clone()],
        &[],
        &[],
    );
    let reverse = correlate_installer_processes(&[], &[control, offset, utc], &[], &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(
        forward[0].correlation_id,
        "installer|7352|2026-07-15T12:00:00Z"
    );
    assert_eq!(forward[0].process_observations.len(), 1);
    assert_eq!(
        forward[0].process_observations[0]
            .context
            .evidence_ref
            .evidence_id,
        "process-excess-fraction-dmtf-control"
    );
    assert_eq!(forward[0].evidence.len(), 1);
    assert_eq!(
        forward[0].evidence[0].evidence_id,
        "process-excess-fraction-dmtf-control"
    );
}

#[test]
fn correlation_repair_canonicalizes_rfc3339_trailing_zero_precision_across_offsets() {
    let starts = [
        (
            "process-trailing-zero-utc",
            "2026-07-15T12:00:00.100000000000Z",
            EspTimestampKind::Utc,
        ),
        (
            "process-trailing-zero-offset",
            "2026-07-15T08:00:00.1000000000-04:00",
            EspTimestampKind::Offset,
        ),
    ];
    let processes = starts
        .into_iter()
        .enumerate()
        .map(|(index, (evidence_id, raw, kind))| {
            let mut process = correlation_process(
                evidence_id,
                7353,
                None,
                "msiexec.exe",
                "2026-07-15T12:00:00Z",
            );
            process.process_start_time =
                timestamp_parts(raw, Some("2026-07-15T12:00:00.100Z"), kind);
            process.context.source_timestamp = None;
            process.context.observed_at_utc = format!("2026-07-15T12:00:0{}Z", index + 1);
            process
        })
        .collect::<Vec<_>>();

    let forward = correlate_installer_processes(&[], &processes, &[], &[]);
    let reverse = correlate_installer_processes(
        &[],
        &processes.iter().cloned().rev().collect::<Vec<_>>(),
        &[],
        &[],
    );

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(
        forward[0].correlation_id,
        "installer|7353|2026-07-15T12:00:00.100Z"
    );
    assert_eq!(forward[0].process_observations.len(), 1);
    assert_eq!(forward[0].evidence.len(), 2);
}

#[test]
fn correlation_repair_canonicalizes_trailing_zero_leap_fraction_with_dmtf() {
    let starts = [
        (
            "process-trailing-zero-leap-utc",
            "2016-12-31T23:59:60.1234560000Z",
            EspTimestampKind::Utc,
        ),
        (
            "process-trailing-zero-leap-offset",
            "2016-12-31T18:59:60.123456000000-05:00",
            EspTimestampKind::Offset,
        ),
        (
            "process-trailing-zero-leap-dmtf",
            "20161231235960.123456+000",
            EspTimestampKind::Offset,
        ),
    ];
    let processes = starts
        .into_iter()
        .enumerate()
        .map(|(index, (evidence_id, raw, kind))| {
            let mut process = correlation_process(
                evidence_id,
                7354,
                None,
                "msiexec.exe",
                "2016-12-31T23:59:59Z",
            );
            process.process_start_time =
                timestamp_parts(raw, Some("2016-12-31T23:59:60.123456Z"), kind);
            process.context.source_timestamp = None;
            process.context.observed_at_utc = format!("2017-01-01T00:00:0{}Z", index + 1);
            process
        })
        .collect::<Vec<_>>();

    let forward = correlate_installer_processes(&[], &processes, &[], &[]);
    let reverse = correlate_installer_processes(
        &[],
        &processes.iter().cloned().rev().collect::<Vec<_>>(),
        &[],
        &[],
    );

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(
        forward[0].correlation_id,
        "installer|7354|2016-12-31T23:59:60.123456Z"
    );
    assert_eq!(forward[0].process_observations.len(), 1);
    assert_eq!(forward[0].evidence.len(), 3);
}

#[test]
fn correlation_repair_canonicalizes_equivalent_rfc_and_dmtf_leap_seconds() {
    let mut rfc = correlation_process(
        "process-rfc-leap-second",
        7351,
        None,
        "msiexec.exe",
        "2016-12-31T23:59:59Z",
    );
    rfc.process_start_time = timestamp_parts(
        "2016-12-31T23:59:60.123456Z",
        Some("2016-12-31T23:59:60.123456Z"),
        EspTimestampKind::Utc,
    );
    rfc.context.source_timestamp = None;
    rfc.context.observed_at_utc = "2017-01-01T00:00:01Z".to_string();
    let mut dmtf = correlation_process(
        "process-dmtf-leap-second",
        7351,
        None,
        "msiexec.exe",
        "2016-12-31T23:59:59Z",
    );
    dmtf.process_start_time = timestamp_parts(
        "20161231235960.123456+000",
        Some("2016-12-31T23:59:60.123456Z"),
        EspTimestampKind::Offset,
    );
    dmtf.context.source_timestamp = None;
    dmtf.context.observed_at_utc = "2017-01-01T00:00:02Z".to_string();

    let forward = correlate_installer_processes(&[], &[rfc.clone(), dmtf.clone()], &[], &[]);
    let reverse = correlate_installer_processes(&[], &[dmtf, rfc], &[], &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(
        forward[0].correlation_id,
        "installer|7351|2016-12-31T23:59:60.123456Z"
    );
}

#[test]
fn correlation_canonicalizes_equivalent_lossless_start_instants() {
    let app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        app_id,
        "2026-07-15T11:59:00Z",
        "2026-07-15T12:05:00Z",
    );
    let mut utc = correlation_process(
        "process-equivalent-utc",
        736,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    utc.process_start_time = timestamp_parts(
        "2026-07-15T12:00:00.100Z",
        Some("2026-07-15T12:00:00Z"),
        EspTimestampKind::Utc,
    );
    utc.app_id = Some(app_id.to_string());
    utc.context.source_timestamp = None;
    utc.context.observed_at_utc = "2026-07-15T12:00:01Z".to_string();
    let mut offset = correlation_process(
        "process-equivalent-offset",
        736,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    offset.process_start_time = timestamp_parts(
        "2026-07-15T08:00:00.100-04:00",
        Some("2026-07-15T08:00:00-04:00"),
        EspTimestampKind::Offset,
    );
    offset.context.source_timestamp = None;
    offset.context.observed_at_utc = "2026-07-15T12:00:02Z".to_string();

    let forward = correlate_installer_processes(
        std::slice::from_ref(&workload),
        &[utc.clone(), offset.clone()],
        &[],
        &[],
    );
    let reverse = correlate_installer_processes(&[workload], &[offset, utc], &[], &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(
        forward[0].correlation_id,
        "installer|736|2026-07-15T12:00:00.100Z"
    );
    assert_eq!(forward[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(forward[0].confidence, EspCorrelationConfidence::Exact);
}

#[test]
fn correlation_never_merges_reused_pid_with_invalid_or_missing_start() {
    let app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-old",
        app_id,
        "2026-07-15T09:55:00Z",
        "2026-07-15T10:05:00Z",
    );
    for (label, start) in [
        (
            "missing",
            timestamp_parts("", None, EspTimestampKind::Unspecified),
        ),
        (
            "invalid",
            timestamp_parts("not-a-process-start", None, EspTimestampKind::Invalid),
        ),
    ] {
        let mut old = correlation_process(
            &format!("process-{label}-old"),
            734,
            None,
            "msiexec.exe",
            "2026-07-15T10:00:00Z",
        );
        old.process_start_time = start.clone();
        old.app_id = Some(app_id.to_string());
        old.context.source_timestamp = None;
        old.context.observed_at_utc = "2026-07-15T10:00:00Z".to_string();
        let mut reused = correlation_process(
            &format!("process-{label}-reused"),
            734,
            None,
            "msiexec.exe",
            "2026-07-15T12:00:00Z",
        );
        reused.process_start_time = start;
        reused.context.source_timestamp = None;
        reused.context.observed_at_utc = "2026-07-15T12:00:00Z".to_string();

        let correlations = correlate_installer_processes(
            std::slice::from_ref(&workload),
            &[old, reused],
            &[],
            &[],
        );

        assert!(correlations.is_empty(), "merged {label} start identity");
    }
}

#[test]
fn correlation_preserves_conflicting_process_samples_without_fabricating_exact_state() {
    let app_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let app_b = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-a",
            app_a,
            "2026-07-15T11:59:00Z",
            "2026-07-15T12:05:00Z",
        ),
        correlation_workload(
            "workload-b",
            app_b,
            "2026-07-15T11:59:00Z",
            "2026-07-15T12:05:00Z",
        ),
    ];
    let sample = |evidence_id: &str, pid: u32, observed_at: &str| {
        let mut process = correlation_process(
            evidence_id,
            pid,
            None,
            "msiexec.exe",
            "2026-07-15T12:00:00Z",
        );
        process.context.source_timestamp = None;
        process.context.observed_at_utc = observed_at.to_string();
        process
    };

    let mut executable_exact = sample("conflict-executable-exact", 740, "2026-07-15T12:01:00Z");
    executable_exact.app_id = Some(app_a.to_string());
    let mut executable_other = sample("conflict-executable-other", 740, "2026-07-15T12:02:00Z");
    executable_other.executable_name = "winget.exe".to_string();

    let mut command_exact = sample("conflict-command-exact", 741, "2026-07-15T12:01:00Z");
    command_exact.app_id = Some(app_a.to_string());
    command_exact.sanitized_command_line = Some("msiexec /i package-a.msi".to_string());
    let mut command_other = sample("conflict-command-other", 741, "2026-07-15T12:02:00Z");
    command_other.sanitized_command_line = Some("msiexec /i package-b.msi".to_string());

    let mut path_exact = sample("conflict-path-exact", 742, "2026-07-15T12:01:00Z");
    path_exact.app_id = Some(app_a.to_string());
    path_exact.referenced_log_path = Some(r"C:\Windows\Temp\package-a.log".to_string());
    let mut path_other = sample("conflict-path-other", 742, "2026-07-15T12:02:00Z");
    path_other.referenced_log_path = Some(r"C:\Windows\Temp\package-b.log".to_string());

    let mut app_exact = sample("conflict-app-a", 743, "2026-07-15T12:01:00Z");
    app_exact.app_id = Some(app_a.to_string());
    let mut app_other = sample("conflict-app-b", 743, "2026-07-15T12:02:00Z");
    app_other.app_id = Some(app_b.to_string());

    let mut product_exact = sample("conflict-product-a", 744, "2026-07-15T12:01:00Z");
    product_exact.product_code = Some(app_a.to_string());
    let mut product_other = sample("conflict-product-b", 744, "2026-07-15T12:02:00Z");
    product_other.product_code = Some(app_b.to_string());

    for (label, first, second, expected_candidates) in [
        (
            "executable",
            executable_exact,
            executable_other,
            vec!["workload-a"],
        ),
        ("command", command_exact, command_other, vec!["workload-a"]),
        ("logPath", path_exact, path_other, vec!["workload-a"]),
        (
            "appId",
            app_exact,
            app_other,
            vec!["workload-a", "workload-b"],
        ),
        (
            "productCode",
            product_exact,
            product_other,
            vec!["workload-a", "workload-b"],
        ),
    ] {
        let forward =
            correlate_installer_processes(&workloads, &[first.clone(), second.clone()], &[], &[]);
        let reverse = correlate_installer_processes(&workloads, &[second, first], &[], &[]);

        assert_eq!(forward, reverse, "input order changed {label} result");
        assert_eq!(forward.len(), 1, "unexpected {label} result count");
        let correlation = &forward[0];
        assert_eq!(correlation.workload_id, None, "attributed {label} conflict");
        assert_eq!(
            correlation.confidence,
            EspCorrelationConfidence::Uncorrelated,
            "promoted {label} conflict"
        );
        assert_eq!(correlation.reason, "conflictingProcessSamples");
        assert_eq!(
            correlation.candidate_workload_ids,
            expected_candidates
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>(),
            "lost {label} conflict candidates"
        );
        assert_eq!(
            correlation.process_observations.len(),
            2,
            "merged {label} conflict into a synthetic observation"
        );
    }
}

#[test]
fn correlation_repair_preserves_deployment_candidates_and_evidence_on_conflict() {
    let product_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let product_b = "11111111-2222-3333-4444-555555555555";
    let workloads = vec![
        correlation_workload(
            "workload-a",
            product_a,
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        ),
        correlation_workload(
            "workload-b",
            product_b,
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut path_a = correlation_process(
        "process-conflicting-path-a",
        7451,
        None,
        "msiexec.exe",
        "2026-07-15T12:01:00Z",
    );
    path_a.referenced_log_path = Some(r"C:\Logs\a.log".to_string());
    path_a.context.source_timestamp = None;
    path_a.context.observed_at_utc = "2026-07-15T12:05:00Z".to_string();
    let mut path_b = correlation_process(
        "process-conflicting-path-b",
        7451,
        None,
        "msiexec.exe",
        "2026-07-15T12:01:00Z",
    );
    path_b.referenced_log_path = Some(r"C:\Logs\b.log".to_string());
    path_b.context.source_timestamp = None;
    path_b.context.observed_at_utc = "2026-07-15T12:06:00Z".to_string();
    let deployment_a = EspDeploymentLogObservation {
        context: fixture_context(
            EspSourceKind::DeploymentLog,
            "deployment-log-a",
            "deployment-conflicting-path-a",
            "2026-07-15T12:02:00Z",
        ),
        component: Some("MsiInstaller".to_string()),
        message: "Product A installation".to_string(),
        product_code: Some(product_a.to_string()),
        log_path: Some(r"c:\logs\A.log".to_string()),
        status: None,
    };
    let deployment_b = EspDeploymentLogObservation {
        context: fixture_context(
            EspSourceKind::DeploymentLog,
            "deployment-log-b",
            "deployment-conflicting-path-b",
            "2026-07-15T12:03:00Z",
        ),
        component: Some("MsiInstaller".to_string()),
        message: "Product B installation".to_string(),
        product_code: Some(product_b.to_string()),
        log_path: Some(r"c:\logs\B.log".to_string()),
        status: None,
    };

    let forward = correlate_installer_processes(
        &workloads,
        &[path_a.clone(), path_b.clone()],
        &[deployment_a.clone(), deployment_b.clone()],
        &[],
    );
    let reverse = correlate_installer_processes(
        &workloads,
        &[path_b, path_a],
        &[deployment_b, deployment_a],
        &[],
    );

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].workload_id, None);
    assert_eq!(
        forward[0].confidence,
        EspCorrelationConfidence::Uncorrelated
    );
    assert_eq!(forward[0].reason, "conflictingProcessSamples");
    assert_eq!(
        forward[0].candidate_workload_ids,
        vec!["workload-a", "workload-b"]
    );
    assert_eq!(forward[0].process_observations.len(), 2);
    let evidence_ids = forward[0]
        .evidence
        .iter()
        .map(|evidence| evidence.evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        evidence_ids,
        BTreeSet::from([
            "deployment-conflicting-path-a",
            "deployment-conflicting-path-b",
            "evidence-workload-a",
            "evidence-workload-b",
            "process-conflicting-path-a",
            "process-conflicting-path-b",
        ])
    );
}

#[test]
fn correlation_repair_preserves_ime_candidate_and_evidence_on_conflict() {
    let app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-ime",
        app_id,
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut command_a = correlation_process(
        "process-conflicting-command-a",
        7452,
        None,
        "msiexec.exe",
        "2026-07-15T12:01:00Z",
    );
    command_a.sanitized_command_line = Some("msiexec.exe /i package-a.msi".to_string());
    command_a.context.source_timestamp = None;
    command_a.context.observed_at_utc = "2026-07-15T12:05:00Z".to_string();
    let mut command_b = correlation_process(
        "process-conflicting-command-b",
        7452,
        None,
        "msiexec.exe",
        "2026-07-15T12:01:00Z",
    );
    command_b.sanitized_command_line = Some("msiexec.exe /i package-b.msi".to_string());
    command_b.context.source_timestamp = None;
    command_b.context.observed_at_utc = "2026-07-15T12:06:00Z".to_string();
    let ime = EspImeObservation {
        context: fixture_context(
            EspSourceKind::ImeLog,
            "ime-log-conflict",
            "ime-conflict-candidate",
            "2026-07-15T12:03:00Z",
        ),
        component: Some("AppWorkload".to_string()),
        message: "Installer process 7452 started".to_string(),
        app_id: Some(app_id.to_string()),
        status: None,
    };

    let forward = correlate_installer_processes(
        std::slice::from_ref(&workload),
        &[command_a.clone(), command_b.clone()],
        &[],
        std::slice::from_ref(&ime),
    );
    let reverse = correlate_installer_processes(&[workload], &[command_b, command_a], &[], &[ime]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].workload_id, None);
    assert_eq!(forward[0].reason, "conflictingProcessSamples");
    assert_eq!(forward[0].candidate_workload_ids, vec!["workload-ime"]);
    assert_eq!(forward[0].process_observations.len(), 2);
    assert!(forward[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "ime-conflict-candidate"));
    assert!(forward[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "evidence-workload-ime"));
}

#[test]
fn correlation_repair_rejects_conflicting_nonempty_parent_pids_without_time_fallback() {
    let workload = correlation_workload(
        "workload-temporal",
        "temporal-only",
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut parent_a = correlation_process(
        "process-parent-pid-a",
        7453,
        Some(101),
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    parent_a.context.source_timestamp = None;
    parent_a.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut parent_b = correlation_process(
        "process-parent-pid-b",
        7453,
        Some(202),
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    parent_b.context.source_timestamp = None;
    parent_b.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();

    let forward = correlate_installer_processes(
        std::slice::from_ref(&workload),
        &[parent_a.clone(), parent_b.clone()],
        &[],
        &[],
    );
    let reverse = correlate_installer_processes(&[workload], &[parent_b, parent_a], &[], &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].workload_id, None);
    assert_eq!(
        forward[0].confidence,
        EspCorrelationConfidence::Uncorrelated
    );
    assert_eq!(forward[0].reason, "conflictingProcessSamples");
    assert!(forward[0].candidate_workload_ids.is_empty());
    assert_eq!(forward[0].process_observations.len(), 2);
}

#[test]
fn correlation_repair_treats_missing_and_known_parent_pid_as_complementary() {
    let app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-parent",
        app_id,
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut exact = correlation_process(
        "process-parent-missing",
        7454,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    exact.app_id = Some(app_id.to_string());
    exact.context.source_timestamp = None;
    exact.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut known = correlation_process(
        "process-parent-known",
        7454,
        Some(100),
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    known.context.source_timestamp = None;
    known.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();

    let forward = correlate_installer_processes(
        std::slice::from_ref(&workload),
        &[exact.clone(), known.clone()],
        &[],
        &[],
    );
    let reverse = correlate_installer_processes(&[workload], &[known, exact], &[], &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward[0].workload_id.as_deref(), Some("workload-parent"));
    assert_eq!(forward[0].confidence, EspCorrelationConfidence::Exact);
    assert_eq!(forward[0].reason, "appId");
    assert_eq!(forward[0].process_observations.len(), 1);
    assert_eq!(forward[0].process_observations[0].parent_pid, Some(100));
}

#[test]
fn correlation_repair_normalizes_only_harmless_command_rendering_differences() {
    let app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-command",
        app_id,
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut quoted = correlation_process(
        "process-command-quoted",
        7455,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    quoted.app_id = Some(app_id.to_string());
    quoted.sanitized_command_line = Some(r#"msiexec.exe /l*v "C:\Temp\App.log""#.to_string());
    quoted.referenced_log_path = Some(r"C:\Temp\App.log".to_string());
    quoted.context.source_timestamp = None;
    quoted.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut unquoted = correlation_process(
        "process-command-unquoted",
        7455,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    unquoted.sanitized_command_line = Some(r"msiexec.exe    /l*v    C:\Temp\App.log".to_string());
    unquoted.referenced_log_path = Some(r"c:/temp/./APP.log".to_string());
    unquoted.context.source_timestamp = None;
    unquoted.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();

    let forward = correlate_installer_processes(
        std::slice::from_ref(&workload),
        &[quoted.clone(), unquoted.clone()],
        &[],
        &[],
    );
    let reverse = correlate_installer_processes(&[workload], &[unquoted, quoted], &[], &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].workload_id.as_deref(), Some("workload-command"));
    assert_eq!(forward[0].confidence, EspCorrelationConfidence::Exact);
    assert_ne!(forward[0].reason, "conflictingProcessSamples");
    assert_eq!(forward[0].process_observations.len(), 1);
}

#[test]
fn correlation_repair_preserves_case_sensitive_command_values_as_conflicts() {
    let workload = correlation_workload(
        "workload-command-case",
        "temporal-only",
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut upper = correlation_process(
        "process-command-value-upper",
        7456,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    upper.sanitized_command_line = Some("msiexec.exe /i package.msi LICENSEKEY=AbC123".to_string());
    upper.context.source_timestamp = None;
    upper.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut lower = correlation_process(
        "process-command-value-lower",
        7456,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    lower.sanitized_command_line = Some("msiexec.exe /i package.msi LICENSEKEY=abc123".to_string());
    lower.context.source_timestamp = None;
    lower.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();

    let forward = correlate_installer_processes(
        std::slice::from_ref(&workload),
        &[upper.clone(), lower.clone()],
        &[],
        &[],
    );
    let reverse = correlate_installer_processes(&[workload], &[lower, upper], &[], &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].workload_id, None);
    assert_eq!(
        forward[0].confidence,
        EspCorrelationConfidence::Uncorrelated
    );
    assert_eq!(forward[0].reason, "conflictingProcessSamples");
    assert!(forward[0].candidate_workload_ids.is_empty());
    assert_eq!(forward[0].process_observations.len(), 2);
}

#[test]
fn correlation_repair_preserves_case_when_command_tokenization_is_uncertain() {
    let workload = correlation_workload(
        "workload-command-fallback",
        "temporal-only",
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut upper = correlation_process(
        "process-command-fallback-upper",
        7457,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    upper.sanitized_command_line =
        Some("msiexec.exe /i package.msi LICENSEKEY=\"AbC123".to_string());
    upper.context.source_timestamp = None;
    upper.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut lower = correlation_process(
        "process-command-fallback-lower",
        7457,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    lower.sanitized_command_line =
        Some("msiexec.exe /i package.msi LICENSEKEY=\"abc123".to_string());
    lower.context.source_timestamp = None;
    lower.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();

    let forward = correlate_installer_processes(
        std::slice::from_ref(&workload),
        &[upper.clone(), lower.clone()],
        &[],
        &[],
    );
    let reverse = correlate_installer_processes(&[workload], &[lower, upper], &[], &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].workload_id, None);
    assert_eq!(forward[0].reason, "conflictingProcessSamples");
    assert_eq!(forward[0].process_observations.len(), 2);
}

#[test]
fn correlation_bounds_parent_cycles_and_is_order_independent() {
    let mut child = correlation_process(
        "cycle-child",
        750,
        Some(751),
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    child.context.source_timestamp = None;
    child.context.observed_at_utc = "2026-07-15T12:02:00Z".to_string();
    let mut parent = correlation_process(
        "cycle-parent",
        751,
        Some(750),
        "launcher.exe",
        "2026-07-15T11:59:00Z",
    );
    parent.context.source_timestamp = None;
    parent.context.observed_at_utc = "2026-07-15T12:01:00Z".to_string();

    let forward = correlate_installer_processes(&[], &[child.clone(), parent.clone()], &[], &[]);
    let reverse = correlate_installer_processes(&[], &[parent, child], &[], &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].process_observations.len(), 2);
}

#[test]
fn correlation_rejects_pre_start_ime_pid_evidence_inside_temporal_slop() {
    let stale_app = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let current_app = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-stale",
            stale_app,
            "2026-07-15T11:50:00Z",
            "2026-07-15T11:59:00Z",
        ),
        correlation_workload(
            "workload-current",
            current_app,
            "2026-07-15T12:02:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut process = correlation_process(
        "process-current-ime",
        723,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    process.context.source_timestamp = None;
    process.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let stale_ime = EspImeObservation {
        context: fixture_context(
            EspSourceKind::ImeLog,
            "ime-log",
            "ime-pre-start-reused-pid",
            "2026-07-15T12:01:30Z",
        ),
        component: Some("AppWorkload".to_string()),
        message: "Installer process 723 started".to_string(),
        app_id: Some(stale_app.to_string()),
        status: None,
    };

    let correlations = correlate_installer_processes(&workloads, &[process], &[], &[stale_ime]);

    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert!(!correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "ime-pre-start-reused-pid"));
}

#[test]
fn correlation_rejects_pre_start_reused_log_evidence_inside_temporal_slop() {
    let stale_product = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let current_product = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-stale",
            stale_product,
            "2026-07-15T11:50:00Z",
            "2026-07-15T11:59:00Z",
        ),
        correlation_workload(
            "workload-current",
            current_product,
            "2026-07-15T12:02:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut process = correlation_process(
        "process-current-log-reuse",
        724,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    process.referenced_log_path = Some(r"C:\Windows\Temp\install.log".to_string());
    process.context.source_timestamp = None;
    process.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let stale_log = EspDeploymentLogObservation {
        context: fixture_context(
            EspSourceKind::DeploymentLog,
            "msi-log",
            "deployment-pre-start-reused-log",
            "2026-07-15T12:01:30Z",
        ),
        component: Some("MsiInstaller".to_string()),
        message: "Previous installation completed".to_string(),
        product_code: Some(stale_product.to_string()),
        log_path: Some(r"c:\windows\temp\INSTALL.log".to_string()),
        status: None,
    };

    let correlations = correlate_installer_processes(&workloads, &[process], &[stale_log], &[]);

    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert!(!correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "deployment-pre-start-reused-log"));
}

#[test]
fn correlation_rejects_post_sample_ime_pid_evidence_inside_temporal_slop() {
    let stale_app = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let current_app = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-stale",
            stale_app,
            "2026-07-15T11:50:00Z",
            "2026-07-15T11:59:00Z",
        ),
        correlation_workload(
            "workload-current",
            current_app,
            "2026-07-15T12:02:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut process = correlation_process(
        "process-current-ime-upper-bound",
        727,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    process.context.source_timestamp = None;
    process.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let stale_ime = EspImeObservation {
        context: fixture_context(
            EspSourceKind::ImeLog,
            "ime-log",
            "ime-post-sample-reused-pid",
            "2026-07-15T12:03:30Z",
        ),
        component: Some("AppWorkload".to_string()),
        message: "Installer process 727 started".to_string(),
        app_id: Some(stale_app.to_string()),
        status: None,
    };

    let correlations = correlate_installer_processes(&workloads, &[process], &[], &[stale_ime]);

    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert!(!correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "ime-post-sample-reused-pid"));
}

#[test]
fn correlation_rejects_post_sample_reused_log_evidence_inside_temporal_slop() {
    let stale_product = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let current_product = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-stale",
            stale_product,
            "2026-07-15T11:50:00Z",
            "2026-07-15T11:59:00Z",
        ),
        correlation_workload(
            "workload-current",
            current_product,
            "2026-07-15T12:02:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut process = correlation_process(
        "process-current-log-upper-bound",
        728,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    process.referenced_log_path = Some(r"C:\Windows\Temp\install.log".to_string());
    process.context.source_timestamp = None;
    process.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let stale_log = EspDeploymentLogObservation {
        context: fixture_context(
            EspSourceKind::DeploymentLog,
            "msi-log",
            "deployment-post-sample-reused-log",
            "2026-07-15T12:03:30Z",
        ),
        component: Some("MsiInstaller".to_string()),
        message: "Later installation started".to_string(),
        product_code: Some(stale_product.to_string()),
        log_path: Some(r"c:\windows\temp\INSTALL.log".to_string()),
        status: None,
    };

    let correlations = correlate_installer_processes(&workloads, &[process], &[stale_log], &[]);

    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert!(!correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "deployment-post-sample-reused-log"));
}

#[test]
fn correlation_rejects_pre_start_parent_sample_inside_temporal_slop() {
    let stale_app = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let current_app = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-stale",
            stale_app,
            "2026-07-15T11:50:00Z",
            "2026-07-15T11:59:00Z",
        ),
        correlation_workload(
            "workload-current",
            current_app,
            "2026-07-15T12:02:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut stale_parent = correlation_process(
        "process-parent-pre-start",
        100,
        None,
        "AgentExecutor.exe",
        "2026-07-15T10:00:00Z",
    );
    stale_parent.app_id = Some(stale_app.to_string());
    stale_parent.context.source_timestamp = None;
    stale_parent.context.observed_at_utc = "2026-07-15T12:01:30Z".to_string();
    let mut child = correlation_process(
        "process-current-child",
        725,
        Some(100),
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    child.context.source_timestamp = None;
    child.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();

    let correlations = correlate_installer_processes(&workloads, &[stale_parent, child], &[], &[]);

    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert_eq!(correlations[0].process_observations.len(), 1);
    assert!(!correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-parent-pre-start"));
}

#[test]
fn correlation_filters_parent_samples_to_the_child_identity_lifetime() {
    let stale_app = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let current_app = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let workloads = vec![
        correlation_workload(
            "workload-stale",
            stale_app,
            "2026-07-15T11:50:00Z",
            "2026-07-15T11:59:00Z",
        ),
        correlation_workload(
            "workload-current",
            current_app,
            "2026-07-15T12:02:00Z",
            "2026-07-15T12:10:00Z",
        ),
    ];
    let mut parent_at_start = correlation_process(
        "process-parent-at-child-start",
        100,
        None,
        "AgentExecutor.exe",
        "2026-07-15T10:00:00Z",
    );
    parent_at_start.context.source_timestamp = None;
    parent_at_start.context.observed_at_utc = "2026-07-15T12:02:00Z".to_string();
    let mut parent_after_latest = correlation_process(
        "process-parent-after-child-latest",
        100,
        None,
        "AgentExecutor.exe",
        "2026-07-15T10:00:00Z",
    );
    parent_after_latest.app_id = Some(stale_app.to_string());
    parent_after_latest.referenced_log_path = Some(r"C:\Windows\Temp\stale-parent.log".to_string());
    parent_after_latest.context.source_timestamp = None;
    parent_after_latest.context.observed_at_utc = "2026-07-15T12:04:00Z".to_string();
    let mut child = correlation_process(
        "process-current-child-parent-window",
        730,
        Some(100),
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    child.context.source_timestamp = None;
    child.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();

    let correlations = correlate_installer_processes(
        &workloads,
        &[parent_after_latest, child, parent_at_start],
        &[],
        &[],
    );

    assert_eq!(correlations.len(), 1);
    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert_eq!(correlations[0].process_observations.len(), 2);
    assert!(correlations[0]
        .process_observations
        .iter()
        .all(|process| process.referenced_log_path.is_none()));
    assert!(correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-parent-at-child-start"));
    assert!(!correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-parent-after-child-latest"));
}

#[test]
fn correlation_parent_window_includes_the_child_latest_sample_boundary() {
    let app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        app_id,
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut parent = correlation_process(
        "process-parent-at-child-latest",
        100,
        None,
        "AgentExecutor.exe",
        "2026-07-15T10:00:00Z",
    );
    parent.app_id = Some(app_id.to_string());
    parent.context.source_timestamp = None;
    parent.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();
    let mut child = correlation_process(
        "process-child-latest-boundary",
        731,
        Some(100),
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    child.context.source_timestamp = None;
    child.context.observed_at_utc = "2026-07-15T12:03:00Z".to_string();

    let correlations = correlate_installer_processes(&[workload], &[parent, child], &[], &[]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(correlations[0].confidence, EspCorrelationConfidence::Exact);
    assert_eq!(correlations[0].reason, "parentAppId");
    assert_eq!(correlations[0].process_observations.len(), 2);
}

#[test]
fn correlation_temporal_slop_includes_exact_two_minute_boundary() {
    let workload = correlation_workload(
        "workload-a",
        "app-a",
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let process = correlation_process(
        "process-at-boundary",
        726,
        None,
        r#""C:\Windows\System32\MSIEXEC.EXE""#,
        "2026-07-15T11:58:00Z",
    );

    let correlations = correlate_installer_processes(&[workload], &[process], &[], &[]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
}

#[test]
fn correlation_uses_pid_bound_ime_app_evidence_without_name_inference() {
    let app_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        app_a,
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let process = correlation_process(
        "process-msi-ime",
        701,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    let ime = EspImeObservation {
        context: fixture_context(
            EspSourceKind::ImeLog,
            "ime-log",
            "ime-app-pid",
            "2026-07-15T12:02:01Z",
        ),
        component: Some("AppWorkload".to_string()),
        message: "Installer process 701 started".to_string(),
        app_id: Some(app_a.to_string()),
        status: None,
    };

    let correlations = correlate_installer_processes(&[workload], &[process], &[], &[ime]);

    assert_eq!(correlations[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(correlations[0].confidence, EspCorrelationConfidence::Exact);
    assert_eq!(correlations[0].reason, "imeProcessAppId");
    assert!(correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "ime-app-pid"));
}

#[test]
fn correlation_time_binds_ime_evidence_to_the_matching_parent_process() {
    let app_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        app_a,
        "2026-07-15T11:45:00Z",
        "2026-07-15T12:10:00Z",
    );
    let parent = correlation_process(
        "process-agent-parent",
        100,
        None,
        "AgentExecutor.exe",
        "2026-07-15T11:50:00Z",
    );
    let process = correlation_process(
        "process-msi-child",
        701,
        Some(100),
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    let ime = EspImeObservation {
        context: fixture_context(
            EspSourceKind::ImeLog,
            "ime-log",
            "ime-parent-pid",
            "2026-07-15T11:50:01Z",
        ),
        component: Some("AppWorkload".to_string()),
        message: "AgentExecutor process 100 started".to_string(),
        app_id: Some(app_a.to_string()),
        status: None,
    };

    let correlations = correlate_installer_processes(&[workload], &[process, parent], &[], &[ime]);

    assert_eq!(correlations[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(correlations[0].confidence, EspCorrelationConfidence::Exact);
    assert_eq!(correlations[0].reason, "imeProcessAppId");
}

#[test]
fn correlation_rejects_stale_ime_pid_evidence_after_pid_reuse() {
    let stale_app = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let current_app = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let stale_workload = correlation_workload(
        "workload-stale",
        stale_app,
        "2026-07-15T10:55:00Z",
        "2026-07-15T11:05:00Z",
    );
    let current_workload = correlation_workload(
        "workload-current",
        current_app,
        "2026-07-15T11:58:00Z",
        "2026-07-15T12:10:00Z",
    );
    let current_process = correlation_process(
        "process-reused-pid",
        701,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    let stale_ime = EspImeObservation {
        context: fixture_context(
            EspSourceKind::ImeLog,
            "ime-log",
            "ime-stale-pid",
            "2026-07-15T11:00:00Z",
        ),
        component: Some("AppWorkload".to_string()),
        message: "Installer process 701 started".to_string(),
        app_id: Some(stale_app.to_string()),
        status: None,
    };

    let correlations = correlate_installer_processes(
        &[stale_workload, current_workload],
        &[current_process],
        &[],
        &[stale_ime],
    );

    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert!(!correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "ime-stale-pid"));
}

#[test]
fn correlation_does_not_treat_unlabelled_number_as_pid_evidence() {
    let app_a = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-a",
        app_a,
        "2026-07-15T11:00:00Z",
        "2026-07-15T11:10:00Z",
    );
    let process = correlation_process(
        "process-current",
        701,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    let unrelated = EspImeObservation {
        context: fixture_context(
            EspSourceKind::ImeLog,
            "ime-log",
            "ime-unrelated-number",
            "2026-07-15T12:02:01Z",
        ),
        component: Some("AppWorkload".to_string()),
        message: "Retry timeout is 701 seconds".to_string(),
        app_id: Some(app_a.to_string()),
        status: None,
    };

    let correlations = correlate_installer_processes(&[workload], &[process], &[], &[unrelated]);

    assert_eq!(correlations[0].workload_id, None);
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Uncorrelated
    );
    assert_eq!(correlations[0].reason, "noEvidenceBackedCandidate");
}

#[test]
fn correlation_temporal_slop_is_limited_to_two_minutes() {
    let workload = correlation_workload(
        "workload-a",
        "app-a",
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let process = correlation_process(
        "process-too-early",
        702,
        None,
        "msiexec.exe",
        "2026-07-15T11:57:59Z",
    );

    let correlations = correlate_installer_processes(&[workload], &[process], &[], &[]);

    assert_eq!(correlations[0].workload_id, None);
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Uncorrelated
    );
}

#[test]
fn correlation_extracts_attached_quoted_msi_log_path() {
    assert_eq!(
        extract_installer_log_path(r#"msiexec /i package.msi /L*v"C:\Temp\Setup Log.log""#)
            .as_deref(),
        Some(r"C:\Temp\Setup Log.log")
    );
}

#[test]
fn correlation_rejects_stale_reused_log_path_product_evidence() {
    let stale_product = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let current_product = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let stale_workload = correlation_workload(
        "workload-stale",
        stale_product,
        "2026-07-15T10:55:00Z",
        "2026-07-15T11:05:00Z",
    );
    let current_workload = correlation_workload(
        "workload-current",
        current_product,
        "2026-07-15T11:58:00Z",
        "2026-07-15T12:10:00Z",
    );
    let mut current_process = correlation_process(
        "process-current-log",
        703,
        None,
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    current_process.referenced_log_path = Some(r"C:\Windows\Temp\install.log".to_string());
    let stale_log = EspDeploymentLogObservation {
        context: fixture_context(
            EspSourceKind::DeploymentLog,
            "msi-log",
            "deployment-stale-log",
            "2026-07-15T11:00:00Z",
        ),
        component: Some("MsiInstaller".to_string()),
        message: "Installation started".to_string(),
        product_code: Some(stale_product.to_string()),
        log_path: Some(r"c:\windows\temp\INSTALL.log".to_string()),
        status: None,
    };

    let correlations = correlate_installer_processes(
        &[stale_workload, current_workload],
        &[current_process],
        &[stale_log],
        &[],
    );

    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(
        correlations[0].confidence,
        EspCorrelationConfidence::Temporal
    );
    assert!(!correlations[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "deployment-stale-log"));
}

#[test]
fn correlation_uses_process_sample_time_for_long_running_installer_evidence() {
    let product = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let workload = correlation_workload(
        "workload-current",
        product,
        "2026-07-15T11:58:00Z",
        "2026-07-15T12:12:00Z",
    );
    let mut process = correlation_process(
        "process-long-running",
        704,
        None,
        "msiexec.exe",
        "2026-07-15T12:00:00Z",
    );
    process.context.source_timestamp = None;
    process.context.observed_at_utc = "2026-07-15T12:10:00Z".to_string();
    process.referenced_log_path = Some(r"C:\Windows\Temp\install.log".to_string());
    let mut deployment = EspDeploymentLogObservation {
        context: fixture_context(
            EspSourceKind::DeploymentLog,
            "msi-log",
            "deployment-current-log",
            "2026-07-15T12:08:00Z",
        ),
        component: Some("MsiInstaller".to_string()),
        message: "Installation is still running".to_string(),
        product_code: Some(product.to_string()),
        log_path: Some(r"c:\windows\temp\INSTALL.log".to_string()),
        status: None,
    };
    deployment.context.source_timestamp = None;
    deployment.context.observed_at_utc = "2026-07-15T12:08:00Z".to_string();

    let correlations = correlate_installer_processes(&[workload], &[process], &[deployment], &[]);

    assert_eq!(
        correlations[0].workload_id.as_deref(),
        Some("workload-current")
    );
    assert_eq!(correlations[0].confidence, EspCorrelationConfidence::Exact);
    assert_eq!(correlations[0].reason, "canonicalLogPath");
}

#[test]
fn correlation_uses_time_only_for_one_candidate_and_keeps_overlap_ambiguous() {
    let workload_a = correlation_workload(
        "workload-a",
        "app-a",
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    let workload_b = correlation_workload(
        "workload-b",
        "app-b",
        "2026-07-15T12:01:00Z",
        "2026-07-15T12:09:00Z",
    );
    let process = correlation_process(
        "process-temporal",
        500,
        None,
        "msiexec.exe",
        "2026-07-15T12:03:00Z",
    );

    let exact_one = correlate_installer_processes(
        std::slice::from_ref(&workload_a),
        std::slice::from_ref(&process),
        &[],
        &[],
    );
    assert_eq!(exact_one[0].workload_id.as_deref(), Some("workload-a"));
    assert_eq!(exact_one[0].confidence, EspCorrelationConfidence::Temporal);
    assert_eq!(exact_one[0].reason, "singleTemporalCandidate");

    let ambiguous = correlate_installer_processes(
        &[workload_a, workload_b],
        std::slice::from_ref(&process),
        &[],
        &[],
    );
    assert_eq!(ambiguous[0].workload_id, None);
    assert_eq!(
        ambiguous[0].confidence,
        EspCorrelationConfidence::Uncorrelated
    );
    assert_eq!(
        ambiguous[0].candidate_workload_ids,
        vec!["workload-a", "workload-b"]
    );
    assert_eq!(ambiguous[0].reason, "multipleTemporalCandidates");

    let mut contradictory = process;
    contradictory.product_code = Some("cccccccc-dddd-eeee-ffff-000000000000".to_string());
    let no_fallback = correlate_installer_processes(
        &[correlation_workload(
            "workload-a",
            "app-a",
            "2026-07-15T12:00:00Z",
            "2026-07-15T12:10:00Z",
        )],
        &[contradictory],
        &[],
        &[],
    );
    assert_eq!(no_fallback[0].workload_id, None);
    assert!(no_fallback[0].candidate_workload_ids.is_empty());
    assert_eq!(no_fallback[0].reason, "exactIdentifierNotTracked");

    let mut non_installer = correlation_workload(
        "policy-a",
        "cccccccc-dddd-eeee-ffff-000000000000",
        "2026-07-15T12:00:00Z",
        "2026-07-15T12:10:00Z",
    );
    non_installer.kind = EspTrackedKind::Policy;
    let mut policy_collision = correlation_process(
        "process-policy-collision",
        501,
        None,
        "msiexec.exe",
        "2026-07-15T12:03:00Z",
    );
    policy_collision.product_code = Some(non_installer.raw_identifier.clone());
    let excluded = correlate_installer_processes(&[non_installer], &[policy_collision], &[], &[]);
    assert_eq!(excluded[0].workload_id, None);
    assert!(excluded[0].candidate_workload_ids.is_empty());
    assert_eq!(excluded[0].reason, "exactIdentifierNotTracked");
}

#[test]
fn correlation_reducer_projects_exact_installer_evidence_before_deriving_findings() {
    let product_code = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let tracking_key = r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\ExpectedMSIAppPackages\2026-07-15T12:00:00Z";
    let mut process = correlation_process(
        "process-reducer-msi",
        6100,
        Some(6000),
        "msiexec.exe",
        "2026-07-15T12:02:00Z",
    );
    process.product_code = Some(format!("{{{}}}", product_code.to_ascii_uppercase()));
    process.sanitized_command_line = Some(format!(
        "msiexec /i {{{}}} /L*v C:\\Windows\\Temp\\app.log --secret [REDACTED]",
        product_code.to_ascii_uppercase()
    ));
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T12:03:00Z".to_string());
    reducer.ingest_all([
        registry_record(
            "esp-workloads",
            "workload-reducer-msi",
            tracking_key,
            &format!(
                "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/{{{}}}/Status",
                product_code.to_ascii_uppercase()
            ),
            EspObservationValue::Integer(70),
            "2026-07-15T12:00:00Z",
        ),
        EspEvidenceRecord::Process(process),
    ]);

    let snapshot = reducer.snapshot();

    assert_eq!(snapshot.workloads.len(), 1);
    assert_eq!(snapshot.installer_correlations.len(), 1);
    let correlation = &snapshot.installer_correlations[0];
    assert_eq!(
        correlation.workload_id.as_deref(),
        Some(snapshot.workloads[0].workload_id.as_str())
    );
    assert_eq!(correlation.confidence, EspCorrelationConfidence::Exact);
    assert_eq!(correlation.reason, "productCode");
    assert!(correlation
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "workload-reducer-msi"));
    assert!(correlation
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "process-reducer-msi"));
    assert!(snapshot
        .findings
        .iter()
        .all(|finding| finding.finding_id != "installer-correlation-ambiguous"));
}

#[test]
fn models_reducer_input_observation_dtos_are_serializable() {
    let observations = vec![
        serde_json::to_value(EspRegistryObservation {
            context: observation_context("registry-1"),
            hive: "HKLM".to_string(),
            key: r"SOFTWARE\Microsoft\Provisioning".to_string(),
            value_name: "CloudAssignedOobeConfig".to_string(),
            value: EspObservationValue::Unsigned(1022),
        })
        .unwrap(),
        serde_json::to_value(EspJsonObservation {
            context: observation_context("json-1"),
            document_type: "autopilotProfile".to_string(),
            json_pointer: "/PolicyDownloadDate".to_string(),
            value: EspObservationValue::Text("2026-07-15T12:00:00Z".to_string()),
        })
        .unwrap(),
        serde_json::to_value(EspEventLogObservation {
            context: observation_context("event-1"),
            channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
                .to_string(),
            event_id: 1924,
            record_id: Some(99),
            named_data: vec![EspNamedValue {
                name: "ProductCode".to_string(),
                value: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_string(),
            }],
            message: Some("Installation failed".to_string()),
        })
        .unwrap(),
        serde_json::to_value(EspImeObservation {
            context: observation_context("ime-1"),
            component: Some("AppWorkload".to_string()),
            message: "Install started".to_string(),
            app_id: Some("app-1".to_string()),
            status: Some(status(
                EspRawStatus::Text("Installing".to_string()),
                EspNormalizedStatus::Installing,
            )),
        })
        .unwrap(),
        serde_json::to_value(EspDeploymentLogObservation {
            context: observation_context("deployment-1"),
            component: Some("MSI".to_string()),
            message: "Action start".to_string(),
            product_code: Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".to_string()),
            log_path: Some(r"C:\Logs\app.log".to_string()),
            status: None,
        })
        .unwrap(),
        serde_json::to_value(EspProcessObservation {
            context: observation_context("process-1"),
            pid: 4242,
            process_start_time: timestamp("2026-07-15T12:00:00Z"),
            parent_pid: Some(1000),
            executable_name: "msiexec.exe".to_string(),
            sanitized_command_line: None,
            referenced_log_path: None,
            app_id: None,
            product_code: None,
        })
        .unwrap(),
        serde_json::to_value(EspSystemObservation {
            context: observation_context("system-1"),
            fact: EspSystemFact::TpmVersion("2.0".to_string()),
        })
        .unwrap(),
        serde_json::to_value(EspDeliveryOptimizationObservation {
            context: observation_context("do-1"),
            kind: EspDeliveryOptimizationEventKind::DownloadStarted,
            content_id: Some("content-1".to_string()),
            app_id: Some("app-1".to_string()),
            http_bytes: Some(100),
            lan_bytes: Some(25),
            cache_host_bytes: Some(10),
        })
        .unwrap(),
        serde_json::to_value(EspGraphObservation {
            context: observation_context("graph-1"),
            section: EspGraphObservationSection::ManagedDevice,
            api_version: GraphApiVersion::V1_0,
            record_id: "managed-1".to_string(),
            display_name: Some("DEVICE-1".to_string()),
            status: None,
        })
        .unwrap(),
    ];

    assert_eq!(observations.len(), 9);
    assert_eq!(observations[0]["value"], json!({"unsigned": 1022}));
    assert_eq!(observations[2]["namedData"][0]["name"], "ProductCode");
    assert_eq!(observations[5]["pid"], 4242);
    assert_eq!(observations[6]["fact"], json!({"tpmVersion": "2.0"}));
    assert_eq!(observations[8]["apiVersion"], "v1.0");
}

#[test]
fn models_cover_profile_enrollment_sessions_findings_and_safe_hardware() {
    let profile = EspProfileEvidence {
        profile_name: Some("Autopilot Profile".to_string()),
        deployment_profile_id: Some("profile-1".to_string()),
        correlation_id: Some("correlation-1".to_string()),
        tenant_domain: Some(sensitive("example.test")),
        tenant_id: Some(sensitive("tenant-1")),
        oobe_config: Some(EspOobeConfig {
            raw_mask: 1022,
            skip_keyboard: false,
            enable_patch_download: true,
            skip_windows_upgrade_ux: true,
            aad_tpm_required: true,
            aad_device_authentication: true,
            tpm_attestation: true,
            skip_eula: true,
            skip_oem_registration: true,
            skip_express_settings: true,
            disallow_admin: true,
        }),
        profile_download_time: Some(timestamp("2026-07-15T12:00:00Z")),
        join_mode: Some(EspJoinMode::HybridEntra),
        odj_applied: Some(true),
        skip_domain_connectivity_check: Some(true),
        device_preparation: Some(EspDevicePreparationEvidence {
            agent_download_timeout_seconds: Some(1800),
            page_timeout_seconds: Some(3600),
            allow_skip_on_failure: Some(true),
            allow_diagnostics: Some(true),
            script_ids: vec!["script-1".to_string()],
            evidence: vec![evidence_ref("device-prep")],
        }),
        evidence: vec![evidence_ref("profile-1")],
    };
    let enrollment = EspEnrollmentEvidence {
        enrollment_id: "enrollment-1".to_string(),
        provider_id: Some("MS DM Server".to_string()),
        tenant_id: Some(sensitive("tenant-1")),
        user_principal_name: Some(sensitive("user@example.test")),
        entdm_id: Some(sensitive("entdm-1")),
        settings: EspEnrollmentSettings {
            device_esp_enabled: Some(true),
            user_esp_enabled: Some(true),
            timeout_seconds: Some(3600),
            blocking: Some(true),
            allow_reset: Some(true),
            allow_retry: Some(true),
            continue_anyway: Some(false),
        },
        evidence: vec![evidence_ref("enrollment-1")],
    };
    let sessions = vec![
        EspSession {
            session_id: "classic-device".to_string(),
            kind: EspSessionKind::Classic,
            scope: EspScope::Device,
            user_sid: None,
            started_at: Some(timestamp("2026-07-15T12:00:00Z")),
            ended_at: None,
            phase: EspPhase::DeviceSetup,
            is_latest: true,
            workload_ids: vec!["workload-1".to_string()],
            evidence: vec![evidence_ref("session-device")],
        },
        EspSession {
            session_id: "v2-device".to_string(),
            kind: EspSessionKind::DevicePreparationV2,
            scope: EspScope::Device,
            user_sid: None,
            started_at: Some(timestamp("2026-07-15T12:01:00Z")),
            ended_at: None,
            phase: EspPhase::DevicePreparation,
            is_latest: true,
            workload_ids: vec!["workload-v2".to_string()],
            evidence: vec![evidence_ref("session-v2")],
        },
    ];
    let finding = EspDiagnosticFinding {
        finding_id: "missing-ime".to_string(),
        severity: EspFindingSeverity::Warning,
        confidence: EspFindingConfidence::High,
        title: "IME evidence is unavailable".to_string(),
        summary: "Protected IME logs could not be read".to_string(),
        recommended_checks: vec!["Restart CMTrace Open as administrator".to_string()],
        evidence: vec![],
        coverage_gap_ids: vec!["ime-logs".to_string()],
    };
    let hardware = EspHardwareEvidence {
        os_version: Some("10.0.26100".to_string()),
        os_build: Some("26100.4652".to_string()),
        manufacturer: Some("Contoso".to_string()),
        model: Some("Model 1".to_string()),
        serial_number: Some(sensitive("SERIAL-1")),
        tpm_version: Some("2.0".to_string()),
        evidence: vec![evidence_ref("hardware-1")],
    };

    let value = serde_json::to_value((profile, enrollment, sessions, finding, hardware)).unwrap();
    assert_eq!(value[0]["oobeConfig"]["rawMask"], 1022);
    assert_eq!(value[1]["settings"]["continueAnyway"], false);
    assert_eq!(value[2][0]["kind"], "classic");
    assert_eq!(value[2][1]["kind"], "devicePreparationV2");
    assert_eq!(value[3]["coverageGapIds"][0], "ime-logs");
    assert_eq!(value[4]["tpmVersion"], "2.0");
    assert!(!serde_json::to_string(&value[4])
        .unwrap()
        .contains("hardwareHash"));
}

#[test]
fn models_cover_registration_delivery_optimization_and_findings() {
    let registration = EspRegistrationEvent {
        event_id: 306,
        record_id: Some(7),
        status: status(
            EspRawStatus::Text("Hybrid AADJ device registration succeeded".to_string()),
            EspNormalizedStatus::Succeeded,
        ),
        message: "Hybrid Entra join succeeded".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: vec![EspNamedValue {
            name: "JoinType".to_string(),
            value: "Hybrid".to_string(),
        }],
        evidence: vec![evidence_ref("event-306")],
    };
    let delivery = EspDeliveryOptimizationEvidence {
        download_http_bytes: 1000,
        download_lan_bytes: 250,
        download_cache_host_bytes: 100,
        peer_share_percent: Some(25.0),
        connected_cache_share_percent: Some(10.0),
        transfers: vec![EspDeliveryOptimizationTransfer {
            transfer_id: "transfer-1".to_string(),
            kind: EspDeliveryOptimizationEventKind::DownloadCompleted,
            content_id: Some("content-1".to_string()),
            app_id: Some("app-1".to_string()),
            timestamp: timestamp("2026-07-15T12:00:00Z"),
            evidence: vec![evidence_ref("do-1")],
        }],
        evidence: vec![evidence_ref("do-stats")],
    };

    let value = serde_json::to_value((registration, delivery)).unwrap();
    assert_eq!(value[0]["eventId"], 306);
    assert_eq!(value[1]["downloadHttpBytes"], 1000);
    assert_eq!(value[1]["transfers"][0]["kind"], "downloadCompleted");
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NormalizationCases {
    office: Vec<StatusCase>,
    classic_esp: Vec<StatusCase>,
    policy: Vec<StatusCase>,
    v2: Vec<StatusCase>,
    unknown_numeric: StatusCase,
    unknown_string: StatusCase,
    timestamps: Vec<TimestampCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusCase {
    raw: EspRawStatus,
    normalized: EspNormalizedStatus,
    display: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimestampCase {
    raw: String,
    explicit_local_offset: Option<String>,
    kind: EspTimestampKind,
    original_offset: Option<String>,
    normalized_utc: Option<String>,
}

fn normalization_cases() -> NormalizationCases {
    serde_json::from_str(include_str!("fixtures/esp/normalization-cases.json"))
        .expect("normalization fixture must be valid")
}

#[test]
fn normalization_status_dictionaries_cover_every_known_and_unknown_value() {
    let cases = normalization_cases();

    for case in cases.office {
        let normalized = normalize_office_detail_status(case.raw.clone());
        assert_eq!(normalized.raw, case.raw);
        assert_eq!(normalized.normalized, case.normalized);
        assert_eq!(normalized.display, case.display);
    }
    for case in cases.classic_esp {
        let normalized = normalize_classic_esp_status(case.raw.clone());
        assert_eq!(normalized.raw, case.raw);
        assert_eq!(normalized.normalized, case.normalized);
        assert_eq!(normalized.display, case.display);
    }
    for case in cases.policy {
        let normalized = normalize_policy_status(case.raw.clone());
        assert_eq!(normalized.raw, case.raw);
        assert_eq!(normalized.normalized, case.normalized);
        assert_eq!(normalized.display, case.display);
    }
    for case in cases.v2 {
        let normalized = normalize_v2_status(case.raw.clone());
        assert_eq!(normalized.raw, case.raw);
        assert_eq!(normalized.normalized, case.normalized);
        assert_eq!(normalized.display, case.display);
    }

    let numeric = normalize_classic_esp_status(cases.unknown_numeric.raw.clone());
    assert_eq!(numeric.raw, cases.unknown_numeric.raw);
    assert_eq!(numeric.normalized, EspNormalizedStatus::Unknown);
    assert_eq!(numeric.display, cases.unknown_numeric.display);

    let text = normalize_v2_status(cases.unknown_string.raw.clone());
    assert_eq!(text.raw, cases.unknown_string.raw);
    assert_eq!(text.normalized, EspNormalizedStatus::Unknown);
    assert_eq!(text.display, cases.unknown_string.display);
}

#[test]
fn normalization_v2_named_status_trims_transport_whitespace_without_changing_raw() {
    let raw = EspRawStatus::Text(" \tCompleted\r\n".to_string());

    let normalized = normalize_v2_status(raw.clone());

    assert_eq!(normalized.raw, raw);
    assert_eq!(normalized.normalized, EspNormalizedStatus::Succeeded);
    assert_eq!(normalized.display, "Completed");
}

#[test]
fn normalization_office_detail_failure_overrides_processed_outer_state() {
    let normalized =
        normalize_office_status(EspRawStatus::Number(1), Some(EspRawStatus::Number(60)));

    assert_eq!(normalized.raw, EspRawStatus::Number(1));
    assert_eq!(normalized.normalized, EspNormalizedStatus::Failed);
    assert_eq!(normalized.display, "Processed / Enforcement Failed");
    assert_eq!(
        normalized.detail,
        Some(EspStatusDetail {
            raw: EspRawStatus::Number(60),
            normalized: EspNormalizedStatus::Failed,
            display: "Enforcement Failed".to_string(),
        })
    );
}

#[test]
fn normalization_percent_decoding_and_guid_extraction_are_bounded() {
    let encoded =
        "./Device/Vendor/MSFT/App/%7BAAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE%7D+Display%20Name";
    let decoded = percent_decode_bounded(encoded).expect("bounded valid URI");

    assert_eq!(
        decoded,
        "./Device/Vendor/MSFT/App/{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}+Display Name"
    );
    assert!(decoded.contains("+Display"), "plus must remain a plus");
    assert_eq!(
        extract_guid(encoded),
        Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string())
    );
    assert_eq!(
        extract_guid("./Cert/AAAAAAAA_BBBB_CCCC_DDDD_EEEEEEEEEEEE/Status"),
        Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string())
    );
    assert!(percent_decode_bounded("bad%2").is_err());
    assert!(percent_decode_bounded("bad%GG").is_err());
    assert!(percent_decode_bounded(&"a".repeat(MAX_PERCENT_DECODE_INPUT_BYTES + 1)).is_err());
}

fn oobe_flags(config: &EspOobeConfig) -> [bool; 10] {
    [
        config.skip_keyboard,
        config.enable_patch_download,
        config.skip_windows_upgrade_ux,
        config.aad_tpm_required,
        config.aad_device_authentication,
        config.tpm_attestation,
        config.skip_eula,
        config.skip_oem_registration,
        config.skip_express_settings,
        config.disallow_admin,
    ]
}

#[test]
fn normalization_oobe_config_retains_raw_mask_and_decodes_all_ten_bits() {
    let bits = [1024_u64, 512, 256, 128, 64, 32, 16, 8, 4, 2];

    for (expected_index, bit) in bits.iter().copied().enumerate() {
        let decoded = decode_oobe_config(bit);
        assert_eq!(decoded.raw_mask, bit);
        for (actual_index, enabled) in oobe_flags(&decoded).iter().copied().enumerate() {
            assert_eq!(
                enabled,
                actual_index == expected_index,
                "bit {bit} decoded the wrong OOBE flag"
            );
        }
    }

    let all = decode_oobe_config(bits.iter().sum());
    assert_eq!(all.raw_mask, 2046);
    assert!(oobe_flags(&all).iter().all(|enabled| *enabled));
}

#[test]
fn normalization_timestamps_are_pure_and_require_an_explicit_local_offset() {
    for case in normalization_cases().timestamps {
        let normalized = normalize_timestamp(&case.raw, case.explicit_local_offset.as_deref());
        assert_eq!(normalized.raw_text, case.raw);
        assert_eq!(normalized.kind, case.kind);
        assert_eq!(normalized.original_offset, case.original_offset);
        assert_eq!(normalized.normalized_utc, case.normalized_utc);
    }

    let unspecified = normalize_timestamp("2026-07-15 08:00:00", None);
    assert_eq!(unspecified.kind, EspTimestampKind::Unspecified);
    assert_eq!(unspecified.normalized_utc, None);

    let invalid_offset = normalize_timestamp("2026-07-15 08:00:00", Some("EDT"));
    assert_eq!(invalid_offset.kind, EspTimestampKind::Invalid);
    assert_eq!(invalid_offset.normalized_utc, None);
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScenarioCases {
    cases: Vec<ScenarioCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScenarioCase {
    name: String,
    expected_scenario: EspScenario,
    records: Vec<ScenarioRegistryRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScenarioRegistryRecord {
    source_artifact_id: String,
    evidence_id: String,
    key: String,
    value_name: String,
    value: EspObservationValue,
    source_timestamp: String,
}

fn fixture_context(
    source_kind: EspSourceKind,
    source_artifact_id: &str,
    evidence_id: &str,
    source_timestamp: &str,
) -> EspObservationContext {
    EspObservationContext {
        evidence_ref: EspEvidenceRef {
            evidence_id: evidence_id.to_string(),
            source_artifact_id: source_artifact_id.to_string(),
        },
        provenance: EspEvidenceProvenance {
            source_kind,
            source_artifact_id: source_artifact_id.to_string(),
            file_path: None,
            line_number: None,
            record_number: None,
            registry: None,
            event: None,
        },
        source_timestamp: Some(timestamp(source_timestamp)),
        observed_at_utc: "2026-07-15T18:00:00Z".to_string(),
        sensitivity: EspSensitivity::Public,
        parse_state: EspParseState::Parsed,
        access_state: EspSourceAccessState::Available,
    }
}

fn registry_record(
    source_artifact_id: &str,
    evidence_id: &str,
    key: &str,
    value_name: &str,
    value: EspObservationValue,
    source_timestamp: &str,
) -> EspEvidenceRecord {
    let mut context = fixture_context(
        EspSourceKind::Registry,
        source_artifact_id,
        evidence_id,
        source_timestamp,
    );
    context.provenance.registry = Some(EspRegistryProvenance {
        hive: "HKLM".to_string(),
        key: key.to_string(),
        value_name: Some(value_name.to_string()),
    });
    EspEvidenceRecord::Registry(EspRegistryObservation {
        context,
        hive: "HKLM".to_string(),
        key: key.to_string(),
        value_name: value_name.to_string(),
        value,
    })
}

fn json_record(
    source_artifact_id: &str,
    evidence_id: &str,
    document_type: &str,
    json_pointer: &str,
    value: EspObservationValue,
    source_timestamp: &str,
) -> EspEvidenceRecord {
    EspEvidenceRecord::Json(EspJsonObservation {
        context: fixture_context(
            EspSourceKind::Json,
            source_artifact_id,
            evidence_id,
            source_timestamp,
        ),
        document_type: document_type.to_string(),
        json_pointer: json_pointer.to_string(),
        value,
    })
}

fn json_registry_document_record(
    source_artifact_id: &str,
    evidence_id: &str,
    registry_value_name: &str,
    json_pointer: &str,
    value: EspObservationValue,
    source_timestamp: &str,
) -> EspEvidenceRecord {
    let mut record = json_record(
        source_artifact_id,
        evidence_id,
        "ProvisioningProgress",
        json_pointer,
        value,
        source_timestamp,
    );
    let EspEvidenceRecord::Json(observation) = &mut record else {
        unreachable!("json_record always returns a JSON observation");
    };
    observation.context.provenance.registry = Some(EspRegistryProvenance {
        hive: "HKLM".to_string(),
        key: r"SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot".to_string(),
        value_name: Some(registry_value_name.to_string()),
    });
    record
}

fn event_record(
    source_artifact_id: &str,
    evidence_id: &str,
    event_id: u32,
    record_id: u64,
    source_timestamp: &str,
    message: &str,
) -> EspEvidenceRecord {
    let mut context = fixture_context(
        EspSourceKind::EventLog,
        source_artifact_id,
        evidence_id,
        source_timestamp,
    );
    context.provenance.record_number = Some(record_id);
    context.provenance.event = Some(EspEventProvenance {
        channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
            .to_string(),
        event_id,
        record_id: Some(record_id),
        named_data: vec![],
    });
    EspEvidenceRecord::EventLog(EspEventLogObservation {
        context,
        channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
            .to_string(),
        event_id,
        record_id: Some(record_id),
        named_data: vec![],
        message: Some(message.to_string()),
    })
}

fn ime_record(
    source_artifact_id: &str,
    evidence_id: &str,
    source_timestamp: &str,
) -> EspEvidenceRecord {
    EspEvidenceRecord::Ime(EspImeObservation {
        context: fixture_context(
            EspSourceKind::ImeLog,
            source_artifact_id,
            evidence_id,
            source_timestamp,
        ),
        component: Some("AppWorkload".to_string()),
        message: "Retry download".to_string(),
        app_id: Some("app-retry".to_string()),
        status: Some(normalize_classic_esp_status(EspRawStatus::Number(2))),
    })
}

fn scenario_cases() -> ScenarioCases {
    serde_json::from_str(include_str!("fixtures/esp/scenario-cases.json"))
        .expect("scenario fixture must be valid")
}

#[test]
fn reducer_classifies_all_five_scenarios_from_explicit_evidence() {
    for case in scenario_cases().cases {
        let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
        reducer.ingest_all(case.records.into_iter().map(|record| {
            registry_record(
                &record.source_artifact_id,
                &record.evidence_id,
                &record.key,
                &record.value_name,
                record.value,
                &record.source_timestamp,
            )
        }));

        assert_eq!(
            reducer.snapshot().scenario,
            case.expected_scenario,
            "{}",
            case.name
        );
    }
}

#[test]
fn reducer_retains_classic_device_and_two_user_sessions_and_marks_latest_by_time() {
    let records = vec![
        registry_record(
            "esp-tracking",
            "device-newer",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\ExpectedPolicies\2026-07-15T12:00:00Z",
            "policy-device-newer",
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            "esp-tracking",
            "user-a-newer",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\S-1-5-21-100\ExpectedPolicies\2026-07-15T13:00:00Z",
            "policy-user-a-newer",
            EspObservationValue::Integer(0),
            "2026-07-15T13:00:00Z",
        ),
        registry_record(
            "esp-tracking",
            "device-older",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\ExpectedPolicies\2026-07-15T09:00:00Z",
            "policy-device-older",
            EspObservationValue::Integer(1),
            "2026-07-15T09:00:00Z",
        ),
        registry_record(
            "esp-tracking",
            "user-b-only",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\S-1-5-21-200\ExpectedPolicies\2026-07-15T11:30:00Z",
            "policy-user-b",
            EspObservationValue::Integer(1),
            "2026-07-15T11:30:00Z",
        ),
        registry_record(
            "esp-tracking",
            "user-a-older",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\S-1-5-21-100\ExpectedPolicies\2026-07-15T10:00:00Z",
            "policy-user-a-older",
            EspObservationValue::Integer(1),
            "2026-07-15T10:00:00Z",
        ),
    ];
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(records);
    let snapshot = reducer.snapshot();

    assert_eq!(snapshot.scenario, EspScenario::EspOnly);
    assert_eq!(snapshot.sessions.len(), 5);
    assert_eq!(
        snapshot
            .sessions
            .iter()
            .map(|session| session
                .started_at
                .as_ref()
                .unwrap()
                .normalized_utc
                .as_deref())
            .collect::<Vec<_>>(),
        vec![
            Some("2026-07-15T09:00:00Z"),
            Some("2026-07-15T12:00:00Z"),
            Some("2026-07-15T10:00:00Z"),
            Some("2026-07-15T13:00:00Z"),
            Some("2026-07-15T11:30:00Z"),
        ]
    );
    let latest = snapshot
        .sessions
        .iter()
        .filter(|session| session.is_latest)
        .map(|session| session.session_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        latest,
        vec![
            "session|esp-tracking|classic:device:2026-07-15T12:00:00Z|0",
            "session|esp-tracking|classic:user:S-1-5-21-100:2026-07-15T13:00:00Z|0",
            "session|esp-tracking|classic:user:S-1-5-21-200:2026-07-15T11:30:00Z|0",
        ]
    );
}

#[test]
fn reducer_isolates_device_preparation_from_classic_device_and_user_evidence() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "autopilot-settings",
            "device-preparation-hint",
            r"SOFTWARE\Microsoft\Provisioning\AutopilotSettings",
            "AutopilotDevicePrepHint",
            EspObservationValue::Text("enabled".to_string()),
            "2026-07-15T08:00:00Z",
        ),
        registry_record(
            "esp-tracking",
            "classic-must-not-leak",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\Sidecar\2026-07-15T09:00:00Z",
            "./Device/Vendor/MSFT/Win32App/classic-app",
            EspObservationValue::Integer(4),
            "2026-07-15T09:00:00Z",
        ),
        json_record(
            "v2-progress",
            "v2-id",
            "ProvisioningProgress",
            "/Workloads/0/WorkloadId",
            EspObservationValue::Text("v2-app".to_string()),
            "2026-07-15T10:00:00Z",
        ),
        json_record(
            "v2-progress",
            "v2-state",
            "ProvisioningProgress",
            "/Workloads/0/WorkloadState",
            EspObservationValue::Integer(5),
            "2026-07-15T10:00:00Z",
        ),
    ]);
    let snapshot = reducer.snapshot();

    assert_eq!(snapshot.scenario, EspScenario::AutopilotDevicePreparationV2);
    assert_eq!(snapshot.sessions.len(), 1);
    assert_eq!(
        snapshot.sessions[0].kind,
        EspSessionKind::DevicePreparationV2
    );
    assert_eq!(snapshot.workloads.len(), 1);
    assert_eq!(snapshot.workloads[0].raw_identifier, "v2-app");
    assert_eq!(
        snapshot.workloads[0].kind,
        EspTrackedKind::DevicePreparationWorkload
    );
    let excluded_classic_raw = snapshot
        .raw_evidence
        .iter()
        .find(|record| record.evidence[0].evidence_id == "classic-must-not-leak")
        .expect("scenario gating must not discard non-hardware-hash raw evidence");
    assert_eq!(
        excluded_classic_raw.record_id,
        "raw|esp-tracking|classic-must-not-leak|0"
    );
    assert_eq!(
        excluded_classic_raw.raw_value,
        EspObservationValue::Integer(4)
    );
    assert!(!snapshot
        .workloads
        .iter()
        .any(|workload| workload.raw_identifier == "classic-app"));
}

#[test]
fn reducer_absent_evidence_never_implies_success() {
    let snapshot = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string()).snapshot();

    assert_eq!(snapshot.scenario, EspScenario::Unknown);
    assert_eq!(snapshot.phase, EspPhase::NotStarted);
    assert!(snapshot.sessions.is_empty());
    assert!(snapshot.workloads.is_empty());
    assert!(snapshot.activity.is_empty());
    assert!(!matches!(snapshot.phase, EspPhase::Completed));
}

#[test]
fn reducer_projects_all_classic_and_v2_workload_kinds_with_identity_based_ids() {
    let classic_key = |family: &str| {
        format!(
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\{family}\2026-07-15T12:00:00Z"
        )
    };
    let mut classic = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    classic.ingest_all(vec![
        registry_record(
            "profile",
            "profile-v1",
            r"SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot",
            "DeploymentProfileName",
            EspObservationValue::Text("Profile".to_string()),
            "2026-07-15T08:00:00Z",
        ),
        registry_record(
            "esp-workloads",
            "msi",
            &classic_key("ExpectedMSIAppPackages"),
            "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/msi-a/Status",
            EspObservationValue::Integer(70),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            "registry:HKLM\\SOFTWARE\\Microsoft\\EnterpriseDesktopAppManagement",
            "msi-detail",
            r"SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI\msi-a",
            "Status",
            EspObservationValue::Integer(70),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            "esp-workloads",
            "office",
            &classic_key("ExpectedMSIAppPackages"),
            "./Vendor/MSFT/Office/Installation/office-a",
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:01Z",
        ),
        registry_record(
            "esp-workloads",
            "office-final-status",
            r"SOFTWARE\Microsoft\OfficeCSP\office-a",
            "FinalStatus",
            EspObservationValue::Integer(60),
            "2026-07-15T12:00:01Z",
        ),
        registry_record(
            "esp-workloads",
            "modern",
            &classic_key("ExpectedModernAppPackages"),
            "./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/modern-a",
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:02Z",
        ),
        registry_record(
            "esp-workloads",
            "win32-a",
            &classic_key("Sidecar"),
            "./Device/Vendor/MSFT/Win32App/win32-a",
            EspObservationValue::Integer(4),
            "2026-07-15T12:00:03Z",
        ),
        registry_record(
            "esp-workloads",
            "win32-b",
            &classic_key("Sidecar"),
            "./Device/Vendor/MSFT/Win32App/win32-b",
            EspObservationValue::Integer(3),
            "2026-07-15T12:00:04Z",
        ),
        registry_record(
            "esp-workloads",
            "policy",
            &classic_key("ExpectedPolicies"),
            "policy-a",
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:05Z",
        ),
        registry_record(
            "esp-workloads",
            "scep",
            &classic_key("ExpectedSCEPCerts"),
            "./Device/Vendor/MSFT/CertificateStore/My/SCEP/cert-a",
            EspObservationValue::Integer(0),
            "2026-07-15T12:00:06Z",
        ),
    ]);
    let classic_snapshot = classic.snapshot();

    assert_eq!(
        classic_snapshot
            .workloads
            .iter()
            .map(|workload| workload.kind.clone())
            .collect::<Vec<_>>(),
        vec![
            EspTrackedKind::Msi,
            EspTrackedKind::Office,
            EspTrackedKind::ModernApp,
            EspTrackedKind::Win32App,
            EspTrackedKind::Win32App,
            EspTrackedKind::Policy,
            EspTrackedKind::ScepCertificate
        ]
    );
    assert_eq!(
        classic_snapshot.workloads[0].status.normalized,
        EspNormalizedStatus::Succeeded
    );
    assert_eq!(
        classic_snapshot.workloads[0].evidence[1].evidence_id,
        "msi-detail"
    );
    assert_eq!(
        classic_snapshot.workloads[1].status.raw,
        EspRawStatus::Number(1)
    );
    assert_eq!(
        classic_snapshot.workloads[1].status.normalized,
        EspNormalizedStatus::Failed
    );
    assert_eq!(
        classic_snapshot.workloads[1]
            .status
            .detail
            .as_ref()
            .unwrap()
            .raw,
        EspRawStatus::Number(60)
    );
    assert_ne!(
        classic_snapshot.workloads[3].workload_id,
        classic_snapshot.workloads[4].workload_id
    );
    assert!(classic_snapshot.workloads[3]
        .workload_id
        .contains("win32-a"));
    assert!(!classic_snapshot.workloads[3]
        .workload_id
        .contains("PowerToys"));

    let mut v2 = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    v2.ingest_all(vec![
        registry_record("autopilot-settings", "v2-hint", r"SOFTWARE\Microsoft\Provisioning\AutopilotSettings", "AutopilotDevicePrepHint", EspObservationValue::Text("enabled".to_string()), "2026-07-15T08:00:00Z"),
        json_record("v2-progress", "v2-id", "ProvisioningProgress", "/Workloads/0/WorkloadId", EspObservationValue::Text("v2-app".to_string()), "2026-07-15T10:00:00Z"),
        json_record("v2-progress", "v2-name", "ProvisioningProgress", "/Workloads/0/FriendlyName", EspObservationValue::Text("PowerToys".to_string()), "2026-07-15T10:00:00Z"),
        json_record("v2-progress", "v2-state", "ProvisioningProgress", "/Workloads/0/WorkloadState", EspObservationValue::Integer(4), "2026-07-15T10:01:00Z"),
        json_record("v2-progress", "v2-exit", "ProvisioningProgress", "/Workloads/0/ErrorCode", EspObservationValue::Integer(-1), "2026-07-15T10:01:00Z"),
        json_record("v2-progress", "v2-enforcement", "ProvisioningProgress", "/Workloads/0/EnforcementErrorCode", EspObservationValue::Text("0x87D30067".to_string()), "2026-07-15T10:01:00Z"),
        registry_record("ime-policies", "script-result", r"SOFTWARE\Microsoft\IntuneManagementExtension\Policies\00000000-0000-0000-0000-000000000000\script-a", "Result", EspObservationValue::Text("Success".to_string()), "2026-07-15T10:02:00Z"),
    ]);
    let v2_snapshot = v2.snapshot();
    assert_eq!(v2_snapshot.workloads.len(), 2);
    assert_eq!(
        v2_snapshot.workloads[0].kind,
        EspTrackedKind::DevicePreparationWorkload
    );
    assert_eq!(
        v2_snapshot.workloads[0].exit_code.as_ref().unwrap().raw,
        "-1"
    );
    assert_eq!(
        v2_snapshot.workloads[0]
            .enforcement_error_code
            .as_ref()
            .unwrap()
            .raw,
        "0x87D30067"
    );
    assert_eq!(
        v2_snapshot.workloads[1].kind,
        EspTrackedKind::PlatformScript
    );
}

#[test]
fn reducer_projects_profile_odj_registration_and_delivery_optimization_evidence() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "profile",
            "profile-v1",
            r"SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot",
            "DeploymentProfileName",
            EspObservationValue::Text("Profile".to_string()),
            "2026-07-15T08:00:00Z",
        ),
        json_record(
            "autopilot-json",
            "profile-download",
            "AutopilotProfile",
            "/PolicyDownloadDate",
            EspObservationValue::Text("2026-07-15T08:30:00Z".to_string()),
            "2026-07-15T08:30:00Z",
        ),
        json_record(
            "autopilot-json",
            "join-mode",
            "AutopilotProfile",
            "/CloudAssignedDomainJoinMethod",
            EspObservationValue::Integer(1),
            "2026-07-15T08:30:00Z",
        ),
        registry_record(
            "odj-registry",
            "odj-applied",
            r"SOFTWARE\Microsoft\Provisioning\OMADM\SyncML",
            "ODJApplied",
            EspObservationValue::Boolean(true),
            "2026-07-15T08:31:00Z",
        ),
        event_record(
            "device-registration",
            "event-306",
            306,
            9001,
            "2026-07-15T08:32:00Z",
            "Hybrid AADJ device registration succeeded",
        ),
        EspEvidenceRecord::DeliveryOptimization(EspDeliveryOptimizationObservation {
            context: fixture_context(
                EspSourceKind::DeliveryOptimization,
                "do-live",
                "do-start",
                "2026-07-15T08:33:00Z",
            ),
            kind: EspDeliveryOptimizationEventKind::DownloadStarted,
            content_id: Some("content-a".to_string()),
            app_id: Some("app-a".to_string()),
            http_bytes: Some(1000),
            lan_bytes: Some(250),
            cache_host_bytes: Some(100),
        }),
        EspEvidenceRecord::DeliveryOptimization(EspDeliveryOptimizationObservation {
            context: fixture_context(
                EspSourceKind::DeliveryOptimization,
                "do-live",
                "do-finish",
                "2026-07-15T08:34:00Z",
            ),
            kind: EspDeliveryOptimizationEventKind::DownloadCompleted,
            content_id: Some("content-a".to_string()),
            app_id: Some("app-a".to_string()),
            http_bytes: None,
            lan_bytes: None,
            cache_host_bytes: None,
        }),
    ]);
    let snapshot = reducer.snapshot();
    let profile = snapshot.profile.as_ref().unwrap();
    assert_eq!(
        profile
            .profile_download_time
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T08:30:00Z")
    );
    assert_eq!(profile.join_mode, Some(EspJoinMode::HybridEntra));
    assert_eq!(profile.odj_applied, Some(true));
    assert_eq!(snapshot.registration_events[0].event_id, 306);
    assert_eq!(snapshot.registration_events[0].record_id, Some(9001));
    let delivery = snapshot.delivery_optimization.as_ref().unwrap();
    assert_eq!(delivery.download_http_bytes, 1000);
    assert_eq!(delivery.download_lan_bytes, 250);
    assert_eq!(delivery.peer_share_percent, Some(250.0 / 1000.0 * 100.0));
    assert_eq!(
        delivery.connected_cache_share_percent,
        Some(100.0 / 1000.0 * 100.0)
    );
    assert_eq!(
        delivery.transfers[0].transfer_id,
        "transfer|do-live|do-start|0"
    );
}

#[test]
fn timeline_preserves_repeated_identical_retries_with_source_record_and_ordinal_ids() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        ime_record("ime-live", "same-retry-record", "2026-07-15T12:00:00Z"),
        ime_record("ime-live", "same-retry-record", "2026-07-15T12:00:00Z"),
    ]);
    let activity = reducer.snapshot().activity;

    assert_eq!(activity.len(), 2);
    assert_eq!(
        activity[0].entry_id,
        "timeline|ime-live|same-retry-record|0"
    );
    assert_eq!(
        activity[1].entry_id,
        "timeline|ime-live|same-retry-record|1"
    );
    assert_eq!(
        activity[0].timestamp.normalized_utc,
        activity[1].timestamp.normalized_utc
    );
    assert_eq!(activity[0].title, activity[1].title);
    assert_eq!(activity[0].status, activity[1].status);
    assert_eq!(
        activity[0].evidence,
        vec![EspEvidenceRef {
            evidence_id: "same-retry-record".to_string(),
            source_artifact_id: "ime-live".to_string()
        }]
    );
}

#[test]
fn timeline_repeated_collisions_keep_source_order_past_single_digit_ordinals() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    for _ in 0..12 {
        reducer.ingest(ime_record(
            "ime-live",
            "same-retry-record",
            "2026-07-15T12:00:00Z",
        ));
    }

    let entry_ids = reducer
        .snapshot()
        .activity
        .into_iter()
        .map(|entry| entry.entry_id)
        .collect::<Vec<_>>();
    assert_eq!(
        entry_ids,
        (0..12)
            .map(|occurrence| format!("timeline|ime-live|same-retry-record|{occurrence}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn reducer_retention_evicts_oldest_stream_records_without_renumbering_occurrences() {
    let mut reducer = EspDiagnosticsReducer::with_retention_limits(
        "2026-07-15T18:00:00Z".to_string(),
        3,
        usize::MAX,
    );
    for _ in 0..4 {
        reducer.ingest(ime_record("ime-live", "retry", "2026-07-15T12:00:00Z"));
    }

    let snapshot = reducer.snapshot();
    let retained_ids = snapshot
        .raw_evidence
        .iter()
        .map(|record| record.evidence[0].evidence_id.as_str())
        .collect::<Vec<_>>();
    let workload_entry_ids = snapshot
        .activity
        .iter()
        .filter(|entry| entry.kind == EspTimelineKind::Workload)
        .map(|entry| entry.entry_id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(retained_ids, vec!["retry", "retry", "retry"]);
    assert_eq!(
        workload_entry_ids,
        vec![
            "timeline|ime-live|retry|1",
            "timeline|ime-live|retry|2",
            "timeline|ime-live|retry|3",
        ]
    );
    let retention = snapshot
        .coverage
        .iter()
        .find(|coverage| coverage.artifact_id == "session.evidence-retention")
        .expect("discarded history must be explicit coverage");
    assert_eq!(retention.status, EspArtifactStatus::ParseFailed);
    assert!(retention
        .detail
        .as_deref()
        .unwrap()
        .contains("1 older or oversized record"));
}

#[test]
fn reducer_retention_releases_occurrence_history_after_a_key_is_fully_evicted() {
    let mut reducer = EspDiagnosticsReducer::with_retention_limits(
        "2026-07-15T18:00:00Z".to_string(),
        1,
        usize::MAX,
    );
    reducer.ingest(ime_record(
        "ime-live",
        "reused-after-eviction",
        "2026-07-15T12:00:00Z",
    ));
    reducer.ingest(ime_record(
        "ime-live",
        "intervening-record",
        "2026-07-15T12:00:01Z",
    ));
    reducer.ingest(ime_record(
        "ime-live",
        "reused-after-eviction",
        "2026-07-15T12:00:02Z",
    ));

    let snapshot = reducer.snapshot();
    assert_eq!(snapshot.activity.len(), 2, "record plus retention coverage");
    assert_eq!(
        snapshot
            .activity
            .iter()
            .find(|entry| entry.kind == EspTimelineKind::Workload)
            .unwrap()
            .entry_id,
        "timeline|ime-live|reused-after-eviction|0"
    );
}

#[test]
fn reducer_retention_bounds_serialized_bytes_and_preserves_rare_profile_state() {
    let mut byte_bounded =
        EspDiagnosticsReducer::with_retention_limits("2026-07-15T18:00:00Z".to_string(), 10, 1);
    byte_bounded.ingest(ime_record("ime-live", "oversized", "2026-07-15T12:00:00Z"));
    let byte_snapshot = byte_bounded.snapshot();
    assert!(byte_snapshot.raw_evidence.is_empty());
    assert!(byte_snapshot.coverage.iter().any(|coverage| {
        coverage.artifact_id == "session.evidence-retention"
            && coverage
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("serialized bytes"))
    }));

    let mut record_bounded = EspDiagnosticsReducer::with_retention_limits(
        "2026-07-15T18:00:00Z".to_string(),
        3,
        usize::MAX,
    );
    record_bounded.ingest(registry_record(
        "profile",
        "profile-name",
        r"SOFTWARE\Microsoft\Provisioning\Diagnostics\AutoPilot",
        "DeploymentProfileName",
        EspObservationValue::Text("Contoso profile".to_string()),
        "2026-07-15T11:59:00Z",
    ));
    for index in 0..3 {
        record_bounded.ingest(ime_record(
            "ime-live",
            &format!("noise-{index}"),
            "2026-07-15T12:00:00Z",
        ));
    }
    let record_snapshot = record_bounded.snapshot();
    assert_eq!(record_snapshot.scenario, EspScenario::AutopilotV1);
    assert_eq!(
        record_snapshot
            .profile
            .as_ref()
            .and_then(|profile| profile.profile_name.as_deref()),
        Some("Contoso profile")
    );
}

#[test]
fn reducer_keeps_ids_source_local_when_unrelated_provider_order_changes() {
    let target = registry_record(
        "profile-provider",
        "profile-name",
        r"SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot",
        "DeploymentProfileName",
        EspObservationValue::Text("Contoso profile".to_string()),
        "2026-07-15T12:00:00Z",
    );
    let noise = ime_record("unrelated-ime-provider", "noise", "2026-07-15T12:00:01Z");

    let mut target_first = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    target_first.ingest(target.clone());
    target_first.ingest(noise.clone());

    let mut target_last = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    target_last.ingest(noise);
    target_last.ingest(target);

    let first = target_first.snapshot();
    let last = target_last.snapshot();
    assert_eq!(first.raw_evidence.len(), 2);
    assert_eq!(last.raw_evidence.len(), 2);

    let target_id = |snapshot: &EspDiagnosticsSnapshot| {
        snapshot
            .raw_evidence
            .iter()
            .find(|record| record.evidence[0].evidence_id == "profile-name")
            .expect("target profile evidence")
            .record_id
            .clone()
    };
    assert_eq!(target_id(&first), target_id(&last));
    assert_eq!(target_id(&first), "raw|profile-provider|profile-name|0");
}

#[test]
fn reducer_mixed_identified_and_normal_ingestion_never_reuses_occurrence() {
    let record = ime_record(
        "mixed-ime-provider",
        "same-evidence",
        "2026-07-15T12:00:00Z",
    );
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_identified(EspIdentifiedEvidenceRecord::with_occurrence(
        record.clone(),
        0,
    ));
    reducer.ingest(record);

    assert_eq!(
        reducer
            .snapshot()
            .raw_evidence
            .into_iter()
            .map(|record| record.record_id)
            .collect::<Vec<_>>(),
        vec![
            "raw|mixed-ime-provider|same-evidence|0",
            "raw|mixed-ime-provider|same-evidence|1",
        ]
    );
}

#[test]
fn reducer_reverse_mixed_ingestion_deduplicates_an_already_accepted_identity() {
    let record = ime_record(
        "reverse-mixed-ime-provider",
        "same-evidence",
        "2026-07-15T12:00:00Z",
    );
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest(record.clone());
    reducer.ingest_identified(EspIdentifiedEvidenceRecord::with_occurrence(record, 0));

    assert_eq!(
        reducer
            .snapshot()
            .raw_evidence
            .into_iter()
            .map(|record| record.record_id)
            .collect::<Vec<_>>(),
        vec!["raw|reverse-mixed-ime-provider|same-evidence|0"]
    );
}

#[test]
fn reducer_repeated_identified_replay_is_idempotent_and_advances_after_high_watermark() {
    let record = ime_record(
        "replayed-ime-provider",
        "same-evidence",
        "2026-07-15T12:00:00Z",
    );
    let identified = EspIdentifiedEvidenceRecord::with_occurrence(record.clone(), 4);
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_identified(identified.clone());
    reducer.ingest_identified(identified);
    reducer.ingest(record);

    assert_eq!(
        reducer
            .snapshot()
            .raw_evidence
            .into_iter()
            .map(|record| record.record_id)
            .collect::<Vec<_>>(),
        vec![
            "raw|replayed-ime-provider|same-evidence|4",
            "raw|replayed-ime-provider|same-evidence|5",
        ]
    );
}

#[test]
fn reducer_identified_watermark_is_monotonic_across_order_and_repeats() {
    let retained_ids = |ordinals: &[usize]| {
        let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
        for (index, ordinal) in ordinals.iter().copied().enumerate() {
            reducer.ingest_identified(EspIdentifiedEvidenceRecord::with_occurrence(
                ime_record(
                    "watermark-provider",
                    &format!("identified-{index}"),
                    "2026-07-15T12:00:00Z",
                ),
                ordinal,
            ));
        }
        reducer.ingest(ime_record(
            "watermark-provider",
            "normal-after-identified",
            "2026-07-15T12:00:01Z",
        ));
        reducer
            .snapshot()
            .raw_evidence
            .into_iter()
            .map(|record| record.record_id)
            .collect::<Vec<_>>()
    };

    assert_eq!(
        retained_ids(&[5, 2, 5]),
        vec![
            "raw|watermark-provider|identified-0|5",
            "raw|watermark-provider|identified-1|2",
            "raw|watermark-provider|identified-2|5",
            "raw|watermark-provider|normal-after-identified|6",
        ]
    );
    assert_eq!(
        retained_ids(&[2, 5, 2]),
        vec![
            "raw|watermark-provider|identified-0|2",
            "raw|watermark-provider|identified-1|5",
            "raw|watermark-provider|identified-2|2",
            "raw|watermark-provider|normal-after-identified|6",
        ]
    );
}

#[test]
fn reducer_retains_out_of_order_occurrences_for_the_same_evidence() {
    let record = ime_record(
        "out-of-order-provider",
        "same-evidence",
        "2026-07-15T12:00:00Z",
    );
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_identified(EspIdentifiedEvidenceRecord::with_occurrence(
        record.clone(),
        5,
    ));
    reducer.ingest_identified(EspIdentifiedEvidenceRecord::with_occurrence(record, 2));
    reducer.ingest(ime_record(
        "out-of-order-provider",
        "normal-after-out-of-order",
        "2026-07-15T12:00:01Z",
    ));

    assert_eq!(
        reducer
            .snapshot()
            .raw_evidence
            .into_iter()
            .map(|record| record.record_id)
            .collect::<Vec<_>>(),
        vec![
            "raw|out-of-order-provider|same-evidence|5",
            "raw|out-of-order-provider|same-evidence|2",
            "raw|out-of-order-provider|normal-after-out-of-order|6",
        ]
    );
}

#[test]
fn reducer_identified_max_occurrence_exhausts_source_without_reuse() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_identified(EspIdentifiedEvidenceRecord::with_occurrence(
        ime_record(
            "overflow-provider",
            "identified-max",
            "2026-07-15T12:00:00Z",
        ),
        usize::MAX,
    ));
    reducer.ingest(ime_record(
        "overflow-provider",
        "normal-after-max",
        "2026-07-15T12:00:01Z",
    ));

    let snapshot = reducer.snapshot();
    assert_eq!(snapshot.raw_evidence.len(), 1);
    assert_eq!(
        snapshot.raw_evidence[0].record_id,
        format!("raw|overflow-provider|identified-max|{}", usize::MAX)
    );
    let coverage = snapshot
        .coverage
        .iter()
        .find(|coverage| coverage.artifact_id == "session.evidence-identity-limit")
        .expect("identity overflow is disclosed");
    assert_eq!(coverage.status, EspArtifactStatus::ParseFailed);
    assert!(coverage
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("occurrence-overflow")));
}

#[test]
fn reducer_identified_sources_respect_allocator_cap_with_explicit_coverage() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    for index in 0..=MAX_EVIDENCE_IDENTITY_SOURCES {
        reducer.ingest_identified(EspIdentifiedEvidenceRecord::with_occurrence(
            registry_record(
                &format!("identified-source-{index}"),
                "identified-cap-record",
                r"SOFTWARE\Contoso\IdentityCap",
                "IgnoredIdentityCapValue",
                EspObservationValue::Integer(index as i64),
                "2026-07-15T12:00:00Z",
            ),
            0,
        ));
    }

    let snapshot = reducer.snapshot();
    assert_eq!(snapshot.raw_evidence.len(), MAX_EVIDENCE_IDENTITY_SOURCES);
    let coverage = snapshot
        .coverage
        .iter()
        .find(|coverage| coverage.artifact_id == "session.evidence-identity-limit")
        .expect("identified source cap is disclosed");
    assert_eq!(coverage.status, EspArtifactStatus::ParseFailed);
    assert!(coverage
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("source-limit")));
}

#[test]
fn evidence_identity_allocator_bounds_sources_and_keeps_existing_source_counters() {
    let mut allocator = EspEvidenceIdentityAllocator::with_source_limit(2);

    let first = allocator
        .try_identify(ime_record("source-a", "first", "2026-07-15T12:00:00Z"))
        .expect("first source is tracked");
    allocator
        .try_identify(ime_record("source-b", "second", "2026-07-15T12:00:01Z"))
        .expect("second source is tracked");
    assert!(allocator
        .try_identify(ime_record("source-c", "third", "2026-07-15T12:00:02Z"))
        .is_err());

    let next_existing = allocator
        .try_identify(ime_record("source-a", "fourth", "2026-07-15T12:00:03Z"))
        .expect("an existing source remains usable at the bound");
    assert_eq!(allocator.tracked_source_count(), 2);
    assert_eq!(first.occurrence_ordinal(), 0);
    assert_eq!(next_existing.occurrence_ordinal(), 1);
}

#[test]
fn evidence_identity_allocator_bounds_the_exact_identity_ledger() {
    let mut allocator = EspEvidenceIdentityAllocator::with_limits(2, 2);

    allocator
        .try_identify(ime_record("source-a", "first", "2026-07-15T12:00:00Z"))
        .expect("first identity is tracked");
    allocator
        .try_identify(ime_record("source-a", "second", "2026-07-15T12:00:01Z"))
        .expect("second identity is tracked");
    assert!(matches!(
        allocator.try_identify(ime_record("source-a", "third", "2026-07-15T12:00:02Z")),
        Err(EspEvidenceIdentityError::IdentityLimit)
    ));
    assert_eq!(allocator.tracked_source_count(), 1);
    assert_eq!(allocator.tracked_identity_count(), 2);
}

#[test]
fn reducer_merges_typed_identity_rejections_without_synthetic_ingestion() {
    let mut rejections = EspEvidenceIdentityRejectionCounts::default();
    rejections.record(EspEvidenceIdentityError::SourceLimit);
    rejections.record(EspEvidenceIdentityError::IdentityLimit);
    rejections.record(EspEvidenceIdentityError::IdentityLimit);

    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.merge_identity_rejections(rejections);
    let snapshot = reducer.snapshot();

    assert!(snapshot.raw_evidence.is_empty());
    let coverage = snapshot
        .coverage
        .iter()
        .find(|coverage| coverage.artifact_id == "session.evidence-identity-limit")
        .expect("merged identity rejections are disclosed");
    assert_eq!(coverage.status, EspArtifactStatus::ParseFailed);
    let detail = coverage.detail.as_deref().expect("identity limit detail");
    assert!(detail.contains("discarded 3 records"), "{detail}");
    assert!(detail.contains("1 source-limit"), "{detail}");
    assert!(detail.contains("2 identity-limit"), "{detail}");
}

#[test]
fn timeline_snapshot_is_deterministic_for_the_same_ordered_evidence() {
    let records = vec![
        event_record(
            "events",
            "event-1920",
            1920,
            10,
            "2026-07-15T12:01:00Z",
            "Installation started",
        ),
        event_record(
            "events",
            "event-1905",
            1905,
            9,
            "2026-07-15T12:00:00Z",
            "Download started",
        ),
        ime_record("ime-live", "retry", "2026-07-15T12:00:30Z"),
    ];
    let mut first = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    first.ingest_all(records.clone());
    let mut second = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    second.ingest_all(records);

    assert_eq!(
        serde_json::to_value(first.snapshot()).unwrap(),
        serde_json::to_value(second.snapshot()).unwrap()
    );
    assert_eq!(
        first
            .snapshot()
            .activity
            .iter()
            .map(|entry| entry.entry_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "timeline|events|event-1905|0",
            "timeline|ime-live|retry|0",
            "timeline|events|event-1920|0"
        ]
    );
}

#[test]
fn timeline_identity_and_equal_timestamp_order_ignore_unrelated_ingestion_order() {
    let event = event_record(
        "events",
        "event-1905",
        1905,
        9,
        "2026-07-15T12:00:00Z",
        "Download started",
    );
    let ime = ime_record("ime-live", "retry", "2026-07-15T12:00:00Z");

    let mut forward = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    forward.ingest_all(vec![event.clone(), ime.clone()]);
    let mut reversed = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reversed.ingest_all(vec![ime, event]);

    let forward_ids = forward
        .snapshot()
        .activity
        .into_iter()
        .map(|entry| entry.entry_id)
        .collect::<Vec<_>>();
    let reversed_ids = reversed
        .snapshot()
        .activity
        .into_iter()
        .map(|entry| entry.entry_id)
        .collect::<Vec<_>>();

    assert_eq!(
        forward_ids,
        vec!["timeline|events|event-1905|0", "timeline|ime-live|retry|0",]
    );
    assert_eq!(reversed_ids, forward_ids);
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EdgeCases {
    classic_registry: Vec<ParityRegistryCase>,
    classic_json: Vec<ParityJsonCase>,
    v2_page_settings: Vec<ParityJsonCase>,
    node_cache: Vec<ParityNodeCase>,
    malformed_json: Vec<ParityJsonCase>,
    v2_states: Vec<ParityStatusCase>,
    coverage: Vec<ParityCoverageCase>,
    events: Vec<ParityEventCase>,
    system_facts: Vec<ParitySystemFactCase>,
    hardware_hash: Vec<ParityJsonCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParityRegistryCase {
    source_artifact_id: String,
    evidence_id: String,
    key: String,
    value_name: String,
    value: EspObservationValue,
    source_timestamp: String,
    sensitivity: Option<EspSensitivity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParityJsonCase {
    source_artifact_id: String,
    evidence_id: String,
    document_type: String,
    json_pointer: String,
    value: EspObservationValue,
    source_timestamp: String,
    parse_state: Option<EspParseState>,
    access_state: Option<EspSourceAccessState>,
    sensitivity: Option<EspSensitivity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParityNodeCase {
    index: u64,
    node_uri: String,
    expected_value: String,
    source_artifact_id: String,
    node_evidence_id: String,
    expected_evidence_id: String,
    source_timestamp: String,
    sensitivity: EspSensitivity,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParityStatusCase {
    index: usize,
    raw_identifier: String,
    raw: EspRawStatus,
    normalized: EspNormalizedStatus,
    source_timestamp: String,
    id_evidence_id: String,
    state_evidence_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParityCoverageCase {
    artifact_id: String,
    family: String,
    status: EspArtifactStatus,
    detail: String,
    observed_at_utc: String,
    source_artifact_id: String,
    evidence_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParityEventCase {
    event_id: u32,
    record_id: u64,
    source_artifact_id: String,
    evidence_id: String,
    channel: String,
    timestamp: String,
    message: String,
    normalized: EspNormalizedStatus,
    timeline_kind: EspTimelineKind,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParitySystemFactCase {
    source_artifact_id: String,
    evidence_id: String,
    fact: String,
    value: String,
    source_timestamp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphCases {
    local_workloads: Vec<GraphLocalWorkloadCase>,
    graph_names: Vec<GraphNameCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphLocalWorkloadCase {
    raw_identifier: String,
    raw_status: i64,
    evidence_id: String,
    timestamp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphNameCase {
    record_id: String,
    display_name: Option<String>,
    evidence_id: String,
    timestamp: String,
    remote_status: EspNormalizedStatus,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EquivalenceCases {
    cases: Vec<EquivalenceCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EquivalenceCase {
    name: String,
    live_source_artifact_id: String,
    captured_source_artifact_id: String,
    live_evidence_id: String,
    captured_evidence_id: String,
    profile_name: String,
    raw_identifier: String,
    raw_status: i64,
    timestamp: String,
}

fn edge_cases() -> EdgeCases {
    serde_json::from_str(include_str!("fixtures/esp/edge-cases.json"))
        .expect("edge-case fixture must be valid")
}

fn graph_cases() -> GraphCases {
    serde_json::from_str(include_str!("fixtures/esp/graph-cases.json"))
        .expect("Graph fixture must be valid")
}

fn equivalence_cases() -> EquivalenceCases {
    serde_json::from_str(include_str!("fixtures/esp/bundle-live-equivalence.json"))
        .expect("equivalence fixture must be valid")
}

fn parity_registry_record(case: &ParityRegistryCase) -> EspEvidenceRecord {
    let mut record = registry_record(
        &case.source_artifact_id,
        &case.evidence_id,
        &case.key,
        &case.value_name,
        case.value.clone(),
        &case.source_timestamp,
    );
    if let EspEvidenceRecord::Registry(observation) = &mut record {
        if let Some(sensitivity) = &case.sensitivity {
            observation.context.sensitivity = sensitivity.clone();
        }
    }
    record
}

fn parity_json_record(case: &ParityJsonCase) -> EspEvidenceRecord {
    let mut record = json_record(
        &case.source_artifact_id,
        &case.evidence_id,
        &case.document_type,
        &case.json_pointer,
        case.value.clone(),
        &case.source_timestamp,
    );
    if let EspEvidenceRecord::Json(observation) = &mut record {
        if let Some(parse_state) = &case.parse_state {
            observation.context.parse_state = parse_state.clone();
        }
        if let Some(access_state) = &case.access_state {
            observation.context.access_state = access_state.clone();
        }
        if let Some(sensitivity) = &case.sensitivity {
            observation.context.sensitivity = sensitivity.clone();
        }
    }
    record
}

fn parity_event_record(case: &ParityEventCase) -> EspEvidenceRecord {
    let mut record = event_record(
        &case.source_artifact_id,
        &case.evidence_id,
        case.event_id,
        case.record_id,
        &case.timestamp,
        &case.message,
    );
    if let EspEvidenceRecord::EventLog(observation) = &mut record {
        observation.channel = case.channel.clone();
        observation.context.provenance.event = Some(EspEventProvenance {
            channel: case.channel.clone(),
            event_id: case.event_id,
            record_id: Some(case.record_id),
            named_data: vec![],
        });
    }
    record
}

fn parity_system_record(case: &ParitySystemFactCase) -> EspEvidenceRecord {
    let fact = match case.fact.as_str() {
        "osVersion" => EspSystemFact::OsVersion(case.value.clone()),
        "osBuild" => EspSystemFact::OsBuild(case.value.clone()),
        "manufacturer" => EspSystemFact::Manufacturer(case.value.clone()),
        "model" => EspSystemFact::Model(case.value.clone()),
        "serialNumber" => EspSystemFact::SerialNumber(case.value.clone()),
        "tpmVersion" => EspSystemFact::TpmVersion(case.value.clone()),
        unexpected => panic!("unknown system fact {unexpected}"),
    };
    let mut context = fixture_context(
        EspSourceKind::System,
        &case.source_artifact_id,
        &case.evidence_id,
        &case.source_timestamp,
    );
    if matches!(fact, EspSystemFact::SerialNumber(_)) {
        context.sensitivity = EspSensitivity::Sensitive;
    }
    EspEvidenceRecord::System(EspSystemObservation { context, fact })
}

#[test]
fn reducer_parity_profile_enrollment_and_v2_page_settings_pin_raw_sources_and_sensitivity() {
    let cases = edge_cases();
    assert_eq!(
        cases.classic_registry.len(),
        15,
        "classic registry parity rows"
    );
    assert_eq!(cases.classic_json.len(), 3, "classic JSON parity rows");
    assert_eq!(
        cases.v2_page_settings.len(),
        5,
        "v2 page-setting parity rows"
    );

    let mut classic = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    classic.ingest_all(
        cases
            .classic_registry
            .iter()
            .map(parity_registry_record)
            .chain(cases.classic_json.iter().map(parity_json_record)),
    );
    let snapshot = classic.snapshot();
    let profile = snapshot.profile.as_ref().expect("classic profile");
    assert_eq!(snapshot.scenario, EspScenario::AutopilotV1);
    assert_eq!(profile.profile_name.as_deref(), Some("Corporate Autopilot"));
    assert_eq!(
        profile.correlation_id.as_deref(),
        Some("correlation-classic")
    );
    assert_eq!(profile.tenant_id.as_ref().unwrap().value, "tenant-classic");
    assert_eq!(
        profile.tenant_id.as_ref().unwrap().sensitivity,
        EspSensitivity::Sensitive
    );
    assert_eq!(profile.oobe_config.as_ref().unwrap().raw_mask, 2046);
    assert!(oobe_flags(profile.oobe_config.as_ref().unwrap())
        .iter()
        .all(|value| *value));
    assert_eq!(profile.join_mode, Some(EspJoinMode::HybridEntra));
    assert_eq!(profile.odj_applied, Some(true));
    assert_eq!(profile.skip_domain_connectivity_check, Some(true));
    assert_eq!(
        profile
            .profile_download_time
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T08:30:00Z")
    );
    assert_eq!(
        snapshot.identity.entdm_id.as_ref().unwrap().value,
        "entdm-classic"
    );
    assert_eq!(
        snapshot
            .identity
            .user_principal_name
            .as_ref()
            .unwrap()
            .sensitivity,
        EspSensitivity::Sensitive
    );
    let enrollment = &snapshot.enrollments[0];
    assert_eq!(
        enrollment.enrollment_id,
        "11111111-1111-1111-1111-111111111111"
    );
    assert_eq!(enrollment.provider_id.as_deref(), Some("MS DM Server"));
    assert_eq!(enrollment.settings.device_esp_enabled, Some(true));
    assert_eq!(enrollment.settings.user_esp_enabled, Some(true));
    assert_eq!(enrollment.settings.timeout_seconds, Some(3600));
    assert_eq!(enrollment.settings.blocking, Some(true));
    assert_eq!(enrollment.settings.allow_reset, Some(true));
    assert_eq!(enrollment.settings.allow_retry, Some(true));
    assert_eq!(enrollment.settings.continue_anyway, Some(false));
    assert_eq!(
        snapshot.raw_evidence[0].record_id,
        "raw|profile-registry|profile-name|0"
    );
    assert_eq!(
        snapshot.raw_evidence[0].raw_value,
        EspObservationValue::Text("Corporate Autopilot".to_string())
    );
    assert_eq!(
        snapshot.raw_evidence[0]
            .source_timestamp
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T08:00:00Z")
    );
    assert_eq!(
        snapshot.raw_evidence[2].sensitivity,
        EspSensitivity::Sensitive
    );
    assert_eq!(
        snapshot.raw_evidence[2].provenance.source_artifact_id,
        "profile-registry"
    );

    let mut v2 = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    v2.ingest(registry_record(
        "autopilot-settings",
        "v2-hint",
        r"SOFTWARE\Microsoft\Provisioning\AutopilotSettings",
        "AutopilotDevicePrepHint",
        EspObservationValue::Text("enabled".to_string()),
        "2026-07-15T09:00:00Z",
    ));
    v2.ingest_all(cases.v2_page_settings.iter().map(parity_json_record));
    let v2_snapshot = v2.snapshot();
    let settings = v2_snapshot
        .profile
        .as_ref()
        .unwrap()
        .device_preparation
        .as_ref()
        .unwrap();
    assert_eq!(
        v2_snapshot.scenario,
        EspScenario::AutopilotDevicePreparationV2
    );
    assert_eq!(settings.agent_download_timeout_seconds, Some(1800));
    assert_eq!(settings.page_timeout_seconds, Some(3600));
    assert_eq!(settings.allow_skip_on_failure, Some(true));
    assert_eq!(settings.allow_diagnostics, Some(true));
    assert_eq!(settings.script_ids, vec!["script-v2"]);
    assert_eq!(
        v2_snapshot.raw_evidence[1].record_id,
        "raw|page-settings|page-agent-timeout|0"
    );
}

#[test]
fn reducer_parity_nodecache_malformed_denied_hardware_and_hash_exclusion_are_lossless() {
    let cases = edge_cases();
    assert_eq!(cases.node_cache.len(), 3, "NodeCache keys 2, 10, and 42");
    assert_eq!(
        cases.malformed_json.len(),
        3,
        "three malformed JSON families"
    );
    assert_eq!(cases.coverage.len(), 1, "permission-denied coverage row");
    assert_eq!(cases.system_facts.len(), 6, "safe hardware facts");
    assert_eq!(cases.hardware_hash.len(), 1, "raw hash exclusion probe");

    let mut records = Vec::new();
    for node in &cases.node_cache {
        let key = format!(
            r"SOFTWARE\Microsoft\Provisioning\NodeCache\CSP\Device\MS DM Server\Nodes\{}",
            node.index
        );
        let mark_sensitive = |mut record: EspEvidenceRecord| {
            if let EspEvidenceRecord::Registry(observation) = &mut record {
                observation.context.sensitivity = node.sensitivity.clone();
            }
            record
        };
        records.push(mark_sensitive(registry_record(
            &node.source_artifact_id,
            &node.node_evidence_id,
            &key,
            "NodeUri",
            EspObservationValue::Text(node.node_uri.clone()),
            &node.source_timestamp,
        )));
        records.push(mark_sensitive(registry_record(
            &node.source_artifact_id,
            &node.expected_evidence_id,
            &key,
            "ExpectedValue",
            EspObservationValue::Text(node.expected_value.clone()),
            &node.source_timestamp,
        )));
    }
    records.extend(cases.malformed_json.iter().map(parity_json_record));
    records.extend(cases.system_facts.iter().map(parity_system_record));
    records.extend(cases.hardware_hash.iter().map(parity_json_record));
    records.extend(cases.coverage.iter().map(|case| {
        EspEvidenceRecord::Coverage(EspArtifactCoverage {
            artifact_id: case.artifact_id.clone(),
            family: case.family.clone(),
            status: case.status.clone(),
            detail: Some(case.detail.clone()),
            observed_at_utc: case.observed_at_utc.clone(),
            evidence: vec![EspEvidenceRef {
                evidence_id: case.evidence_id.clone(),
                source_artifact_id: case.source_artifact_id.clone(),
            }],
        })
    }));
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(records);
    let snapshot = reducer.snapshot();

    assert_eq!(
        snapshot
            .node_cache
            .iter()
            .map(|entry| entry.index)
            .collect::<Vec<_>>(),
        vec![2, 10, 42]
    );
    assert_eq!(
        snapshot.node_cache[0].node_uri,
        "./Vendor/MSFT/Policy/Config/Node2"
    );
    assert_eq!(
        snapshot.node_cache[1].expected_value.as_deref(),
        Some("expected-10")
    );
    assert_eq!(
        snapshot.node_cache[2].evidence[1].evidence_id,
        "node-42-expected"
    );
    assert!(snapshot
        .node_cache
        .iter()
        .all(|entry| entry.sensitivity == EspSensitivity::Sensitive));
    let node_42_raw = snapshot
        .raw_evidence
        .iter()
        .find(|record| record.evidence[0].evidence_id == "node-42-expected")
        .unwrap();
    assert_eq!(
        node_42_raw.record_id,
        "raw|node-cache-registry|node-42-expected|0"
    );
    assert_eq!(
        node_42_raw.raw_value,
        EspObservationValue::Text("expected-42".to_string())
    );
    assert_eq!(
        node_42_raw
            .source_timestamp
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T10:00:42Z")
    );
    assert_eq!(node_42_raw.sensitivity, EspSensitivity::Sensitive);
    let malformed = snapshot
        .raw_evidence
        .iter()
        .filter(|record| record.parse_state == EspParseState::Malformed)
        .collect::<Vec<_>>();
    assert_eq!(malformed.len(), 3);
    assert_eq!(
        malformed[0].raw_value,
        EspObservationValue::Text("{bad-page-settings".to_string())
    );
    assert_eq!(
        malformed[0].record_id,
        "raw|malformed-json|malformed-page-settings|0"
    );
    assert_eq!(malformed[1].provenance.source_artifact_id, "malformed-json");
    assert!(
        snapshot.workloads.is_empty(),
        "malformed progress must not fabricate success"
    );
    assert_eq!(
        snapshot.coverage[0].status,
        EspArtifactStatus::PermissionDenied
    );
    assert_eq!(
        snapshot.coverage[0].evidence[0].source_artifact_id,
        "protected-registry"
    );
    assert_eq!(snapshot.coverage[0].artifact_id, "protected-esp-registry");
    assert_eq!(snapshot.coverage[0].observed_at_utc, "2026-07-15T12:00:00Z");
    let coverage_activity = snapshot
        .activity
        .iter()
        .find(|entry| entry.evidence[0].evidence_id == "coverage-denied")
        .unwrap();
    assert_eq!(
        coverage_activity.entry_id,
        "timeline|protected-registry|coverage-denied|0"
    );
    assert_eq!(
        coverage_activity.timestamp.normalized_utc.as_deref(),
        Some("2026-07-15T12:00:00Z")
    );
    let hardware = snapshot.hardware.as_ref().unwrap();
    assert_eq!(hardware.os_version.as_deref(), Some("10.0.26100"));
    assert_eq!(hardware.os_build.as_deref(), Some("26100.4652"));
    assert_eq!(hardware.manufacturer.as_deref(), Some("Contoso"));
    assert_eq!(hardware.model.as_deref(), Some("Model 42"));
    assert_eq!(
        hardware.serial_number.as_ref().unwrap().sensitivity,
        EspSensitivity::Sensitive
    );
    assert_eq!(hardware.tpm_version.as_deref(), Some("2.0"));
    let serial_raw = snapshot
        .raw_evidence
        .iter()
        .find(|record| record.evidence[0].evidence_id == "serial")
        .unwrap();
    assert_eq!(serial_raw.record_id, "raw|system-facts|serial|0");
    assert_eq!(serial_raw.sensitivity, EspSensitivity::Sensitive);
    assert_eq!(
        serial_raw
            .source_timestamp
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T14:00:04Z")
    );
    let serialized = serde_json::to_string(&snapshot).unwrap();
    assert!(!serialized.contains("RAW-HARDWARE-HASH-MUST-NOT-APPEAR"));
    assert!(!serialized.to_ascii_lowercase().contains("hardwarehash"));
}

#[test]
fn reducer_drops_hardware_hash_material_hidden_in_generic_registry_value_data() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest(registry_record(
        "captured-registry",
        "generic-secret-payload",
        r"SOFTWARE\Microsoft\Provisioning\Diagnostics",
        "Payload",
        EspObservationValue::Text("DeviceHardwareData=BASE64-REDUCER-SECRET".to_string()),
        "2026-07-15T17:00:00Z",
    ));
    reducer.ingest(registry_record(
        "captured-registry",
        "safe-adjacent-value",
        r"SOFTWARE\Microsoft\Provisioning\Diagnostics",
        "SafeSetting",
        EspObservationValue::Text("retained-safe-value".to_string()),
        "2026-07-15T17:00:01Z",
    ));

    let snapshot = reducer.snapshot();
    let serialized = serde_json::to_string(&snapshot).expect("serialize reducer snapshot");

    assert!(serialized.contains("retained-safe-value"));
    assert!(!serialized.contains("BASE64-REDUCER-SECRET"));
    assert!(!serialized
        .to_ascii_lowercase()
        .contains("devicehardwaredata"));
    assert!(snapshot
        .raw_evidence
        .iter()
        .all(|record| { record.evidence[0].evidence_id != "generic-secret-payload" }));
}

#[test]
fn reducer_parity_all_v2_states_pin_raw_normalized_sources_times_and_stable_ids() {
    let cases = edge_cases();
    assert_eq!(
        cases.v2_states.len(),
        9,
        "eight known states plus one unknown"
    );
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest(registry_record(
        "autopilot-settings",
        "v2-hint",
        r"SOFTWARE\Microsoft\Provisioning\AutopilotSettings",
        "AutopilotDevicePrepHint",
        EspObservationValue::Text("enabled".to_string()),
        "2026-07-15T09:00:00Z",
    ));
    for case in &cases.v2_states {
        reducer.ingest(json_record(
            "v2-progress",
            &case.id_evidence_id,
            "ProvisioningProgress",
            &format!("/Workloads/{}/WorkloadId", case.index),
            EspObservationValue::Text(case.raw_identifier.clone()),
            &case.source_timestamp,
        ));
        reducer.ingest(json_record(
            "v2-progress",
            &case.state_evidence_id,
            "ProvisioningProgress",
            &format!("/Workloads/{}/WorkloadState", case.index),
            match &case.raw {
                EspRawStatus::Number(value) => EspObservationValue::Integer(*value),
                EspRawStatus::Text(value) => EspObservationValue::Text(value.clone()),
                EspRawStatus::Other(value) => EspObservationValue::Text(value.to_string()),
            },
            &case.source_timestamp,
        ));
    }
    let snapshot = reducer.snapshot();
    assert_eq!(snapshot.workloads.len(), 9);
    for (position, case) in cases.v2_states.iter().enumerate() {
        let workload = &snapshot.workloads[position];
        assert_eq!(workload.raw_identifier, case.raw_identifier);
        assert_eq!(workload.status.raw, case.raw);
        assert_eq!(workload.status.normalized, case.normalized);
        assert_eq!(
            workload
                .timestamps
                .last_updated
                .as_ref()
                .unwrap()
                .normalized_utc
                .as_deref(),
            Some(case.source_timestamp.as_str())
        );
        assert_eq!(workload.evidence[0].source_artifact_id, "v2-progress");
        assert_eq!(workload.evidence[1].evidence_id, case.state_evidence_id);
        assert_eq!(
            workload.workload_id,
            format!(
                "workload|v2-progress|devicePreparationV2:device:{}:{}|0",
                case.index, case.raw_identifier
            )
        );
    }
    let unknown = snapshot.workloads.last().unwrap();
    assert_eq!(
        unknown.status.raw,
        EspRawStatus::Text("FutureState".to_string())
    );
    assert_eq!(unknown.status.normalized, EspNormalizedStatus::Unknown);
    let first_activity = snapshot
        .activity
        .iter()
        .find(|entry| entry.evidence[0].evidence_id == "v2-state-0")
        .unwrap();
    assert_eq!(first_activity.entry_id, "timeline|v2-progress|v2-state-0|0");
    assert_eq!(
        first_activity.status.as_ref().unwrap().raw,
        EspRawStatus::Number(0)
    );
    assert_eq!(
        first_activity.timestamp.normalized_utc.as_deref(),
        Some("2026-07-15T11:00:00Z")
    );
    assert!(!matches!(snapshot.phase, EspPhase::Completed));
}

#[test]
fn reducer_parity_every_required_event_id_pins_raw_normalized_source_time_and_entry_id() {
    let cases = edge_cases();
    assert_eq!(
        cases
            .events
            .iter()
            .map(|case| case.event_id)
            .collect::<Vec<_>>(),
        vec![72, 100, 101, 107, 109, 110, 111, 304, 306, 1905, 1906, 1920, 1922, 1924]
    );
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(cases.events.iter().map(parity_event_record));
    let snapshot = reducer.snapshot();
    assert_eq!(snapshot.activity.len(), 14);
    for case in &cases.events {
        let activity = snapshot
            .activity
            .iter()
            .find(|entry| entry.evidence[0].evidence_id == case.evidence_id)
            .unwrap();
        assert_eq!(
            activity.entry_id,
            format!(
                "timeline|{}|{}|0",
                case.source_artifact_id, case.evidence_id
            )
        );
        assert_eq!(activity.kind, case.timeline_kind);
        assert_eq!(activity.timestamp.raw_text, case.timestamp);
        assert_eq!(
            activity.timestamp.normalized_utc.as_deref(),
            Some(case.timestamp.as_str())
        );
        assert_eq!(
            activity.status.as_ref().unwrap().raw,
            EspRawStatus::Text(case.message.clone())
        );
        assert_eq!(
            activity.status.as_ref().unwrap().normalized,
            case.normalized
        );
        assert_eq!(
            activity.evidence[0].source_artifact_id,
            case.source_artifact_id
        );
        let raw = snapshot
            .raw_evidence
            .iter()
            .find(|record| record.evidence[0].evidence_id == case.evidence_id)
            .unwrap();
        assert_eq!(
            raw.record_id,
            format!("raw|{}|{}|0", case.source_artifact_id, case.evidence_id)
        );
        assert_eq!(
            raw.raw_value,
            EspObservationValue::Text(case.message.clone())
        );
        assert_eq!(
            raw.provenance.event.as_ref().unwrap().event_id,
            case.event_id
        );
    }
    assert!(snapshot
        .activity
        .iter()
        .any(|entry| entry.evidence[0].evidence_id == "event-304"));
    assert!(snapshot
        .activity
        .iter()
        .any(|entry| entry.evidence[0].evidence_id == "event-1924"));
    assert_eq!(
        snapshot
            .registration_events
            .iter()
            .map(|event| event.event_id)
            .collect::<Vec<_>>(),
        vec![101, 304, 306]
    );
}

#[test]
fn reducer_parity_partial_graph_names_never_replace_raw_ids_or_local_status() {
    let cases = graph_cases();
    assert_eq!(cases.local_workloads.len(), 3, "three local workloads");
    assert_eq!(cases.graph_names.len(), 2, "partial Graph coverage");
    let session_key = r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\Sidecar\2026-07-15T12:00:00Z";
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    for case in &cases.local_workloads {
        reducer.ingest(registry_record(
            "esp-workloads",
            &case.evidence_id,
            session_key,
            &format!("./Device/Vendor/MSFT/Win32App/{}", case.raw_identifier),
            EspObservationValue::Integer(case.raw_status),
            &case.timestamp,
        ));
    }
    for case in &cases.graph_names {
        reducer.ingest(EspEvidenceRecord::Graph(EspGraphObservation {
            context: fixture_context(
                EspSourceKind::Graph,
                "graph-apps",
                &case.evidence_id,
                &case.timestamp,
            ),
            section: EspGraphObservationSection::App,
            api_version: GraphApiVersion::V1_0,
            record_id: case.record_id.clone(),
            display_name: case.display_name.clone(),
            status: Some(status(
                EspRawStatus::Text("remote".to_string()),
                case.remote_status.clone(),
            )),
        }));
    }
    let snapshot = reducer.snapshot();
    assert_eq!(snapshot.workloads[0].raw_identifier, "app-a");
    assert_eq!(
        snapshot.workloads[0].display_name.as_deref(),
        Some("Contoso App A")
    );
    assert_eq!(snapshot.workloads[0].status.raw, EspRawStatus::Number(4));
    assert_eq!(
        snapshot.workloads[0].status.normalized,
        EspNormalizedStatus::Failed
    );
    assert_eq!(
        snapshot.workloads[0].evidence[0].source_artifact_id,
        "esp-workloads"
    );
    assert_eq!(
        snapshot.workloads[0].evidence[1],
        EspEvidenceRef {
            evidence_id: "graph-app-a".to_string(),
            source_artifact_id: "graph-apps".to_string()
        }
    );
    assert_eq!(snapshot.workloads[1].raw_identifier, "app-b");
    assert_eq!(snapshot.workloads[1].display_name, None);
    assert_eq!(snapshot.workloads[2].raw_identifier, "app-c");
    assert_eq!(snapshot.workloads[2].evidence.len(), 1);
    assert_eq!(
        snapshot.raw_evidence[0].record_id,
        "raw|esp-workloads|local-app-a|0"
    );
    assert_eq!(
        snapshot.raw_evidence[0].raw_value,
        EspObservationValue::Integer(4)
    );
    assert_eq!(
        snapshot.raw_evidence[0]
            .source_timestamp
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T15:00:00Z")
    );
    assert_eq!(
        snapshot.raw_evidence[3].record_id,
        "raw|graph-apps|graph-app-a|0"
    );
}

#[test]
fn reducer_parity_live_and_captured_equivalent_inputs_keep_equal_logic_and_source_specific_ids() {
    let cases = equivalence_cases();
    assert_eq!(cases.cases.len(), 1, "live/captured equivalence row");
    for case in cases.cases {
        let build = |source: &str, evidence: &str| {
            let session_key = r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\Sidecar\2026-07-15T12:00:00Z";
            let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
            reducer.ingest(registry_record(
                source,
                &format!("{evidence}-profile"),
                r"SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot",
                "DeploymentProfileName",
                EspObservationValue::Text(case.profile_name.clone()),
                "2026-07-15T08:00:00Z",
            ));
            reducer.ingest(registry_record(
                source,
                evidence,
                session_key,
                &format!("./Device/Vendor/MSFT/Win32App/{}", case.raw_identifier),
                EspObservationValue::Integer(case.raw_status),
                &case.timestamp,
            ));
            reducer.snapshot()
        };
        let live = build(&case.live_source_artifact_id, &case.live_evidence_id);
        let captured = build(
            &case.captured_source_artifact_id,
            &case.captured_evidence_id,
        );
        assert_eq!(live.scenario, captured.scenario, "{} scenario", case.name);
        assert_eq!(live.phase, captured.phase, "{} phase", case.name);
        assert_eq!(
            live.profile.as_ref().unwrap().profile_name,
            captured.profile.as_ref().unwrap().profile_name
        );
        assert_eq!(live.workloads[0].kind, captured.workloads[0].kind);
        assert_eq!(
            live.workloads[0].raw_identifier,
            captured.workloads[0].raw_identifier
        );
        assert_eq!(live.workloads[0].status, captured.workloads[0].status);
        assert_eq!(
            live.workloads[0].timestamps,
            captured.workloads[0].timestamps
        );
        assert_eq!(
            live.workloads[0].workload_id,
            "workload|live-registry|classic:device:2026-07-15T12:00:00Z:win32App:equivalent-app|0"
        );
        assert_eq!(captured.workloads[0].workload_id, "workload|captured-registry|classic:device:2026-07-15T12:00:00Z:win32App:equivalent-app|0");
        assert_eq!(
            live.raw_evidence[1].record_id,
            "raw|live-registry|live-workload|0"
        );
        assert_eq!(
            captured.raw_evidence[1].record_id,
            "raw|captured-registry|captured-workload|0"
        );
        assert_eq!(
            live.activity[0].evidence[0].source_artifact_id,
            "live-registry"
        );
        assert_eq!(
            captured.activity[0].evidence[0].source_artifact_id,
            "captured-registry"
        );
    }
}

#[test]
fn reducer_review_v2_retries_remain_distinct_and_current_state_is_chronological() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "autopilot-settings",
            "v2-hint",
            r"SOFTWARE\Microsoft\Provisioning\AutopilotSettings",
            "AutopilotDevicePrepHint",
            EspObservationValue::Text("enabled".to_string()),
            "2026-07-15T08:00:00Z",
        ),
        json_record(
            "v2-progress",
            "workload-a-id",
            "ProvisioningProgress",
            "/Workloads/0/WorkloadId",
            EspObservationValue::Text("workload-a".to_string()),
            "2026-07-15T10:00:00Z",
        ),
        json_record(
            "v2-progress",
            "workload-a-completed",
            "ProvisioningProgress",
            "/Workloads/0/WorkloadState",
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:00Z",
        ),
        json_record(
            "v2-progress",
            "workload-a-older-retry",
            "ProvisioningProgress",
            "/Workloads/0/WorkloadState",
            EspObservationValue::Integer(5),
            "2026-07-15T11:00:00Z",
        ),
        json_record(
            "v2-progress",
            "workload-b-id",
            "ProvisioningProgress",
            "/Workloads/1/WorkloadId",
            EspObservationValue::Text("workload-b".to_string()),
            "2026-07-15T10:05:00Z",
        ),
        json_record(
            "v2-progress",
            "workload-b-state",
            "ProvisioningProgress",
            "/Workloads/1/WorkloadState",
            EspObservationValue::Integer(0),
            "2026-07-15T10:06:00Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    let workload_a = snapshot
        .workloads
        .iter()
        .find(|workload| workload.raw_identifier == "workload-a")
        .unwrap();
    assert_eq!(workload_a.status.raw, EspRawStatus::Number(1));
    assert_eq!(workload_a.status.normalized, EspNormalizedStatus::Succeeded);
    assert_eq!(
        workload_a
            .timestamps
            .last_updated
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T12:00:00Z")
    );
    assert_eq!(
        snapshot
            .activity
            .iter()
            .filter(|entry| {
                matches!(
                    entry.evidence[0].evidence_id.as_str(),
                    "workload-a-completed" | "workload-a-older-retry" | "workload-b-state"
                )
            })
            .map(|entry| entry.evidence[0].evidence_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "workload-b-state",
            "workload-a-older-retry",
            "workload-a-completed"
        ]
    );
    assert_eq!(
        snapshot.sessions[0]
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "workload-a-id",
            "workload-a-completed",
            "workload-a-older-retry",
            "workload-b-id",
            "workload-b-state"
        ]
    );
}

#[test]
fn reducer_review_snapshot_phase_uses_latest_sessions_only() {
    let session_key = |time: &str| {
        format!(
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\Sidecar\{time}"
        )
    };
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "esp-workloads",
            "historical-failure",
            &session_key("2026-07-15T09:00:00Z"),
            "./Device/Vendor/MSFT/Win32App/app-a",
            EspObservationValue::Integer(4),
            "2026-07-15T09:10:00Z",
        ),
        registry_record(
            "esp-workloads",
            "latest-success",
            &session_key("2026-07-15T12:00:00Z"),
            "./Device/Vendor/MSFT/Win32App/app-a",
            EspObservationValue::Integer(3),
            "2026-07-15T12:10:00Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    assert_eq!(snapshot.sessions.len(), 2);
    assert_eq!(
        snapshot
            .sessions
            .iter()
            .find(|session| !session.is_latest)
            .unwrap()
            .phase,
        EspPhase::Failed
    );
    assert_eq!(
        snapshot
            .sessions
            .iter()
            .find(|session| session.is_latest)
            .unwrap()
            .phase,
        EspPhase::Completed
    );
    assert_eq!(snapshot.phase, EspPhase::Completed);
}

#[test]
fn reducer_review_office_outer_status_uses_final_officecsp_detail() {
    let office_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "esp-workloads",
            "office-outer",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\ExpectedMSIAppPackages\2026-07-15T12:00:00Z",
            &format!("./Vendor/MSFT/Office/Installation/{office_id}"),
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            "esp-workloads",
            "office-status",
            &format!(r"SOFTWARE\Microsoft\OfficeCSP\{office_id}"),
            "Status",
            EspObservationValue::Integer(50),
            "2026-07-15T11:59:00Z",
        ),
        registry_record(
            "esp-workloads",
            "office-final-status",
            &format!(r"SOFTWARE\Microsoft\OfficeCSP\{office_id}"),
            "FinalStatus",
            EspObservationValue::Integer(60),
            "2026-07-15T12:01:00Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    let office = snapshot
        .workloads
        .iter()
        .find(|workload| workload.kind == EspTrackedKind::Office)
        .unwrap();
    assert_eq!(office.status.raw, EspRawStatus::Number(1));
    assert_eq!(office.status.normalized, EspNormalizedStatus::Failed);
    assert_eq!(
        office.status.detail.as_ref().unwrap().raw,
        EspRawStatus::Number(60)
    );
    assert_eq!(
        office
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_id.as_str())
            .collect::<Vec<_>>(),
        vec!["office-outer", "office-final-status"]
    );
    assert_eq!(
        office
            .timestamps
            .last_updated
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T12:01:00Z")
    );
    assert_eq!(
        office
            .timestamps
            .ended
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T12:01:00Z")
    );
}

#[test]
fn reducer_review_graph_enrichment_is_lossless_section_compatible_and_additive() {
    let session_key = |time: &str, family: &str| {
        format!(
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\{family}\{time}"
        )
    };
    let graph = |evidence_id: &str,
                 section: EspGraphObservationSection,
                 display_name: &str,
                 normalized: EspNormalizedStatus| {
        EspEvidenceRecord::Graph(EspGraphObservation {
            context: fixture_context(
                EspSourceKind::Graph,
                "graph-thin",
                evidence_id,
                "2026-07-15T15:00:00Z",
            ),
            section,
            api_version: GraphApiVersion::Beta,
            record_id: "shared-id".to_string(),
            display_name: Some(display_name.to_string()),
            status: Some(status(
                EspRawStatus::Text("remoteFailed".to_string()),
                normalized,
            )),
        })
    };
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "esp-workloads",
            "app-old",
            &session_key("2026-07-15T10:00:00Z", "Sidecar"),
            "./Device/Vendor/MSFT/Win32App/shared-id",
            EspObservationValue::Integer(4),
            "2026-07-15T10:00:00Z",
        ),
        registry_record(
            "esp-workloads",
            "app-new",
            &session_key("2026-07-15T12:00:00Z", "Sidecar"),
            "./Device/Vendor/MSFT/Win32App/shared-id",
            EspObservationValue::Integer(3),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            "esp-workloads",
            "policy-local",
            &session_key("2026-07-15T12:00:00Z", "ExpectedPolicies"),
            "shared-id",
            EspObservationValue::Integer(1),
            "2026-07-15T12:01:00Z",
        ),
        graph(
            "graph-app",
            EspGraphObservationSection::App,
            "App display",
            EspNormalizedStatus::Failed,
        ),
        graph(
            "graph-policy",
            EspGraphObservationSection::Policy,
            "Policy display",
            EspNormalizedStatus::Failed,
        ),
    ]);
    let snapshot = reducer.snapshot();
    let apps = snapshot
        .workloads
        .iter()
        .filter(|workload| workload.kind == EspTrackedKind::Win32App)
        .collect::<Vec<_>>();
    assert_eq!(apps.len(), 2);
    assert!(apps
        .iter()
        .all(|workload| workload.display_name.as_deref() == Some("App display")));
    assert_eq!(apps[0].status.raw, EspRawStatus::Number(4));
    assert_eq!(apps[1].status.raw, EspRawStatus::Number(3));
    assert!(apps.iter().all(|workload| workload
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "graph-app")));
    assert!(apps.iter().all(|workload| !workload
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "graph-policy")));
    let policy = snapshot
        .workloads
        .iter()
        .find(|workload| workload.kind == EspTrackedKind::Policy)
        .unwrap();
    assert_eq!(policy.display_name.as_deref(), Some("Policy display"));
    assert_eq!(policy.status.raw, EspRawStatus::Number(1));
    assert_eq!(
        snapshot
            .raw_evidence
            .iter()
            .find(|record| record.evidence[0].evidence_id == "graph-app")
            .unwrap()
            .raw_value,
        EspObservationValue::StringList(vec![
            "section=app".to_string(),
            "apiVersion=beta".to_string(),
            "recordId=shared-id".to_string(),
            "displayName=App display".to_string(),
            "remoteStatus.raw=remoteFailed".to_string(),
            "remoteStatus.normalized=failed".to_string(),
            "remoteStatus.display=status".to_string(),
        ])
    );
    assert!(snapshot.graph.is_none());

    let mut scripts = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    scripts.ingest_all(vec![
        registry_record(
            "autopilot-settings",
            "v2-hint",
            r"SOFTWARE\Microsoft\Provisioning\AutopilotSettings",
            "AutopilotDevicePrepHint",
            EspObservationValue::Text("enabled".to_string()),
            "2026-07-15T08:00:00Z",
        ),
        registry_record(
            "ime-policies",
            "script-local",
            r"SOFTWARE\Microsoft\IntuneManagementExtension\Policies\00000000-0000-0000-0000-000000000000\shared-id",
            "Result",
            EspObservationValue::Text("Success".to_string()),
            "2026-07-15T12:00:00Z",
        ),
        graph(
            "graph-wrong-app",
            EspGraphObservationSection::App,
            "Wrong app display",
            EspNormalizedStatus::Failed,
        ),
        graph(
            "graph-script",
            EspGraphObservationSection::Script,
            "Script display",
            EspNormalizedStatus::Failed,
        ),
    ]);
    let script_snapshot = scripts.snapshot();
    let script = script_snapshot
        .workloads
        .iter()
        .find(|workload| workload.kind == EspTrackedKind::PlatformScript)
        .unwrap();
    assert_eq!(script.display_name.as_deref(), Some("Script display"));
    assert_eq!(script.status.normalized, EspNormalizedStatus::Succeeded);
    assert!(script
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "graph-script"));
    assert!(!script
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "graph-wrong-app"));
}

#[test]
fn reducer_review_deferred_codes_require_exact_unambiguous_session_identity() {
    let sidecar_key = |scope: Option<&str>, time: &str| match scope {
        Some(sid) => format!(
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\{sid}\Sidecar\{time}"
        ),
        None => format!(
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\Sidecar\{time}"
        ),
    };
    let workload = |evidence: &str, scope: Option<&str>, time: &str, id: &str| {
        registry_record(
            "esp-workloads",
            evidence,
            &sidecar_key(scope, time),
            &format!("./Device/Vendor/MSFT/Win32App/{id}"),
            EspObservationValue::Integer(4),
            time,
        )
    };
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        workload("explicit-old", None, "2026-07-15T09:00:00Z", "app-explicit"),
        workload("explicit-new", None, "2026-07-15T12:00:00Z", "app-explicit"),
        workload("scoped-old", None, "2026-07-15T09:00:00Z", "app-scoped"),
        workload("scoped-new", None, "2026-07-15T12:00:00Z", "app-scoped"),
        workload(
            "scoped-user",
            Some("S-1-5-21-100"),
            "2026-07-15T11:00:00Z",
            "app-scoped",
        ),
        workload("short-collision", None, "2026-07-15T12:00:00Z", "short-extra"),
        workload("ambiguous-device", None, "2026-07-15T12:00:00Z", "app-ambiguous"),
        workload(
            "ambiguous-user",
            Some("S-1-5-21-100"),
            "2026-07-15T11:00:00Z",
            "app-ambiguous",
        ),
        registry_record(
            "esp-workloads",
            "explicit-old-code",
            &format!(
                r"{}\app-explicit",
                sidecar_key(None, "2026-07-15T09:00:00Z")
            ),
            "ExitCode",
            EspObservationValue::Integer(101),
            "2026-07-15T12:30:00Z",
        ),
        registry_record(
            "esp-workloads",
            "device-latest-code",
            r"SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\S-0-0-00-0000000000-0000000000-000000000-000\app-scoped",
            "ExitCode",
            EspObservationValue::Integer(202),
            "2026-07-15T12:31:00Z",
        ),
        registry_record(
            "esp-workloads",
            "user-code",
            r"SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\S-1-5-21-100\app-scoped",
            "EnforcementErrorCode",
            EspObservationValue::Integer(303),
            "2026-07-15T12:32:00Z",
        ),
        registry_record(
            "esp-workloads",
            "short-code",
            r"SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\short",
            "ExitCode",
            EspObservationValue::Integer(404),
            "2026-07-15T12:33:00Z",
        ),
        registry_record(
            "esp-workloads",
            "ambiguous-code",
            r"SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\app-ambiguous",
            "ExitCode",
            EspObservationValue::Integer(505),
            "2026-07-15T12:34:00Z",
        ),
    ]);
    let snapshot = reducer.snapshot();
    let find = |evidence_id: &str| {
        snapshot
            .workloads
            .iter()
            .find(|workload| workload.evidence[0].evidence_id == evidence_id)
            .unwrap()
    };
    assert_eq!(find("explicit-old").exit_code.as_ref().unwrap().raw, "101");
    assert!(find("explicit-new").exit_code.is_none());
    assert!(find("scoped-old").exit_code.is_none());
    assert_eq!(find("scoped-new").exit_code.as_ref().unwrap().raw, "202");
    assert_eq!(
        find("scoped-user")
            .enforcement_error_code
            .as_ref()
            .unwrap()
            .raw,
        "303"
    );
    assert!(find("short-collision").exit_code.is_none());
    assert!(find("ambiguous-device").exit_code.is_none());
    assert!(find("ambiguous-user").exit_code.is_none());
    assert!(snapshot
        .raw_evidence
        .iter()
        .any(|raw| raw.evidence[0].evidence_id == "ambiguous-code"));
}

#[test]
fn reducer_review_classic_transitions_merge_timestamps_chronologically() {
    let key = r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\Sidecar\2026-07-15T08:00:00Z";
    let value_name = "./Device/Vendor/MSFT/Win32App/app-a";
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "esp-workloads",
            "completed-newest",
            key,
            value_name,
            EspObservationValue::Integer(3),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            "esp-workloads",
            "not-installed-oldest",
            key,
            value_name,
            EspObservationValue::Integer(1),
            "2026-07-15T09:00:00Z",
        ),
        registry_record(
            "esp-workloads",
            "in-progress-middle",
            key,
            value_name,
            EspObservationValue::Integer(2),
            "2026-07-15T10:00:00Z",
        ),
    ]);
    let snapshot = reducer.snapshot();
    let workload = &snapshot.workloads[0];
    assert_eq!(workload.status.raw, EspRawStatus::Number(3));
    assert_eq!(workload.status.normalized, EspNormalizedStatus::Succeeded);
    assert_eq!(
        workload.timestamps.first_observed.normalized_utc.as_deref(),
        Some("2026-07-15T09:00:00Z")
    );
    assert_eq!(
        workload
            .timestamps
            .started
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T10:00:00Z")
    );
    assert_eq!(
        workload
            .timestamps
            .ended
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T12:00:00Z")
    );
    assert_eq!(
        workload
            .timestamps
            .last_updated
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T12:00:00Z")
    );
    assert_eq!(
        snapshot.sessions[0]
            .ended_at
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T12:00:00Z")
    );
}

#[test]
fn reducer_review_nodecache_sensitivity_is_monotonic_and_unknown_rows_are_raw_only() {
    let node_key = r"SOFTWARE\Microsoft\Provisioning\NodeCache\CSP\Device\MS DM Server\Nodes\2";
    let mut node_uri = registry_record(
        "registry",
        "node-public",
        node_key,
        "NodeUri",
        EspObservationValue::Text("./Vendor/MSFT/Policy/Config/Node2".to_string()),
        "2026-07-15T10:00:00Z",
    );
    let mut expected = registry_record(
        "registry",
        "node-restricted",
        node_key,
        "ExpectedValue",
        EspObservationValue::Text("secret".to_string()),
        "2026-07-15T10:01:00Z",
    );
    if let EspEvidenceRecord::Registry(observation) = &mut node_uri {
        observation.context.sensitivity = EspSensitivity::Public;
    }
    if let EspEvidenceRecord::Registry(observation) = &mut expected {
        observation.context.sensitivity = EspSensitivity::Restricted;
    }
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        node_uri,
        expected,
        registry_record(
            "registry",
            "unknown-node-field",
            r"SOFTWARE\Microsoft\Provisioning\NodeCache\CSP\Device\MS DM Server\Nodes\99",
            "UnknownField",
            EspObservationValue::Text("raw-only".to_string()),
            "2026-07-15T10:02:00Z",
        ),
        registry_record(
            "registry",
            "unknown-enrollment-field",
            r"SOFTWARE\Microsoft\Enrollments\ghost",
            "UnknownField",
            EspObservationValue::Text("raw-only".to_string()),
            "2026-07-15T10:03:00Z",
        ),
        registry_record(
            "registry",
            "invalid-enrollment-field",
            r"SOFTWARE\Microsoft\Enrollments\invalid",
            "SkipDeviceStatusPage",
            EspObservationValue::StringList(vec!["not-a-number".to_string()]),
            "2026-07-15T10:04:00Z",
        ),
        registry_record(
            "registry",
            "valid-enrollment-field",
            r"SOFTWARE\Microsoft\Enrollments\valid",
            "ProviderID",
            EspObservationValue::Text("MS DM Server".to_string()),
            "2026-07-15T10:05:00Z",
        ),
    ]);
    let snapshot = reducer.snapshot();
    assert_eq!(snapshot.node_cache.len(), 1);
    assert_eq!(
        snapshot.node_cache[0].sensitivity,
        EspSensitivity::Restricted
    );
    assert_eq!(snapshot.enrollments.len(), 1);
    assert_eq!(snapshot.enrollments[0].enrollment_id, "valid");
    for raw_id in [
        "unknown-node-field",
        "unknown-enrollment-field",
        "invalid-enrollment-field",
    ] {
        assert!(snapshot
            .raw_evidence
            .iter()
            .any(|raw| raw.evidence[0].evidence_id == raw_id));
    }
}

#[test]
fn timeline_review_download_completion_uses_downloaded_semantics() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        EspEvidenceRecord::DeliveryOptimization(EspDeliveryOptimizationObservation {
            context: fixture_context(
                EspSourceKind::DeliveryOptimization,
                "do-live",
                "do-start",
                "2026-07-15T10:00:00Z",
            ),
            kind: EspDeliveryOptimizationEventKind::DownloadStarted,
            content_id: Some("content-a".to_string()),
            app_id: Some("app-a".to_string()),
            http_bytes: None,
            lan_bytes: None,
            cache_host_bytes: None,
        }),
        EspEvidenceRecord::DeliveryOptimization(EspDeliveryOptimizationObservation {
            context: fixture_context(
                EspSourceKind::DeliveryOptimization,
                "do-live",
                "do-complete",
                "2026-07-15T10:01:00Z",
            ),
            kind: EspDeliveryOptimizationEventKind::DownloadCompleted,
            content_id: Some("content-a".to_string()),
            app_id: Some("app-a".to_string()),
            http_bytes: None,
            lan_bytes: None,
            cache_host_bytes: None,
        }),
        event_record(
            "events",
            "event-1906",
            1906,
            1906,
            "2026-07-15T10:02:00Z",
            "Download finished",
        ),
    ]);
    let snapshot = reducer.snapshot();
    assert_eq!(
        snapshot
            .activity
            .iter()
            .find(|entry| entry.evidence[0].evidence_id == "do-start")
            .unwrap()
            .status
            .as_ref()
            .unwrap()
            .normalized,
        EspNormalizedStatus::Downloading
    );
    for evidence_id in ["do-complete", "event-1906"] {
        assert_eq!(
            snapshot
                .activity
                .iter()
                .find(|entry| entry.evidence[0].evidence_id == evidence_id)
                .unwrap()
                .status
                .as_ref()
                .unwrap()
                .normalized,
            EspNormalizedStatus::Downloaded
        );
    }
}

#[test]
fn reducer_rereview_split_root_exit_codes_and_v2_enforcement_json_correlate_and_emit_timeline() {
    const CLASSIC_ROOT: &str =
        r"registry:HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking";
    const IME_ROOT: &str = r"registry:HKLM\SOFTWARE\Microsoft\IntuneManagementExtension";
    let app_id = "11111111-2222-3333-4444-555555555555";
    let second_app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    let mut classic = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    classic.ingest_all(vec![
        registry_record(
            CLASSIC_ROOT,
            "classic-workload",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\Sidecar\2026-07-15T12:00:00Z",
            &format!("./Device/Vendor/MSFT/Win32App/{app_id}"),
            EspObservationValue::Integer(4),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            IME_ROOT,
            "classic-exit-code",
            &format!(
                r"SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\S-0-0-00-0000000000-0000000000-000000000-000\{app_id}"
            ),
            "ExitCode",
            EspObservationValue::Integer(-2016345060),
            "2026-07-15T12:01:00Z",
        ),
    ]);
    let classic_snapshot = classic.snapshot();
    assert_eq!(
        classic_snapshot.workloads[0]
            .exit_code
            .as_ref()
            .unwrap()
            .raw,
        "-2016345060"
    );
    assert!(classic_snapshot.activity.iter().any(|entry| {
        entry.evidence[0].evidence_id == "classic-exit-code"
            && entry.detail.as_deref() == Some("Exit code -2016345060")
    }));

    let mut v2 = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    v2.ingest_all(vec![
        json_record(
            CLASSIC_ROOT,
            "v2-workload-id",
            "ProvisioningProgress",
            "/Workloads/0/WorkloadId",
            EspObservationValue::Text(app_id.to_string()),
            "2026-07-15T12:02:00Z",
        ),
        json_record(
            CLASSIC_ROOT,
            "v2-workload-state",
            "ProvisioningProgress",
            "/Workloads/0/WorkloadState",
            EspObservationValue::Integer(4),
            "2026-07-15T12:02:01Z",
        ),
        json_record(
            CLASSIC_ROOT,
            "v2-second-workload-id",
            "ProvisioningProgress",
            "/Workloads/1/WorkloadId",
            EspObservationValue::Text(second_app_id.to_string()),
            "2026-07-15T12:02:02Z",
        ),
        json_record(
            CLASSIC_ROOT,
            "v2-second-workload-state",
            "ProvisioningProgress",
            "/Workloads/1/WorkloadState",
            EspObservationValue::Integer(1),
            "2026-07-15T12:02:03Z",
        ),
        json_record(
            IME_ROOT,
            "v2-enforcement-id",
            "EnforcementStateMessage",
            "/0/AppId",
            EspObservationValue::Text(app_id.to_string()),
            "2026-07-15T12:03:00Z",
        ),
        json_record(
            IME_ROOT,
            "v2-enforcement-code",
            "EnforcementStateMessage",
            "/0/EnforcementStateMessage/ErrorCode",
            EspObservationValue::Integer(-2016345060),
            "2026-07-15T12:03:01Z",
        ),
        json_record(
            IME_ROOT,
            "v2-second-enforcement-id",
            "EnforcementStateMessage",
            "/1/AppId",
            EspObservationValue::Text(second_app_id.to_string()),
            "2026-07-15T12:03:02Z",
        ),
        json_record(
            IME_ROOT,
            "v2-second-enforcement-code",
            "EnforcementStateMessage",
            "/1/EnforcementStateMessage/ErrorCode",
            EspObservationValue::Integer(0),
            "2026-07-15T12:03:03Z",
        ),
    ]);
    let v2_snapshot = v2.snapshot();
    let v2_workload = v2_snapshot
        .workloads
        .iter()
        .find(|workload| workload.raw_identifier == app_id)
        .unwrap();
    assert_eq!(
        v2_workload.enforcement_error_code.as_ref().unwrap().raw,
        "-2016345060"
    );
    let second_v2_workload = v2_snapshot
        .workloads
        .iter()
        .find(|workload| workload.raw_identifier == second_app_id)
        .unwrap();
    assert_eq!(
        second_v2_workload
            .enforcement_error_code
            .as_ref()
            .unwrap()
            .raw,
        "0"
    );
    assert!(v2_snapshot.activity.iter().any(|entry| {
        entry.evidence[0].evidence_id == "v2-enforcement-code"
            && entry.detail.as_deref() == Some("Enforcement error code -2016345060")
    }));
}

#[test]
fn reducer_rereview_expected_msi_identity_uses_split_enterprise_status_evidence() {
    const TRACKING_ROOT: &str =
        r"registry:HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking";
    const MSI_ROOT: &str = r"registry:HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement";
    let product_id = "{11111111-2222-3333-4444-555555555555}";
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            TRACKING_ROOT,
            "expected-msi",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\ExpectedMSIAppPackages\2026-07-15T12:00:00Z",
            &format!(
                "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/{product_id}/Status"
            ),
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            MSI_ROOT,
            "enterprise-msi-status",
            &format!(
                r"SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI\{product_id}"
            ),
            "Status",
            EspObservationValue::Integer(70),
            "2026-07-15T12:01:00Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    let workload = snapshot
        .workloads
        .iter()
        .find(|workload| workload.kind == EspTrackedKind::Msi)
        .unwrap();
    assert_eq!(workload.raw_identifier, product_id);
    assert_eq!(workload.status.raw, EspRawStatus::Number(70));
    assert_eq!(workload.status.normalized, EspNormalizedStatus::Succeeded);
    assert!(workload
        .evidence
        .iter()
        .any(|evidence| evidence.evidence_id == "enterprise-msi-status"));
    assert!(snapshot.activity.iter().any(|entry| {
        entry.evidence[0].evidence_id == "enterprise-msi-status"
            && entry.status.as_ref().map(|status| &status.normalized)
                == Some(&EspNormalizedStatus::Succeeded)
    }));
}

#[test]
fn timeline_rereview_office_detail_failure_replaces_outer_success_semantics() {
    const TRACKING_ROOT: &str =
        r"registry:HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking";
    const OFFICE_ROOT: &str = r"registry:HKLM\SOFTWARE\Microsoft\OfficeCSP";
    let office_id = "11111111-2222-3333-4444-555555555555";
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            TRACKING_ROOT,
            "office-outer-success",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\ExpectedMSIAppPackages\2026-07-15T12:00:00Z",
            &format!("./Vendor/MSFT/Office/Installation/{office_id}"),
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            OFFICE_ROOT,
            "office-detail-failure",
            &format!(
                r"SOFTWARE\Microsoft\OfficeCSP\{}",
                office_id.to_ascii_uppercase()
            ),
            "FinalStatus",
            EspObservationValue::Integer(60),
            "2026-07-15T12:01:00Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    let office_activity = snapshot
        .activity
        .iter()
        .filter(|entry| entry.title == office_id)
        .collect::<Vec<_>>();
    assert!(office_activity.iter().any(|entry| {
        entry.evidence[0].evidence_id == "office-detail-failure"
            && entry.status.as_ref().map(|status| &status.normalized)
                == Some(&EspNormalizedStatus::Failed)
    }));
    assert!(office_activity.iter().all(|entry| {
        !matches!(
            entry.status.as_ref().map(|status| &status.normalized),
            Some(EspNormalizedStatus::Succeeded | EspNormalizedStatus::Processed)
        )
    }));
}

#[test]
fn timeline_rereview_v2_dotnet_dates_drive_start_and_terminal_entries() {
    let source = r"registry:HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking";
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        json_record(
            source,
            "v2-id",
            "ProvisioningProgress",
            "/Workloads/0/WorkloadId",
            EspObservationValue::Text("v2-app".to_string()),
            "2026-07-15T12:00:00Z",
        ),
        json_record(
            source,
            "v2-start-time",
            "ProvisioningProgress",
            "/Workloads/0/StartTime",
            EspObservationValue::Text(r"\/Date(1745871176634)\/".to_string()),
            "2026-07-15T12:00:01Z",
        ),
        json_record(
            source,
            "v2-end-time",
            "ProvisioningProgress",
            "/Workloads/0/EndTime",
            EspObservationValue::Text(r"\/Date(1745871256672)\/".to_string()),
            "2026-07-15T12:00:02Z",
        ),
        json_record(
            source,
            "v2-state",
            "ProvisioningProgress",
            "/Workloads/0/WorkloadState",
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:03Z",
        ),
        json_record(
            source,
            "v2-direct-exit-code",
            "ProvisioningProgress",
            "/Workloads/0/ErrorCode",
            EspObservationValue::Integer(-1),
            "2026-07-15T12:00:04Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    let workload = &snapshot.workloads[0];
    assert_eq!(
        workload
            .timestamps
            .started
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2025-04-28T20:12:56.634Z")
    );
    assert_eq!(
        workload
            .timestamps
            .ended
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2025-04-28T20:14:16.672Z")
    );
    let start = snapshot
        .activity
        .iter()
        .find(|entry| entry.evidence[0].evidence_id == "v2-start-time")
        .unwrap();
    assert_eq!(
        start.timestamp.normalized_utc.as_deref(),
        Some("2025-04-28T20:12:56.634Z")
    );
    assert_eq!(
        start.status.as_ref().unwrap().normalized,
        EspNormalizedStatus::Installing
    );
    let end = snapshot
        .activity
        .iter()
        .find(|entry| entry.evidence[0].evidence_id == "v2-end-time")
        .unwrap();
    assert_eq!(
        end.timestamp.normalized_utc.as_deref(),
        Some("2025-04-28T20:14:16.672Z")
    );
    assert_eq!(
        end.status.as_ref().unwrap().normalized,
        EspNormalizedStatus::Succeeded
    );
    assert_eq!(workload.exit_code.as_ref().unwrap().raw, "-1");
    assert!(snapshot.activity.iter().any(|entry| {
        entry.evidence[0].evidence_id == "v2-direct-exit-code"
            && entry.detail.as_deref() == Some("Exit code -1")
    }));
}

#[test]
fn reducer_rereview_platform_script_polls_reduce_by_identity_and_merge_last_updated() {
    let source = r"registry:HKLM\SOFTWARE\Microsoft\IntuneManagementExtension";
    let script_id = "11111111-2222-3333-4444-555555555555";
    let script_key = format!(
        r"SOFTWARE\Microsoft\IntuneManagementExtension\Policies\00000000-0000-0000-0000-000000000000\{script_id}"
    );
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "registry:HKLM\\SOFTWARE\\Microsoft\\Provisioning\\AutopilotSettings",
            "v2-hint",
            r"SOFTWARE\Microsoft\Provisioning\AutopilotSettings",
            "AutopilotDevicePrepHint",
            EspObservationValue::Text("enabled".to_string()),
            "2026-07-15T11:59:00Z",
        ),
        registry_record(
            source,
            "script-result-pending",
            &script_key,
            "Result",
            EspObservationValue::Text("InProgress".to_string()),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            source,
            "script-last-updated",
            &script_key,
            "LastUpdatedTimeUtc",
            EspObservationValue::Text("2026-07-15T12:02:00Z".to_string()),
            "2026-07-15T12:03:00Z",
        ),
        registry_record(
            source,
            "script-result-success",
            &script_key,
            "Result",
            EspObservationValue::Text("Success".to_string()),
            "2026-07-15T12:01:00Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    let scripts = snapshot
        .workloads
        .iter()
        .filter(|workload| workload.kind == EspTrackedKind::PlatformScript)
        .collect::<Vec<_>>();
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts[0].status.normalized, EspNormalizedStatus::Succeeded);
    assert_eq!(
        scripts[0]
            .timestamps
            .last_updated
            .as_ref()
            .unwrap()
            .normalized_utc
            .as_deref(),
        Some("2026-07-15T12:02:00Z")
    );
    assert_eq!(
        scripts[0]
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "script-result-pending",
            "script-last-updated",
            "script-result-success"
        ]
    );
    let script_session = snapshot
        .sessions
        .iter()
        .find(|session| session.workload_ids.contains(&scripts[0].workload_id))
        .unwrap();
    assert_eq!(script_session.workload_ids.len(), 1);
    assert_eq!(
        snapshot
            .activity
            .iter()
            .filter(|entry| {
                matches!(
                    entry.evidence[0].evidence_id.as_str(),
                    "script-result-pending" | "script-result-success"
                )
            })
            .count(),
        2
    );
}

#[test]
fn timeline_rereview_odj_109_110_payload_states_decode_zero_through_three() {
    let cases = [
        (
            109,
            "State",
            "0",
            "Offline domain join not configured",
            EspNormalizedStatus::NotStarted,
        ),
        (
            110,
            "ODJState",
            "1",
            "Waiting for ODJ blob",
            EspNormalizedStatus::InProgress,
        ),
        (
            109,
            "Status",
            "2",
            "Processed ODJ blob",
            EspNormalizedStatus::Processed,
        ),
        (
            110,
            "Param1",
            "3",
            "Timed out waiting for ODJ blob or connectivity",
            EspNormalizedStatus::Failed,
        ),
    ];
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    for (ordinal, (event_id, name, value, _, _)) in cases.iter().enumerate() {
        let evidence_id = format!("odj-state-{value}");
        let mut record = event_record(
            "eventlog:Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
            &evidence_id,
            *event_id,
            2000 + ordinal as u64,
            &format!("2026-07-15T12:0{ordinal}:00Z"),
            "raw localized event text",
        );
        if let EspEvidenceRecord::EventLog(observation) = &mut record {
            let payload = vec![EspNamedValue {
                name: (*name).to_string(),
                value: (*value).to_string(),
            }];
            if ordinal == 3 {
                observation
                    .context
                    .provenance
                    .event
                    .as_mut()
                    .unwrap()
                    .named_data = payload;
            } else {
                observation.named_data = payload;
            }
        }
        reducer.ingest(record);
    }

    let snapshot = reducer.snapshot();
    for (_, _, value, message, normalized) in cases {
        let entry = snapshot
            .activity
            .iter()
            .find(|entry| entry.evidence[0].evidence_id == format!("odj-state-{value}"))
            .unwrap();
        assert_eq!(entry.detail.as_deref(), Some(message));
        assert_eq!(entry.status.as_ref().unwrap().normalized, normalized);
    }
}

#[test]
fn reducer_rereview_delivery_optimization_live_and_captured_use_http_bytes_denominator() {
    let snapshot = |source_kind: EspSourceKind, source: &str, evidence: &str, values| {
        let (http_bytes, lan_bytes, cache_host_bytes) = values;
        let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
        reducer.ingest(EspEvidenceRecord::DeliveryOptimization(
            EspDeliveryOptimizationObservation {
                context: fixture_context(source_kind, source, evidence, "2026-07-15T12:00:00Z"),
                kind: EspDeliveryOptimizationEventKind::DownloadCompleted,
                content_id: Some("content-a".to_string()),
                app_id: Some("app-a".to_string()),
                http_bytes: Some(http_bytes),
                lan_bytes: Some(lan_bytes),
                cache_host_bytes: Some(cache_host_bytes),
            },
        ));
        reducer.snapshot()
    };

    let live = snapshot(
        EspSourceKind::DeliveryOptimization,
        "delivery-optimization:live",
        "do-live",
        (700, 200, 100),
    );
    let captured = snapshot(
        EspSourceKind::DeliveryOptimization,
        "delivery-optimization:captured",
        "do-captured",
        (700, 200, 100),
    );
    let live_delivery = live.delivery_optimization.as_ref().unwrap();
    let captured_delivery = captured.delivery_optimization.as_ref().unwrap();
    assert_eq!(
        live_delivery.peer_share_percent,
        Some(200.0 / 700.0 * 100.0)
    );
    assert_eq!(
        live_delivery.connected_cache_share_percent,
        Some(100.0 / 700.0 * 100.0)
    );
    assert_eq!(
        live_delivery.peer_share_percent,
        captured_delivery.peer_share_percent
    );
    assert_eq!(
        live_delivery.connected_cache_share_percent,
        captured_delivery.connected_cache_share_percent
    );
}

#[test]
fn reducer_rereview_delivery_optimization_zero_http_with_nonzero_components_is_unavailable() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest(EspEvidenceRecord::DeliveryOptimization(
        EspDeliveryOptimizationObservation {
            context: fixture_context(
                EspSourceKind::DeliveryOptimization,
                "delivery-optimization:live",
                "do-zero-http",
                "2026-07-15T12:00:00Z",
            ),
            kind: EspDeliveryOptimizationEventKind::DownloadCompleted,
            content_id: Some("content-a".to_string()),
            app_id: Some("app-a".to_string()),
            http_bytes: Some(0),
            lan_bytes: Some(200),
            cache_host_bytes: Some(100),
        },
    ));

    let snapshot = reducer.snapshot();
    let delivery = snapshot.delivery_optimization.as_ref().unwrap();
    assert_eq!(delivery.peer_share_percent, None);
    assert_eq!(delivery.connected_cache_share_percent, None);
}

#[test]
fn reducer_review_percent_encoded_office_paths_are_classified_before_detail_correlation() {
    let office_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let encoded_path = format!(".%2FVendor%2FMSFT%2FOffice%2FInstallation%2F{office_id}");
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "esp-workloads",
            "office-outer-encoded",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\ExpectedMSIAppPackages\2026-07-15T12:00:00Z",
            &encoded_path,
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            "office-csp",
            "office-final-encoded",
            &format!(r"SOFTWARE\Microsoft\OfficeCSP\{office_id}"),
            "FinalStatus",
            EspObservationValue::Integer(60),
            "2026-07-15T12:01:00Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    let workload = snapshot.workloads.first().unwrap();
    assert_eq!(workload.kind, EspTrackedKind::Office);
    assert_eq!(workload.raw_identifier, office_id);
    assert_eq!(workload.status.normalized, EspNormalizedStatus::Failed);
}

#[test]
fn reducer_review_empty_json_identity_values_do_not_classify_scenario() {
    for (pointer, evidence_id) in [
        ("/DeploymentProfileName", "blank-profile"),
        ("/ZtdCorrelationId", "blank-correlation"),
    ] {
        let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
        reducer.ingest(json_record(
            "autopilot-json",
            evidence_id,
            "autopilotProfile",
            pointer,
            EspObservationValue::Text(" \t\r\n".to_string()),
            "2026-07-15T12:00:00Z",
        ));

        assert_eq!(reducer.snapshot().scenario, EspScenario::Unknown);
    }
}

#[test]
fn reducer_review_malformed_hex_codes_remain_unknown() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        json_record(
            "v2-progress",
            "v2-invalid-id",
            "ProvisioningProgress",
            "/Workloads/0/WorkloadId",
            EspObservationValue::Text("workload-invalid-code".to_string()),
            "2026-07-15T12:00:00Z",
        ),
        json_record(
            "v2-progress",
            "v2-invalid-code",
            "ProvisioningProgress",
            "/Workloads/0/ErrorCode",
            EspObservationValue::Text("0xINVALID".to_string()),
            "2026-07-15T12:01:00Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    let code = snapshot.workloads[0].exit_code.as_ref().unwrap();
    assert_eq!(code.raw, "0xINVALID");
    assert_eq!(code.decimal, None);
    assert_eq!(code.hex, None);
    let activity = snapshot
        .activity
        .iter()
        .find(|entry| entry.evidence[0].evidence_id == "v2-invalid-code")
        .unwrap();
    assert_eq!(
        activity.status.as_ref().unwrap().normalized,
        EspNormalizedStatus::Unknown
    );
}

#[test]
fn reducer_review_office_details_only_update_latest_matching_session() {
    let office_id = "11111111-2222-3333-4444-555555555555";
    let value_name = format!("./Vendor/MSFT/Office/Installation/{office_id}");
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "esp-workloads",
            "office-old-session",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\ExpectedMSIAppPackages\2026-07-15T10:00:00Z",
            &value_name,
            EspObservationValue::Integer(1),
            "2026-07-15T10:00:00Z",
        ),
        registry_record(
            "esp-workloads",
            "office-latest-session",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\ExpectedMSIAppPackages\2026-07-15T12:00:00Z",
            &value_name,
            EspObservationValue::Integer(1),
            "2026-07-15T12:00:00Z",
        ),
        registry_record(
            "office-csp",
            "office-latest-detail",
            &format!(r"SOFTWARE\Microsoft\OfficeCSP\{office_id}"),
            "FinalStatus",
            EspObservationValue::Integer(60),
            "2026-07-15T12:01:00Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    let mut workloads = snapshot
        .workloads
        .iter()
        .filter(|workload| workload.kind == EspTrackedKind::Office)
        .collect::<Vec<_>>();
    workloads.sort_by_key(|workload| workload.timestamps.first_observed.raw_text.clone());
    assert_eq!(workloads.len(), 2);
    assert_eq!(
        workloads[0].status.normalized,
        EspNormalizedStatus::Processed
    );
    assert_eq!(workloads[0].status.detail, None);
    assert_eq!(workloads[1].status.normalized, EspNormalizedStatus::Failed);
    assert_eq!(
        workloads[1].status.detail.as_ref().unwrap().raw,
        EspRawStatus::Number(60)
    );
}

#[test]
fn reducer_review_v2_document_identity_prevents_cross_document_index_merges() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        json_registry_document_record(
            "captured-autopilot-registry",
            "document-a-id",
            "ProvisioningProgressA",
            "/Workloads/0/WorkloadId",
            EspObservationValue::Text("workload-a".to_string()),
            "2026-07-15T10:00:00Z",
        ),
        json_registry_document_record(
            "captured-autopilot-registry",
            "document-a-state",
            "ProvisioningProgressA",
            "/Workloads/0/WorkloadState",
            EspObservationValue::Integer(1),
            "2026-07-15T10:01:00Z",
        ),
        json_registry_document_record(
            "captured-autopilot-registry",
            "document-b-id",
            "ProvisioningProgressB",
            "/Workloads/0/WorkloadId",
            EspObservationValue::Text("workload-b".to_string()),
            "2026-07-15T11:00:00Z",
        ),
        json_registry_document_record(
            "captured-autopilot-registry",
            "document-b-state",
            "ProvisioningProgressB",
            "/Workloads/0/WorkloadState",
            EspObservationValue::Integer(4),
            "2026-07-15T11:01:00Z",
        ),
    ]);

    let snapshot = reducer.snapshot();
    let workload_a = snapshot
        .workloads
        .iter()
        .find(|workload| workload.raw_identifier == "workload-a")
        .unwrap();
    let workload_b = snapshot
        .workloads
        .iter()
        .find(|workload| workload.raw_identifier == "workload-b")
        .unwrap();
    assert_eq!(workload_a.status.normalized, EspNormalizedStatus::Succeeded);
    assert_eq!(workload_b.status.normalized, EspNormalizedStatus::Failed);
}
fn findings_snapshot() -> EspDiagnosticsSnapshot {
    EspDiagnosticsSnapshot {
        schema_version: ESP_DIAGNOSTICS_SCHEMA_VERSION,
        scenario: EspScenario::AutopilotV1,
        phase: EspPhase::DeviceSetup,
        generated_at_utc: "2026-07-15T12:30:00Z".to_string(),
        elevation: EspElevationState {
            is_elevated: true,
            restart_supported: true,
            restricted_sources: vec![],
        },
        identity: EspIdentityEvidence {
            device_name: Some("DEVICE-1".to_string()),
            managed_device_id: None,
            entra_device_id: None,
            entdm_id: None,
            tenant_id: None,
            tenant_domain: None,
            user_principal_name: None,
            serial_number: None,
            evidence: vec![],
        },
        profile: None,
        enrollments: vec![],
        sessions: vec![],
        workloads: vec![],
        installer_correlations: vec![],
        node_cache: vec![],
        registration_events: vec![],
        delivery_optimization: None,
        hardware: None,
        activity: vec![],
        findings: vec![],
        coverage: vec![],
        raw_evidence: vec![],
        graph: None,
    }
}

fn findings_workload(
    id: &str,
    kind: EspTrackedKind,
    normalized: EspNormalizedStatus,
    blocking: Option<bool>,
    last_updated: &str,
) -> EspWorkload {
    EspWorkload {
        workload_id: format!("workload-{id}"),
        session_id: "session-device".to_string(),
        kind,
        scope: EspScope::Device,
        raw_identifier: id.to_string(),
        display_name: Some(format!("Workload {id}")),
        status: status(EspRawStatus::Text(format!("{normalized:?}")), normalized),
        timestamps: EspWorkloadTimestamps {
            first_observed: timestamp("2026-07-15T12:00:00Z"),
            started: Some(timestamp("2026-07-15T12:01:00Z")),
            ended: None,
            last_updated: Some(timestamp(last_updated)),
        },
        exit_code: None,
        enforcement_error_code: None,
        blocking,
        evidence: vec![evidence_ref(&format!("evidence-{id}"))],
    }
}

fn assert_finding_contract(
    finding: &EspDiagnosticFinding,
    id: &str,
    severity: EspFindingSeverity,
    confidence: EspFindingConfidence,
    recommended_check: &str,
    expected_evidence: &[(&str, &str)],
    expected_coverage_gap_ids: &[&str],
) {
    assert_eq!(finding.finding_id, id);
    assert_eq!(finding.severity, severity);
    assert_eq!(finding.confidence, confidence);
    assert_eq!(
        finding.recommended_checks,
        vec![recommended_check.to_string()],
        "recommended checks changed for {id}"
    );
    assert_eq!(
        finding
            .evidence
            .iter()
            .map(|evidence| (
                evidence.evidence_id.as_str(),
                evidence.source_artifact_id.as_str(),
            ))
            .collect::<Vec<_>>(),
        expected_evidence,
        "evidence changed for {id}"
    );
    assert_eq!(
        finding
            .coverage_gap_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected_coverage_gap_ids,
        "coverage gaps changed for {id}"
    );
}

fn finding_by_id<'a>(findings: &'a [EspDiagnosticFinding], id: &str) -> &'a EspDiagnosticFinding {
    findings
        .iter()
        .find(|finding| finding.finding_id == id)
        .unwrap_or_else(|| panic!("missing finding {id}: {findings:#?}"))
}

#[test]
fn findings_failed_blocking_app_and_stalled_install_are_evidence_backed() {
    let mut snapshot = findings_snapshot();
    snapshot.workloads = vec![
        findings_workload(
            "app-failed",
            EspTrackedKind::Win32App,
            EspNormalizedStatus::Failed,
            Some(true),
            "2026-07-15T12:29:00Z",
        ),
        findings_workload(
            "app-stalled",
            EspTrackedKind::Msi,
            EspNormalizedStatus::Installing,
            Some(false),
            "2026-07-15T12:05:00Z",
        ),
    ];

    let findings = derive_findings(&snapshot);
    assert_finding_contract(
        finding_by_id(&findings, "blocking-app-failed"),
        "blocking-app-failed",
        EspFindingSeverity::Blocker,
        EspFindingConfidence::High,
        "Inspect the cited IME or deployment log around the app's final failure.",
        &[("evidence-app-failed", "artifact-registry")],
        &[],
    );
    assert_finding_contract(
        finding_by_id(&findings, "workload-stalled"),
        "workload-stalled",
        EspFindingSeverity::Error,
        EspFindingConfidence::High,
        "Compare the cited workload's last update with IME and Delivery Optimization activity.",
        &[("evidence-app-stalled", "artifact-registry")],
        &[],
    );
}

#[test]
fn findings_ignore_workloads_that_belong_only_to_non_latest_sessions() {
    let mut snapshot = findings_snapshot();
    snapshot.sessions = vec![
        EspSession {
            session_id: "session-old".to_string(),
            kind: EspSessionKind::Classic,
            scope: EspScope::Device,
            user_sid: None,
            started_at: Some(timestamp("2026-07-15T11:00:00Z")),
            ended_at: Some(timestamp("2026-07-15T11:30:00Z")),
            phase: EspPhase::Failed,
            is_latest: false,
            workload_ids: vec![
                "workload-current".to_string(),
                "workload-old-stalled".to_string(),
                "workload-old-policy".to_string(),
            ],
            evidence: vec![evidence_ref("session-old")],
        },
        EspSession {
            session_id: "session-current".to_string(),
            kind: EspSessionKind::Classic,
            scope: EspScope::Device,
            user_sid: None,
            started_at: Some(timestamp("2026-07-15T12:20:00Z")),
            ended_at: None,
            phase: EspPhase::DeviceSetup,
            is_latest: true,
            workload_ids: vec!["workload-current".to_string()],
            evidence: vec![evidence_ref("session-current")],
        },
    ];
    let mut old_failed = findings_workload(
        "old-failed",
        EspTrackedKind::Win32App,
        EspNormalizedStatus::Failed,
        Some(true),
        "2026-07-15T11:05:00Z",
    );
    old_failed.session_id = "session-old".to_string();
    old_failed.workload_id = "workload-current".to_string();
    let mut old_stalled = findings_workload(
        "old-stalled",
        EspTrackedKind::Msi,
        EspNormalizedStatus::Installing,
        Some(false),
        "2026-07-15T11:05:00Z",
    );
    old_stalled.session_id = "session-old".to_string();
    let mut old_policy = findings_workload(
        "old-policy",
        EspTrackedKind::Policy,
        EspNormalizedStatus::Pending,
        Some(true),
        "2026-07-15T11:05:00Z",
    );
    old_policy.session_id = "session-old".to_string();
    let mut current = findings_workload(
        "current",
        EspTrackedKind::Win32App,
        EspNormalizedStatus::Installing,
        Some(true),
        "2026-07-15T12:29:00Z",
    );
    current.session_id = "session-current".to_string();
    snapshot.workloads = vec![old_failed, old_stalled, old_policy, current];

    let findings = derive_findings(&snapshot);
    for stale_id in [
        "blocking-app-failed",
        "workload-stalled",
        "policy-not-processed",
    ] {
        assert!(
            findings
                .iter()
                .all(|finding| finding.finding_id != stale_id),
            "historical workload emitted stale finding {stale_id}: {findings:#?}"
        );
    }
}

#[test]
fn findings_do_not_cross_join_latest_session_and_workload_id_membership() {
    let mut snapshot = findings_snapshot();
    snapshot.sessions = vec![
        EspSession {
            session_id: "session-a".to_string(),
            kind: EspSessionKind::Classic,
            scope: EspScope::Device,
            user_sid: None,
            started_at: Some(timestamp("2026-07-15T12:00:00Z")),
            ended_at: None,
            phase: EspPhase::DeviceSetup,
            is_latest: true,
            workload_ids: vec!["workload-a".to_string()],
            evidence: vec![evidence_ref("session-a")],
        },
        EspSession {
            session_id: "session-b".to_string(),
            kind: EspSessionKind::Classic,
            scope: EspScope::User,
            user_sid: Some(sensitive("S-1-5-21-111-222-333-1001")),
            started_at: Some(timestamp("2026-07-15T12:00:00Z")),
            ended_at: None,
            phase: EspPhase::AccountSetup,
            is_latest: true,
            workload_ids: vec!["workload-b".to_string()],
            evidence: vec![evidence_ref("session-b")],
        },
    ];
    let mut cross_joined = findings_workload(
        "cross-joined",
        EspTrackedKind::Win32App,
        EspNormalizedStatus::Failed,
        Some(true),
        "2026-07-15T12:29:00Z",
    );
    cross_joined.session_id = "session-a".to_string();
    cross_joined.workload_id = "workload-b".to_string();
    snapshot.workloads = vec![cross_joined];

    assert!(derive_findings(&snapshot)
        .iter()
        .all(|finding| finding.finding_id != "blocking-app-failed"));
}

#[test]
fn findings_keep_sessionless_workload_evidence_eligible() {
    let mut snapshot = findings_snapshot();
    snapshot.workloads.push(findings_workload(
        "sessionless-failed",
        EspTrackedKind::Win32App,
        EspNormalizedStatus::Failed,
        Some(true),
        "2026-07-15T12:29:00Z",
    ));

    assert!(derive_findings(&snapshot)
        .iter()
        .any(|finding| finding.finding_id == "blocking-app-failed"));
}

#[test]
fn findings_timeout_registration_policy_and_certificate_states_require_exact_evidence() {
    let mut snapshot = findings_snapshot();
    snapshot.enrollments.push(EspEnrollmentEvidence {
        enrollment_id: "enrollment-1".to_string(),
        provider_id: Some("MS DM Server".to_string()),
        tenant_id: None,
        user_principal_name: None,
        entdm_id: None,
        settings: EspEnrollmentSettings {
            device_esp_enabled: Some(true),
            user_esp_enabled: None,
            timeout_seconds: Some(600),
            blocking: Some(true),
            allow_reset: None,
            allow_retry: None,
            continue_anyway: None,
        },
        evidence: vec![evidence_ref("enrollment-timeout")],
    });
    snapshot.sessions.push(EspSession {
        session_id: "session-device".to_string(),
        kind: EspSessionKind::Classic,
        scope: EspScope::Device,
        user_sid: None,
        started_at: Some(timestamp("2026-07-15T12:00:00Z")),
        ended_at: None,
        phase: EspPhase::DeviceSetup,
        is_latest: true,
        workload_ids: vec!["workload-policy".to_string(), "workload-cert".to_string()],
        evidence: vec![evidence_ref("session-timeout")],
    });
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("Hybrid AADJ device registration failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Hybrid AADJ device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:02:00Z"),
        named_data: vec![],
        evidence: vec![evidence_ref("registration-failed")],
    });
    snapshot.workloads = vec![
        findings_workload(
            "policy",
            EspTrackedKind::Policy,
            EspNormalizedStatus::Pending,
            Some(true),
            "2026-07-15T12:29:00Z",
        ),
        findings_workload(
            "cert",
            EspTrackedKind::ScepCertificate,
            EspNormalizedStatus::NotStarted,
            Some(true),
            "2026-07-15T12:29:00Z",
        ),
    ];

    let findings = derive_findings(&snapshot);
    assert_finding_contract(
        finding_by_id(&findings, "esp-timeout-reached"),
        "esp-timeout-reached",
        EspFindingSeverity::Blocker,
        EspFindingConfidence::High,
        "Compare the cited ESP session start time with the configured timeout.",
        &[
            ("enrollment-timeout", "artifact-registry"),
            ("session-timeout", "artifact-registry"),
        ],
        &[],
    );
    assert_finding_contract(
        finding_by_id(&findings, "registration-or-join-failed"),
        "registration-or-join-failed",
        EspFindingSeverity::Error,
        EspFindingConfidence::High,
        "Inspect the cited Device Registration or Offline Domain Join event and its named data.",
        &[("registration-failed", "artifact-registry")],
        &[],
    );
    assert_finding_contract(
        finding_by_id(&findings, "policy-not-processed"),
        "policy-not-processed",
        EspFindingSeverity::Warning,
        EspFindingConfidence::High,
        "Inspect the cited policy tracking state and enrollment scope.",
        &[("evidence-policy", "artifact-registry")],
        &[],
    );
    assert_finding_contract(
        finding_by_id(&findings, "certificate-not-processed"),
        "certificate-not-processed",
        EspFindingSeverity::Warning,
        EspFindingConfidence::High,
        "Inspect the cited certificate tracking state and enrollment scope.",
        &[("evidence-cert", "artifact-registry")],
        &[],
    );
}

fn assert_reduced_join_failure(event_id: u32, message: &str, evidence_id: &str, record_id: u64) {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T12:30:00Z".to_string());
    reducer.ingest(event_record(
        "device-registration-admin",
        evidence_id,
        event_id,
        record_id,
        "2026-07-15T12:02:00Z",
        message,
    ));

    let snapshot = reducer.snapshot();
    let activity = snapshot
        .activity
        .iter()
        .find(|entry| entry.evidence[0].evidence_id == evidence_id)
        .unwrap();
    assert_eq!(activity.kind, EspTimelineKind::OfflineDomainJoin);
    assert_eq!(
        activity.status.as_ref().unwrap().normalized,
        EspNormalizedStatus::Failed
    );
    assert_finding_contract(
        finding_by_id(&snapshot.findings, "registration-or-join-failed"),
        "registration-or-join-failed",
        EspFindingSeverity::Error,
        EspFindingConfidence::High,
        "Inspect the cited Device Registration or Offline Domain Join event and its named data.",
        &[(evidence_id, "device-registration-admin")],
        &[],
    );
}

#[test]
fn findings_reducer_surfaces_offline_domain_join_connectivity_failure() {
    assert_reduced_join_failure(
        100,
        "Could not establish connectivity",
        "odj-connectivity-failed",
        100,
    );
}

#[test]
fn findings_reducer_surfaces_offline_domain_join_timeout_state() {
    assert_reduced_join_failure(
        109,
        "Timed out waiting for ODJ blob or connectivity",
        "odj-timeout",
        109,
    );
}

#[test]
fn findings_do_not_misclassify_installation_failure_as_join_failure() {
    let mut snapshot = findings_snapshot();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 1924,
        record_id: Some(1924),
        status: status(
            EspRawStatus::Text("Installation failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Installation failed".to_string(),
        timestamp: timestamp("2026-07-15T12:02:00Z"),
        named_data: vec![],
        evidence: vec![evidence_ref_from(
            "installation-failed",
            "device-registration-admin",
        )],
    });

    assert!(derive_findings(&snapshot)
        .iter()
        .all(|finding| finding.finding_id != "registration-or-join-failed"));

    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T12:30:00Z".to_string());
    reducer.ingest(event_record(
        "device-registration-admin",
        "installation-failed",
        1924,
        1924,
        "2026-07-15T12:02:00Z",
        "Installation failed",
    ));
    assert!(reducer
        .snapshot()
        .findings
        .iter()
        .all(|finding| finding.finding_id != "registration-or-join-failed"));
}

#[test]
fn findings_timeout_is_not_inferred_from_ambiguous_or_unrepresentable_settings() {
    let mut snapshot = findings_snapshot();
    snapshot.sessions.push(EspSession {
        session_id: "session-device".to_string(),
        kind: EspSessionKind::Classic,
        scope: EspScope::Device,
        user_sid: None,
        started_at: Some(timestamp("2026-07-15T12:00:00Z")),
        ended_at: None,
        phase: EspPhase::DeviceSetup,
        is_latest: true,
        workload_ids: vec![],
        evidence: vec![evidence_ref("session-timeout-ambiguous")],
    });
    let enrollment = |id: &str, timeout_seconds| EspEnrollmentEvidence {
        enrollment_id: id.to_string(),
        provider_id: Some("MS DM Server".to_string()),
        tenant_id: None,
        user_principal_name: None,
        entdm_id: None,
        settings: EspEnrollmentSettings {
            device_esp_enabled: Some(true),
            user_esp_enabled: None,
            timeout_seconds: Some(timeout_seconds),
            blocking: Some(true),
            allow_reset: None,
            allow_retry: None,
            continue_anyway: None,
        },
        evidence: vec![evidence_ref(id)],
    };
    snapshot.enrollments = vec![
        enrollment("timeout-10m", 600),
        enrollment("timeout-20m", 1200),
    ];

    assert!(derive_findings(&snapshot)
        .iter()
        .all(|finding| finding.finding_id != "esp-timeout-reached"));

    snapshot.enrollments = vec![enrollment("timeout-overflow", u64::MAX)];
    assert!(derive_findings(&snapshot)
        .iter()
        .all(|finding| finding.finding_id != "esp-timeout-reached"));
}

#[test]
fn findings_coverage_ambiguity_and_malformed_source_are_never_unpinned() {
    let mut snapshot = findings_snapshot();
    snapshot.elevation = EspElevationState {
        is_elevated: false,
        restart_supported: true,
        restricted_sources: vec!["ime-logs".to_string()],
    };
    snapshot.coverage = vec![
        EspArtifactCoverage {
            artifact_id: "ime-logs".to_string(),
            family: "Intune Management Extension logs".to_string(),
            status: EspArtifactStatus::PermissionDenied,
            detail: Some("Administrator access is required".to_string()),
            observed_at_utc: "2026-07-15T12:30:00Z".to_string(),
            evidence: vec![evidence_ref_from("ime-coverage", "ime-logs")],
        },
        EspArtifactCoverage {
            artifact_id: "page-settings-json".to_string(),
            family: "ESP PageSettings".to_string(),
            status: EspArtifactStatus::ParseFailed,
            detail: Some("invalid JSON".to_string()),
            observed_at_utc: "2026-07-15T12:30:00Z".to_string(),
            evidence: vec![evidence_ref_from(
                "malformed-coverage",
                "page-settings-json",
            )],
        },
    ];
    snapshot
        .installer_correlations
        .push(EspInstallerCorrelation {
            correlation_id: "correlation-ambiguous".to_string(),
            workload_id: None,
            confidence: EspCorrelationConfidence::Uncorrelated,
            reason: "two candidates overlap".to_string(),
            candidate_workload_ids: vec!["app-a".to_string(), "app-b".to_string()],
            process_observations: vec![],
            evidence: vec![evidence_ref("ambiguous-msi")],
        });

    let findings = derive_findings(&snapshot);
    assert_finding_contract(
        finding_by_id(&findings, "ime-evidence-unavailable"),
        "ime-evidence-unavailable",
        EspFindingSeverity::Warning,
        EspFindingConfidence::High,
        "Open the cited IME coverage entry and verify the protected log path is readable.",
        &[("ime-coverage", "ime-logs")],
        &["ime-logs"],
    );
    assert_finding_contract(
        finding_by_id(&findings, "non-elevated-coverage-loss"),
        "non-elevated-coverage-loss",
        EspFindingSeverity::Warning,
        EspFindingConfidence::High,
        "Review the cited coverage gaps, then relaunch CMTrace Open as administrator if deeper evidence is required.",
        &[("ime-coverage", "ime-logs")],
        &["ime-logs"],
    );
    assert_finding_contract(
        finding_by_id(&findings, "installer-correlation-ambiguous"),
        "installer-correlation-ambiguous",
        EspFindingSeverity::Warning,
        EspFindingConfidence::Medium,
        "Compare the cited process start time, log path, app ID, and product code with each candidate workload.",
        &[("ambiguous-msi", "artifact-registry")],
        &[],
    );
    assert_finding_contract(
        finding_by_id(&findings, "source-evidence-malformed"),
        "source-evidence-malformed",
        EspFindingSeverity::Warning,
        EspFindingConfidence::High,
        "Inspect the cited source coverage and any available raw evidence.",
        &[("malformed-coverage", "page-settings-json")],
        &["page-settings-json"],
    );
    assert_eq!(
        finding_by_id(&findings, "source-evidence-malformed").summary,
        "At least one cited diagnostic source failed parsing."
    );
}

#[test]
fn findings_ime_coverage_uses_explicit_artifact_and_family_identities() {
    let mut snapshot = findings_snapshot();
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: "management-extension-primary".to_string(),
        family: "Intune Management Extension".to_string(),
        status: EspArtifactStatus::Missing,
        detail: Some("not collected".to_string()),
        observed_at_utc: "2026-07-15T12:30:00Z".to_string(),
        evidence: vec![evidence_ref_from(
            "full-ime-family",
            "management-extension-primary",
        )],
    });

    let finding = finding_by_id(&derive_findings(&snapshot), "ime-evidence-unavailable").clone();
    assert_eq!(
        finding.coverage_gap_ids,
        vec!["management-extension-primary"]
    );
    assert_eq!(
        (
            finding.evidence[0].evidence_id.as_str(),
            finding.evidence[0].source_artifact_id.as_str(),
        ),
        ("full-ime-family", "management-extension-primary")
    );

    snapshot.coverage = vec![EspArtifactCoverage {
        artifact_id: "runtime-images".to_string(),
        family: "deployment-timers".to_string(),
        status: EspArtifactStatus::Missing,
        detail: Some("optional image inventory absent".to_string()),
        observed_at_utc: "2026-07-15T12:30:00Z".to_string(),
        evidence: vec![evidence_ref("unrelated-runtime-images")],
    }];
    assert!(derive_findings(&snapshot)
        .iter()
        .all(|finding| finding.finding_id != "ime-evidence-unavailable"));
}

fn findings_graph_overlay(app: EspGraphAppRecord) -> EspGraphOverlay {
    EspGraphOverlay {
        request_id: "request-findings".to_string(),
        requested_at_utc: "2026-07-15T12:30:00Z".to_string(),
        device_match: graph_section(
            GraphSectionStatus::Skipped,
            "DeviceManagementManagedDevices.Read.All",
            GraphApiVersion::V1_0,
            None,
            None,
        ),
        autopilot_identity: graph_section(
            GraphSectionStatus::Skipped,
            "DeviceManagementServiceConfig.Read.All",
            GraphApiVersion::V1_0,
            None,
            None,
        ),
        deployment_profile: graph_section(
            GraphSectionStatus::Skipped,
            "DeviceManagementServiceConfig.Read.All",
            GraphApiVersion::Beta,
            None,
            None,
        ),
        intended_deployment_profile: graph_section(
            GraphSectionStatus::Skipped,
            "DeviceManagementServiceConfig.Read.All",
            GraphApiVersion::Beta,
            None,
            None,
        ),
        profile_assignments: graph_section(
            GraphSectionStatus::Skipped,
            "DeviceManagementServiceConfig.Read.All",
            GraphApiVersion::Beta,
            None,
            None,
        ),
        autopilot_events: graph_section(
            GraphSectionStatus::Skipped,
            "DeviceManagementManagedDevices.Read.All",
            GraphApiVersion::Beta,
            None,
            None,
        ),
        enrollment_configuration: graph_section(
            GraphSectionStatus::Skipped,
            "DeviceManagementServiceConfig.Read.All",
            GraphApiVersion::V1_0,
            None,
            None,
        ),
        apps: graph_section(
            GraphSectionStatus::Available,
            "DeviceManagementApps.Read.All",
            GraphApiVersion::V1_0,
            Some(vec![app]),
            None,
        ),
        policies: graph_section(
            GraphSectionStatus::Skipped,
            "DeviceManagementConfiguration.Read.All",
            GraphApiVersion::V1_0,
            None,
            None,
        ),
        scripts: graph_section(
            GraphSectionStatus::Skipped,
            "DeviceManagementScripts.Read.All",
            GraphApiVersion::Beta,
            None,
            None,
        ),
    }
}

#[test]
fn findings_report_exact_local_graph_status_conflicts_with_both_sources() {
    let mut snapshot = findings_snapshot();
    snapshot.workloads.push(findings_workload(
        "app-conflict",
        EspTrackedKind::Win32App,
        EspNormalizedStatus::Failed,
        Some(false),
        "2026-07-15T12:29:00Z",
    ));

    let graph_app = EspGraphAppRecord {
        app_id: "app-conflict".to_string(),
        display_name: Some("Conflicting App".to_string()),
        tracked_on_enrollment_status: Some(true),
        status: Some(status(
            EspRawStatus::Text("installed".to_string()),
            EspNormalizedStatus::Succeeded,
        )),
        intent_state: not_requested_intent_state(),
        assignments: vec![],
        evidence: vec![evidence_ref_from("graph-app-succeeded", "graph-apps")],
    };

    let graph = findings_graph_overlay(graph_app);
    let original = snapshot.clone();
    assert!(derive_findings(&original)
        .iter()
        .all(|finding| finding.finding_id != "local-graph-state-conflict"));
    let snapshot = attach_graph_overlay(&snapshot, graph.clone());
    assert_eq!(original.graph, None);
    assert!(original
        .findings
        .iter()
        .all(|finding| finding.finding_id != "local-graph-state-conflict"));
    let finding = finding_by_id(&snapshot.findings, "local-graph-state-conflict").clone();
    assert_finding_contract(
        &finding,
        "local-graph-state-conflict",
        EspFindingSeverity::Warning,
        EspFindingConfidence::High,
        "Compare the cited local workload state with the current Intune Graph status.",
        &[
            ("evidence-app-conflict", "artifact-registry"),
            ("graph-app-succeeded", "graph-apps"),
        ],
        &[],
    );

    let mut unavailable_graph = graph.clone();
    unavailable_graph.apps.status = GraphSectionStatus::PermissionDenied;
    let unavailable = attach_graph_overlay(&snapshot, unavailable_graph);
    assert!(unavailable
        .findings
        .iter()
        .all(|finding| finding.finding_id != "local-graph-state-conflict"));

    let mut missing_graph_evidence = graph.clone();
    missing_graph_evidence.apps.data.as_mut().unwrap()[0]
        .evidence
        .clear();
    assert!(attach_graph_overlay(&snapshot, missing_graph_evidence)
        .findings
        .iter()
        .all(|finding| finding.finding_id != "local-graph-state-conflict"));

    let mut unmatched_graph = graph.clone();
    unmatched_graph.apps.data.as_mut().unwrap()[0].app_id = "unmatched-app".to_string();
    assert!(attach_graph_overlay(&snapshot, unmatched_graph)
        .findings
        .iter()
        .all(|finding| finding.finding_id != "local-graph-state-conflict"));

    let mut empty_local_id = snapshot.clone();
    empty_local_id.workloads[0].raw_identifier.clear();
    let mut empty_graph_id = graph.clone();
    empty_graph_id.apps.data.as_mut().unwrap()[0].app_id.clear();
    assert!(attach_graph_overlay(&empty_local_id, empty_graph_id)
        .findings
        .iter()
        .all(|finding| finding.finding_id != "local-graph-state-conflict"));

    let mut consistent = snapshot.clone();
    consistent.workloads[0].status.normalized = EspNormalizedStatus::Succeeded;
    assert!(attach_graph_overlay(&consistent, graph)
        .findings
        .iter()
        .all(|finding| finding.finding_id != "local-graph-state-conflict"));
}

#[test]
fn findings_report_cancelled_success_terminal_conflicts_in_both_directions() {
    let contradictory_statuses = [
        (
            EspNormalizedStatus::Cancelled,
            EspNormalizedStatus::Succeeded,
        ),
        (
            EspNormalizedStatus::Succeeded,
            EspNormalizedStatus::Cancelled,
        ),
        (
            EspNormalizedStatus::Cancelled,
            EspNormalizedStatus::Processed,
        ),
        (
            EspNormalizedStatus::Processed,
            EspNormalizedStatus::Cancelled,
        ),
        (EspNormalizedStatus::Cancelled, EspNormalizedStatus::Skipped),
        (EspNormalizedStatus::Skipped, EspNormalizedStatus::Cancelled),
        (
            EspNormalizedStatus::Cancelled,
            EspNormalizedStatus::Uninstalled,
        ),
        (
            EspNormalizedStatus::Uninstalled,
            EspNormalizedStatus::Cancelled,
        ),
    ];

    for (case_index, (local_status, graph_status)) in contradictory_statuses.into_iter().enumerate()
    {
        let app_id = format!("cancelled-conflict-{case_index}");
        let local_evidence_id = format!("local-cancelled-conflict-{case_index}");
        let graph_evidence_id = format!("graph-cancelled-conflict-{case_index}");
        let mut snapshot = findings_snapshot();
        let mut workload = findings_workload(
            &app_id,
            EspTrackedKind::Win32App,
            local_status,
            Some(true),
            "2026-07-15T12:29:00Z",
        );
        workload.evidence = vec![evidence_ref_from(&local_evidence_id, "artifact-registry")];
        snapshot.workloads.push(workload);

        let graph_app = EspGraphAppRecord {
            app_id,
            display_name: Some("Terminal conflict".to_string()),
            tracked_on_enrollment_status: Some(true),
            status: Some(status(
                EspRawStatus::Text(format!("graph-status-{case_index}")),
                graph_status,
            )),
            intent_state: not_requested_intent_state(),
            assignments: vec![],
            evidence: vec![evidence_ref_from(&graph_evidence_id, "graph-apps")],
        };

        let overlaid = attach_graph_overlay(&snapshot, findings_graph_overlay(graph_app));
        assert_finding_contract(
            finding_by_id(&overlaid.findings, "local-graph-state-conflict"),
            "local-graph-state-conflict",
            EspFindingSeverity::Warning,
            EspFindingConfidence::High,
            "Compare the cited local workload state with the current Intune Graph status.",
            &[
                (graph_evidence_id.as_str(), "graph-apps"),
                (local_evidence_id.as_str(), "artifact-registry"),
            ],
            &[],
        );
    }
}

#[test]
fn findings_do_not_report_noncontradictory_cancelled_graph_pairs() {
    let noncontradictory_statuses = [
        (
            EspNormalizedStatus::Cancelled,
            EspNormalizedStatus::Cancelled,
        ),
        (EspNormalizedStatus::Cancelled, EspNormalizedStatus::Failed),
        (EspNormalizedStatus::Failed, EspNormalizedStatus::Cancelled),
        (EspNormalizedStatus::Cancelled, EspNormalizedStatus::Pending),
        (EspNormalizedStatus::Pending, EspNormalizedStatus::Cancelled),
        (
            EspNormalizedStatus::Cancelled,
            EspNormalizedStatus::Installing,
        ),
        (
            EspNormalizedStatus::Installing,
            EspNormalizedStatus::Cancelled,
        ),
    ];

    for (case_index, (local_status, graph_status)) in
        noncontradictory_statuses.into_iter().enumerate()
    {
        let app_id = format!("cancelled-consistent-{case_index}");
        let mut snapshot = findings_snapshot();
        snapshot.workloads.push(findings_workload(
            &app_id,
            EspTrackedKind::Win32App,
            local_status,
            Some(true),
            "2026-07-15T12:29:00Z",
        ));
        let graph_app = EspGraphAppRecord {
            app_id,
            display_name: None,
            tracked_on_enrollment_status: Some(true),
            status: Some(status(
                EspRawStatus::Text(format!("graph-status-{case_index}")),
                graph_status,
            )),
            intent_state: not_requested_intent_state(),
            assignments: vec![],
            evidence: vec![evidence_ref_from(
                &format!("graph-cancelled-consistent-{case_index}"),
                "graph-apps",
            )],
        };

        assert!(
            attach_graph_overlay(&snapshot, findings_graph_overlay(graph_app))
                .findings
                .iter()
                .all(|finding| finding.finding_id != "local-graph-state-conflict"),
            "case {case_index} produced a false-positive conflict"
        );
    }
}

#[test]
fn findings_report_policy_certificate_and_script_graph_conflicts() {
    let mut snapshot = findings_snapshot();
    snapshot.workloads = vec![
        findings_workload(
            "policy-conflict",
            EspTrackedKind::Policy,
            EspNormalizedStatus::Failed,
            Some(true),
            "2026-07-15T12:29:00Z",
        ),
        findings_workload(
            "scep-conflict",
            EspTrackedKind::ScepCertificate,
            EspNormalizedStatus::Failed,
            Some(true),
            "2026-07-15T12:29:00Z",
        ),
        findings_workload(
            "script-conflict",
            EspTrackedKind::PlatformScript,
            EspNormalizedStatus::Succeeded,
            Some(true),
            "2026-07-15T12:29:00Z",
        ),
    ];
    let unrelated_app = EspGraphAppRecord {
        app_id: "unrelated-app".to_string(),
        display_name: None,
        tracked_on_enrollment_status: Some(true),
        status: Some(status(
            EspRawStatus::Text("installed".to_string()),
            EspNormalizedStatus::Succeeded,
        )),
        intent_state: not_requested_intent_state(),
        assignments: vec![],
        evidence: vec![evidence_ref_from("graph-unrelated-app", "graph-apps")],
    };
    let mut graph = findings_graph_overlay(unrelated_app);
    graph.policies = graph_section(
        GraphSectionStatus::Available,
        "DeviceManagementConfiguration.Read.All",
        GraphApiVersion::V1_0,
        Some(vec![
            EspGraphPolicyRecord {
                policy_id: "POLICY-CONFLICT".to_string(),
                display_name: None,
                kind: EspGraphPolicyKind::DeviceConfiguration,
                status: Some(status(
                    EspRawStatus::Text("succeeded".to_string()),
                    EspNormalizedStatus::Succeeded,
                )),
                assignments: vec![],
                evidence: vec![evidence_ref_from(
                    "graph-policy-succeeded",
                    "graph-policies",
                )],
            },
            EspGraphPolicyRecord {
                policy_id: "scep-conflict".to_string(),
                display_name: None,
                kind: EspGraphPolicyKind::ScepCertificate,
                status: Some(status(
                    EspRawStatus::Text("processed".to_string()),
                    EspNormalizedStatus::Processed,
                )),
                assignments: vec![],
                evidence: vec![evidence_ref_from("graph-scep-succeeded", "graph-policies")],
            },
        ]),
        None,
    );
    graph.scripts = graph_section(
        GraphSectionStatus::Available,
        "DeviceManagementScripts.Read.All",
        GraphApiVersion::Beta,
        Some(vec![EspGraphScriptRecord {
            script_id: "script-conflict".to_string(),
            display_name: None,
            kind: EspGraphScriptKind::PlatformScript,
            status: Some(status(
                EspRawStatus::Text("failed".to_string()),
                EspNormalizedStatus::Failed,
            )),
            assignments: vec![],
            evidence: vec![evidence_ref_from("graph-script-failed", "graph-scripts")],
        }]),
        None,
    );
    snapshot.graph = Some(graph);

    assert_finding_contract(
        finding_by_id(&derive_findings(&snapshot), "local-graph-state-conflict"),
        "local-graph-state-conflict",
        EspFindingSeverity::Warning,
        EspFindingConfidence::High,
        "Compare the cited local workload state with the current Intune Graph status.",
        &[
            ("evidence-policy-conflict", "artifact-registry"),
            ("evidence-scep-conflict", "artifact-registry"),
            ("evidence-script-conflict", "artifact-registry"),
            ("graph-policy-succeeded", "graph-policies"),
            ("graph-scep-succeeded", "graph-policies"),
            ("graph-script-failed", "graph-scripts"),
        ],
        &[],
    );
}

#[test]
fn findings_completed_session_emits_only_evidence_backed_info() {
    let mut snapshot = findings_snapshot();
    snapshot.phase = EspPhase::Completed;
    snapshot.sessions.push(EspSession {
        session_id: "session-completed".to_string(),
        kind: EspSessionKind::Classic,
        scope: EspScope::Device,
        user_sid: None,
        started_at: Some(timestamp("2026-07-15T12:00:00Z")),
        ended_at: Some(timestamp("2026-07-15T12:10:00Z")),
        phase: EspPhase::Completed,
        is_latest: true,
        workload_ids: vec!["workload-app-success".to_string()],
        evidence: vec![evidence_ref_from(
            "session-completed",
            "esp-session-registry",
        )],
    });
    let mut successful_workload = findings_workload(
        "app-success",
        EspTrackedKind::Win32App,
        EspNormalizedStatus::Succeeded,
        Some(true),
        "2026-07-15T12:10:00Z",
    );
    successful_workload.session_id = "session-completed".to_string();
    successful_workload.evidence = vec![evidence_ref_from(
        "evidence-app-success",
        "esp-session-registry",
    )];
    snapshot.workloads.push(successful_workload);
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: "esp-session-registry".to_string(),
        family: "ESP session evidence".to_string(),
        status: EspArtifactStatus::Available,
        detail: None,
        observed_at_utc: "2026-07-15T12:10:00Z".to_string(),
        evidence: vec![evidence_ref_from(
            "coverage-complete",
            "esp-session-registry",
        )],
    });

    let findings = derive_findings(&snapshot);
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.finding_id.as_str())
            .collect::<Vec<_>>(),
        vec!["esp-completed"]
    );
    assert_finding_contract(
        &findings[0],
        "esp-completed",
        EspFindingSeverity::Info,
        EspFindingConfidence::High,
        "Review the cited completed session and terminal workload states.",
        &[
            ("evidence-app-success", "esp-session-registry"),
            ("session-completed", "esp-session-registry"),
        ],
        &[],
    );
}

fn completion_snapshot_with_duplicate_workload_ids(
    old_status: EspNormalizedStatus,
    current_status: EspNormalizedStatus,
) -> EspDiagnosticsSnapshot {
    let mut snapshot = findings_snapshot();
    snapshot.phase = EspPhase::Completed;
    snapshot.sessions = vec![
        EspSession {
            session_id: "session-old".to_string(),
            kind: EspSessionKind::Classic,
            scope: EspScope::Device,
            user_sid: None,
            started_at: Some(timestamp("2026-07-15T11:00:00Z")),
            ended_at: Some(timestamp("2026-07-15T11:10:00Z")),
            phase: EspPhase::Completed,
            is_latest: false,
            workload_ids: vec!["workload-duplicate".to_string()],
            evidence: vec![evidence_ref_from("old-session", "old-source")],
        },
        EspSession {
            session_id: "session-current".to_string(),
            kind: EspSessionKind::Classic,
            scope: EspScope::Device,
            user_sid: None,
            started_at: Some(timestamp("2026-07-15T12:00:00Z")),
            ended_at: Some(timestamp("2026-07-15T12:10:00Z")),
            phase: EspPhase::Completed,
            is_latest: true,
            workload_ids: vec!["workload-duplicate".to_string()],
            evidence: vec![evidence_ref_from("current-session", "current-source")],
        },
    ];
    let mut old_workload = findings_workload(
        "old-duplicate",
        EspTrackedKind::Win32App,
        old_status,
        Some(true),
        "2026-07-15T11:10:00Z",
    );
    old_workload.workload_id = "workload-duplicate".to_string();
    old_workload.session_id = "session-old".to_string();
    old_workload.evidence = vec![evidence_ref_from("old-workload", "old-source")];
    let mut current_workload = findings_workload(
        "current-duplicate",
        EspTrackedKind::Win32App,
        current_status,
        Some(true),
        "2026-07-15T12:10:00Z",
    );
    current_workload.workload_id = "workload-duplicate".to_string();
    current_workload.session_id = "session-current".to_string();
    current_workload.evidence = vec![evidence_ref_from("current-workload", "current-source")];
    snapshot.workloads = vec![old_workload, current_workload];
    snapshot.coverage = ["old-source", "current-source"]
        .into_iter()
        .map(|source| EspArtifactCoverage {
            artifact_id: source.to_string(),
            family: "ESP supporting evidence".to_string(),
            status: EspArtifactStatus::Available,
            detail: None,
            observed_at_utc: "2026-07-15T12:10:00Z".to_string(),
            evidence: vec![evidence_ref_from(&format!("coverage-{source}"), source)],
        })
        .collect();
    snapshot
}

#[test]
fn findings_success_does_not_use_succeeded_duplicate_from_non_latest_session() {
    let snapshot = completion_snapshot_with_duplicate_workload_ids(
        EspNormalizedStatus::Succeeded,
        EspNormalizedStatus::Failed,
    );

    let findings = derive_findings(&snapshot);
    assert!(findings
        .iter()
        .all(|finding| finding.finding_id != "esp-completed"));
    assert_eq!(
        finding_by_id(&findings, "blocking-app-failed").evidence,
        vec![evidence_ref_from("current-workload", "current-source")]
    );
}

#[test]
fn findings_success_uses_succeeded_duplicate_from_latest_session() {
    let snapshot = completion_snapshot_with_duplicate_workload_ids(
        EspNormalizedStatus::Failed,
        EspNormalizedStatus::Succeeded,
    );

    let finding = finding_by_id(&derive_findings(&snapshot), "esp-completed").clone();
    assert_eq!(
        finding.evidence,
        vec![
            evidence_ref_from("current-session", "current-source"),
            evidence_ref_from("current-workload", "current-source"),
        ]
    );
    assert!(finding
        .evidence
        .iter()
        .all(|evidence| !evidence.evidence_id.starts_with("old-")));
}

#[test]
fn findings_success_requires_observed_declared_workloads_and_relevant_coverage() {
    let completed_session = |workload_ids: Vec<String>| EspSession {
        session_id: "session-completed".to_string(),
        kind: EspSessionKind::Classic,
        scope: EspScope::Device,
        user_sid: None,
        started_at: Some(timestamp("2026-07-15T12:00:00Z")),
        ended_at: Some(timestamp("2026-07-15T12:10:00Z")),
        phase: EspPhase::Completed,
        is_latest: true,
        workload_ids,
        evidence: vec![evidence_ref_from(
            "session-completed",
            "esp-session-registry",
        )],
    };
    let available_coverage = || EspArtifactCoverage {
        artifact_id: "esp-session-registry".to_string(),
        family: "ESP session evidence".to_string(),
        status: EspArtifactStatus::Available,
        detail: None,
        observed_at_utc: "2026-07-15T12:10:00Z".to_string(),
        evidence: vec![evidence_ref_from(
            "coverage-complete",
            "esp-session-registry",
        )],
    };
    let has_success = |snapshot: &EspDiagnosticsSnapshot| {
        derive_findings(snapshot)
            .iter()
            .any(|finding| finding.finding_id == "esp-completed")
    };

    let mut no_workloads = findings_snapshot();
    no_workloads.phase = EspPhase::Completed;
    no_workloads.sessions.push(completed_session(vec![]));
    no_workloads.coverage.push(available_coverage());
    assert!(!has_success(&no_workloads));

    let mut unobserved_declared = findings_snapshot();
    unobserved_declared.phase = EspPhase::Completed;
    unobserved_declared
        .sessions
        .push(completed_session(vec!["workload-not-observed".to_string()]));
    let mut unrelated_workload = findings_workload(
        "different-success",
        EspTrackedKind::Win32App,
        EspNormalizedStatus::Succeeded,
        Some(true),
        "2026-07-15T12:10:00Z",
    );
    unrelated_workload.session_id = "session-completed".to_string();
    unrelated_workload.evidence = vec![evidence_ref_from(
        "evidence-different-success",
        "esp-session-registry",
    )];
    unobserved_declared.workloads.push(unrelated_workload);
    unobserved_declared.coverage.push(available_coverage());
    assert!(!has_success(&unobserved_declared));

    let mut missing_coverage = findings_snapshot();
    missing_coverage.phase = EspPhase::Completed;
    missing_coverage
        .sessions
        .push(completed_session(vec!["workload-app-success".to_string()]));
    let mut observed_workload = findings_workload(
        "app-success",
        EspTrackedKind::Win32App,
        EspNormalizedStatus::Succeeded,
        Some(true),
        "2026-07-15T12:10:00Z",
    );
    observed_workload.session_id = "session-completed".to_string();
    observed_workload.evidence = vec![evidence_ref_from(
        "evidence-app-success",
        "esp-session-registry",
    )];
    missing_coverage.workloads.push(observed_workload);
    let mut gap = available_coverage();
    gap.status = EspArtifactStatus::PermissionDenied;
    missing_coverage.coverage.push(gap);
    assert!(!has_success(&missing_coverage));
}

#[test]
fn findings_success_ignores_unrelated_optional_coverage_gaps() {
    let mut snapshot = findings_snapshot();
    snapshot.phase = EspPhase::Completed;
    snapshot.sessions.push(EspSession {
        session_id: "session-completed".to_string(),
        kind: EspSessionKind::Classic,
        scope: EspScope::Device,
        user_sid: None,
        started_at: Some(timestamp("2026-07-15T12:00:00Z")),
        ended_at: Some(timestamp("2026-07-15T12:10:00Z")),
        phase: EspPhase::Completed,
        is_latest: true,
        workload_ids: vec!["workload-app-success".to_string()],
        evidence: vec![evidence_ref_from(
            "session-completed",
            "esp-session-registry",
        )],
    });
    let mut successful_workload = findings_workload(
        "app-success",
        EspTrackedKind::Win32App,
        EspNormalizedStatus::Succeeded,
        Some(true),
        "2026-07-15T12:10:00Z",
    );
    successful_workload.session_id = "session-completed".to_string();
    successful_workload.evidence = vec![evidence_ref_from(
        "evidence-app-success",
        "esp-session-registry",
    )];
    snapshot.workloads.push(successful_workload);
    snapshot.coverage = vec![
        EspArtifactCoverage {
            artifact_id: "esp-session-registry".to_string(),
            family: "ESP session evidence".to_string(),
            status: EspArtifactStatus::Available,
            detail: None,
            observed_at_utc: "2026-07-15T12:10:00Z".to_string(),
            evidence: vec![evidence_ref_from(
                "coverage-complete",
                "esp-session-registry",
            )],
        },
        EspArtifactCoverage {
            artifact_id: "optional-patchmypc-logs".to_string(),
            family: "Optional software deployment logs".to_string(),
            status: EspArtifactStatus::Missing,
            detail: Some("product is not installed".to_string()),
            observed_at_utc: "2026-07-15T12:10:00Z".to_string(),
            evidence: vec![evidence_ref_from(
                "optional-patchmypc-missing",
                "optional-patchmypc-logs",
            )],
        },
    ];

    assert!(derive_findings(&snapshot)
        .iter()
        .any(|finding| finding.finding_id == "esp-completed"));
}

#[test]
fn findings_success_requires_available_coverage_for_every_supporting_source() {
    let completed_session =
        |session_id: &str, workload_id: &str, source_artifact_id: &str| EspSession {
            session_id: session_id.to_string(),
            kind: EspSessionKind::Classic,
            scope: EspScope::Device,
            user_sid: None,
            started_at: Some(timestamp("2026-07-15T12:00:00Z")),
            ended_at: Some(timestamp("2026-07-15T12:10:00Z")),
            phase: EspPhase::Completed,
            is_latest: true,
            workload_ids: vec![workload_id.to_string()],
            evidence: vec![evidence_ref_from(
                &format!("evidence-{session_id}"),
                source_artifact_id,
            )],
        };
    let successful_workload = |workload_id: &str, session_id: &str, source_artifact_id: &str| {
        let mut workload = findings_workload(
            workload_id,
            EspTrackedKind::Win32App,
            EspNormalizedStatus::Succeeded,
            Some(true),
            "2026-07-15T12:10:00Z",
        );
        workload.workload_id = workload_id.to_string();
        workload.session_id = session_id.to_string();
        workload.evidence = vec![evidence_ref_from(
            &format!("evidence-{workload_id}"),
            source_artifact_id,
        )];
        workload
    };
    let available_coverage = |source_artifact_id: &str| EspArtifactCoverage {
        artifact_id: source_artifact_id.to_string(),
        family: "ESP supporting evidence".to_string(),
        status: EspArtifactStatus::Available,
        detail: None,
        observed_at_utc: "2026-07-15T12:10:00Z".to_string(),
        evidence: vec![evidence_ref_from(
            &format!("coverage-{source_artifact_id}"),
            source_artifact_id,
        )],
    };
    let has_success = |snapshot: &EspDiagnosticsSnapshot| {
        derive_findings(snapshot)
            .iter()
            .any(|finding| finding.finding_id == "esp-completed")
    };

    let mut snapshot = findings_snapshot();
    snapshot.phase = EspPhase::Completed;
    snapshot.sessions = vec![
        completed_session("session-a", "workload-a", "source-a"),
        completed_session("session-b", "workload-b", "source-b"),
    ];
    snapshot.workloads = vec![
        successful_workload("workload-a", "session-a", "source-a"),
        successful_workload("workload-b", "session-b", "source-b"),
    ];
    snapshot.coverage = vec![available_coverage("source-a")];

    assert!(!has_success(&snapshot));

    snapshot.coverage.push(available_coverage("source-b"));
    assert!(has_success(&snapshot));
}

#[test]
fn findings_reducer_snapshot_populates_rules_without_mutating_raw_evidence() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T12:30:00Z".to_string());
    reducer.ingest(EspEvidenceRecord::Coverage(EspArtifactCoverage {
        artifact_id: "ime-logs".to_string(),
        family: "IME logs".to_string(),
        status: EspArtifactStatus::Missing,
        detail: Some("not found".to_string()),
        observed_at_utc: "2026-07-15T12:30:00Z".to_string(),
        evidence: vec![evidence_ref_from("ime-missing", "ime-logs")],
    }));

    let snapshot = reducer.snapshot();
    assert_eq!(snapshot.coverage.len(), 1);
    let finding = finding_by_id(&snapshot.findings, "ime-evidence-unavailable");
    assert_eq!(
        finding
            .evidence
            .iter()
            .map(|evidence| (
                evidence.evidence_id.as_str(),
                evidence.source_artifact_id.as_str(),
            ))
            .collect::<Vec<_>>(),
        vec![("ime-missing", "ime-logs")]
    );
    assert_eq!(finding.coverage_gap_ids, vec!["ime-logs"]);
}

fn raw_export_record(
    id: &str,
    source_kind: EspSourceKind,
    source_artifact_id: &str,
    registry_value_name: Option<&str>,
    value: &str,
) -> EspRawEvidenceRecord {
    EspRawEvidenceRecord {
        record_id: id.to_string(),
        provenance: EspEvidenceProvenance {
            source_kind,
            source_artifact_id: source_artifact_id.to_string(),
            file_path: None,
            line_number: Some(1),
            record_number: None,
            registry: registry_value_name.map(|value_name| EspRegistryProvenance {
                hive: "HKLM".to_string(),
                key: r"SOFTWARE\Microsoft\Provisioning".to_string(),
                value_name: Some(value_name.to_string()),
            }),
            event: None,
        },
        source_timestamp: Some(timestamp("2026-07-15T12:00:00Z")),
        observed_at_utc: "2026-07-15T12:00:01Z".to_string(),
        raw_value: EspObservationValue::Text(value.to_string()),
        sensitivity: EspSensitivity::Sensitive,
        parse_state: EspParseState::Raw,
        access_state: EspSourceAccessState::Available,
        evidence: vec![evidence_ref_from(id, source_artifact_id)],
    }
}

#[test]
fn redaction_projection_removes_json_quoted_tokens_and_authorization() {
    let mut snapshot = findings_snapshot();
    let mut access_token = raw_export_record(
        "json-secret-one",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        r#"{"access_token":"opaque-access-token-value"}"#,
    );
    access_token.sensitivity = EspSensitivity::Public;
    let mut authorization = raw_export_record(
        "json-secret-two",
        EspSourceKind::ImeLog,
        "ime-log",
        None,
        r#"{"authorization" : "opaque-authorization-value"}"#,
    );
    authorization.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![access_token, authorization];

    assert!(redacted_export_projection(&snapshot)
        .raw_evidence
        .is_empty());
    assert_eq!(snapshot.raw_evidence.len(), 2);
}

#[test]
fn redaction_projection_masks_json_quoted_secret_keys() {
    let mut snapshot = findings_snapshot();
    let mut api_key = raw_export_record(
        "json-config",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        r#"{"api_key" : "opaque-api-key-value", "state":"safe"}"#,
    );
    api_key.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![api_key];

    let safe = redacted_export_projection(&snapshot);
    let EspObservationValue::Text(value) = &safe.raw_evidence[0].raw_value else {
        panic!("expected text raw evidence")
    };
    assert!(!value.contains("opaque-api-key-value"));
    assert!(value.contains("[redacted]"));
    assert!(value.contains("safe"));
}

#[test]
fn redaction_projection_masks_registration_named_data_by_label() {
    let mut snapshot = findings_snapshot();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "TenantId".to_string(),
                value: "opaque-tenant-guid".to_string(),
            },
            EspNamedValue {
                name: "AccessToken".to_string(),
                value: "opaque-registration-token".to_string(),
            },
            EspNamedValue {
                name: "State".to_string(),
                value: "safe-state".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-sensitive")],
    });

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.registration_events[0].named_data[0].value,
        "[redacted]"
    );
    assert_eq!(
        safe.registration_events[0].named_data[1].value,
        "[redacted]"
    );
    assert_eq!(
        safe.registration_events[0].named_data[2].value,
        "safe-state"
    );
    assert_eq!(
        snapshot.registration_events[0].named_data[0].value,
        "opaque-tenant-guid"
    );
}

#[test]
fn redaction_projection_masks_standalone_bearer_tokens_in_generic_named_data() {
    let direct_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature123";
    let structured_token = "opaque-token-value-1234567890";
    let prose_shaped_arbitrary_value = "Bearer authentication is required for this endpoint";
    let named_data = || {
        vec![
            EspNamedValue {
                name: "Payload".to_string(),
                value: format!("bEaReR {direct_token}"),
            },
            EspNamedValue {
                name: "StructuredPayload".to_string(),
                value: format!(r#"{{"payload":"BEARER {structured_token}","state":"safe"}}"#),
            },
            EspNamedValue {
                name: "Description".to_string(),
                value: prose_shaped_arbitrary_value.to_string(),
            },
            EspNamedValue {
                name: "PayloadWithContext".to_string(),
                value: format!("Bearer {direct_token} expires soon"),
            },
        ]
    };
    let mut snapshot = findings_snapshot();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: named_data(),
        evidence: vec![evidence_ref("registration-bearer")],
    });
    let mut raw = raw_export_record(
        "raw-event-bearer",
        EspSourceKind::EventLog,
        "event-log",
        None,
        "safe raw event payload",
    );
    raw.sensitivity = EspSensitivity::Public;
    raw.provenance.event = Some(EspEventProvenance {
        channel: "Generic event channel".to_string(),
        event_id: 1,
        record_id: Some(1),
        named_data: named_data(),
    });
    snapshot.raw_evidence = vec![raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();
    for fragment in [
        direct_token,
        "eyJhbGciOiJIUzI1NiJ9",
        "signature123",
        structured_token,
        "opaque-token-value",
        "1234567890",
    ] {
        assert!(
            !safe_json.contains(fragment),
            "safe export leaked {fragment}"
        );
    }
    for values in [
        &safe.registration_events[0].named_data,
        &safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data,
    ] {
        assert_eq!(values[0].value, "bEaReR [redacted]");
        assert!(values[1].value.contains(r#""payload":"BEARER [redacted]"#));
        assert!(values[1].value.contains(r#""state":"safe""#));
        assert_eq!(
            values[2].value,
            "Bearer [redacted] is required for this endpoint"
        );
        assert_eq!(values[3].value, "Bearer [redacted] expires soon");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_short_alphabetic_bearers_across_safe_export_paths() {
    let short_token = "Q";
    let medium_token = "qwertyz";
    let mut snapshot = findings_snapshot();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: vec![EspNamedValue {
            name: "Payload".to_string(),
            value: format!("Bearer {short_token}"),
        }],
        evidence: vec![evidence_ref("registration-short-bearer")],
    });

    let mut named_value = raw_export_record(
        "raw-named-bearer",
        EspSourceKind::EventLog,
        "event-log",
        None,
        "safe raw event payload",
    );
    named_value.sensitivity = EspSensitivity::Public;
    named_value.provenance.event = Some(EspEventProvenance {
        channel: "Generic event channel".to_string(),
        event_id: 1,
        record_id: Some(1),
        named_data: vec![EspNamedValue {
            name: "Payload".to_string(),
            value: format!("Bearer {medium_token}"),
        }],
    });

    let mut raw_text = raw_export_record(
        "raw-text-bearer",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        &format!("Bearer {short_token}"),
    );
    raw_text.sensitivity = EspSensitivity::Public;
    let mut raw_list = raw_export_record(
        "raw-list-bearer",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "placeholder",
    );
    raw_list.sensitivity = EspSensitivity::Public;
    raw_list.raw_value = EspObservationValue::StringList(vec![
        "safe list value".to_string(),
        format!("Bearer {medium_token}"),
    ]);
    snapshot.raw_evidence = vec![named_value, raw_text, raw_list];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.registration_events[0].named_data[0].value,
        "Bearer [redacted]"
    );
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["raw-named-bearer"]
    );
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data[0]
            .value,
        "Bearer [redacted]"
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    assert!(!safe_json.contains(&format!("Bearer {short_token}")));
    assert!(!safe_json.contains(medium_token));
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_generic_token_labels_without_matching_token_count() {
    let mut snapshot = findings_snapshot();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "Token".to_string(),
                value: "abcdefgh".to_string(),
            },
            EspNamedValue {
                name: "AuthToken".to_string(),
                value: "ijklmnop".to_string(),
            },
            EspNamedValue {
                name: "BearerToken".to_string(),
                value: "qrstuvwx".to_string(),
            },
            EspNamedValue {
                name: "Password".to_string(),
                value: "passwordvalue".to_string(),
            },
            EspNamedValue {
                name: "ClientSecret".to_string(),
                value: "clientsecretvalue".to_string(),
            },
            EspNamedValue {
                name: "ApiKey".to_string(),
                value: "apikeyvalue".to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "5".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-token-labels")],
    });

    let mut event_token = raw_export_record(
        "raw-event-token-label",
        EspSourceKind::EventLog,
        "event-log",
        None,
        "safe raw event payload",
    );
    event_token.sensitivity = EspSensitivity::Public;
    event_token.provenance.event = Some(EspEventProvenance {
        channel: "Generic event channel".to_string(),
        event_id: 1,
        record_id: Some(1),
        named_data: vec![EspNamedValue {
            name: "Token".to_string(),
            value: "abcdefgh".to_string(),
        }],
    });
    let mut registry_auth_token = raw_export_record(
        "raw-registry-auth-token",
        EspSourceKind::Registry,
        "registry",
        Some("AuthToken"),
        "ijklmnop",
    );
    registry_auth_token.sensitivity = EspSensitivity::Public;
    let mut registry_client_secret = raw_export_record(
        "raw-registry-client-secret",
        EspSourceKind::Registry,
        "registry",
        Some("ClientSecret"),
        "clientsecretvalue",
    );
    registry_client_secret.sensitivity = EspSensitivity::Public;
    let mut registry_api_key = raw_export_record(
        "raw-registry-api-key",
        EspSourceKind::Registry,
        "registry",
        Some("ApiKey"),
        "apikeyvalue",
    );
    registry_api_key.sensitivity = EspSensitivity::Public;
    let mut token_count = raw_export_record(
        "raw-token-count",
        EspSourceKind::Registry,
        "registry",
        Some("TokenCount"),
        "5",
    );
    token_count.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![
        event_token,
        registry_auth_token,
        registry_client_secret,
        registry_api_key,
        token_count,
    ];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "[redacted]",
            "[redacted]",
            "[redacted]",
            "[redacted]",
            "[redacted]",
            "[redacted]",
            "5",
        ]
    );
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["raw-token-count"]
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for credential in [
        "abcdefgh",
        "ijklmnop",
        "qrstuvwx",
        "passwordvalue",
        "clientsecretvalue",
        "apikeyvalue",
    ] {
        assert!(!safe_json.contains(credential));
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_removes_all_bearer_shapes_from_arbitrary_raw_evidence() {
    let mut token_text = raw_export_record(
        "bearer-token-text",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "BEARER opaque-token-value-1234567890",
    );
    token_text.sensitivity = EspSensitivity::Public;
    let mut token_list = raw_export_record(
        "bearer-token-list",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "placeholder",
    );
    token_list.sensitivity = EspSensitivity::Public;
    token_list.raw_value = EspObservationValue::StringList(vec![
        "safe list value".to_string(),
        "bEaReR eyJhbGciOiJIUzI1NiJ9.payload.signature123 expires soon".to_string(),
    ]);
    let mut prose_text = raw_export_record(
        "bearer-prose-text",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "Bearer authentication remains available",
    );
    prose_text.sensitivity = EspSensitivity::Public;
    let mut prose_list = raw_export_record(
        "bearer-prose-list",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "placeholder",
    );
    prose_list.sensitivity = EspSensitivity::Public;
    prose_list.raw_value = EspObservationValue::StringList(vec![
        "Bearer authentication remains available".to_string(),
        "Bearer scheme negotiation was retried".to_string(),
    ]);
    let mut snapshot = findings_snapshot();
    snapshot.raw_evidence = vec![token_text, token_list, prose_text, prose_list];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert!(safe.raw_evidence.is_empty());
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_quoted_and_descriptor_bearers_in_arbitrary_evidence() {
    let arbitrary_values = || {
        vec![
            EspNamedValue {
                name: "DoubleQuotedPayload".to_string(),
                value: r#"Bearer "Q""#.to_string(),
            },
            EspNamedValue {
                name: "SingleQuotedPayload".to_string(),
                value: "Bearer 'Z'".to_string(),
            },
            EspNamedValue {
                name: "DescriptorPayload".to_string(),
                value: "Bearer token expires soon".to_string(),
            },
            EspNamedValue {
                name: "ProseShapedPayload".to_string(),
                value: "Bearer authorization is required".to_string(),
            },
        ]
    };
    let mut snapshot = findings_snapshot();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: arbitrary_values(),
        evidence: vec![evidence_ref("registration-arbitrary-bearers")],
    });

    let mut named_value = raw_export_record(
        "raw-named-arbitrary-bearers",
        EspSourceKind::EventLog,
        "event-log",
        None,
        "safe raw event payload",
    );
    named_value.sensitivity = EspSensitivity::Public;
    named_value.provenance.event = Some(EspEventProvenance {
        channel: "Generic event channel".to_string(),
        event_id: 1,
        record_id: Some(1),
        named_data: arbitrary_values(),
    });

    let mut raw_text = raw_export_record(
        "raw-double-quoted-bearer",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        r#"Bearer "Q""#,
    );
    raw_text.sensitivity = EspSensitivity::Public;
    let mut raw_list = raw_export_record(
        "raw-single-quoted-bearer",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "placeholder",
    );
    raw_list.sensitivity = EspSensitivity::Public;
    raw_list.raw_value = EspObservationValue::StringList(vec![
        "safe list value".to_string(),
        "Bearer 'Z'".to_string(),
    ]);
    let mut raw_descriptor = raw_export_record(
        "raw-descriptor-bearer",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "Bearer token expires soon",
    );
    raw_descriptor.sensitivity = EspSensitivity::Public;
    let mut raw_prose_shape = raw_export_record(
        "raw-prose-shaped-bearer",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "Bearer authorization is required",
    );
    raw_prose_shape.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![
        named_value,
        raw_text,
        raw_list,
        raw_descriptor,
        raw_prose_shape,
    ];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let expected_values = vec![
        "Bearer [redacted]",
        "Bearer [redacted]",
        "Bearer [redacted] expires soon",
        "Bearer [redacted] is required",
    ];
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        expected_values
    );
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["raw-named-arbitrary-bearers"]
    );
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        expected_values
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for credential in [r#"Bearer "Q""#, "Bearer 'Z'", "Bearer token"] {
        assert!(
            !safe_json.contains(credential),
            "safe export leaked {credential}"
        );
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_preserves_safe_bearer_prose_only_in_typed_narratives() {
    let mut snapshot = findings_snapshot();
    snapshot.registration_events = vec![
        EspRegistrationEvent {
            event_id: 304,
            record_id: Some(42),
            status: status(
                EspRawStatus::Text("failed".to_string()),
                EspNormalizedStatus::Failed,
            ),
            message: "Bearer authorization is required".to_string(),
            timestamp: timestamp("2026-07-15T12:00:00Z"),
            named_data: vec![],
            evidence: vec![evidence_ref("registration-safe-bearer-prose")],
        },
        EspRegistrationEvent {
            event_id: 304,
            record_id: Some(43),
            status: status(
                EspRawStatus::Text("failed".to_string()),
                EspNormalizedStatus::Failed,
            ),
            message: r#"Bearer "Q" expires soon"#.to_string(),
            timestamp: timestamp("2026-07-15T12:01:00Z"),
            named_data: vec![],
            evidence: vec![evidence_ref("registration-quoted-bearer")],
        },
    ];
    snapshot.activity = vec![
        EspTimelineEntry {
            entry_id: "safe-bearer-prose".to_string(),
            timestamp: timestamp("2026-07-15T12:02:00Z"),
            kind: EspTimelineKind::Other,
            title: "Bearer token support is enabled".to_string(),
            detail: Some("Bearer authentication remains available".to_string()),
            status: None,
            evidence: vec![evidence_ref("timeline-safe-bearer-prose")],
        },
        EspTimelineEntry {
            entry_id: "true-bearer-credential".to_string(),
            timestamp: timestamp("2026-07-15T12:03:00Z"),
            kind: EspTimelineKind::Other,
            title: "Bearer qwertyz expires soon".to_string(),
            detail: None,
            status: None,
            evidence: vec![evidence_ref("timeline-bearer-credential")],
        },
        EspTimelineEntry {
            entry_id: "descriptor-bearer-credential".to_string(),
            timestamp: timestamp("2026-07-15T12:03:30Z"),
            kind: EspTimelineKind::Other,
            title: "Bearer token expires soon".to_string(),
            detail: None,
            status: None,
            evidence: vec![evidence_ref("timeline-descriptor-bearer-credential")],
        },
    ];
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: "safe-prose".to_string(),
        family: "Safe prose".to_string(),
        status: EspArtifactStatus::Available,
        detail: Some("Bearer scheme negotiation was retried".to_string()),
        observed_at_utc: "2026-07-15T12:04:00Z".to_string(),
        evidence: vec![evidence_ref("coverage-safe-bearer-prose")],
    });
    let mut graph = findings_graph_overlay(EspGraphAppRecord {
        app_id: "safe-prose-app".to_string(),
        display_name: None,
        tracked_on_enrollment_status: Some(true),
        status: None,
        intent_state: not_requested_intent_state(),
        assignments: vec![],
        evidence: vec![evidence_ref_from("graph-safe-prose-app", "graph-apps")],
    });
    graph.device_match.error = Some(GraphSectionError {
        code: "safeProse".to_string(),
        message: "Bearer token support is enabled".to_string(),
        request_id: None,
        blocked_by: None,
        retry_after_seconds: None,
    });
    snapshot.graph = Some(graph);
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.registration_events[0].message,
        "Bearer authorization is required"
    );
    assert_eq!(
        safe.registration_events[1].message,
        "Bearer [redacted] expires soon"
    );
    assert_eq!(safe.activity[0].title, "Bearer token support is enabled");
    assert_eq!(
        safe.activity[0].detail.as_deref(),
        Some("Bearer authentication remains available")
    );
    assert_eq!(safe.activity[1].title, "Bearer [redacted] expires soon");
    assert_eq!(safe.activity[2].title, "Bearer [redacted] expires soon");
    assert_eq!(
        safe.coverage.last().unwrap().detail.as_deref(),
        Some("Bearer scheme negotiation was retried")
    );
    assert_eq!(
        safe.graph
            .as_ref()
            .unwrap()
            .device_match
            .error
            .as_ref()
            .unwrap()
            .message,
        "Bearer token support is enabled"
    );
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_bare_whitespace_secret_arguments_without_prose_regressions() {
    let mut snapshot = findings_snapshot();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Installer reported password hunter2".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "Payload".to_string(),
                value: "password qwertyz".to_string(),
            },
            EspNamedValue {
                name: "AdditionalPayload".to_string(),
                value: "token abcdefg".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-bare-secret-arguments")],
    });
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "authorization-secret".to_string(),
        timestamp: timestamp("2026-07-15T12:01:00Z"),
        kind: EspTimelineKind::Other,
        title: "Authorization Basic qwertyz failed".to_string(),
        detail: None,
        status: None,
        evidence: vec![evidence_ref("timeline-authorization-secret")],
    });
    let mut raw_text = raw_export_record(
        "raw-bare-password",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "password hunter2",
    );
    raw_text.sensitivity = EspSensitivity::Public;
    let mut raw_list = raw_export_record(
        "raw-bare-token",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "placeholder",
    );
    raw_list.sensitivity = EspSensitivity::Public;
    raw_list.raw_value = EspObservationValue::StringList(vec![
        "safe list value".to_string(),
        "token qwertyz".to_string(),
    ]);
    snapshot.raw_evidence = vec![raw_text, raw_list];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.registration_events[0].message,
        "Installer reported password [redacted]"
    );
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec!["password [redacted]", "token [redacted]"]
    );
    assert_eq!(safe.activity[0].title, "Authorization [redacted] failed");
    assert_eq!(
        safe.raw_evidence[0].raw_value,
        EspObservationValue::Text("password [redacted]".to_string())
    );
    assert_eq!(
        safe.raw_evidence[1].raw_value,
        EspObservationValue::StringList(vec![
            "safe list value".to_string(),
            "token [redacted]".to_string(),
        ])
    );
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_bare_credentials_in_references_and_provenance() {
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        "Authorization Basic evidence-secret",
        "password artifact-secret",
    )];

    let mut raw = raw_export_record(
        "token record-secret",
        EspSourceKind::DeploymentLog,
        "password provenance-secret",
        None,
        "safe raw payload",
    );
    raw.sensitivity = EspSensitivity::Public;
    raw.evidence = vec![evidence_ref_from(
        "Authorization Basic raw-evidence-secret",
        "token raw-source-secret",
    )];
    snapshot.raw_evidence = vec![raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();
    for credential in [
        "evidence-secret",
        "artifact-secret",
        "record-secret",
        "provenance-secret",
        "raw-evidence-secret",
        "raw-source-secret",
    ] {
        assert!(
            !safe_json.contains(credential),
            "safe export leaked bare reference credential {credential}"
        );
    }
    assert_eq!(
        safe.identity.evidence[0].evidence_id,
        "Authorization [redacted]"
    );
    assert_eq!(
        safe.identity.evidence[0].source_artifact_id,
        "password [redacted]"
    );
    assert_eq!(safe.raw_evidence[0].record_id, "token [redacted]");
    assert_eq!(
        safe.raw_evidence[0].provenance.source_artifact_id,
        "password [redacted]"
    );
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_token_aliases_and_basic_credentials_across_arbitrary_fields() {
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![
        evidence_ref_from("AuthToken Q", r#"BearerToken "Z""#),
        evidence_ref_from("Basic 'Y'", "safe-basic-source"),
    ];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "Payload".to_string(),
                value: r#"AuthToken "A""#.to_string(),
            },
            EspNamedValue {
                name: "AlternatePayload".to_string(),
                value: "BearerToken B".to_string(),
            },
            EspNamedValue {
                name: "BasicPayload".to_string(),
                value: "Basic 'C'".to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "5".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-token-aliases")],
    });

    let mut raw_event = raw_export_record(
        "safe-event-record",
        EspSourceKind::EventLog,
        "safe-event-source",
        None,
        "safe raw event payload",
    );
    raw_event.sensitivity = EspSensitivity::Public;
    raw_event.provenance.source_artifact_id = "BearerToken J".to_string();
    raw_event.provenance.event = Some(EspEventProvenance {
        channel: "Generic event channel".to_string(),
        event_id: 1,
        record_id: Some(1),
        named_data: vec![
            EspNamedValue {
                name: "Payload".to_string(),
                value: "AuthToken D".to_string(),
            },
            EspNamedValue {
                name: "AlternatePayload".to_string(),
                value: "BearerToken 'E'".to_string(),
            },
            EspNamedValue {
                name: "BasicPayload".to_string(),
                value: r#"Basic "F""#.to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "7".to_string(),
            },
        ],
    });
    let mut raw_text = raw_export_record(
        "raw-auth-token",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "AuthToken G",
    );
    raw_text.sensitivity = EspSensitivity::Public;
    let mut raw_list = raw_export_record(
        "raw-bearer-token-and-basic",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "placeholder",
    );
    raw_list.sensitivity = EspSensitivity::Public;
    raw_list.raw_value = EspObservationValue::StringList(vec![
        "safe list value".to_string(),
        "BearerToken 'H'".to_string(),
        r#"Basic "I""#.to_string(),
    ]);
    snapshot.raw_evidence = vec![raw_event, raw_text, raw_list];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0].evidence_id,
        "AuthToken [redacted]"
    );
    assert_eq!(
        safe.identity.evidence[0].source_artifact_id,
        "BearerToken [redacted]"
    );
    assert_eq!(safe.identity.evidence[1].evidence_id, "Basic [redacted]");
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "AuthToken [redacted]",
            "BearerToken [redacted]",
            "Basic [redacted]",
            "5",
        ]
    );
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["safe-event-record"]
    );
    assert_eq!(
        safe.raw_evidence[0].provenance.source_artifact_id,
        "BearerToken [redacted]"
    );
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "AuthToken [redacted]",
            "BearerToken [redacted]",
            "Basic [redacted]",
            "7",
        ]
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for credential in [
        "AuthToken Q",
        r#"BearerToken "Z""#,
        "Basic 'Y'",
        r#"AuthToken "A""#,
        "BearerToken B",
        "Basic 'C'",
        "AuthToken D",
        "BearerToken 'E'",
        r#"Basic "F""#,
        "AuthToken G",
        "BearerToken 'H'",
        r#"Basic "I""#,
        "BearerToken J",
    ] {
        assert!(
            !safe_json.contains(credential),
            "safe export leaked {credential}"
        );
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_preserves_typed_basic_authentication_prose() {
    let mut snapshot = findings_snapshot();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Basic authentication is configured".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: vec![],
        evidence: vec![evidence_ref("registration-basic-auth-prose")],
    });
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "basic-auth-prose".to_string(),
        timestamp: timestamp("2026-07-15T12:01:00Z"),
        kind: EspTimelineKind::Other,
        title: "Basic authorization is required".to_string(),
        detail: Some("Basic scheme negotiation was retried".to_string()),
        status: None,
        evidence: vec![evidence_ref("timeline-basic-auth-prose")],
    });
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.registration_events.last().unwrap().message,
        "Basic authentication is configured"
    );
    assert_eq!(
        safe.activity.last().unwrap().title,
        "Basic authorization is required"
    );
    assert_eq!(
        safe.activity.last().unwrap().detail.as_deref(),
        Some("Basic scheme negotiation was retried")
    );
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_preserves_ordinary_secret_words_in_typed_narratives() {
    let mut snapshot = findings_snapshot();
    let mut registration_status = status(
        EspRawStatus::Text("failed".to_string()),
        EspNormalizedStatus::Failed,
    );
    registration_status.display = "Token acquisition failed".to_string();
    registration_status.detail = Some(EspStatusDetail {
        raw: EspRawStatus::Text("failed".to_string()),
        normalized: EspNormalizedStatus::Failed,
        display: "Authorization remains required".to_string(),
    });
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: registration_status,
        message: "Device password policy is configured".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: vec![],
        evidence: vec![evidence_ref("registration-safe-secret-prose")],
    });
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "safe-secret-prose".to_string(),
        timestamp: timestamp("2026-07-15T12:01:00Z"),
        kind: EspTimelineKind::Other,
        title: "Serial number is unavailable".to_string(),
        detail: Some("Secret retrieval failed".to_string()),
        status: None,
        evidence: vec![evidence_ref("timeline-safe-secret-prose")],
    });
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: "safe-secret-prose".to_string(),
        family: "Safe prose".to_string(),
        status: EspArtifactStatus::Available,
        detail: Some("Tenant ID is missing".to_string()),
        observed_at_utc: "2026-07-15T12:02:00Z".to_string(),
        evidence: vec![evidence_ref("coverage-safe-secret-prose")],
    });
    let mut graph = findings_graph_overlay(EspGraphAppRecord {
        app_id: "safe-secret-prose-app".to_string(),
        display_name: None,
        tracked_on_enrollment_status: Some(true),
        status: None,
        intent_state: not_requested_intent_state(),
        assignments: vec![],
        evidence: vec![evidence_ref_from(
            "graph-safe-secret-prose-app",
            "graph-apps",
        )],
    });
    graph.device_match.error = Some(GraphSectionError {
        code: "safeProse".to_string(),
        message: "Password policy evaluation failed".to_string(),
        request_id: None,
        blocked_by: None,
        retry_after_seconds: None,
    });
    snapshot.graph = Some(graph);
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let registration = safe.registration_events.last().unwrap();
    assert_eq!(registration.message, "Device password policy is configured");
    assert_eq!(registration.status.display, "Token acquisition failed");
    assert_eq!(
        registration.status.detail.as_ref().unwrap().display,
        "Authorization remains required"
    );
    assert_eq!(
        safe.activity.last().unwrap().title,
        "Serial number is unavailable"
    );
    assert_eq!(
        safe.activity.last().unwrap().detail.as_deref(),
        Some("Secret retrieval failed")
    );
    assert_eq!(
        safe.coverage.last().unwrap().detail.as_deref(),
        Some("Tenant ID is missing")
    );
    assert_eq!(
        safe.graph
            .as_ref()
            .unwrap()
            .device_match
            .error
            .as_ref()
            .unwrap()
            .message,
        "Password policy evaluation failed"
    );
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_removes_whitespace_basic_authorization_raw_records() {
    let mut raw_text = raw_export_record(
        "raw-basic-text",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "Authorization Basic Q",
    );
    raw_text.sensitivity = EspSensitivity::Public;
    let mut raw_list = raw_export_record(
        "raw-basic-list",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "placeholder",
    );
    raw_list.sensitivity = EspSensitivity::Public;
    raw_list.raw_value = EspObservationValue::StringList(vec![
        "safe list value".to_string(),
        "Authorization Basic qwertyz".to_string(),
    ]);
    let mut snapshot = findings_snapshot();
    snapshot.raw_evidence = vec![raw_text, raw_list];
    let original = snapshot.clone();

    assert!(redacted_export_projection(&snapshot)
        .raw_evidence
        .is_empty());
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_removes_quoted_and_assignment_authorization_forms() {
    let mut snapshot = findings_snapshot();
    for (index, scheme) in ["Basic", "Digest", "ApiKey", "Bearer"]
        .into_iter()
        .enumerate()
    {
        snapshot.identity.evidence.push(evidence_ref_from(
            &format!(r#"Authorization "{scheme}" "{scheme}-double-reference-secret""#),
            &format!("Authorization '{scheme}' '{scheme}-single-reference-secret'"),
        ));

        let mut assignment = raw_export_record(
            &format!("raw-{index}-assignment"),
            EspSourceKind::DeploymentLog,
            "deployment-log",
            None,
            &format!("Authorization={scheme} Q"),
        );
        assignment.sensitivity = EspSensitivity::Public;
        snapshot.raw_evidence.push(assignment);

        let mut combined_quote = raw_export_record(
            &format!("raw-{index}-combined-quote"),
            EspSourceKind::DeploymentLog,
            "deployment-log",
            None,
            &format!(r#"Authorization="{scheme} {scheme}-combined-secret""#),
        );
        combined_quote.sensitivity = EspSensitivity::Public;
        snapshot.raw_evidence.push(combined_quote);

        let mut quoted_forms = raw_export_record(
            &format!("raw-{index}-quoted-forms"),
            EspSourceKind::DeploymentLog,
            "deployment-log",
            None,
            "placeholder",
        );
        quoted_forms.sensitivity = EspSensitivity::Public;
        quoted_forms.raw_value = EspObservationValue::StringList(vec![
            "safe list value".to_string(),
            format!("Authorization '{scheme} {scheme}-single-combined-secret'"),
            format!(r#"Authorization "{scheme}" "{scheme}-double-secret""#),
            format!("Authorization '{scheme}' '{scheme}-single-secret'"),
        ]);
        snapshot.raw_evidence.push(quoted_forms);
    }
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert!(safe.raw_evidence.is_empty());
    for evidence in &safe.identity.evidence {
        assert_eq!(evidence.evidence_id, "Authorization [redacted]");
        assert_eq!(evidence.source_artifact_id, "Authorization [redacted]");
    }
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret_fragment in [
        "double-reference-secret",
        "single-reference-secret",
        "combined-secret",
        "single-combined-secret",
        "double-secret",
        "single-secret",
    ] {
        assert!(
            !safe_json.contains(secret_fragment),
            "safe export leaked {secret_fragment}"
        );
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_entire_digest_challenges_across_public_boundaries() {
    let evidence_challenge = r#"Authorization Digest username="evidence-user", realm="evidence-realm", nonce="evidence-nonce""#;
    let source_challenge = r#"Authorization Digest username="source-user", realm="source-realm", nonce="source-nonce""#;
    let named_challenge =
        r#"Authorization Digest username="named-user", realm="named-realm", nonce="named-nonce""#;
    let raw_challenge =
        r#"Authorization Digest username="raw-user", realm="raw-realm", nonce="raw-nonce""#;

    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(evidence_challenge, source_challenge)];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: vec![EspNamedValue {
            name: "Payload".to_string(),
            value: named_challenge.to_string(),
        }],
        evidence: vec![evidence_ref("registration-digest-challenge")],
    });

    let mut raw = raw_export_record(
        "raw-digest-challenge",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        raw_challenge,
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from("Authorization [redacted]", "Authorization [redacted]")
    );
    assert_eq!(
        safe.registration_events[0].named_data[0].value,
        "Authorization [redacted]"
    );
    assert!(safe.raw_evidence.is_empty());
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "evidence-user",
        "evidence-realm",
        "evidence-nonce",
        "source-user",
        "source-realm",
        "source-nonce",
        "named-user",
        "named-realm",
        "named-nonce",
        "raw-user",
        "raw-realm",
        "raw-nonce",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_folded_digest_challenges_across_serialized_public_boundaries() {
    let evidence_challenge = "trace Authorization Digest username=\"folded-evidence-user\",\r\n realm=\"folded-evidence-realm\",\r\n nonce=\"folded-evidence-nonce\"";
    let source_challenge = "trace Authorization Digest username=\"folded-source-user\",\n\trealm=\"folded-source-realm\",\n\tnonce=\"folded-source-nonce\"";
    let named_challenge = "trace Authorization Digest username=\"folded-named-user\",\r\n\trealm=\"folded-named-realm\",\r\n\tnonce=\"folded-named-nonce\"";
    let raw_challenge = "trace Authorization Digest username=\"folded-raw-user\",\n realm=\"folded-raw-realm\",\n nonce=\"folded-raw-nonce\"";

    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(evidence_challenge, source_challenge)];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(43),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:01:00Z"),
        named_data: vec![EspNamedValue {
            name: "Payload".to_string(),
            value: named_challenge.to_string(),
        }],
        evidence: vec![evidence_ref("registration-folded-digest-challenge")],
    });

    let mut raw = raw_export_record(
        "raw-folded-digest-challenge",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        raw_challenge,
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from(
            "trace Authorization [redacted]",
            "trace Authorization [redacted]"
        )
    );
    assert_eq!(
        safe.registration_events[0].named_data[0].value,
        "trace Authorization [redacted]"
    );
    assert!(safe.raw_evidence.is_empty());
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "folded-evidence-user",
        "folded-evidence-realm",
        "folded-evidence-nonce",
        "folded-source-user",
        "folded-source-realm",
        "folded-source-nonce",
        "folded-named-user",
        "folded-named-realm",
        "folded-named-nonce",
        "folded-raw-user",
        "folded-raw-realm",
        "folded-raw-nonce",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_digest_challenges_folded_immediately_after_the_scheme() {
    let evidence_challenge = "Authorization: Digest\r\n username=\"scheme-fold-evidence-user\",\r\n realm=\"scheme-fold-evidence-realm\", nonce=\"scheme-fold-evidence-nonce\"";
    let source_challenge = "Authorization Digest\n\tusername=\"scheme-fold-source-user\",\n\trealm=\"scheme-fold-source-realm\", nonce=\"scheme-fold-source-nonce\"";
    let named_challenge = "Authorization: Digest\r\n\tusername=\"scheme-fold-named-user\",\r\n\trealm=\"scheme-fold-named-realm\", nonce=\"scheme-fold-named-nonce\"";
    let raw_challenge = "Authorization: Digest\n username=\"scheme-fold-raw-user\",\n realm=\"scheme-fold-raw-realm\", nonce=\"scheme-fold-raw-nonce\"";

    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(evidence_challenge, source_challenge)];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(45),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:03:00Z"),
        named_data: vec![EspNamedValue {
            name: "Payload".to_string(),
            value: named_challenge.to_string(),
        }],
        evidence: vec![evidence_ref("registration-scheme-folded-digest-challenge")],
    });

    let mut raw = raw_export_record(
        "raw-scheme-folded-digest-challenge",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        raw_challenge,
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from("Authorization: [redacted]", "Authorization [redacted]")
    );
    assert_eq!(
        safe.registration_events[0].named_data[0].value,
        "Authorization: [redacted]"
    );
    assert!(safe.raw_evidence.is_empty());
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "scheme-fold-evidence-user",
        "scheme-fold-evidence-realm",
        "scheme-fold-evidence-nonce",
        "scheme-fold-source-user",
        "scheme-fold-source-realm",
        "scheme-fold-source-nonce",
        "scheme-fold-named-user",
        "scheme-fold-named-realm",
        "scheme-fold-named-nonce",
        "scheme-fold-raw-user",
        "scheme-fold-raw-realm",
        "scheme-fold-raw-nonce",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_generic_hardware_material_across_public_boundaries() {
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        "HardwareHash evidence-hardware-secret",
        "DeviceHardwareData source-hardware-secret",
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(42),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "Payload".to_string(),
                value: "HardwareHash named-hardware-secret".to_string(),
            },
            EspNamedValue {
                name: "AdditionalPayload".to_string(),
                value: "DeviceHardwareData named-device-data-secret".to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "5".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-generic-hardware-material")],
    });

    let mut event = raw_export_record(
        "safe-event-record",
        EspSourceKind::EventLog,
        "event-log",
        None,
        "safe raw event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Generic event channel".to_string(),
        event_id: 1,
        record_id: Some(1),
        named_data: vec![
            EspNamedValue {
                name: "Payload".to_string(),
                value: "HardwareHash event-hardware-secret".to_string(),
            },
            EspNamedValue {
                name: "AdditionalPayload".to_string(),
                value: "DeviceHardwareData event-device-data-secret".to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "7".to_string(),
            },
        ],
    });
    let mut raw_hash = raw_export_record(
        "raw-three",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "HardwareHash raw-hardware-secret",
    );
    raw_hash.sensitivity = EspSensitivity::Public;
    let mut raw_device_data = raw_export_record(
        "raw-four",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "DeviceHardwareData raw-device-data-secret",
    );
    raw_device_data.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw_hash, raw_device_data];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from("HardwareHash [redacted]", "DeviceHardwareData [redacted]")
    );
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "HardwareHash [redacted]",
            "DeviceHardwareData [redacted]",
            "5",
        ]
    );
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["safe-event-record"]
    );
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "HardwareHash [redacted]",
            "DeviceHardwareData [redacted]",
            "7",
        ]
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "evidence-hardware-secret",
        "source-hardware-secret",
        "named-hardware-secret",
        "named-device-data-secret",
        "event-hardware-secret",
        "event-device-data-secret",
        "raw-hardware-secret",
        "raw-device-data-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_one_layer_escaped_json_secrets_across_serialized_public_boundaries() {
    let evidence_payload = r#"neutral-ref {\"HardwareHash\":\"escaped-evidence-hardware-secret\"}"#;
    let source_payload =
        r#"neutral-source {\"DeviceHardwareData\":\"escaped-source-device-secret\"}"#;
    let named_hardware = r#"neutral-named {\"HardwareHash\":\"escaped-named-hardware-secret\"}"#;
    let named_device = r#"neutral-named {\"DeviceHardwareData\":\"escaped-named-device-secret\"}"#;
    let named_authorization =
        r#"neutral-named {\"Authorization\":\"Custom escaped-named-authorization-secret\"}"#;
    let raw_payload = r#"neutral-json {\"HardwareHash\":\"escaped-raw-hardware-secret\",\"DeviceHardwareData\":\"escaped-raw-device-secret\",\"Authorization\":\"Custom escaped-raw-authorization-secret\"}"#;

    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(evidence_payload, source_payload)];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(44),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:02:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "Metadata".to_string(),
                value: named_hardware.to_string(),
            },
            EspNamedValue {
                name: "AdditionalMetadata".to_string(),
                value: named_device.to_string(),
            },
            EspNamedValue {
                name: "RequestMetadata".to_string(),
                value: named_authorization.to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-escaped-json-secrets")],
    });

    let mut raw = raw_export_record(
        "neutral-json-record",
        EspSourceKind::Json,
        "neutral-json-source",
        None,
        raw_payload,
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from(
            r#"neutral-ref {\"HardwareHash\":\"[redacted]\"}"#,
            r#"neutral-source {\"DeviceHardwareData\":\"[redacted]\"}"#,
        )
    );
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            r#"neutral-named {\"HardwareHash\":\"[redacted]\"}"#,
            r#"neutral-named {\"DeviceHardwareData\":\"[redacted]\"}"#,
            r#"neutral-named {\"Authorization\":\"[redacted]\"}"#,
        ]
    );
    assert!(safe.raw_evidence.is_empty());
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "escaped-evidence-hardware-secret",
        "escaped-source-device-secret",
        "escaped-named-hardware-secret",
        "escaped-named-device-secret",
        "escaped-named-authorization-secret",
        "escaped-raw-hardware-secret",
        "escaped-raw-device-secret",
        "escaped-raw-authorization-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_pretty_printed_one_layer_escaped_json_secrets() {
    let evidence_secret = "pretty-evidence-authorization-secret";
    let source_secret = "pretty-source-hardware-secret";
    let named_secret = "pretty-named-device-secret";
    let event_secret = "pretty-event-authorization-secret";
    let raw_json_secret = "pretty-raw-json-secret";
    let raw_registry_secret = "pretty-raw-registry-secret";
    let raw_list_secret = "pretty-raw-list-secret";
    let safe_token_count_payload =
        "neutral-control {\n\\\"TokenCount\\\"\n:\n\\\"7\\\"\n}".to_string();

    let evidence_payload =
        format!("neutral-ref {{\r\n\\\"aUtHoRiZaTiOn\\\"\r\n:\r\n\\\"{evidence_secret}\\\"\r\n}}");
    let source_payload =
        format!("neutral-source {{\n\\\"hardware_hash\\\"\n:\n\\\"{source_secret}\\\"\n}}");
    let named_payload = format!(
        "neutral-named {{\r\n\\\"DEVICE-HARDWARE-DATA\\\"\r\n:\r\n\\\"{named_secret}\\\"\r\n}}"
    );
    let event_payload =
        format!("neutral-event {{\n\\\"aUtHoRiZaTiOn\\\"\n:\n\\\"{event_secret}\\\"\n}}");
    let raw_json_payload =
        format!("neutral-json {{\r\n\\\"hardware_hash\\\"\r\n:\r\n\\\"{raw_json_secret}\\\"\r\n}}");
    let raw_registry_payload = format!(
        "neutral-registry {{\n\\\"DEVICE-HARDWARE-DATA\\\"\n:\n\\\"{raw_registry_secret}\\\"\n}}"
    );
    let raw_list_payload =
        format!("neutral-list {{\r\n\\\"aUtHoRiZaTiOn\\\"\r\n:\r\n\\\"{raw_list_secret}\\\"\r\n}}");

    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(&evidence_payload, &source_payload)];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(46),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:04:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "Metadata".to_string(),
                value: named_payload.clone(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "5".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-pretty-escaped-json-secrets")],
    });

    let mut event = raw_export_record(
        "neutral-event-record",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe raw event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(2),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: event_payload.clone(),
        }],
    });

    let mut raw_json = raw_export_record(
        "neutral-pretty-json-record",
        EspSourceKind::Json,
        "neutral-pretty-json-source",
        None,
        &raw_json_payload,
    );
    raw_json.sensitivity = EspSensitivity::Public;

    let mut raw_registry = raw_export_record(
        "neutral-pretty-registry-record",
        EspSourceKind::Registry,
        "neutral-pretty-registry-source",
        Some("Metadata"),
        &raw_registry_payload,
    );
    raw_registry.sensitivity = EspSensitivity::Public;

    let mut raw_list = raw_export_record(
        "neutral-pretty-list-record",
        EspSourceKind::Json,
        "neutral-pretty-list-source",
        None,
        "placeholder",
    );
    raw_list.sensitivity = EspSensitivity::Public;
    raw_list.raw_value =
        EspObservationValue::StringList(vec!["safe list value".to_string(), raw_list_payload]);

    let mut safe_token_count = raw_export_record(
        "neutral-pretty-token-count-record",
        EspSourceKind::Json,
        "neutral-pretty-token-count-source",
        None,
        &safe_token_count_payload,
    );
    safe_token_count.sensitivity = EspSensitivity::Public;

    snapshot.raw_evidence = vec![event, raw_json, raw_registry, raw_list, safe_token_count];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0].evidence_id,
        evidence_payload.replace(evidence_secret, "[redacted]")
    );
    assert_eq!(
        safe.identity.evidence[0].source_artifact_id,
        source_payload.replace(source_secret, "[redacted]")
    );
    assert_eq!(
        safe.registration_events[0].named_data[0].value,
        named_payload.replace(named_secret, "[redacted]")
    );
    assert_eq!(safe.registration_events[0].named_data[1].value, "5");
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["neutral-event-record", "neutral-pretty-token-count-record"]
    );
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data[0]
            .value,
        event_payload.replace(event_secret, "[redacted]")
    );
    assert_eq!(
        safe.raw_evidence[1].raw_value,
        EspObservationValue::Text(safe_token_count_payload)
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        evidence_secret,
        source_secret,
        named_secret,
        event_secret,
        raw_json_secret,
        raw_registry_secret,
        raw_list_secret,
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_omits_bare_and_unknown_authorization_raw_records() {
    let mut bare = raw_export_record(
        "raw-one",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "Authorization qwertyz",
    );
    bare.sensitivity = EspSensitivity::Public;
    let mut unknown_scheme = raw_export_record(
        "raw-two",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "Authorization Custom custom-authorization-secret",
    );
    unknown_scheme.sensitivity = EspSensitivity::Public;
    let mut safe_control = raw_export_record(
        "raw-safe-control",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "safe control value",
    );
    safe_control.sensitivity = EspSensitivity::Public;

    let mut snapshot = findings_snapshot();
    snapshot.raw_evidence = vec![bare, unknown_scheme, safe_control];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["raw-safe-control"]
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in ["qwertyz", "Custom", "custom-authorization-secret"] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_scrubs_raw_metadata_and_all_matching_evidence_references() {
    let sid = "S-1-5-21-111-222-333-1001";
    let source_artifact_id = format!("source:{sid}:person@example.test");
    let evidence_id = format!(r"evidence:{sid}:C:\Users\Adam.Gell\trace.log");
    let evidence = || evidence_ref_from(&evidence_id, &source_artifact_id);
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence()];
    snapshot.profile = Some(EspProfileEvidence {
        profile_name: None,
        deployment_profile_id: None,
        correlation_id: None,
        tenant_domain: None,
        tenant_id: None,
        oobe_config: None,
        profile_download_time: None,
        join_mode: None,
        odj_applied: None,
        skip_domain_connectivity_check: None,
        device_preparation: None,
        evidence: vec![evidence()],
    });
    snapshot.sessions.push(EspSession {
        session_id: format!("session|source|classic:user:{sid}:time|0"),
        kind: EspSessionKind::Classic,
        scope: EspScope::User,
        user_sid: Some(sensitive(sid)),
        started_at: None,
        ended_at: None,
        phase: EspPhase::AccountSetup,
        is_latest: true,
        workload_ids: vec![format!("workload|source|classic:user:{sid}:app|0")],
        evidence: vec![evidence()],
    });
    let mut workload = findings_workload(
        "metadata-reference",
        EspTrackedKind::Win32App,
        EspNormalizedStatus::Installing,
        Some(true),
        "2026-07-15T12:00:00Z",
    );
    workload.workload_id = format!("workload|source|classic:user:{sid}:app|0");
    workload.session_id = snapshot.sessions[0].session_id.clone();
    workload.evidence = vec![evidence()];
    snapshot.workloads.push(workload);
    let mut process_context = observation_context(&evidence_id);
    process_context.evidence_ref = evidence();
    process_context.provenance.source_artifact_id = source_artifact_id.clone();
    process_context.provenance.file_path =
        Some(r"C:\Users\Adam.Gell\AppData\Local\Temp\installer-inventory.json".to_string());
    snapshot
        .installer_correlations
        .push(EspInstallerCorrelation {
            correlation_id: "metadata-correlation".to_string(),
            workload_id: Some(snapshot.workloads[0].workload_id.clone()),
            confidence: EspCorrelationConfidence::Exact,
            reason: "safe exact correlation".to_string(),
            candidate_workload_ids: vec![],
            process_observations: vec![EspProcessObservation {
                context: process_context,
                pid: 42,
                process_start_time: timestamp("2026-07-15T12:00:00Z"),
                parent_pid: None,
                executable_name: "msiexec.exe".to_string(),
                sanitized_command_line: None,
                referenced_log_path: None,
                app_id: Some("safe-app".to_string()),
                product_code: None,
            }],
            evidence: vec![evidence()],
        });
    snapshot.node_cache.push(EspNodeCacheEntry {
        index: 1,
        node_uri: "./Vendor/MSFT/Node".to_string(),
        expected_value: None,
        sensitivity: EspSensitivity::Public,
        evidence: vec![evidence()],
    });
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "timeline-safe".to_string(),
        timestamp: timestamp("2026-07-15T12:00:00Z"),
        kind: EspTimelineKind::Other,
        title: "Safe timeline entry".to_string(),
        detail: None,
        status: None,
        evidence: vec![evidence()],
    });
    snapshot.findings.push(EspDiagnosticFinding {
        finding_id: "safe-finding".to_string(),
        severity: EspFindingSeverity::Info,
        confidence: EspFindingConfidence::High,
        title: "Safe finding".to_string(),
        summary: "Safe summary".to_string(),
        recommended_checks: vec!["Safe check".to_string()],
        evidence: vec![evidence()],
        coverage_gap_ids: vec![],
    });
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: "safe-coverage".to_string(),
        family: "Safe coverage".to_string(),
        status: EspArtifactStatus::Available,
        detail: None,
        observed_at_utc: "2026-07-15T12:00:00Z".to_string(),
        evidence: vec![evidence()],
    });
    let mut graph_app = EspGraphAppRecord {
        app_id: "safe-app".to_string(),
        display_name: None,
        tracked_on_enrollment_status: Some(true),
        status: None,
        intent_state: not_requested_intent_state(),
        assignments: vec![],
        evidence: vec![evidence()],
    };
    graph_app.assignments.push(EspGraphAssignment {
        assignment_id: "safe-assignment".to_string(),
        target_id: None,
        filter_id: None,
        intent: EspGraphAssignmentIntent::Required,
        target_kind: EspGraphTargetKind::AllDevices,
        targeting: EspGraphTargeting::Declared,
        evidence: vec![evidence()],
    });
    snapshot.graph = Some(findings_graph_overlay(graph_app));

    let mut raw = raw_export_record(
        &format!("raw|{source_artifact_id}|{evidence_id}|0"),
        EspSourceKind::Registry,
        &source_artifact_id,
        Some(&format!("Value:{sid}:person@example.test")),
        "safe-value",
    );
    raw.sensitivity = EspSensitivity::Public;
    raw.provenance.registry.as_mut().unwrap().key = format!(r"SOFTWARE\ProfileList\{sid}");
    raw.evidence = vec![evidence()];
    snapshot.raw_evidence = vec![raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();
    assert!(!safe_json.contains(sid));
    assert!(!safe_json.contains("person@example.test"));
    assert!(!safe_json.contains("Adam.Gell"));

    let expected = &safe.raw_evidence[0].evidence[0];
    assert!(expected.evidence_id.contains("[redacted-sid-1]"));
    assert!(expected.source_artifact_id.contains("[redacted-sid-1]"));
    for matching in [
        &safe.identity.evidence[0],
        &safe.profile.as_ref().unwrap().evidence[0],
        &safe.sessions[0].evidence[0],
        &safe.workloads[0].evidence[0],
        &safe.installer_correlations[0].evidence[0],
        &safe.installer_correlations[0].process_observations[0]
            .context
            .evidence_ref,
        &safe.node_cache[0].evidence[0],
        &safe.activity[0].evidence[0],
        &safe.findings[0].evidence[0],
        &safe.coverage[0].evidence[0],
        &safe.graph.as_ref().unwrap().apps.data.as_ref().unwrap()[0].evidence[0],
        &safe.graph.as_ref().unwrap().apps.data.as_ref().unwrap()[0].assignments[0].evidence[0],
    ] {
        assert_eq!(matching, expected);
    }
    assert!(safe.raw_evidence[0].record_id.contains("[redacted-sid-1]"));
    assert_eq!(
        safe.raw_evidence[0].provenance.source_artifact_id,
        expected.source_artifact_id
    );
    assert_eq!(
        safe.installer_correlations[0].process_observations[0]
            .context
            .provenance
            .source_artifact_id,
        expected.source_artifact_id
    );
    assert!(safe.raw_evidence[0]
        .provenance
        .registry
        .as_ref()
        .unwrap()
        .value_name
        .as_ref()
        .unwrap()
        .contains("[redacted-sid-1]"));
    assert_eq!(redacted_export_projection(&snapshot), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_keeps_distinct_email_and_profile_references_distinct() {
    let mut snapshot = findings_snapshot();
    snapshot.raw_evidence = [("Alice", "alice@example.test"), ("Bob", "bob@example.test")]
        .into_iter()
        .enumerate()
        .map(|(ordinal, (user, email))| {
            let source_artifact_id = format!("source:{email}");
            let evidence_id = format!(r"C:\Users\{user}\trace.log");
            let mut record = raw_export_record(
                &format!("raw|{source_artifact_id}|{evidence_id}|{ordinal}"),
                EspSourceKind::DeploymentLog,
                &source_artifact_id,
                None,
                "safe-value",
            );
            record.sensitivity = EspSensitivity::Public;
            record.evidence = vec![evidence_ref_from(&evidence_id, &source_artifact_id)];
            record
        })
        .collect();

    let safe = redacted_export_projection(&snapshot);
    assert_ne!(
        safe.raw_evidence[0].evidence[0].source_artifact_id,
        safe.raw_evidence[1].evidence[0].source_artifact_id
    );
    assert_ne!(
        safe.raw_evidence[0].evidence[0].evidence_id,
        safe.raw_evidence[1].evidence[0].evidence_id
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for sensitive in ["Alice", "Bob", "alice@example.test", "bob@example.test"] {
        assert!(!safe_json.contains(sensitive));
    }
    assert_eq!(redacted_export_projection(&snapshot), safe);
}

#[test]
fn redaction_projection_honors_raw_sensitivity_and_scrubs_provenance_paths() {
    let mut snapshot = findings_snapshot();
    let mut sensitive_log = raw_export_record(
        "sensitive-log",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "opaque-sensitive-payload",
    );
    sensitive_log.provenance.file_path =
        Some(r"C:\Users\Adam.Gell\AppData\Local\Temp\install.log".to_string());

    let mut restricted_number = raw_export_record(
        "restricted-number",
        EspSourceKind::System,
        "system-private-fact",
        None,
        "placeholder",
    );
    restricted_number.sensitivity = EspSensitivity::Restricted;
    restricted_number.raw_value = EspObservationValue::Unsigned(123456789);

    let mut registry_path = raw_export_record(
        "profile-list-key",
        EspSourceKind::Registry,
        "profile-list",
        Some("ProfileImagePath"),
        r"C:\Users\Adam.Gell",
    );
    registry_path.sensitivity = EspSensitivity::Public;
    registry_path.provenance.registry.as_mut().unwrap().key =
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-111-222-333-1001"
            .to_string();
    snapshot.raw_evidence = vec![sensitive_log, restricted_number, registry_path];

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.raw_evidence[0].raw_value,
        EspObservationValue::Text("[redacted]".to_string())
    );
    assert_eq!(
        safe.raw_evidence[1].raw_value,
        EspObservationValue::Text("[redacted]".to_string())
    );
    assert_eq!(
        safe.raw_evidence[0].provenance.file_path.as_deref(),
        Some(r"C:\Users\[redacted]\AppData\Local\Temp\install.log")
    );
    assert_eq!(
        safe.raw_evidence[2]
            .provenance
            .registry
            .as_ref()
            .unwrap()
            .key,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\[redacted]"
    );
    assert_eq!(
        snapshot.raw_evidence[0].provenance.file_path.as_deref(),
        Some(r"C:\Users\Adam.Gell\AppData\Local\Temp\install.log")
    );
}

#[test]
fn redaction_projection_masks_every_registry_value_variant_when_classified_sensitive() {
    let variants = vec![
        EspObservationValue::Text("opaque-text".to_string()),
        EspObservationValue::StringList(vec!["opaque-a".to_string(), "opaque-b".to_string()]),
        EspObservationValue::Integer(-42),
        EspObservationValue::Unsigned(42),
        EspObservationValue::Boolean(true),
    ];
    let mut snapshot = findings_snapshot();
    snapshot.raw_evidence = variants
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, raw_value)| {
            let mut record = raw_export_record(
                &format!("registry-sensitive-{index}"),
                EspSourceKind::Registry,
                "generic-registry-source",
                Some("OpaqueValue"),
                "placeholder",
            );
            record.raw_value = raw_value;
            record.sensitivity = if index % 2 == 0 {
                EspSensitivity::Sensitive
            } else {
                EspSensitivity::Restricted
            };
            record
        })
        .collect();

    let safe = redacted_export_projection(&snapshot);

    assert_eq!(safe.raw_evidence.len(), variants.len());
    assert!(safe
        .raw_evidence
        .iter()
        .all(|record| { record.raw_value == EspObservationValue::Text("[redacted]".to_string()) }));
    assert_eq!(
        snapshot
            .raw_evidence
            .iter()
            .map(|record| record.raw_value.clone())
            .collect::<Vec<_>>(),
        variants
    );
}

#[test]
fn redaction_projection_pseudonymizes_full_valid_windows_sid_grammar() {
    let sid_hex_authority = "S-1-0x28651FE848-12-72-9-110";
    let sid_twelve_hex_authority = "S-1-0x0028651FE848-12-72-9-110";
    let sid_max_subauthorities = "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15";
    let mut snapshot = findings_snapshot();

    for (ordinal, sid) in [
        sid_hex_authority,
        sid_twelve_hex_authority,
        sid_max_subauthorities,
    ]
    .into_iter()
    .enumerate()
    {
        let session_id = format!("session|source|classic:user:{sid}:time|0");
        let workload_id = format!("workload|source|classic:user:{sid}:app|0");
        snapshot.sessions.push(EspSession {
            session_id: session_id.clone(),
            kind: EspSessionKind::Classic,
            scope: EspScope::User,
            user_sid: Some(sensitive(sid)),
            started_at: Some(timestamp("2026-07-15T12:00:00Z")),
            ended_at: None,
            phase: EspPhase::AccountSetup,
            is_latest: true,
            workload_ids: vec![workload_id.clone()],
            evidence: vec![evidence_ref(&format!("session-sid-{ordinal}"))],
        });
        let mut workload = findings_workload(
            &format!("sid-{ordinal}"),
            EspTrackedKind::Win32App,
            EspNormalizedStatus::Installing,
            Some(true),
            "2026-07-15T12:00:00Z",
        );
        workload.workload_id = workload_id;
        workload.session_id = session_id;
        snapshot.workloads.push(workload);
    }
    snapshot
        .installer_correlations
        .push(EspInstallerCorrelation {
            correlation_id: "correlation-valid-sids".to_string(),
            workload_id: Some(snapshot.workloads[0].workload_id.clone()),
            confidence: EspCorrelationConfidence::Temporal,
            reason: "valid SID references".to_string(),
            candidate_workload_ids: vec![snapshot.workloads[1].workload_id.clone()],
            process_observations: vec![],
            evidence: vec![evidence_ref("correlation-valid-sids")],
        });
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();

    assert!(!safe_json.contains(sid_hex_authority));
    assert!(!safe_json.contains(sid_twelve_hex_authority));
    assert!(!safe_json.contains(sid_max_subauthorities));
    assert!(!safe_json.contains("0x28651FE848"));
    assert!(!safe.sessions[2].session_id.ends_with("-15:time|0"));
    assert!(safe.sessions[0].session_id.contains("[redacted-sid-2]"));
    assert!(safe.sessions[1].session_id.contains("[redacted-sid-1]"));
    assert!(safe.sessions[2].session_id.contains("[redacted-sid-3]"));
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_pseudonymizes_reducer_sid_ids_and_preserves_references() {
    let mut reducer = EspDiagnosticsReducer::new("2026-07-15T18:00:00Z".to_string());
    reducer.ingest_all(vec![
        registry_record(
            "esp-tracking",
            "user-a",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\S-1-5-21-100\Sidecar\2026-07-15T13:00:00Z",
            "app-a",
            EspObservationValue::Integer(4),
            "2026-07-15T13:00:00Z",
        ),
        registry_record(
            "esp-tracking",
            "user-b",
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\S-1-5-21-200\Sidecar\2026-07-15T13:00:00Z",
            "app-b",
            EspObservationValue::Integer(4),
            "2026-07-15T13:00:00Z",
        ),
    ]);
    let mut snapshot = reducer.snapshot();
    assert_eq!(snapshot.sessions.len(), 2);
    assert_eq!(snapshot.workloads.len(), 2);
    snapshot
        .installer_correlations
        .push(EspInstallerCorrelation {
            correlation_id: "correlation-user-apps".to_string(),
            workload_id: Some(snapshot.workloads[0].workload_id.clone()),
            confidence: EspCorrelationConfidence::Temporal,
            reason: "both user apps overlap".to_string(),
            candidate_workload_ids: vec![snapshot.workloads[1].workload_id.clone()],
            process_observations: vec![],
            evidence: vec![evidence_ref("correlation-user-apps")],
        });
    let original_json = serde_json::to_string(&snapshot).unwrap();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();

    assert!(original_json.contains("S-1-5-21-100"));
    assert!(original_json.contains("S-1-5-21-200"));
    assert!(!safe_json.contains("S-1-5-21-100"));
    assert!(!safe_json.contains("S-1-5-21-200"));
    assert_ne!(safe.sessions[0].session_id, safe.sessions[1].session_id);
    assert!(safe
        .sessions
        .iter()
        .all(|session| session.session_id.contains("[redacted-sid-")));
    let exported_user_sids = safe
        .sessions
        .iter()
        .map(|session| session.user_sid.as_ref().unwrap().value.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        exported_user_sids,
        BTreeSet::from(["[redacted-sid-1]", "[redacted-sid-2]"])
    );
    for session in &safe.sessions {
        assert!(session
            .session_id
            .contains(&session.user_sid.as_ref().unwrap().value));
    }
    for session in &safe.sessions {
        assert!(session.workload_ids.iter().all(|workload_id| safe
            .workloads
            .iter()
            .any(|workload| &workload.workload_id == workload_id)));
    }
    for workload in &safe.workloads {
        assert!(safe
            .sessions
            .iter()
            .any(|session| session.session_id == workload.session_id));
    }
    let correlation = &safe.installer_correlations[0];
    assert_eq!(
        correlation.workload_id.as_deref(),
        Some(safe.workloads[0].workload_id.as_str())
    );
    assert_eq!(
        correlation.candidate_workload_ids,
        vec![safe.workloads[1].workload_id.clone()]
    );
    assert_eq!(redacted_export_projection(&snapshot), safe);
    assert_eq!(serde_json::to_string(&snapshot).unwrap(), original_json);
}

#[test]
fn redaction_projection_masks_identity_session_node_cache_hardware_and_command_secrets() {
    let mut snapshot = findings_snapshot();
    let mut process_context = observation_context("process-sensitive");
    process_context.provenance.event = Some(EspEventProvenance {
        channel: "Process inventory".to_string(),
        event_id: 1,
        record_id: Some(1),
        named_data: vec![EspNamedValue {
            name: "Authorization".to_string(),
            value: "Bearer process-context-secret".to_string(),
        }],
    });
    snapshot.identity.user_principal_name = Some(sensitive("person@example.test"));
    snapshot.identity.tenant_id = Some(sensitive("tenant-secret"));
    snapshot.identity.entdm_id = Some(sensitive("entdm-secret"));
    snapshot.identity.serial_number = Some(sensitive("SERIAL-SECRET"));
    snapshot.sessions.push(EspSession {
        session_id: "session-sensitive".to_string(),
        kind: EspSessionKind::Classic,
        scope: EspScope::User,
        user_sid: Some(sensitive("S-1-5-21-111-222-333-1001")),
        started_at: None,
        ended_at: None,
        phase: EspPhase::AccountSetup,
        is_latest: true,
        workload_ids: vec![],
        evidence: vec![evidence_ref("session-sensitive")],
    });
    snapshot.node_cache.push(EspNodeCacheEntry {
        index: 1,
        node_uri: "./Vendor/MSFT/Secret".to_string(),
        expected_value: Some("NodeCache private payload".to_string()),
        sensitivity: EspSensitivity::Sensitive,
        evidence: vec![evidence_ref("node-sensitive")],
    });
    snapshot.hardware = Some(EspHardwareEvidence {
        os_version: Some("10.0.26100".to_string()),
        os_build: Some("26100.1".to_string()),
        manufacturer: Some("Contoso".to_string()),
        model: Some("Model 1".to_string()),
        serial_number: Some(sensitive("SERIAL-HARDWARE")),
        tpm_version: Some("2.0".to_string()),
        evidence: vec![evidence_ref("hardware-sensitive")],
    });
    snapshot.installer_correlations.push(EspInstallerCorrelation {
        correlation_id: "correlation-1".to_string(),
        workload_id: Some("app-1".to_string()),
        confidence: EspCorrelationConfidence::Exact,
        reason: "exact product code".to_string(),
        candidate_workload_ids: vec![],
        process_observations: vec![EspProcessObservation {
            context: process_context,
            pid: 42,
            process_start_time: timestamp("2026-07-15T12:00:00Z"),
            parent_pid: None,
            executable_name: "msiexec.exe".to_string(),
            sanitized_command_line: Some(
                r#"msiexec /i {11111111-2222-3333-4444-555555555555} /L*V C:\Windows\Temp\install.log --password hunter2 --api-key=topsecret"#.to_string(),
            ),
            referenced_log_path: Some(
                r"C:\Users\person@example.test\AppData\Local\Temp\install.log".to_string(),
            ),
            app_id: Some("app-1".to_string()),
            product_code: Some("{11111111-2222-3333-4444-555555555555}".to_string()),
        }],
        evidence: vec![evidence_ref("process-sensitive")],
    });

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "person@example.test",
        "tenant-secret",
        "entdm-secret",
        "SERIAL-SECRET",
        "S-1-5-21-111-222-333-1001",
        "NodeCache private payload",
        "SERIAL-HARDWARE",
        "hunter2",
        "topsecret",
        "process-context-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    let command = safe.installer_correlations[0].process_observations[0]
        .sanitized_command_line
        .as_deref()
        .unwrap();
    assert!(command.contains("{11111111-2222-3333-4444-555555555555}"));
    assert!(command.contains(r"C:\Windows\Temp\install.log"));
    assert_eq!(
        safe.installer_correlations[0].process_observations[0]
            .product_code
            .as_deref(),
        Some("{11111111-2222-3333-4444-555555555555}")
    );
    assert_eq!(
        safe.installer_correlations[0].process_observations[0]
            .referenced_log_path
            .as_deref(),
        Some(r"C:\Users\[redacted]\AppData\Local\Temp\install.log")
    );
    assert_eq!(
        snapshot.installer_correlations[0].process_observations[0]
            .referenced_log_path
            .as_deref(),
        Some(r"C:\Users\person@example.test\AppData\Local\Temp\install.log")
    );
    assert!(serde_json::to_string(&snapshot)
        .unwrap()
        .contains("hunter2"));
}

#[test]
fn redaction_projection_removes_tokens_authorization_graph_bodies_and_hardware_hashes() {
    let mut snapshot = findings_snapshot();
    let mut raw_log_safe = raw_export_record(
        "raw-log-safe",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        r"MSI {11111111-2222-3333-4444-555555555555} wrote C:\Windows\Temp\install.log for person@example.test",
    );
    raw_log_safe.sensitivity = EspSensitivity::Public;
    let mut raw_node_cache = raw_export_record(
        "raw-node-cache",
        EspSourceKind::Registry,
        "esp-node-cache",
        Some("ExpectedValue"),
        "opaque-node-secret",
    );
    raw_node_cache.provenance.registry.as_mut().unwrap().key =
        r"SOFTWARE\Microsoft\Enrollments\Enrollment-1\NodeCache\42".to_string();
    snapshot.raw_evidence = vec![
        raw_log_safe,
        raw_export_record(
            "raw-authorization",
            EspSourceKind::ImeLog,
            "ime-log",
            None,
            "Authorization: Bearer ey.secret.token",
        ),
        raw_export_record(
            "raw-token",
            EspSourceKind::Registry,
            "wam-access-token",
            Some("AccessToken"),
            "ey.another.secret",
        ),
        raw_export_record(
            "raw-graph-body",
            EspSourceKind::Graph,
            "graph-response-body",
            None,
            r#"{"value":[{"userPrincipalName":"person@example.test"}]}"#,
        ),
        raw_export_record(
            "raw-hardware-hash",
            EspSourceKind::Registry,
            "autopilot-hardware-hash",
            Some("HardwareHash"),
            "BASE64-HARDWARE-HASH",
        ),
        raw_node_cache,
        raw_export_record(
            "raw-tenant",
            EspSourceKind::Registry,
            "autopilot-profile",
            Some("AADTenantID"),
            "tenant-from-registry",
        ),
        raw_export_record(
            "raw-serial",
            EspSourceKind::Registry,
            "system-hardware",
            Some("SerialNumber"),
            "SERIAL-FROM-REGISTRY",
        ),
    ];

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["raw-log-safe", "raw-node-cache", "raw-tenant", "raw-serial"]
    );
    let safe_text = match &safe.raw_evidence[0].raw_value {
        EspObservationValue::Text(value) => value,
        other => panic!("unexpected safe raw value: {other:?}"),
    };
    assert!(!safe_text.contains("person@example.test"));
    assert!(safe_text.contains("{11111111-2222-3333-4444-555555555555}"));
    assert!(safe_text.contains(r"C:\Windows\Temp\install.log"));
    for record in &safe.raw_evidence[1..] {
        assert_eq!(
            record.raw_value,
            EspObservationValue::Text("[redacted]".to_string()),
            "sensitive raw field was not fully masked: {record:?}"
        );
    }
    assert_eq!(snapshot.raw_evidence.len(), 8);
}

#[test]
fn redaction_projection_removes_device_hardware_data_from_every_raw_boundary() {
    let mut safe_control = raw_export_record(
        "raw-safe-control",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "safe control value",
    );
    safe_control.sensitivity = EspSensitivity::Public;

    let mut registry = raw_export_record(
        "raw-registry-hardware-data",
        EspSourceKind::Registry,
        "autopilot-registry",
        Some("DeviceHardwareData"),
        "REGISTRY-DEVICE-HARDWARE-SECRET",
    );
    registry.sensitivity = EspSensitivity::Public;

    let mut json = raw_export_record(
        "raw-json-hardware-data",
        EspSourceKind::Json,
        "autopilot-json:/DeviceHardwareData",
        None,
        "JSON-DEVICE-HARDWARE-SECRET",
    );
    json.sensitivity = EspSensitivity::Public;

    let mut raw = raw_export_record(
        "DeviceHardwareData",
        EspSourceKind::DeploymentLog,
        "deployment-log",
        None,
        "RAW-DEVICE-HARDWARE-SECRET",
    );
    raw.sensitivity = EspSensitivity::Public;

    let mut snapshot = findings_snapshot();
    snapshot.raw_evidence = vec![safe_control, registry, json, raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["raw-safe-control"]
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for forbidden in [
        "DeviceHardwareData",
        "REGISTRY-DEVICE-HARDWARE-SECRET",
        "JSON-DEVICE-HARDWARE-SECRET",
        "RAW-DEVICE-HARDWARE-SECRET",
    ] {
        assert!(
            !safe_json.contains(forbidden),
            "safe export leaked {forbidden}"
        );
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_unknown_authorization_schemes_and_uncommaed_digest_tails() {
    let folded_digest = "Authorization: Digest username=\"digest-user\";\r\n realm=\"digest-realm\"\r\n nonce=\"digest-tail-secret\"";
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        "Authorization: Negotiate evidence-negotiate-secret",
        "Authorization Custom source-custom-secret",
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(47),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:05:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "RequestMetadata".to_string(),
                value: "Authorization Custom registration-custom-secret".to_string(),
            },
            EspNamedValue {
                name: "ChallengeMetadata".to_string(),
                value: folded_digest.to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "11".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-unknown-authorization")],
    });

    let mut event = raw_export_record(
        "neutral-auth-scheme-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(3),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: "Negotiate event-negotiate-secret".to_string(),
        }],
    });
    let mut raw_authorization = raw_export_record(
        "neutral-unknown-authorization-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        "Authorization Custom raw-custom-secret",
    );
    raw_authorization.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw_authorization];
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "typed-basic-prose-control".to_string(),
        timestamp: timestamp("2026-07-15T12:05:01Z"),
        kind: EspTimelineKind::Other,
        title: "Basic authentication is configured".to_string(),
        detail: Some("Authorization remains required".to_string()),
        status: None,
        evidence: vec![evidence_ref("typed-basic-prose-control")],
    });
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from("Authorization: [redacted]", "Authorization [redacted]")
    );
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "Authorization [redacted]",
            "Authorization: [redacted]",
            "11"
        ]
    );
    assert_eq!(safe.raw_evidence.len(), 1);
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data[0]
            .value,
        "Negotiate [redacted]"
    );
    assert_eq!(safe.activity[0].title, "Basic authentication is configured");
    assert_eq!(
        safe.activity[0].detail.as_deref(),
        Some("Authorization remains required")
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "evidence-negotiate-secret",
        "source-custom-secret",
        "registration-custom-secret",
        "digest-user",
        "digest-realm",
        "digest-tail-secret",
        "event-negotiate-secret",
        "raw-custom-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_nested_one_layer_escaped_json_secret_values() {
    let evidence_payload =
        r#"neutral-ref {\"Authorization\":{\"credential\":\"nested-evidence-secret\"}}"#;
    let source_payload = r#"neutral-source {\"HardwareHash\":[\"nested-source-secret\"]}"#;
    let named_payload =
        r#"neutral-named {\"HardwareHash\":{\"payload\":[\"nested-named-secret\"]}}"#;
    let event_payload =
        r#"neutral-event {\"Authorization\":[{\"credential\":\"nested-event-secret\"}]}"#;

    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(evidence_payload, source_payload)];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(48),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:06:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "Metadata".to_string(),
                value: named_payload.to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "13".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-nested-escaped-json")],
    });

    let mut event = raw_export_record(
        "neutral-nested-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(4),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: event_payload.to_string(),
        }],
    });
    let mut registry = raw_export_record(
        "neutral-nested-registry",
        EspSourceKind::Registry,
        "neutral-registry-source",
        Some("Metadata"),
        r#"{\"DeviceHardwareData\":{\"value\":\"nested-registry-secret\"}}"#,
    );
    registry.sensitivity = EspSensitivity::Public;
    let mut json = raw_export_record(
        "neutral-nested-json",
        EspSourceKind::Json,
        "neutral-json-source",
        None,
        r#"{\"Authorization\":[\"nested-json-secret\"]}"#,
    );
    json.sensitivity = EspSensitivity::Public;
    let mut text = raw_export_record(
        "neutral-nested-text",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        r#"{\"HardwareHash\":{\"value\":\"nested-text-secret\"}}"#,
    );
    text.sensitivity = EspSensitivity::Public;
    let mut string_list = raw_export_record(
        "neutral-nested-string-list",
        EspSourceKind::Json,
        "neutral-list-source",
        None,
        "placeholder",
    );
    string_list.sensitivity = EspSensitivity::Public;
    string_list.raw_value = EspObservationValue::StringList(vec![
        "safe list value".to_string(),
        r#"{\"DeviceHardwareData\":[\"nested-list-secret\"]}"#.to_string(),
    ]);
    let mut safe_control = raw_export_record(
        "neutral-nested-safe-control",
        EspSourceKind::Json,
        "neutral-safe-source",
        None,
        r#"{\"TokenCount\":[13]}"#,
    );
    safe_control.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, registry, json, text, string_list, safe_control];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from(
            r#"neutral-ref {\"Authorization\":\"[redacted]\"}"#,
            r#"neutral-source {\"HardwareHash\":\"[redacted]\"}"#,
        )
    );
    assert_eq!(
        safe.registration_events[0].named_data[0].value,
        r#"neutral-named {\"HardwareHash\":\"[redacted]\"}"#
    );
    assert_eq!(safe.registration_events[0].named_data[1].value, "13");
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["neutral-nested-event", "neutral-nested-safe-control"]
    );
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data[0]
            .value,
        r#"neutral-event {\"Authorization\":\"[redacted]\"}"#
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "nested-evidence-secret",
        "nested-source-secret",
        "nested-named-secret",
        "nested-event-secret",
        "nested-registry-secret",
        "nested-json-secret",
        "nested-text-secret",
        "nested-list-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_arrow_delimited_hardware_material() {
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        "HardwareHash -> arrow-evidence-secret",
        "DeviceHardwareData -> arrow-source-secret",
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(49),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:07:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "HardwareMetadata".to_string(),
                value: "HardwareHash -> arrow-named-hardware-secret".to_string(),
            },
            EspNamedValue {
                name: "DeviceMetadata".to_string(),
                value: "DeviceHardwareData -> arrow-named-device-secret".to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "17".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-arrow-hardware-material")],
    });

    let mut event = raw_export_record(
        "neutral-arrow-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(5),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: "DeviceHardwareData -> arrow-event-secret".to_string(),
        }],
    });
    let mut raw = raw_export_record(
        "neutral-arrow-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        "HardwareHash -> arrow-raw-secret",
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from(
            "HardwareHash -> [redacted]",
            "DeviceHardwareData -> [redacted]"
        )
    );
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "HardwareHash -> [redacted]",
            "DeviceHardwareData -> [redacted]",
            "17",
        ]
    );
    assert_eq!(safe.raw_evidence.len(), 1);
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data[0]
            .value,
        "DeviceHardwareData -> [redacted]"
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "arrow-evidence-secret",
        "arrow-source-secret",
        "arrow-named-hardware-secret",
        "arrow-named-device-secret",
        "arrow-event-secret",
        "arrow-raw-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_rfc_token_authorization_schemes_and_extended_digest_fields() {
    let evidence_secret = "scheme-token-evidence-secret";
    let source_secret = "digest-extended-source-secret";
    let registration_secret = "scheme-token-registration-secret";
    let digest_secret = "digest-extended-registration-secret";
    let event_secret = "scheme-token-event-secret";
    let raw_secret = "scheme-token-raw-secret";
    let source_digest = format!(
        "Authorization: Digest realm=\"source-realm\";\r\n username*=UTF-8''{source_secret}"
    );
    let registration_digest = format!(
        "Authorization Digest realm=\"registration-realm\"\r\n username*=UTF-8''{digest_secret}"
    );

    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        &format!("Authorization Custom+V1 {evidence_secret}"),
        &source_digest,
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(50),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:08:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "RequestMetadata".to_string(),
                value: format!("Authorization: Custom+V1 {registration_secret}"),
            },
            EspNamedValue {
                name: "ChallengeMetadata".to_string(),
                value: registration_digest,
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "19".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-rfc-token-authorization")],
    });

    let mut event = raw_export_record(
        "neutral-rfc-scheme-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(6),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: format!("Authorization Custom+V1 {event_secret}"),
        }],
    });
    let mut raw = raw_export_record(
        "neutral-rfc-scheme-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        &format!("Authorization: Custom+V1 {raw_secret}"),
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw];
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "rfc-scheme-narrative-controls".to_string(),
        timestamp: timestamp("2026-07-15T12:08:01Z"),
        kind: EspTimelineKind::Other,
        title: "Basic authentication is configured".to_string(),
        detail: Some("Authorization remains required".to_string()),
        status: None,
        evidence: vec![evidence_ref("rfc-scheme-narrative-controls")],
    });
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from("Authorization [redacted]", "Authorization: [redacted]")
    );
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "Authorization: [redacted]",
            "Authorization [redacted]",
            "19"
        ]
    );
    assert_eq!(safe.raw_evidence.len(), 1);
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data[0]
            .value,
        "Authorization [redacted]"
    );
    assert_eq!(safe.activity[0].title, "Basic authentication is configured");
    assert_eq!(
        safe.activity[0].detail.as_deref(),
        Some("Authorization remains required")
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        evidence_secret,
        source_secret,
        registration_secret,
        digest_secret,
        event_secret,
        raw_secret,
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_equals_arrow_and_folded_hardware_material() {
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        "HardwareHash => equals-arrow-evidence-secret",
        "DeviceHardwareData => equals-arrow-source-secret",
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(51),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:09:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "HardwareMetadata".to_string(),
                value: "HardwareHash => equals-arrow-registration-secret".to_string(),
            },
            EspNamedValue {
                name: "DeviceMetadata".to_string(),
                value: "DeviceHardwareData ->\r\n folded-arrow-registration-secret".to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "21".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-folded-arrow-hardware")],
    });

    let mut event = raw_export_record(
        "neutral-folded-arrow-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(7),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: "DeviceHardwareData ->\n folded-arrow-event-secret".to_string(),
        }],
    });
    let mut raw_text = raw_export_record(
        "neutral-folded-arrow-text",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        "HardwareHash => equals-arrow-raw-secret",
    );
    raw_text.sensitivity = EspSensitivity::Public;
    let mut raw_list = raw_export_record(
        "neutral-folded-arrow-list",
        EspSourceKind::Json,
        "neutral-list-source",
        None,
        "placeholder",
    );
    raw_list.sensitivity = EspSensitivity::Public;
    raw_list.raw_value = EspObservationValue::StringList(vec![
        "safe list value".to_string(),
        "DeviceHardwareData ->\r\n folded-arrow-list-secret".to_string(),
    ]);
    snapshot.raw_evidence = vec![event, raw_text, raw_list];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from(
            "HardwareHash => [redacted]",
            "DeviceHardwareData => [redacted]"
        )
    );
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "HardwareHash => [redacted]",
            "DeviceHardwareData ->\r\n [redacted]",
            "21",
        ]
    );
    assert_eq!(safe.raw_evidence.len(), 1);
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data[0]
            .value,
        "DeviceHardwareData ->\n [redacted]"
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "equals-arrow-evidence-secret",
        "equals-arrow-source-secret",
        "equals-arrow-registration-secret",
        "folded-arrow-registration-secret",
        "folded-arrow-event-secret",
        "equals-arrow-raw-secret",
        "folded-arrow-list-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_plain_nested_json_secret_values_across_public_boundaries() {
    let evidence_payload =
        r#"neutral-ref {"Authorization":{"credential":"plain-evidence-secret"}}"#;
    let source_payload = r#"neutral-source {"Authorization":["plain-source-secret"]}"#;
    let registration_payload =
        r#"neutral-named {"Authorization":{"credential":"plain-registration-secret"}}"#;
    let event_payload = r#"neutral-event {"Authorization":[{"credential":"plain-event-secret"}]}"#;

    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(evidence_payload, source_payload)];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(52),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:10:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "Metadata".to_string(),
                value: registration_payload.to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "23".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-plain-nested-json")],
    });

    let mut event = raw_export_record(
        "neutral-plain-nested-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(8),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: event_payload.to_string(),
        }],
    });
    let mut registry = raw_export_record(
        "neutral-plain-nested-registry",
        EspSourceKind::Registry,
        "neutral-registry-source",
        Some("Metadata"),
        r#"{"Authorization":{"value":"plain-registry-secret"}}"#,
    );
    registry.sensitivity = EspSensitivity::Public;
    let mut json = raw_export_record(
        "neutral-plain-nested-json",
        EspSourceKind::Json,
        "neutral-json-source",
        None,
        r#"{"Authorization":["plain-json-secret"]}"#,
    );
    json.sensitivity = EspSensitivity::Public;
    let mut text = raw_export_record(
        "neutral-plain-nested-text",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        r#"{"Authorization":{"value":"plain-text-secret"}}"#,
    );
    text.sensitivity = EspSensitivity::Public;
    let mut string_list = raw_export_record(
        "neutral-plain-nested-list",
        EspSourceKind::Json,
        "neutral-list-source",
        None,
        "placeholder",
    );
    string_list.sensitivity = EspSensitivity::Public;
    string_list.raw_value = EspObservationValue::StringList(vec![
        "safe list value".to_string(),
        r#"{"Authorization":["plain-list-secret"]}"#.to_string(),
    ]);
    let mut safe_control = raw_export_record(
        "neutral-plain-nested-control",
        EspSourceKind::Json,
        "neutral-safe-source",
        None,
        r#"{"TokenCount":{"value":23}}"#,
    );
    safe_control.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, registry, json, text, string_list, safe_control];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from(
            r#"neutral-ref {"Authorization":"[redacted]"}"#,
            r#"neutral-source {"Authorization":"[redacted]"}"#,
        )
    );
    assert_eq!(
        safe.registration_events[0].named_data[0].value,
        r#"neutral-named {"Authorization":"[redacted]"}"#
    );
    assert_eq!(safe.registration_events[0].named_data[1].value, "23");
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["neutral-plain-nested-event", "neutral-plain-nested-control"]
    );
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data[0]
            .value,
        r#"neutral-event {"Authorization":"[redacted]"}"#
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "plain-evidence-secret",
        "plain-source-secret",
        "plain-registration-secret",
        "plain-event-secret",
        "plain-registry-secret",
        "plain-json-secret",
        "plain-text-secret",
        "plain-list-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_authorization_arrow_delimiters_across_public_boundaries() {
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        "Authorization -> AUTH_ARROW_SECRET",
        "Authorization => AUTH_EQUALS_ARROW_SECRET",
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(53),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:11:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "TightEnvelope".to_string(),
                value: "Authorization->AUTH_TIGHT_ARROW_SECRET".to_string(),
            },
            EspNamedValue {
                name: "FoldedEnvelope".to_string(),
                value: "Authorization ->\r\n AUTH_ARROW_FOLD_AFTER_SECRET".to_string(),
            },
            EspNamedValue {
                name: "RfcSchemeControl".to_string(),
                value: "Authorization Custom+V1 rfc-scheme-control-secret".to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "29".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-authorization-arrows")],
    });

    let mut event = raw_export_record(
        "neutral-review6-arrow-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(9),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: "Authorization\r\n -> AUTH_ARROW_FOLD_BEFORE_SECRET".to_string(),
        }],
    });
    let mut raw = raw_export_record(
        "neutral-review6-arrow-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        "Authorization->AUTH_TIGHT_ARROW_SECRET",
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw];
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "authorization-arrow-narrative-controls".to_string(),
        timestamp: timestamp("2026-07-15T12:11:01Z"),
        kind: EspTimelineKind::Other,
        title: "Basic authentication is configured".to_string(),
        detail: Some("Authorization remains required".to_string()),
        status: None,
        evidence: vec![evidence_ref("authorization-arrow-narrative-controls")],
    });
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(safe.raw_evidence.len(), 1);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from("Authorization -> [redacted]", "Authorization => [redacted]")
    );
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "Authorization->[redacted]",
            "Authorization ->\r\n [redacted]",
            "Authorization [redacted]",
            "29",
        ]
    );
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data[0]
            .value,
        "Authorization\r\n -> [redacted]"
    );
    assert_eq!(safe.activity[0].title, "Basic authentication is configured");
    assert_eq!(
        safe.activity[0].detail.as_deref(),
        Some("Authorization remains required")
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "AUTH_ARROW_SECRET",
        "AUTH_EQUALS_ARROW_SECRET",
        "AUTH_TIGHT_ARROW_SECRET",
        "AUTH_ARROW_FOLD_AFTER_SECRET",
        "AUTH_ARROW_FOLD_BEFORE_SECRET",
        "rfc-scheme-control-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_folded_authorization_continuation_tails() {
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        "Authorization: Custom unknown-first-line-secret\r\n UNKNOWN_TAIL_SECRET",
        "Authorization: Negotiate negotiate-first-line-secret\r\n NEGOTIATE_TAIL_SECRET",
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(54),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:12:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "RequestMetadata".to_string(),
                value: "Authorization: NTLM ntlm-first-line-secret\r\n NTLM_TAIL_SECRET"
                    .to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "31".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-folded-authorization-tail")],
    });

    let mut event = raw_export_record(
        "neutral-review6-folded-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(10),
        named_data: vec![
            EspNamedValue {
                name: "NegotiateEnvelope".to_string(),
                value: "Negotiate negotiate-event-secret\r\n NEGOTIATE_TAIL_SECRET".to_string(),
            },
            EspNamedValue {
                name: "NtlmEnvelope".to_string(),
                value: "NTLM ntlm-event-secret\n NTLM_TAIL_SECRET".to_string(),
            },
        ],
    });
    let mut raw = raw_export_record(
        "neutral-review6-folded-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        "Authorization Custom raw-first-line-secret\r\n UNKNOWN_TAIL_SECRET",
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from("Authorization: [redacted]", "Authorization: [redacted]")
    );
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec!["Authorization: [redacted]", "31"]
    );
    assert_eq!(safe.raw_evidence.len(), 1);
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec!["Negotiate [redacted]", "NTLM [redacted]"]
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "UNKNOWN_TAIL_SECRET",
        "NEGOTIATE_TAIL_SECRET",
        "NTLM_TAIL_SECRET",
        "unknown-first-line-secret",
        "negotiate-first-line-secret",
        "ntlm-first-line-secret",
        "negotiate-event-secret",
        "ntlm-event-secret",
        "raw-first-line-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_rfc_digest_params_and_hardware_arrows_folded_before_delimiter() {
    let digest = concat!(
        "Authorization: Digest realm=\"neutral\";\r\n",
        " user.name=\"DIGEST_DOT_PARAM_SECRET\"\r\n",
        " user+name=\"DIGEST_PLUS_PARAM_SECRET\"\r\n",
        " user~name=\"DIGEST_TILDE_PARAM_SECRET\""
    );
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        digest,
        "HardwareHash\r\n -> HASH_ARROW_FOLD_BEFORE_SECRET",
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(55),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:13:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "HardwareMetadata".to_string(),
                value: "DeviceHardwareData\r\n => DEVICE_ARROW_FOLD_BEFORE_SECRET".to_string(),
            },
            EspNamedValue {
                name: "PlainJsonControl".to_string(),
                value: r#"neutral {"Authorization":{"credential":"plain-json-control-secret"}}"#
                    .to_string(),
            },
            EspNamedValue {
                name: "EscapedJsonControl".to_string(),
                value: r#"neutral {\"Authorization\":{\"credential\":\"escaped-json-control-secret\"}}"#
                    .to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "37".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-fold-before-hardware-arrow")],
    });

    let mut event = raw_export_record(
        "neutral-fold-before-hardware-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(11),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: "HardwareHash\n -> HASH_ARROW_FOLD_BEFORE_SECRET".to_string(),
        }],
    });
    let mut raw_digest = raw_export_record(
        "neutral-rfc-digest-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        digest,
    );
    raw_digest.sensitivity = EspSensitivity::Public;
    let mut raw_hardware = raw_export_record(
        "neutral-fold-before-hardware-raw",
        EspSourceKind::Registry,
        "neutral-registry-source",
        None,
        "DeviceHardwareData\r\n => DEVICE_ARROW_FOLD_BEFORE_SECRET",
    );
    raw_hardware.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw_digest, raw_hardware];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.identity.evidence[0],
        evidence_ref_from(
            "Authorization: [redacted]",
            "HardwareHash\r\n -> [redacted]"
        )
    );
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec![
            "DeviceHardwareData\r\n => [redacted]",
            r#"neutral {"Authorization":"[redacted]"}"#,
            r#"neutral {\"Authorization\":\"[redacted]\"}"#,
            "37",
        ]
    );
    assert_eq!(safe.raw_evidence.len(), 1);
    assert_eq!(
        safe.raw_evidence[0]
            .provenance
            .event
            .as_ref()
            .unwrap()
            .named_data[0]
            .value,
        "HardwareHash\n -> [redacted]"
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "DIGEST_DOT_PARAM_SECRET",
        "DIGEST_PLUS_PARAM_SECRET",
        "DIGEST_TILDE_PARAM_SECRET",
        "HASH_ARROW_FOLD_BEFORE_SECRET",
        "DEVICE_ARROW_FOLD_BEFORE_SECRET",
        "plain-json-control-secret",
        "escaped-json-control-secret",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_one_layer_escaped_json_token_members_across_public_boundaries() {
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        r#"neutral {\"access_token\":\"ESCAPED_ACCESS_TOKEN_SENTINEL\"}"#,
        r#"neutral {\"refresh_token\":\"ESCAPED_REFRESH_TOKEN_SENTINEL\"}"#,
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(56),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:14:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "EscapedTokenEnvelope".to_string(),
                value: r#"neutral {\"id_token\":\"ESCAPED_NAMED_ID_TOKEN_SENTINEL\"}"#.to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "41".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-escaped-token-member")],
    });

    let mut event = raw_export_record(
        "neutral-review7-escaped-token-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(12),
        named_data: vec![EspNamedValue {
            name: "EscapedApiEnvelope".to_string(),
            value: r#"neutral {\"api_key\":\"ESCAPED_EVENT_API_KEY_SENTINEL\"}"#.to_string(),
        }],
    });
    let mut raw = raw_export_record(
        "neutral-review7-escaped-token-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        r#"{\"access_token\":\"ESCAPED_RAW_ACCESS_TOKEN_SENTINEL\"}"#,
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(safe.registration_events[0].named_data[1].value, "41");
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["neutral-review7-escaped-token-event"]
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "ESCAPED_ACCESS_TOKEN_SENTINEL",
        "ESCAPED_REFRESH_TOKEN_SENTINEL",
        "ESCAPED_NAMED_ID_TOKEN_SENTINEL",
        "ESCAPED_EVENT_API_KEY_SENTINEL",
        "ESCAPED_RAW_ACCESS_TOKEN_SENTINEL",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_complete_standalone_digest_challenges_across_public_boundaries() {
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(
        r#"Digest username="DIGEST_EVIDENCE_USER", realm="DIGEST_EVIDENCE_REALM", nonce="DIGEST_EVIDENCE_NONCE""#,
        r#"Digest username="DIGEST_SOURCE_USER", realm="DIGEST_SOURCE_REALM", nonce="DIGEST_SOURCE_NONCE""#,
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(57),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: r#"Digest username="DIGEST_MESSAGE_USER", realm="DIGEST_MESSAGE_REALM", nonce="DIGEST_MESSAGE_NONCE""#.to_string(),
        timestamp: timestamp("2026-07-15T12:15:00Z"),
        named_data: vec![EspNamedValue {
            name: "Payload".to_string(),
            value: r#"Digest username="DIGEST_NAMED_USER", realm="DIGEST_NAMED_REALM", nonce="DIGEST_NAMED_NONCE""#.to_string(),
        }],
        evidence: vec![evidence_ref("registration-standalone-digest")],
    });
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "standalone-digest-narrative".to_string(),
        timestamp: timestamp("2026-07-15T12:15:01Z"),
        kind: EspTimelineKind::Other,
        title: r#"Digest username="DIGEST_TITLE_USER", realm="DIGEST_TITLE_REALM", nonce="DIGEST_TITLE_NONCE""#.to_string(),
        detail: Some(
            r#"Digest username="DIGEST_DETAIL_USER", realm="DIGEST_DETAIL_REALM", nonce="DIGEST_DETAIL_NONCE""#.to_string(),
        ),
        status: None,
        evidence: vec![evidence_ref("timeline-standalone-digest")],
    });
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: "standalone-digest-coverage".to_string(),
        family: "review".to_string(),
        status: EspArtifactStatus::Available,
        detail: Some(
            r#"Digest username="DIGEST_COVERAGE_USER", realm="DIGEST_COVERAGE_REALM", nonce="DIGEST_COVERAGE_NONCE""#.to_string(),
        ),
        observed_at_utc: "2026-07-15T12:15:02Z".to_string(),
        evidence: vec![],
    });

    let mut event = raw_export_record(
        "neutral-review7-standalone-digest-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(13),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: r#"Digest username="DIGEST_EVENT_USER", realm="DIGEST_EVENT_REALM", nonce="DIGEST_EVENT_NONCE""#.to_string(),
        }],
    });
    let mut raw = raw_export_record(
        "neutral-review7-standalone-digest-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        r#"Digest username="DIGEST_RAW_USER", realm="DIGEST_RAW_REALM", nonce="DIGEST_RAW_NONCE""#,
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["neutral-review7-standalone-digest-event"]
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "DIGEST_EVIDENCE_USER",
        "DIGEST_EVIDENCE_REALM",
        "DIGEST_EVIDENCE_NONCE",
        "DIGEST_SOURCE_USER",
        "DIGEST_SOURCE_REALM",
        "DIGEST_SOURCE_NONCE",
        "DIGEST_MESSAGE_USER",
        "DIGEST_MESSAGE_REALM",
        "DIGEST_MESSAGE_NONCE",
        "DIGEST_NAMED_USER",
        "DIGEST_NAMED_REALM",
        "DIGEST_NAMED_NONCE",
        "DIGEST_TITLE_USER",
        "DIGEST_TITLE_REALM",
        "DIGEST_TITLE_NONCE",
        "DIGEST_DETAIL_USER",
        "DIGEST_DETAIL_REALM",
        "DIGEST_DETAIL_NONCE",
        "DIGEST_COVERAGE_USER",
        "DIGEST_COVERAGE_REALM",
        "DIGEST_COVERAGE_NONCE",
        "DIGEST_EVENT_USER",
        "DIGEST_EVENT_REALM",
        "DIGEST_EVENT_NONCE",
        "DIGEST_RAW_USER",
        "DIGEST_RAW_REALM",
        "DIGEST_RAW_NONCE",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_sanitizes_production_coverage_and_gap_identifiers() {
    let artifact_id =
        "ime-logs|person-review7@example.test|Authorization Bearer COVERAGE_ID_SENTINEL";
    let restricted_source =
        r"C:\Users\review7.user\AppData\Local\Temp\Authorization Bearer RESTRICTED_SOURCE_SENTINEL";
    let mut snapshot = findings_snapshot();
    snapshot.elevation.is_elevated = false;
    snapshot.elevation.restricted_sources = vec![restricted_source.to_string()];
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: artifact_id.to_string(),
        family: "IntuneManagementExtensionLogs".to_string(),
        status: EspArtifactStatus::PermissionDenied,
        detail: Some("Protected log path is unreadable".to_string()),
        observed_at_utc: "2026-07-15T12:16:00Z".to_string(),
        evidence: vec![],
    });
    snapshot.findings = derive_findings(&snapshot);
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "person-review7@example.test",
        "review7.user",
        "COVERAGE_ID_SENTINEL",
        "RESTRICTED_SOURCE_SENTINEL",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }

    let ime = finding_by_id(&safe.findings, "ime-evidence-unavailable");
    assert_eq!(
        ime.coverage_gap_ids,
        vec![safe.coverage[0].artifact_id.clone()]
    );
    let non_elevated = finding_by_id(&safe.findings, "non-elevated-coverage-loss");
    assert_eq!(
        non_elevated
            .coverage_gap_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        [
            safe.coverage[0].artifact_id.clone(),
            safe.elevation.restricted_sources[0].clone(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_device_serial_and_azure_tenant_aliases() {
    let mut snapshot = findings_snapshot();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(58),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: "Device registration failed".to_string(),
        timestamp: timestamp("2026-07-15T12:17:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "DeviceSerialNumber".to_string(),
                value: "NAMED_DEVICE_SERIAL_SENTINEL".to_string(),
            },
            EspNamedValue {
                name: "AzureADTenantID".to_string(),
                value: "NAMED_AZURE_TENANT_SENTINEL".to_string(),
            },
            EspNamedValue {
                name: "TokenCount".to_string(),
                value: "43".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-sensitive-aliases")],
    });
    let mut serial = raw_export_record(
        "review7-device-serial",
        EspSourceKind::Registry,
        "review7-registry-source",
        Some("DeviceSerialNumber"),
        "RAW_DEVICE_SERIAL_SENTINEL",
    );
    serial.sensitivity = EspSensitivity::Public;
    let mut tenant = raw_export_record(
        "review7-azure-tenant",
        EspSourceKind::Registry,
        "review7-registry-source",
        Some("AzureADTenantID"),
        "RAW_AZURE_TENANT_SENTINEL",
    );
    tenant.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![serial, tenant];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(
        safe.registration_events[0]
            .named_data
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec!["[redacted]", "[redacted]", "43"]
    );
    assert!(safe
        .raw_evidence
        .iter()
        .all(|record| { record.raw_value == EspObservationValue::Text("[redacted]".to_string()) }));
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "NAMED_DEVICE_SERIAL_SENTINEL",
        "NAMED_AZURE_TENANT_SENTINEL",
        "RAW_DEVICE_SERIAL_SENTINEL",
        "RAW_AZURE_TENANT_SENTINEL",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_sensitive_aliases_across_generic_public_boundaries() {
    let coverage_id = "ime|AzureADTenantID=COVERAGE_AZURE_TENANT_ALIAS";
    let restricted_source =
        r#"restricted|{\"DeviceSerialNumber\":\"RESTRICTED_DEVICE_SERIAL_ALIAS\"}"#;
    let mut snapshot = findings_snapshot();
    snapshot.elevation.is_elevated = false;
    snapshot.elevation.restricted_sources = vec![restricted_source.to_string()];
    snapshot.identity.evidence = vec![evidence_ref_from(
        r#"evidence|{\"AzureADTenantID\":\"EVIDENCE_AZURE_TENANT_ALIAS\"}"#,
        r#"source|{"DeviceSerialNumber":"SOURCE_DEVICE_SERIAL_ALIAS"}"#,
    )];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(59),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: concat!(
            "AzureADTenantID=REGISTRATION_MESSAGE_TENANT_ALIAS ",
            "DeviceSerialNumber: REGISTRATION_MESSAGE_SERIAL_ALIAS",
        )
        .to_string(),
        timestamp: timestamp("2026-07-15T12:18:00Z"),
        named_data: vec![
            EspNamedValue {
                name: "AssignedEnvelope".to_string(),
                value: concat!(
                    "AADTenantID=ASSIGNED_AAD_TENANT_ALIAS ",
                    "DeviceSerialNumber: ASSIGNED_DEVICE_SERIAL_ALIAS",
                )
                .to_string(),
            },
            EspNamedValue {
                name: "BareEnvelope".to_string(),
                value: concat!(
                    "AzureADTenantID BARE_AZURE_TENANT_ALIAS ",
                    "DeviceSerialNumber BARE_DEVICE_SERIAL_ALIAS",
                )
                .to_string(),
            },
            EspNamedValue {
                name: "EscapedJsonEnvelope".to_string(),
                value: concat!(
                    r#"{\"AzureADTenantID\":\"ESCAPED_AZURE_TENANT_ALIAS\","#,
                    r#"\"DeviceSerialNumber\":\"ESCAPED_DEVICE_SERIAL_ALIAS\"}"#,
                )
                .to_string(),
            },
            EspNamedValue {
                name: "PlainJsonEnvelope".to_string(),
                value: concat!(
                    r#"{"AADTenantID":"PLAIN_AAD_TENANT_ALIAS","#,
                    r#""DeviceSerialNumber":"PLAIN_DEVICE_SERIAL_ALIAS"}"#,
                )
                .to_string(),
            },
            EspNamedValue {
                name: "AzureADTenantIDPolicy".to_string(),
                value: "keep-safe-alias-control".to_string(),
            },
        ],
        evidence: vec![evidence_ref("registration-sensitive-alias-envelopes")],
    });
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: coverage_id.to_string(),
        family: r#"family|{"DeviceSerialNumber":"COVERAGE_FAMILY_SERIAL_ALIAS"}"#.to_string(),
        status: EspArtifactStatus::PermissionDenied,
        detail: Some("Protected source is unavailable".to_string()),
        observed_at_utc: "2026-07-15T12:18:01Z".to_string(),
        evidence: vec![],
    });
    snapshot.findings.push(EspDiagnosticFinding {
        finding_id: "sensitive-alias-coverage".to_string(),
        severity: EspFindingSeverity::Warning,
        confidence: EspFindingConfidence::High,
        title: "Sensitive alias coverage".to_string(),
        summary: "The source inventory has a coverage gap.".to_string(),
        recommended_checks: vec!["Review the cited coverage gaps.".to_string()],
        evidence: vec![],
        coverage_gap_ids: vec![coverage_id.to_string(), restricted_source.to_string()],
    });

    let mut event = raw_export_record(
        "neutral-sensitive-alias-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(14),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: concat!(
                r#"{\"AzureADTenantID\":\"EVENT_AZURE_TENANT_ALIAS\","#,
                r#"\"DeviceSerialNumber\":\"EVENT_DEVICE_SERIAL_ALIAS\"}"#,
            )
            .to_string(),
        }],
    });
    let mut raw_json = raw_export_record(
        "neutral-sensitive-alias-json-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        concat!(
            r#"{\"AzureADTenantID\":\"RAW_JSON_AZURE_TENANT_ALIAS\","#,
            r#"\"DeviceSerialNumber\":\"RAW_JSON_DEVICE_SERIAL_ALIAS\"}"#,
        ),
    );
    raw_json.sensitivity = EspSensitivity::Public;
    let mut raw_text = raw_export_record(
        "neutral-sensitive-alias-text-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        concat!(
            "AzureADTenantID=RAW_TEXT_AZURE_TENANT_ALIAS ",
            "DeviceSerialNumber RAW_TEXT_DEVICE_SERIAL_ALIAS",
        ),
    );
    raw_text.sensitivity = EspSensitivity::Public;
    let mut safe_control = raw_export_record(
        "neutral-sensitive-alias-safe-control",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        "AzureADTenantIDPolicy=keep-raw-safe-alias-control",
    );
    safe_control.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw_json, raw_text, safe_control];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);

    assert_eq!(
        safe.registration_events[0].named_data[4].value,
        "keep-safe-alias-control"
    );
    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "neutral-sensitive-alias-event",
            "neutral-sensitive-alias-text-raw",
            "neutral-sensitive-alias-safe-control",
        ]
    );
    assert_eq!(
        safe.findings[0]
            .coverage_gap_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        [
            safe.coverage[0].artifact_id.clone(),
            safe.elevation.restricted_sources[0].clone(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "COVERAGE_AZURE_TENANT_ALIAS",
        "RESTRICTED_DEVICE_SERIAL_ALIAS",
        "EVIDENCE_AZURE_TENANT_ALIAS",
        "SOURCE_DEVICE_SERIAL_ALIAS",
        "REGISTRATION_MESSAGE_TENANT_ALIAS",
        "REGISTRATION_MESSAGE_SERIAL_ALIAS",
        "ASSIGNED_AAD_TENANT_ALIAS",
        "ASSIGNED_DEVICE_SERIAL_ALIAS",
        "BARE_AZURE_TENANT_ALIAS",
        "BARE_DEVICE_SERIAL_ALIAS",
        "ESCAPED_AZURE_TENANT_ALIAS",
        "ESCAPED_DEVICE_SERIAL_ALIAS",
        "PLAIN_AAD_TENANT_ALIAS",
        "PLAIN_DEVICE_SERIAL_ALIAS",
        "COVERAGE_FAMILY_SERIAL_ALIAS",
        "EVENT_AZURE_TENANT_ALIAS",
        "EVENT_DEVICE_SERIAL_ALIAS",
        "RAW_JSON_AZURE_TENANT_ALIAS",
        "RAW_JSON_DEVICE_SERIAL_ALIAS",
        "RAW_TEXT_AZURE_TENANT_ALIAS",
        "RAW_TEXT_DEVICE_SERIAL_ALIAS",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert!(safe_json.contains("keep-safe-alias-control"));
    assert!(safe_json.contains("keep-raw-safe-alias-control"));
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_escaped_digest_quoted_comma_and_complete_tails() {
    let standalone = concat!(
        r#"Digest username=\"STANDALONE_DIGEST_USER\", "#,
        r#"qop=\"auth,STANDALONE_DIGEST_QOP_TAIL\", "#,
        r#"nonce=\"STANDALONE_DIGEST_NONCE\""#,
    );
    let authorized = concat!(
        r#"Authorization: Digest realm=\"AUTHORIZED_DIGEST_REALM\", "#,
        r#"qop=\"auth,AUTHORIZED_DIGEST_QOP_TAIL\", "#,
        r#"nonce=\"AUTHORIZED_DIGEST_NONCE\""#,
    );
    let space_separated = concat!(
        r#"Digest username=\"SPACE_DIGEST_USER\" "#,
        r#"realm=\"SPACE_DIGEST_REALM\" nonce=\"SPACE_DIGEST_NONCE\""#,
    );
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = vec![evidence_ref_from(standalone, authorized)];
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(60),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: standalone.to_string(),
        timestamp: timestamp("2026-07-15T12:19:00Z"),
        named_data: vec![EspNamedValue {
            name: "DigestEnvelope".to_string(),
            value: space_separated.to_string(),
        }],
        evidence: vec![evidence_ref("registration-complete-digest-tail")],
    });
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: "digest-tail-coverage".to_string(),
        family: "review".to_string(),
        status: EspArtifactStatus::Available,
        detail: Some(authorized.to_string()),
        observed_at_utc: "2026-07-15T12:19:01Z".to_string(),
        evidence: vec![],
    });

    let mut event = raw_export_record(
        "neutral-complete-digest-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(15),
        named_data: vec![EspNamedValue {
            name: "Envelope".to_string(),
            value: authorized.to_string(),
        }],
    });
    let mut raw = raw_export_record(
        "neutral-complete-digest-raw",
        EspSourceKind::DeploymentLog,
        "neutral-deployment-source",
        None,
        standalone,
    );
    raw.sensitivity = EspSensitivity::Public;
    snapshot.raw_evidence = vec![event, raw];
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);

    assert_eq!(
        safe.raw_evidence
            .iter()
            .map(|record| record.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["neutral-complete-digest-event"]
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "STANDALONE_DIGEST_USER",
        "STANDALONE_DIGEST_QOP_TAIL",
        "STANDALONE_DIGEST_NONCE",
        "AUTHORIZED_DIGEST_REALM",
        "AUTHORIZED_DIGEST_QOP_TAIL",
        "AUTHORIZED_DIGEST_NONCE",
        "SPACE_DIGEST_USER",
        "SPACE_DIGEST_REALM",
        "SPACE_DIGEST_NONCE",
    ] {
        assert!(!safe_json.contains(secret), "safe export leaked {secret}");
    }
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_preserves_safe_digest_key_value_narratives() {
    let mut snapshot = findings_snapshot();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 100,
        record_id: Some(61),
        status: status(
            EspRawStatus::Text("informational".to_string()),
            EspNormalizedStatus::InProgress,
        ),
        message: "Digest algorithm=SHA-256 is supported".to_string(),
        timestamp: timestamp("2026-07-15T12:20:00Z"),
        named_data: vec![],
        evidence: vec![evidence_ref("registration-safe-digest-narrative")],
    });
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "safe-digest-narrative".to_string(),
        timestamp: timestamp("2026-07-15T12:20:01Z"),
        kind: EspTimelineKind::Other,
        title: "Digest algorithm=SHA-256 is supported".to_string(),
        detail: Some("Digest retry-count=2 remains within policy".to_string()),
        status: None,
        evidence: vec![evidence_ref("safe-digest-narrative")],
    });
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: "safe-digest-narrative-coverage".to_string(),
        family: "review".to_string(),
        status: EspArtifactStatus::Available,
        detail: Some("Digest algorithm=SHA-256 remains configured".to_string()),
        observed_at_utc: "2026-07-15T12:20:02Z".to_string(),
        evidence: vec![],
    });
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "real-digest-challenge-control".to_string(),
        timestamp: timestamp("2026-07-15T12:20:03Z"),
        kind: EspTimelineKind::Other,
        title: "Digest algorithm=SHA-256 nonce=REAL_DIGEST_NONCE_CONTROL".to_string(),
        detail: None,
        status: None,
        evidence: vec![evidence_ref("real-digest-challenge-control")],
    });
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);

    assert_eq!(
        safe.registration_events[0].message,
        "Digest algorithm=SHA-256 is supported"
    );
    assert_eq!(
        safe.activity[0].title,
        "Digest algorithm=SHA-256 is supported"
    );
    assert_eq!(
        safe.activity[0].detail.as_deref(),
        Some("Digest retry-count=2 remains within policy")
    );
    assert_eq!(
        safe.coverage[0].detail.as_deref(),
        Some("Digest algorithm=SHA-256 remains configured")
    );
    assert!(!serde_json::to_string(&safe)
        .unwrap()
        .contains("REAL_DIGEST_NONCE_CONTROL"));
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_literal_and_serialized_credentials_across_public_boundaries() {
    let credential_payloads = [
        (
            "literal-bearer",
            r#"Bearer "LITERAL_BEARER_HEAD LITERAL_BEARER_TAIL_SECRET""#,
        ),
        (
            "escaped-bearer",
            r#"Bearer \"ESCAPED_BEARER_HEAD ESCAPED_BEARER_TAIL_SECRET\""#,
        ),
        (
            "twice-escaped-bearer",
            r#"Bearer \\\"TWICE_BEARER_HEAD TWICE_BEARER_TAIL_SECRET\\\""#,
        ),
        (
            "literal-basic",
            r#"Basic "LITERAL_BASIC_HEAD LITERAL_BASIC_TAIL_SECRET""#,
        ),
        (
            "escaped-basic",
            r#"Basic \"ESCAPED_BASIC_HEAD ESCAPED_BASIC_TAIL_SECRET\""#,
        ),
        (
            "twice-escaped-basic",
            r#"Basic \\\"TWICE_BASIC_HEAD TWICE_BASIC_TAIL_SECRET\\\""#,
        ),
        (
            "literal-authorization",
            r#"Authorization: Bearer "LITERAL_AUTH_HEAD LITERAL_AUTH_TAIL_SECRET""#,
        ),
        (
            "escaped-authorization",
            r#"Authorization: Bearer \"ESCAPED_AUTH_HEAD ESCAPED_AUTH_TAIL_SECRET\""#,
        ),
        (
            "twice-escaped-authorization",
            r#"Authorization: Basic \\\"TWICE_AUTH_HEAD TWICE_AUTH_TAIL_SECRET\\\""#,
        ),
    ];
    let identity_payloads = [
        (
            "literal-aad-tenant",
            r#"AADTenantID="LITERAL_AAD_HEAD LITERAL_AAD_TAIL_SECRET""#,
        ),
        (
            "escaped-azure-tenant",
            r#"AzureADTenantID=\"ESCAPED_AZURE_HEAD ESCAPED_AZURE_TAIL_SECRET\""#,
        ),
        (
            "twice-escaped-device-serial",
            r#"DeviceSerialNumber \\\"TWICE_SERIAL_HEAD TWICE_SERIAL_TAIL_SECRET\\\""#,
        ),
    ];
    let all_payloads = credential_payloads
        .iter()
        .chain(identity_payloads.iter())
        .copied()
        .collect::<Vec<_>>();
    let combined = all_payloads
        .iter()
        .map(|(_, payload)| *payload)
        .collect::<Vec<_>>()
        .join("\n");

    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = all_payloads
        .iter()
        .map(|(id, payload)| evidence_ref_from(&format!("{id}|{payload}"), payload))
        .collect();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(62),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: combined.clone(),
        timestamp: timestamp("2026-07-16T10:00:00Z"),
        named_data: all_payloads
            .iter()
            .map(|(id, payload)| EspNamedValue {
                name: format!("Envelope-{id}"),
                value: (*payload).to_string(),
            })
            .collect(),
        evidence: vec![evidence_ref("registration-serialized-credential-matrix")],
    });
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "serialized-credential-matrix".to_string(),
        timestamp: timestamp("2026-07-16T10:00:01Z"),
        kind: EspTimelineKind::Other,
        title: combined.clone(),
        detail: Some(combined.clone()),
        status: None,
        evidence: vec![evidence_ref("timeline-serialized-credential-matrix")],
    });
    snapshot.coverage = all_payloads
        .iter()
        .map(|(id, payload)| EspArtifactCoverage {
            artifact_id: format!("{id}|{payload}"),
            family: (*payload).to_string(),
            status: EspArtifactStatus::Available,
            detail: Some((*payload).to_string()),
            observed_at_utc: "2026-07-16T10:00:02Z".to_string(),
            evidence: vec![],
        })
        .collect();

    let mut event = raw_export_record(
        "serialized-credential-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(16),
        named_data: all_payloads
            .iter()
            .map(|(id, payload)| EspNamedValue {
                name: format!("Envelope-{id}"),
                value: (*payload).to_string(),
            })
            .collect(),
    });
    let raw_credentials = credential_payloads.iter().map(|(id, payload)| {
        let mut record = raw_export_record(
            &format!("credential-{id}"),
            EspSourceKind::DeploymentLog,
            "neutral-deployment-source",
            None,
            payload,
        );
        record.sensitivity = EspSensitivity::Public;
        record
    });
    let raw_identities = identity_payloads.iter().map(|(id, payload)| {
        let mut record = raw_export_record(
            &format!("identity-{id}"),
            EspSourceKind::DeploymentLog,
            "neutral-deployment-source",
            None,
            payload,
        );
        record.sensitivity = EspSensitivity::Public;
        record
    });
    snapshot.raw_evidence = std::iter::once(event)
        .chain(raw_credentials)
        .chain(raw_identities)
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();
    let secrets = [
        "LITERAL_BEARER_TAIL_SECRET",
        "ESCAPED_BEARER_TAIL_SECRET",
        "TWICE_BEARER_TAIL_SECRET",
        "LITERAL_BASIC_TAIL_SECRET",
        "ESCAPED_BASIC_TAIL_SECRET",
        "TWICE_BASIC_TAIL_SECRET",
        "LITERAL_AUTH_TAIL_SECRET",
        "ESCAPED_AUTH_TAIL_SECRET",
        "TWICE_AUTH_TAIL_SECRET",
        "LITERAL_AAD_TAIL_SECRET",
        "ESCAPED_AZURE_TAIL_SECRET",
        "TWICE_SERIAL_TAIL_SECRET",
    ];
    let leaked = secrets
        .iter()
        .copied()
        .filter(|secret| safe_json.contains(secret))
        .collect::<Vec<_>>();
    let retained_credential_raw = safe
        .raw_evidence
        .iter()
        .map(|record| record.record_id.as_str())
        .filter(|record_id| record_id.starts_with("credential-"))
        .collect::<Vec<_>>();
    assert!(
        leaked.is_empty() && retained_credential_raw.is_empty(),
        "serialized credential matrix leaked {leaked:?}; retained Public credential records {retained_credential_raw:?}"
    );
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_normalizes_existing_separator_aliases_without_prefix_overreach() {
    let aliases = [
        "tenant_id",
        "tenant-id",
        "entdm_id",
        "entdm-id",
        "serial_number",
        "serial-number",
    ];
    let mut payloads = Vec::new();
    let mut secrets = Vec::new();
    for (index, alias) in aliases.iter().enumerate() {
        let secret = format!("SEPARATOR_ALIAS_SECRET_{index}");
        secrets.push(secret.clone());
        payloads.extend([
            format!("{alias}={secret}"),
            format!("{alias} {secret}"),
            format!(r#"{{"{alias}":"{secret}"}}"#),
            format!(r#"{{\"{alias}\":\"{secret}\"}}"#),
        ]);
    }
    let safe_controls = [
        "tenant_id_policy=KEEP_TENANT_ID_POLICY_CONTROL",
        "entdm_id_state=KEEP_ENTDM_ID_STATE_CONTROL",
        "serial_number_policy=KEEP_SERIAL_NUMBER_POLICY_CONTROL",
    ];
    let combined = payloads.join("\n");
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| evidence_ref_from(&format!("alias-{index}|{payload}"), payload))
        .collect();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(63),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: combined.clone(),
        timestamp: timestamp("2026-07-16T10:01:00Z"),
        named_data: payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| EspNamedValue {
                name: format!("Envelope-{index}"),
                value: payload.clone(),
            })
            .chain(
                safe_controls
                    .iter()
                    .enumerate()
                    .map(|(index, payload)| EspNamedValue {
                        name: format!("SafeControl-{index}"),
                        value: (*payload).to_string(),
                    }),
            )
            .collect(),
        evidence: vec![evidence_ref("registration-separator-alias-matrix")],
    });
    snapshot.coverage = payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| EspArtifactCoverage {
            artifact_id: format!("alias-{index}|{payload}"),
            family: payload.clone(),
            status: EspArtifactStatus::Available,
            detail: Some(payload.clone()),
            observed_at_utc: "2026-07-16T10:01:01Z".to_string(),
            evidence: vec![],
        })
        .collect();
    snapshot.raw_evidence = payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            let mut record = raw_export_record(
                &format!("separator-alias-{index}"),
                EspSourceKind::DeploymentLog,
                "neutral-deployment-source",
                None,
                payload,
            );
            record.sensitivity = EspSensitivity::Public;
            record
        })
        .chain(safe_controls.iter().enumerate().map(|(index, payload)| {
            let mut record = raw_export_record(
                &format!("separator-control-{index}"),
                EspSourceKind::DeploymentLog,
                "neutral-deployment-source",
                None,
                payload,
            );
            record.sensitivity = EspSensitivity::Public;
            record
        }))
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();
    let leaked = secrets
        .iter()
        .map(String::as_str)
        .filter(|secret| safe_json.contains(secret))
        .collect::<Vec<_>>();
    let missing_controls = [
        "KEEP_TENANT_ID_POLICY_CONTROL",
        "KEEP_ENTDM_ID_STATE_CONTROL",
        "KEEP_SERIAL_NUMBER_POLICY_CONTROL",
    ]
    .into_iter()
    .filter(|control| !safe_json.contains(control))
    .collect::<Vec<_>>();
    assert!(
        leaked.is_empty() && missing_controls.is_empty(),
        "separator aliases leaked {leaked:?}; safe prefix controls removed {missing_controls:?}"
    );
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_fails_closed_for_complete_digest_tails_and_serialization_layers() {
    let digest_payloads = [
        concat!(
            r#"Digest username="LITERAL_DIGEST_USER", "#,
            r#"qop="auth,LITERAL_DIGEST_QOP_TAIL", "#,
            r#"nonce="LITERAL_DIGEST_NONCE""#,
        ),
        concat!(
            r#"Digest username=\"ESCAPED_DIGEST_USER\", "#,
            r#"qop=\"auth,ESCAPED_DIGEST_QOP_TAIL\", "#,
            r#"nonce=\"ESCAPED_DIGEST_NONCE\""#,
        ),
        concat!(
            r#"Digest username=\\\"TWICE_DIGEST_USER\\\", "#,
            r#"qop=\\\"auth,TWICE_DIGEST_QOP_TAIL\\\", "#,
            r#"nonce=\\\"TWICE_DIGEST_NONCE\\\""#,
        ),
        concat!(
            r#"Digest username=\"KNOWN_DIGEST_USER\" "#,
            "opaque UNKNOWN_DIGEST_TAIL_SECRET ",
            "nonce=LATE_DIGEST_NONCE_SECRET",
        ),
        concat!(
            r#"Authorization: Digest realm=\\\"TWICE_AUTH_DIGEST_REALM\\\", "#,
            r#"qop=\\\"auth,TWICE_AUTH_DIGEST_QOP_TAIL\\\", "#,
            r#"nonce=\\\"TWICE_AUTH_DIGEST_NONCE\\\""#,
        ),
    ];
    let combined = digest_payloads.join("\n");
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = digest_payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| evidence_ref_from(&format!("digest-{index}|{payload}"), payload))
        .collect();
    snapshot.registration_events.push(EspRegistrationEvent {
        event_id: 304,
        record_id: Some(64),
        status: status(
            EspRawStatus::Text("failed".to_string()),
            EspNormalizedStatus::Failed,
        ),
        message: combined.clone(),
        timestamp: timestamp("2026-07-16T10:02:00Z"),
        named_data: digest_payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| EspNamedValue {
                name: format!("DigestEnvelope-{index}"),
                value: (*payload).to_string(),
            })
            .collect(),
        evidence: vec![evidence_ref("registration-complete-digest-matrix")],
    });
    snapshot.activity.push(EspTimelineEntry {
        entry_id: "complete-digest-matrix".to_string(),
        timestamp: timestamp("2026-07-16T10:02:01Z"),
        kind: EspTimelineKind::Other,
        title: combined.clone(),
        detail: Some(combined.clone()),
        status: None,
        evidence: vec![evidence_ref("timeline-complete-digest-matrix")],
    });
    snapshot.coverage = digest_payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| EspArtifactCoverage {
            artifact_id: format!("digest-{index}|{payload}"),
            family: (*payload).to_string(),
            status: EspArtifactStatus::Available,
            detail: Some((*payload).to_string()),
            observed_at_utc: "2026-07-16T10:02:02Z".to_string(),
            evidence: vec![],
        })
        .collect();
    let mut event = raw_export_record(
        "complete-digest-event",
        EspSourceKind::EventLog,
        "neutral-event-source",
        None,
        "safe event payload",
    );
    event.sensitivity = EspSensitivity::Public;
    event.provenance.event = Some(EspEventProvenance {
        channel: "Neutral event channel".to_string(),
        event_id: 1,
        record_id: Some(17),
        named_data: digest_payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| EspNamedValue {
                name: format!("DigestEnvelope-{index}"),
                value: (*payload).to_string(),
            })
            .collect(),
    });
    snapshot.raw_evidence = std::iter::once(event)
        .chain(digest_payloads.iter().enumerate().map(|(index, payload)| {
            let mut record = raw_export_record(
                &format!("digest-raw-{index}"),
                EspSourceKind::DeploymentLog,
                "neutral-deployment-source",
                None,
                payload,
            );
            record.sensitivity = EspSensitivity::Public;
            record
        }))
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();
    let secrets = [
        "LITERAL_DIGEST_USER",
        "LITERAL_DIGEST_QOP_TAIL",
        "LITERAL_DIGEST_NONCE",
        "ESCAPED_DIGEST_USER",
        "ESCAPED_DIGEST_QOP_TAIL",
        "ESCAPED_DIGEST_NONCE",
        "TWICE_DIGEST_USER",
        "TWICE_DIGEST_QOP_TAIL",
        "TWICE_DIGEST_NONCE",
        "KNOWN_DIGEST_USER",
        "UNKNOWN_DIGEST_TAIL_SECRET",
        "LATE_DIGEST_NONCE_SECRET",
        "TWICE_AUTH_DIGEST_REALM",
        "TWICE_AUTH_DIGEST_QOP_TAIL",
        "TWICE_AUTH_DIGEST_NONCE",
    ];
    let leaked = secrets
        .iter()
        .copied()
        .filter(|secret| safe_json.contains(secret))
        .collect::<Vec<_>>();
    let retained_raw = safe
        .raw_evidence
        .iter()
        .map(|record| record.record_id.as_str())
        .filter(|record_id| record_id.starts_with("digest-raw-"))
        .collect::<Vec<_>>();
    assert!(
        leaked.is_empty() && retained_raw.is_empty(),
        "complete Digest matrix leaked {leaked:?}; retained Public Digest records {retained_raw:?}"
    );
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_safe_digest_prose_rejects_late_credential_parameters() {
    let safe_algorithm = "Digest algorithm=SHA-256 is supported";
    let safe_retry = "Digest retry-count=2 remains within policy";
    let smuggled_nonce =
        "Digest algorithm=SHA-256 is supported, nonce=SAFE_PROSE_NONCE_TAIL_SECRET";
    let smuggled_username =
        "Digest retry-count=2 remains within policy; username=SAFE_PROSE_USERNAME_TAIL_SECRET";
    let smuggled_colon =
        "Digest algorithm=SHA-256 remains configured; nonce: SAFE_PROSE_COLON_TAIL_SECRET";
    let mut snapshot = findings_snapshot();
    snapshot.registration_events = vec![
        EspRegistrationEvent {
            event_id: 100,
            record_id: Some(65),
            status: status(
                EspRawStatus::Text("informational".to_string()),
                EspNormalizedStatus::InProgress,
            ),
            message: safe_algorithm.to_string(),
            timestamp: timestamp("2026-07-16T10:03:00Z"),
            named_data: vec![],
            evidence: vec![evidence_ref("registration-safe-digest-algorithm")],
        },
        EspRegistrationEvent {
            event_id: 100,
            record_id: Some(66),
            status: status(
                EspRawStatus::Text("informational".to_string()),
                EspNormalizedStatus::InProgress,
            ),
            message: smuggled_nonce.to_string(),
            timestamp: timestamp("2026-07-16T10:03:01Z"),
            named_data: vec![],
            evidence: vec![evidence_ref("registration-smuggled-digest-nonce")],
        },
    ];
    snapshot.activity = vec![
        EspTimelineEntry {
            entry_id: "safe-digest-retry".to_string(),
            timestamp: timestamp("2026-07-16T10:03:02Z"),
            kind: EspTimelineKind::Other,
            title: safe_retry.to_string(),
            detail: Some(safe_algorithm.to_string()),
            status: None,
            evidence: vec![evidence_ref("timeline-safe-digest-retry")],
        },
        EspTimelineEntry {
            entry_id: "smuggled-digest-username".to_string(),
            timestamp: timestamp("2026-07-16T10:03:03Z"),
            kind: EspTimelineKind::Other,
            title: smuggled_username.to_string(),
            detail: Some(smuggled_nonce.to_string()),
            status: None,
            evidence: vec![evidence_ref("timeline-smuggled-digest-username")],
        },
        EspTimelineEntry {
            entry_id: "smuggled-digest-colon".to_string(),
            timestamp: timestamp("2026-07-16T10:03:04Z"),
            kind: EspTimelineKind::Other,
            title: smuggled_colon.to_string(),
            detail: None,
            status: None,
            evidence: vec![evidence_ref("timeline-smuggled-digest-colon")],
        },
    ];
    snapshot.coverage.push(EspArtifactCoverage {
        artifact_id: "safe-digest-anti-smuggling".to_string(),
        family: "review".to_string(),
        status: EspArtifactStatus::Available,
        detail: Some(smuggled_username.to_string()),
        observed_at_utc: "2026-07-16T10:03:04Z".to_string(),
        evidence: vec![],
    });
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    assert_eq!(safe.registration_events[0].message, safe_algorithm);
    assert_eq!(safe.activity[0].title, safe_retry);
    assert_eq!(safe.activity[0].detail.as_deref(), Some(safe_algorithm));
    let safe_json = serde_json::to_string(&safe).unwrap();
    for secret in [
        "SAFE_PROSE_NONCE_TAIL_SECRET",
        "SAFE_PROSE_USERNAME_TAIL_SECRET",
        "SAFE_PROSE_COLON_TAIL_SECRET",
    ] {
        assert!(
            !safe_json.contains(secret),
            "safe Digest prose leaked {secret}"
        );
    }
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_masks_nested_inner_quotes_at_every_serialization_layer() {
    let payloads = [
        (
            "bearer-literal",
            r#"Bearer "HEAD \"INNER\" BEARER_LITERAL_NESTED_TAIL_SECRET""#,
            "BEARER_LITERAL_NESTED_TAIL_SECRET",
        ),
        (
            "bearer-escaped",
            r#"Bearer \"HEAD \\\"INNER\\\" BEARER_ESCAPED_NESTED_TAIL_SECRET\""#,
            "BEARER_ESCAPED_NESTED_TAIL_SECRET",
        ),
        (
            "bearer-twice",
            r#"Bearer \\\"HEAD \\\\\\\"INNER\\\\\\\" BEARER_TWICE_NESTED_TAIL_SECRET\\\""#,
            "BEARER_TWICE_NESTED_TAIL_SECRET",
        ),
        (
            "basic-literal",
            r#"Basic "HEAD \"INNER\" BASIC_LITERAL_NESTED_TAIL_SECRET""#,
            "BASIC_LITERAL_NESTED_TAIL_SECRET",
        ),
        (
            "basic-escaped",
            r#"Basic \"HEAD \\\"INNER\\\" BASIC_ESCAPED_NESTED_TAIL_SECRET\""#,
            "BASIC_ESCAPED_NESTED_TAIL_SECRET",
        ),
        (
            "basic-twice",
            r#"Basic \\\"HEAD \\\\\\\"INNER\\\\\\\" BASIC_TWICE_NESTED_TAIL_SECRET\\\""#,
            "BASIC_TWICE_NESTED_TAIL_SECRET",
        ),
        (
            "authorization-literal",
            r#"Authorization: Bearer "HEAD \"INNER\" AUTH_LITERAL_NESTED_TAIL_SECRET""#,
            "AUTH_LITERAL_NESTED_TAIL_SECRET",
        ),
        (
            "authorization-escaped",
            r#"Authorization: Basic \"HEAD \\\"INNER\\\" AUTH_ESCAPED_NESTED_TAIL_SECRET\""#,
            "AUTH_ESCAPED_NESTED_TAIL_SECRET",
        ),
        (
            "authorization-twice",
            r#"Authorization: Bearer \\\"HEAD \\\\\\\"INNER\\\\\\\" AUTH_TWICE_NESTED_TAIL_SECRET\\\""#,
            "AUTH_TWICE_NESTED_TAIL_SECRET",
        ),
    ];
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = payloads
        .iter()
        .map(|(label, payload, _)| evidence_ref_from(&format!("{label}|{payload}"), payload))
        .collect();
    snapshot.activity = payloads
        .iter()
        .enumerate()
        .map(|(index, (label, payload, _))| EspTimelineEntry {
            entry_id: format!("nested-quote-{label}"),
            timestamp: timestamp(&format!("2026-07-16T11:{index:02}:00Z")),
            kind: EspTimelineKind::Other,
            title: (*payload).to_string(),
            detail: Some((*payload).to_string()),
            status: None,
            evidence: vec![evidence_ref_from(
                &format!("timeline-{label}|{payload}"),
                payload,
            )],
        })
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();

    for (label, _, secret) in payloads {
        assert!(
            !safe_json.contains(secret),
            "nested {label} credential leaked from the public projection: {safe_json}"
        );
    }
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_rejects_complete_tail_smuggling_after_safe_prose_prefixes() {
    let base64_credential = "QmFzaWM6QkFTSUNfU0FGRV9CQVNFNjRfU01VR0dMRV9TRUNSRVQ=";
    let payloads = [
        (
            "digest-space-nonce",
            "Digest algorithm=SHA-256 is supported nonce DIGEST_SPACE_NONCE_SECRET",
            "DIGEST_SPACE_NONCE_SECRET",
        ),
        (
            "digest-space-username",
            "Digest retry-count=2 remains within policy username DIGEST_SPACE_USERNAME_SECRET",
            "DIGEST_SPACE_USERNAME_SECRET",
        ),
        (
            "bearer-quoted",
            r#"Bearer authentication is "BEARER_SAFE_QUOTED_SECRET WITH_TAIL""#,
            "BEARER_SAFE_QUOTED_SECRET",
        ),
        (
            "bearer-jwt",
            "Bearer token support is eyJhbGciOiJIUzI1NiJ9.BEARER_SAFE_JWT_SECRET.signature",
            "BEARER_SAFE_JWT_SECRET",
        ),
        (
            "bearer-late-nonce",
            "Bearer authentication remains available nonce BEARER_SAFE_LATE_NONCE_SECRET",
            "BEARER_SAFE_LATE_NONCE_SECRET",
        ),
        (
            "basic-base64",
            "Basic authorization is QmFzaWM6QkFTSUNfU0FGRV9CQVNFNjRfU01VR0dMRV9TRUNSRVQ=",
            base64_credential,
        ),
        (
            "basic-late-credential",
            "Basic scheme negotiation was retried credential BASIC_SAFE_LATE_CREDENTIAL_SECRET",
            "BASIC_SAFE_LATE_CREDENTIAL_SECRET",
        ),
        (
            "authorization-custom",
            "Authorization policy is Custom+V1 AUTH_SAFE_CUSTOM_SECRET",
            "AUTH_SAFE_CUSTOM_SECRET",
        ),
        (
            "authorization-quoted",
            r#"Authorization status is "AUTH_SAFE_QUOTED_SECRET WITH_TAIL""#,
            "AUTH_SAFE_QUOTED_SECRET",
        ),
        (
            "authorization-late-credential",
            "Authorization policy remains enforced credential AUTH_SAFE_LATE_CREDENTIAL_SECRET",
            "AUTH_SAFE_LATE_CREDENTIAL_SECRET",
        ),
    ];
    let positive_controls = [
        "Digest algorithm=SHA-256 is supported",
        "Digest retry-count=2 remains within policy",
        "Bearer authentication is configured",
        "Bearer token support is enabled",
        "Basic authorization is required",
        "Basic scheme negotiation was retried",
        "Authorization policy is enforced",
        "Authorization status remains available",
    ];
    let mut snapshot = findings_snapshot();
    snapshot.activity = payloads
        .iter()
        .enumerate()
        .map(|(index, (label, payload, _))| EspTimelineEntry {
            entry_id: format!("safe-prose-smuggling-{label}"),
            timestamp: timestamp(&format!("2026-07-16T12:{index:02}:00Z")),
            kind: EspTimelineKind::Other,
            title: (*payload).to_string(),
            detail: Some((*payload).to_string()),
            status: None,
            evidence: vec![],
        })
        .chain(
            positive_controls
                .iter()
                .enumerate()
                .map(|(index, control)| EspTimelineEntry {
                    entry_id: format!("safe-prose-positive-control-{index}"),
                    timestamp: timestamp(&format!("2026-07-16T13:{index:02}:00Z")),
                    kind: EspTimelineKind::Other,
                    title: (*control).to_string(),
                    detail: Some((*control).to_string()),
                    status: None,
                    evidence: vec![],
                }),
        )
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();

    for (label, _, secret) in payloads {
        assert!(
            !safe_json.contains(secret),
            "{label} credential survived a safe-prose prefix: {safe_json}"
        );
    }
    let positive_start = safe.activity.len() - positive_controls.len();
    for (index, control) in positive_controls.into_iter().enumerate() {
        assert_eq!(safe.activity[positive_start + index].title, control);
        assert_eq!(
            safe.activity[positive_start + index].detail.as_deref(),
            Some(control)
        );
    }
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

fn folded_quoted_credential_matrix() -> Vec<(String, String, String)> {
    let schemes = ["Basic", "Bearer", "Negotiate", "NTLM"];
    let serializations = [
        ("literal", r#"""#),
        ("escaped", r#"\""#),
        ("twice-escaped", r#"\\\""#),
    ];
    let line_endings = [
        ("lf", "\n"),
        ("lf-with-ows", " \t\n"),
        ("crlf", "\r\n"),
        ("crlf-with-ows", "\t \r\n"),
    ];
    let mut matrix = Vec::new();

    for scheme in schemes {
        for (serialization, delimiter) in serializations {
            for (line_ending_name, line_ending) in line_endings {
                for closed in [true, false] {
                    let closure_name = if closed { "closed" } else { "unclosed" };
                    let label = format!(
                        "{}-{serialization}-{line_ending_name}-{closure_name}",
                        scheme.to_ascii_lowercase()
                    );
                    let secret = format!(
                        "FOLDED_{}_{}_{}_{}_SECRET",
                        scheme.to_ascii_uppercase(),
                        serialization.replace('-', "_").to_ascii_uppercase(),
                        line_ending_name.to_ascii_uppercase(),
                        closure_name.to_ascii_uppercase()
                    );
                    let closing_delimiter = if closed { delimiter } else { "" };
                    let payload = format!(
                        "{scheme} {delimiter}CREDENTIAL_HEAD{closing_delimiter}{line_ending} {secret}"
                    );
                    matrix.push((label, payload, secret));
                }
            }
        }
    }

    matrix
}

#[test]
fn redaction_projection_masks_folded_quoted_credentials_across_public_typed_and_reference_surfaces()
{
    let matrix = folded_quoted_credential_matrix();
    let safe_prose = ["Basic", "Bearer", "Negotiate", "NTLM"]
        .into_iter()
        .flat_map(|scheme| {
            [
                format!("{scheme} authentication is configured"),
                format!("{scheme} authentication remains available"),
                format!("{scheme} authorization is required"),
                format!("{scheme} scheme negotiation was retried"),
                format!("{scheme} token support is enabled"),
            ]
        })
        .collect::<Vec<_>>();
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = matrix
        .iter()
        .map(|(label, payload, _)| {
            evidence_ref_from(
                &format!("identity-{label}|{payload}"),
                &format!("identity-source-{label}|{payload}"),
            )
        })
        .collect();
    snapshot.activity = matrix
        .iter()
        .enumerate()
        .map(|(index, (label, payload, _))| EspTimelineEntry {
            entry_id: format!("folded-credential-{label}"),
            timestamp: timestamp(&format!("2026-07-16T14:{:02}:00Z", index % 60)),
            kind: EspTimelineKind::Other,
            title: payload.clone(),
            detail: Some(payload.clone()),
            status: None,
            evidence: vec![evidence_ref_from(
                &format!("timeline-{label}|{payload}"),
                &format!("timeline-source-{label}|{payload}"),
            )],
        })
        .chain(
            safe_prose
                .iter()
                .enumerate()
                .map(|(index, control)| EspTimelineEntry {
                    entry_id: format!("folded-credential-safe-prose-{index}"),
                    timestamp: timestamp(&format!("2026-07-16T15:{index:02}:00Z")),
                    kind: EspTimelineKind::Other,
                    title: control.clone(),
                    detail: Some(control.clone()),
                    status: None,
                    evidence: vec![],
                }),
        )
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();

    for (label, _, secret) in &matrix {
        assert!(
            !safe_json.contains(secret),
            "folded {label} credential leaked from a public typed or reference surface: {safe_json}"
        );
    }
    let safe_prose_start = safe.activity.len() - safe_prose.len();
    for (index, control) in safe_prose.iter().enumerate() {
        assert_eq!(safe.activity[safe_prose_start + index].title, *control);
        assert_eq!(
            safe.activity[safe_prose_start + index].detail.as_ref(),
            Some(control)
        );
    }
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_removes_folded_quoted_credentials_from_public_raw_evidence() {
    let matrix = folded_quoted_credential_matrix();
    let mut snapshot = findings_snapshot();
    snapshot.raw_evidence = matrix
        .iter()
        .enumerate()
        .map(|(index, (label, payload, _))| {
            let mut record = raw_export_record(
                &format!("folded-credential-{label}"),
                EspSourceKind::DeploymentLog,
                "neutral-folded-credential-source",
                None,
                payload,
            );
            record.sensitivity = EspSensitivity::Public;
            if index % 2 == 1 {
                record.raw_value = EspObservationValue::StringList(vec![
                    "safe-list-control".to_string(),
                    payload.clone(),
                ]);
            }
            record
        })
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let retained_record_ids = safe
        .raw_evidence
        .iter()
        .map(|record| record.record_id.as_str())
        .collect::<Vec<_>>();
    let safe_json = serde_json::to_string(&safe).unwrap();

    assert!(
        retained_record_ids.is_empty(),
        "folded credentials survived Public raw-evidence classification: {retained_record_ids:?}; {safe_json}"
    );
    for (label, _, secret) in &matrix {
        assert!(
            !safe_json.contains(secret),
            "folded {label} credential leaked from Public raw evidence: {safe_json}"
        );
    }
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

struct FoldedSchemeSeparatorCase {
    label: String,
    payload: String,
    head_secret: String,
    tail_secret: String,
    boundary_control: String,
}

fn folded_scheme_separator_credential_matrix() -> Vec<FoldedSchemeSeparatorCase> {
    let schemes = ["Basic", "Bearer", "Digest", "ApiKey", "Negotiate", "NTLM"];
    let logical_separators = [
        ("lf", "\n ", "\n"),
        ("crlf", "\r\n ", "\r\n"),
        ("lf-with-ows", " \t\n ", "\n"),
        ("crlf-with-ows", "\t \r\n ", "\r\n"),
        ("lf-repeated", "\n \n\t", "\n"),
        ("crlf-repeated", "\r\n \r\n\t", "\r\n"),
    ];
    let quoted_forms = [
        ("literal-quoted", "\"", true),
        ("literal-unclosed-quoted", "\"", false),
        ("escaped-quoted", "\\\"", true),
        ("twice-escaped-quoted", "\\\\\"", true),
    ];
    let mut matrix = Vec::new();

    for scheme in schemes {
        for (separator_name, separator, continuation_line_ending) in logical_separators {
            let bare_label = format!("{}-{separator_name}-bare", scheme.to_ascii_lowercase());
            let bare_head = format!("{}_HEAD_SECRET", bare_label.to_ascii_uppercase());
            let bare_tail = format!("{}_TAIL_SECRET", bare_label.to_ascii_uppercase());
            let bare_boundary = format!("{}_BOUNDARY_CONTROL", bare_label.to_ascii_uppercase());
            matrix.push(FoldedSchemeSeparatorCase {
                label: bare_label,
                payload: format!(
                    "{scheme}{separator}{bare_head}{continuation_line_ending}\t{bare_tail}{continuation_line_ending}{bare_boundary}"
                ),
                head_secret: bare_head,
                tail_secret: bare_tail,
                boundary_control: bare_boundary,
            });

            for (form, delimiter, closed) in quoted_forms {
                let label = format!("{}-{separator_name}-{form}", scheme.to_ascii_lowercase());
                let head_secret = format!("{}_HEAD_SECRET", label.to_ascii_uppercase());
                let tail_secret = format!("{}_TAIL_SECRET", label.to_ascii_uppercase());
                let boundary_control = format!("{}_BOUNDARY_CONTROL", label.to_ascii_uppercase());
                let closing_delimiter = if closed { delimiter } else { "" };
                matrix.push(FoldedSchemeSeparatorCase {
                    label,
                    payload: format!(
                        "{scheme}{separator}{delimiter}{head_secret}{closing_delimiter}{continuation_line_ending}\t{tail_secret}{continuation_line_ending}{boundary_control}"
                    ),
                    head_secret,
                    tail_secret,
                    boundary_control,
                });
            }
        }
    }

    matrix
}

#[test]
fn redaction_projection_masks_folded_standalone_scheme_separators_on_typed_and_reference_surfaces()
{
    let matrix = folded_scheme_separator_credential_matrix();
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = matrix
        .iter()
        .map(|case| evidence_ref_from(&case.payload, &case.payload))
        .collect();
    snapshot.activity = matrix
        .iter()
        .enumerate()
        .map(|(index, case)| EspTimelineEntry {
            entry_id: format!("folded-scheme-separator-{}", case.label),
            timestamp: timestamp(&format!("2026-07-16T16:{:02}:00Z", index % 60)),
            kind: EspTimelineKind::Other,
            title: case.payload.clone(),
            detail: Some(case.payload.clone()),
            status: None,
            evidence: vec![],
        })
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();

    for (index, case) in matrix.iter().enumerate() {
        assert!(
            !safe_json.contains(&case.head_secret) && !safe_json.contains(&case.tail_secret),
            "folded standalone {} credential leaked: {safe_json}",
            case.label
        );
        let reference = &safe.identity.evidence[index];
        let activity = &safe.activity[index];
        for surface in [
            reference.evidence_id.as_str(),
            reference.source_artifact_id.as_str(),
            activity.title.as_str(),
            activity
                .detail
                .as_deref()
                .expect("matrix activity keeps detail"),
        ] {
            assert!(
                surface.contains(&case.boundary_control),
                "folded standalone {} consumed the next non-continuation line on a typed or reference surface: {surface}",
                case.label
            );
        }
    }
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_removes_folded_standalone_scheme_separators_from_public_raw_evidence() {
    let matrix = folded_scheme_separator_credential_matrix();
    let mut snapshot = findings_snapshot();
    snapshot.raw_evidence = matrix
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let mut record = raw_export_record(
                &format!("folded-scheme-separator-{index}"),
                EspSourceKind::DeploymentLog,
                "neutral-folded-scheme-source",
                None,
                &case.payload,
            );
            record.sensitivity = EspSensitivity::Public;
            if index % 2 == 1 {
                record.raw_value = EspObservationValue::StringList(vec![
                    "safe-list-control".to_string(),
                    case.payload.clone(),
                ]);
            }
            record
        })
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();

    assert!(
        safe.raw_evidence.is_empty(),
        "folded standalone credentials survived Public raw-evidence classification: {safe_json}"
    );
    for case in &matrix {
        assert!(
            !safe_json.contains(&case.head_secret) && !safe_json.contains(&case.tail_secret),
            "folded standalone {} credential leaked from Public raw evidence: {safe_json}",
            case.label
        );
    }
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

struct FoldedDigestParameterCase {
    label: String,
    payload: String,
    secrets: [String; 3],
    boundary_control: String,
}

fn folded_digest_parameter_matrix() -> Vec<FoldedDigestParameterCase> {
    let logical_separators = [
        ("mixed-ows-crlf", " \t\r\n "),
        ("repeated-crlf", "\r\n \r\n\t"),
    ];
    let serializations = [
        ("literal", r#"""#),
        ("escaped", r#"\""#),
        ("twice-escaped", r#"\\\""#),
    ];
    let mut matrix = Vec::new();

    for (separator_name, separator) in logical_separators {
        for (serialization_name, delimiter) in serializations {
            let label = format!("{separator_name}-{serialization_name}");
            let username_secret = format!("{}_USERNAME_SECRET", label.to_ascii_uppercase());
            let qop_secret = format!("{}_QOP_SECRET", label.to_ascii_uppercase());
            let nonce_secret = format!("{}_NONCE_SECRET", label.to_ascii_uppercase());
            let boundary_control = format!("{}_BOUNDARY_CONTROL", label.to_ascii_uppercase());
            let payload = format!(
                "Digest{separator}username={delimiter}{username_secret}{delimiter}, qop={delimiter}auth,{qop_secret}{delimiter}, nonce={delimiter}{nonce_secret}{delimiter}\r\n{boundary_control}"
            );
            matrix.push(FoldedDigestParameterCase {
                label,
                payload,
                secrets: [username_secret, qop_secret, nonce_secret],
                boundary_control,
            });
        }
    }

    matrix
}

#[test]
fn redaction_projection_masks_parameterized_digest_after_mixed_and_repeated_obs_fold_on_typed_and_reference_surfaces(
) {
    let matrix = folded_digest_parameter_matrix();
    let mut snapshot = findings_snapshot();
    snapshot.identity.evidence = matrix
        .iter()
        .map(|case| evidence_ref_from(&case.payload, &case.payload))
        .collect();
    snapshot.activity = matrix
        .iter()
        .enumerate()
        .map(|(index, case)| EspTimelineEntry {
            entry_id: format!("folded-digest-parameters-{}", case.label),
            timestamp: timestamp(&format!("2026-07-16T17:{index:02}:00Z")),
            kind: EspTimelineKind::Other,
            title: case.payload.clone(),
            detail: Some(case.payload.clone()),
            status: None,
            evidence: vec![],
        })
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();

    for (index, case) in matrix.iter().enumerate() {
        for secret in &case.secrets {
            assert!(
                !safe_json.contains(secret),
                "folded parameterized Digest {} leaked {secret}: {safe_json}",
                case.label
            );
        }
        let reference = &safe.identity.evidence[index];
        let activity = &safe.activity[index];
        for surface in [
            reference.evidence_id.as_str(),
            reference.source_artifact_id.as_str(),
            activity.title.as_str(),
            activity
                .detail
                .as_deref()
                .expect("Digest matrix activity keeps detail"),
        ] {
            assert!(
                surface.contains(&case.boundary_control),
                "folded parameterized Digest {} consumed the next non-continuation line: {surface}",
                case.label
            );
        }
    }
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}

#[test]
fn redaction_projection_removes_parameterized_digest_after_mixed_and_repeated_obs_fold_from_public_raw_evidence(
) {
    let matrix = folded_digest_parameter_matrix();
    let mut snapshot = findings_snapshot();
    snapshot.raw_evidence = matrix
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let mut record = raw_export_record(
                &format!("folded-digest-parameters-{index}"),
                EspSourceKind::DeploymentLog,
                "neutral-folded-digest-source",
                None,
                &case.payload,
            );
            record.sensitivity = EspSensitivity::Public;
            if index % 2 == 1 {
                record.raw_value = EspObservationValue::StringList(vec![
                    "safe-list-control".to_string(),
                    case.payload.clone(),
                ]);
            }
            record
        })
        .collect();
    let original = snapshot.clone();

    let safe = redacted_export_projection(&snapshot);
    let safe_json = serde_json::to_string(&safe).unwrap();

    assert!(
        safe.raw_evidence.is_empty(),
        "folded parameterized Digest survived Public raw classification: {safe_json}"
    );
    for case in &matrix {
        for secret in &case.secrets {
            assert!(
                !safe_json.contains(secret),
                "folded parameterized Digest {} leaked {secret} from Public raw evidence: {safe_json}",
                case.label
            );
        }
    }
    assert_eq!(redacted_export_projection(&safe), safe);
    assert_eq!(snapshot, original);
}
