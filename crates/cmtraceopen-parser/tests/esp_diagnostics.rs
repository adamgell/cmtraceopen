use cmtraceopen_parser::esp::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn assert_unit_variants<T: Serialize>(variants: &[T], expected: Value) {
    assert_eq!(serde_json::to_value(variants).unwrap(), expected);
}

fn evidence_ref(id: &str) -> EspEvidenceRef {
    EspEvidenceRef {
        evidence_id: id.to_string(),
        source_artifact_id: "artifact-registry".to_string(),
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
    api_version: GraphApiVersion,
    data: Option<T>,
    error: Option<GraphSectionError>,
) -> GraphSection<T> {
    GraphSection {
        status,
        required_scope: Some("DeviceManagementManagedDevices.Read.All".to_string()),
        api_version,
        data,
        error,
    }
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
        &[GraphApiVersion::V1_0, GraphApiVersion::Beta],
        json!(["v1.0", "beta"]),
    );

    let section = GraphSection::<EspGraphDeviceMatch> {
        status: GraphSectionStatus::Skipped,
        required_scope: Some("DeviceManagementManagedDevices.Read.All".to_string()),
        api_version: GraphApiVersion::V1_0,
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
            "apiVersion": "v1.0",
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
            GraphApiVersion::V1_0,
            None,
            None,
        ),
        deployment_profile: graph_section(
            GraphSectionStatus::PermissionDenied,
            GraphApiVersion::Beta,
            None,
            Some(graph_error("permissionDenied")),
        ),
        intended_deployment_profile: graph_section(
            GraphSectionStatus::Available,
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
            GraphApiVersion::Beta,
            None,
            Some(graph_error("transportFailure")),
        ),
        autopilot_events: graph_section(
            GraphSectionStatus::Skipped,
            GraphApiVersion::Beta,
            None,
            Some(GraphSectionError {
                blocked_by: Some("deviceMatch".to_string()),
                ..graph_error("blocked")
            }),
        ),
        enrollment_configuration: graph_section(
            GraphSectionStatus::Cancelled,
            GraphApiVersion::V1_0,
            None,
            Some(graph_error("cancelled")),
        ),
        apps: graph_section(
            GraphSectionStatus::Available,
            GraphApiVersion::V1_0,
            Some(vec![EspGraphAppRecord {
                app_id: "app-1".to_string(),
                display_name: Some("App One".to_string()),
                tracked_on_enrollment_status: Some(true),
                status: Some(status(
                    EspRawStatus::Text("installed".to_string()),
                    EspNormalizedStatus::Succeeded,
                )),
                assignments: vec![assignment("app-assignment")],
                evidence: vec![evidence_ref("app-1")],
            }]),
            None,
        ),
        policies: graph_section(
            GraphSectionStatus::Available,
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
    assert_eq!(value["enrollmentConfiguration"]["status"], "cancelled");
    assert_eq!(value["deploymentProfile"]["apiVersion"], "beta");
    assert_eq!(
        value["apps"]["data"][0]["evidence"][0]["evidenceId"],
        "app-1"
    );
    assert_eq!(
        value["profileAssignments"]["error"]["requestId"],
        "request-1"
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
        correlation_confidence: EspCorrelationConfidence::Uncorrelated,
        evidence: vec![evidence_ref("detail-1")],
    };
    let event = EspGraphAutopilotEvent {
        event_id: "event-1".to_string(),
        managed_device_id: Some("managed-1".to_string()),
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
        device_esp_enabled: Some(true),
        user_esp_enabled: Some(true),
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
    assert!(!snapshot
        .raw_evidence
        .iter()
        .any(|record| record.record_id.contains("classic-must-not-leak")));
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
            "esp-workloads",
            "office",
            &classic_key("ExpectedMSIAppPackages"),
            "./Vendor/MSFT/Office/Installation/office-a",
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
        classic_snapshot.workloads[1].status.raw,
        EspRawStatus::Number(60)
    );
    assert_eq!(
        classic_snapshot.workloads[1].status.normalized,
        EspNormalizedStatus::Failed
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
    assert_eq!(delivery.peer_share_percent, Some(25.0));
    assert_eq!(
        delivery.transfers[0].transfer_id,
        "transfer|do-live|do-start|5"
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
            "timeline|events|event-1905|1",
            "timeline|ime-live|retry|2",
            "timeline|events|event-1920|0"
        ]
    );
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
        "raw|page-settings|page-agent-timeout|1"
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
        "raw|node-cache-registry|node-42-expected|5"
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
        "raw|malformed-json|malformed-page-settings|6"
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
        "timeline|protected-registry|coverage-denied|16"
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
    assert_eq!(serial_raw.record_id, "raw|system-facts|serial|13");
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
    assert_eq!(first_activity.entry_id, "timeline|v2-progress|v2-state-0|2");
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
    for (ordinal, case) in cases.events.iter().enumerate() {
        let activity = snapshot
            .activity
            .iter()
            .find(|entry| entry.evidence[0].evidence_id == case.evidence_id)
            .unwrap();
        assert_eq!(
            activity.entry_id,
            format!(
                "timeline|{}|{}|{ordinal}",
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
            format!(
                "raw|{}|{}|{ordinal}",
                case.source_artifact_id, case.evidence_id
            )
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
        "raw|graph-apps|graph-app-a|3"
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
            "raw|live-registry|live-workload|1"
        );
        assert_eq!(
            captured.raw_evidence[1].record_id,
            "raw|captured-registry|captured-workload|1"
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
