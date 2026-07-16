use cmtraceopen_parser::esp::*;
use serde::Serialize;
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
            EspJoinMode::Unknown,
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
            EspGraphAssignmentIntent::Unknown,
        ],
        json!(["required", "available", "uninstall", "unknown"]),
    );
    assert_unit_variants(
        &[
            EspGraphTargetKind::AllDevices,
            EspGraphTargetKind::AllUsers,
            EspGraphTargetKind::Group,
            EspGraphTargetKind::Filter,
            EspGraphTargetKind::Unknown,
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
            EspGraphPolicyKind::Unknown,
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
        serial_number: Some("serial-1".to_string()),
        device_name: Some("DEVICE-1".to_string()),
        user_id: Some("user-1".to_string()),
        user_principal_name: Some("user@example.test".to_string()),
        tenant_id: Some("tenant-1".to_string()),
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
        serial_number: Some("serial-1".to_string()),
        deployment_profile_id: Some("profile-1".to_string()),
        group_tag: Some("group-tag".to_string()),
        evidence: vec![evidence_ref("autopilot-1")],
    };
    let detail = EspGraphPolicyStatusDetail {
        status_detail_id: "detail-object-1".to_string(),
        related_object_id: None,
        display_name: Some("Policy detail".to_string()),
        kind: EspGraphPolicyKind::Unknown,
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
        tenant_domain: Some("example.test".to_string()),
        tenant_id: Some("tenant-1".to_string()),
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
        tenant_id: Some("tenant-1".to_string()),
        user_principal_name: Some("user@example.test".to_string()),
        entdm_id: Some("entdm-1".to_string()),
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
        serial_number: Some("SERIAL-1".to_string()),
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
