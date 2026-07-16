//! Portable, read-only Microsoft Graph orchestration for ESP diagnostics.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use cmtraceopen_parser::esp::{
    EspClassifiedString, EspCorrelationConfidence, EspEvidenceRef, EspGraphAppRecord,
    EspGraphAssignment, EspGraphAssignmentIntent, EspGraphAutopilotEvent,
    EspGraphAutopilotIdentity, EspGraphDeploymentProfile, EspGraphEnrollmentConfiguration,
    EspGraphManagedDevice, EspGraphOverlay, EspGraphPolicyKind, EspGraphPolicyRecord,
    EspGraphPolicyStatusDetail, EspGraphPolicyStatusDetailKind, EspGraphScriptKind,
    EspGraphScriptRecord, EspGraphTargetKind, EspGraphTargeting, EspIdentityEvidence, EspJoinMode,
    EspNormalizedStatus, EspRawStatus, EspSensitivity, EspStatus, EspStatusDetail, EspTimestamp,
    EspTimestampKind, GraphApiVersion, GraphSection, GraphSectionError, GraphSectionStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::client::{
    GraphCancellation, GraphClient, GraphClientError, GraphClientErrorKind, GraphTransport,
};
use super::correlation::correlate_managed_device;
use super::{normalize_graph_guid, GraphHttpMethod, GraphTransportRequest};

pub const MANAGED_DEVICES_SCOPE: &str = "DeviceManagementManagedDevices.Read.All";
pub const SERVICE_CONFIG_SCOPE: &str = "DeviceManagementServiceConfig.Read.All";
pub const APPS_SCOPE: &str = "DeviceManagementApps.Read.All";
pub const CONFIGURATION_SCOPE: &str = "DeviceManagementConfiguration.Read.All";
pub const SCRIPTS_SCOPE: &str = "DeviceManagementScripts.Read.All";
const GRAPH_ARTIFACT_ID: &str = "microsoft-graph";
const MAX_REFERENCED_OBJECTS: usize = 100;
const MAX_GRAPH_REQUEST_ID_BYTES: usize = 128;
const MAX_ACTIVE_ESP_GRAPH_OPERATIONS: usize = 32;
pub const ESP_GRAPH_OVERALL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspGraphOperationError {
    InvalidRequestId,
    DuplicateRequest,
    ResourceLimit,
}

impl fmt::Display for EspGraphOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequestId => "InvalidGraphRequestId",
            Self::DuplicateRequest => "GraphRequestAlreadyActive",
            Self::ResourceLimit => "GraphRequestLimitReached",
        })
    }
}

impl std::error::Error for EspGraphOperationError {}

#[derive(Default)]
struct EspGraphOperationRegistryInner {
    operations: Mutex<HashMap<String, Arc<EspGraphCancellationState>>>,
}

/// Request-owned cancellation registry shared by the Tauri command adapter.
/// Dropping an operation removes only that exact ownership instance, so a late
/// completion cannot delete a newer operation that reused the same request ID.
#[derive(Clone, Default)]
pub struct EspGraphOperationRegistry {
    inner: Arc<EspGraphOperationRegistryInner>,
}

impl EspGraphOperationRegistry {
    pub fn begin(&self, request_id: &str) -> Result<EspGraphOperation, EspGraphOperationError> {
        if !valid_graph_request_id(request_id) {
            return Err(EspGraphOperationError::InvalidRequestId);
        }

        let state = Arc::new(EspGraphCancellationState {
            cancelled: Mutex::new(false),
            wake: Condvar::new(),
            deadline: Instant::now() + ESP_GRAPH_OVERALL_TIMEOUT,
        });
        let mut operations = self
            .inner
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if operations.contains_key(request_id) {
            return Err(EspGraphOperationError::DuplicateRequest);
        }
        if operations.len() >= MAX_ACTIVE_ESP_GRAPH_OPERATIONS {
            return Err(EspGraphOperationError::ResourceLimit);
        }
        operations.insert(request_id.to_string(), Arc::clone(&state));
        Ok(EspGraphOperation {
            request_id: request_id.to_string(),
            state,
            registry: Arc::downgrade(&self.inner),
        })
    }

    pub fn cancel(&self, request_id: &str) -> bool {
        if !valid_graph_request_id(request_id) {
            return false;
        }
        let state = self
            .inner
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(request_id)
            .cloned();
        state.is_some_and(|state| {
            state.cancel();
            true
        })
    }

    pub fn cancel_all(&self) {
        let operations: Vec<Arc<EspGraphCancellationState>> = self
            .inner
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        for operation in operations {
            operation.cancel();
        }
    }
}

fn valid_graph_request_id(request_id: &str) -> bool {
    !request_id.is_empty()
        && request_id.len() <= MAX_GRAPH_REQUEST_ID_BYTES
        && request_id.trim() == request_id
        && !request_id.chars().any(char::is_control)
}

struct EspGraphCancellationState {
    cancelled: Mutex<bool>,
    wake: Condvar,
    deadline: Instant,
}

impl EspGraphCancellationState {
    fn cancel(&self) {
        *self
            .cancelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.wake.notify_all();
    }

    fn is_cancelled(&self) -> bool {
        *self
            .cancelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            || Instant::now() >= self.deadline
    }
}

pub struct EspGraphOperation {
    request_id: String,
    state: Arc<EspGraphCancellationState>,
    registry: Weak<EspGraphOperationRegistryInner>,
}

impl EspGraphOperation {
    pub fn remaining(&self) -> Duration {
        self.state
            .deadline
            .saturating_duration_since(Instant::now())
    }
}

impl GraphCancellation for EspGraphOperation {
    fn is_cancelled(&self) -> bool {
        self.state.is_cancelled()
    }

    fn wait_for_retry(&self, duration: Duration) -> bool {
        let requested_deadline = Instant::now()
            .checked_add(duration)
            .unwrap_or(self.state.deadline)
            .min(self.state.deadline);
        let mut cancelled = self
            .state
            .cancelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if *cancelled {
                return false;
            }
            let now = Instant::now();
            if now >= self.state.deadline {
                *cancelled = true;
                return false;
            }
            if now >= requested_deadline {
                return true;
            }
            let wait = requested_deadline.saturating_duration_since(now);
            let (guard, _) = self
                .state
                .wake
                .wait_timeout(cancelled, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cancelled = guard;
        }
    }
}

impl Drop for EspGraphOperation {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let mut operations = registry
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if operations
            .get(&self.request_id)
            .is_some_and(|current| Arc::ptr_eq(current, &self.state))
        {
            operations.remove(&self.request_id);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphPolicyReference {
    pub id: String,
    pub kind: EspGraphPolicyKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphScriptReference {
    pub id: String,
    pub kind: EspGraphScriptKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphRequest {
    pub request_id: String,
    pub identity: EspIdentityEvidence,
    #[serde(default)]
    pub workload_ids: Vec<String>,
    #[serde(default)]
    pub selected_managed_device_id: Option<String>,
    #[serde(default)]
    pub evidence_window_start_utc: Option<String>,
    #[serde(default)]
    pub evidence_window_end_utc: Option<String>,
    #[serde(default)]
    pub enrollment_configuration_ids: Vec<String>,
    #[serde(default)]
    pub app_ids: Vec<String>,
    #[serde(default)]
    pub policy_references: Vec<EspGraphPolicyReference>,
    #[serde(default)]
    pub script_references: Vec<EspGraphScriptReference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspGraphEndpoint {
    pub path: String,
    pub required_scope: String,
    pub api_version: GraphApiVersion,
}

impl EspGraphEndpoint {
    fn new(path: String, required_scope: &str, api_version: GraphApiVersion) -> Self {
        Self {
            path,
            required_scope: required_scope.to_string(),
            api_version,
        }
    }
}

/// Portable endpoint provider. The Windows adapter attaches the in-memory WAM
/// token; fake providers exercise this orchestration on every host platform.
pub trait EspGraphProvider: Send + Sync {
    fn get(
        &self,
        endpoint: &EspGraphEndpoint,
        cancellation: &dyn GraphCancellation,
    ) -> Result<Value, GraphClientError>;

    /// Return a complete, bounded collection envelope. Implementations must
    /// reject unsafe continuation URLs and limit exhaustion instead of
    /// returning a successful first-page subset.
    fn get_collection(
        &self,
        endpoint: &EspGraphEndpoint,
        cancellation: &dyn GraphCancellation,
    ) -> Result<Value, GraphClientError>;
}

/// Token-free adapter from ESP orchestration endpoints to the bounded Graph
/// client. Concrete platform transports retain ownership of authentication and
/// HTTP I/O while every collection read shares the client's pagination, URL,
/// response-size, item-count, retry, and cancellation policy.
pub struct EspGraphClientProvider<'a, T: GraphTransport> {
    transport: &'a T,
}

impl<'a, T: GraphTransport> EspGraphClientProvider<'a, T> {
    pub fn new(transport: &'a T) -> Self {
        Self { transport }
    }

    fn url(endpoint: &EspGraphEndpoint) -> String {
        format!("https://graph.microsoft.com{}", endpoint.path)
    }
}

impl<T: GraphTransport> EspGraphProvider for EspGraphClientProvider<'_, T> {
    fn get(
        &self,
        endpoint: &EspGraphEndpoint,
        cancellation: &dyn GraphCancellation,
    ) -> Result<Value, GraphClientError> {
        let client = GraphClient::new("graph.microsoft.com", self.transport, cancellation);
        client.request_json(GraphTransportRequest {
            method: GraphHttpMethod::Get,
            url: Self::url(endpoint),
            consistency_level: None,
            content_type: None,
            body: None,
            required_scope: endpoint.required_scope.clone(),
        })
    }

    fn get_collection(
        &self,
        endpoint: &EspGraphEndpoint,
        cancellation: &dyn GraphCancellation,
    ) -> Result<Value, GraphClientError> {
        let client = GraphClient::new("graph.microsoft.com", self.transport, cancellation);
        let items = client
            .get_paginated::<Value>(&Self::url(endpoint), endpoint.required_scope.as_str())?;
        Ok(serde_json::json!({ "value": items }))
    }
}

pub fn fetch_esp_graph_overlay<P: EspGraphProvider>(
    provider: &P,
    request: &EspGraphRequest,
    cancellation: &dyn GraphCancellation,
    requested_at_utc: &str,
) -> EspGraphOverlay {
    let mut overlay = empty_overlay(request, requested_at_utc);
    let candidates = match fetch_managed_candidates(provider, request, cancellation) {
        Ok(candidates) => candidates,
        Err(error) => {
            let cancelled = error.kind == GraphClientErrorKind::Cancelled;
            overlay.device_match =
                error_section(error, MANAGED_DEVICES_SCOPE, GraphApiVersion::V1_0, None);
            if cancelled {
                cancel_device_dependents(&mut overlay);
            } else {
                skip_device_dependents(&mut overlay);
            }
            return overlay;
        }
    };

    let device_match = correlate_managed_device(
        &request.identity,
        request.selected_managed_device_id.as_deref(),
        candidates,
    );
    let selected = device_match.selected.clone();
    overlay.device_match =
        available_section(MANAGED_DEVICES_SCOPE, GraphApiVersion::V1_0, device_match);
    let Some(device) = selected else {
        skip_device_dependents(&mut overlay);
        return overlay;
    };

    overlay.autopilot_identity = fetch_autopilot_identity(provider, &device, cancellation);
    if let Some(autopilot) = overlay.autopilot_identity.data.clone() {
        overlay.deployment_profile = fetch_profile(
            provider,
            &autopilot.autopilot_device_id,
            "deploymentProfile",
            cancellation,
        );
        overlay.intended_deployment_profile = fetch_profile(
            provider,
            &autopilot.autopilot_device_id,
            "intendedDeploymentProfile",
            cancellation,
        );
        overlay.profile_assignments =
            if let Some(profile) = overlay.deployment_profile.data.as_ref() {
                fetch_profile_assignments(provider, &profile.profile_id, cancellation)
            } else if overlay.deployment_profile.status == GraphSectionStatus::Cancelled {
                cancelled_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta)
            } else {
                skipped_section(
                    SERVICE_CONFIG_SCOPE,
                    GraphApiVersion::Beta,
                    "deploymentProfile",
                )
            };
    } else if overlay.autopilot_identity.status == GraphSectionStatus::Cancelled {
        overlay.deployment_profile = cancelled_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta);
        overlay.intended_deployment_profile =
            cancelled_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta);
        overlay.profile_assignments =
            cancelled_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta);
    } else {
        overlay.deployment_profile = skipped_section(
            SERVICE_CONFIG_SCOPE,
            GraphApiVersion::Beta,
            "autopilotIdentity",
        );
        overlay.intended_deployment_profile = skipped_section(
            SERVICE_CONFIG_SCOPE,
            GraphApiVersion::Beta,
            "autopilotIdentity",
        );
        overlay.profile_assignments = skipped_section(
            SERVICE_CONFIG_SCOPE,
            GraphApiVersion::Beta,
            "autopilotIdentity",
        );
    }

    overlay.autopilot_events = fetch_autopilot_events(provider, request, &device, cancellation);
    overlay.enrollment_configuration = fetch_enrollment_configuration(
        provider,
        request,
        overlay.autopilot_events.data.as_deref(),
        cancellation,
    );
    overlay.apps = fetch_apps(provider, request, &device, &overlay, cancellation);
    overlay.policies = fetch_policies(provider, request, &device, cancellation);
    overlay.scripts = fetch_scripts(provider, request, &device, cancellation);
    correlate_policy_status_details(&mut overlay);
    overlay
}

fn empty_overlay(request: &EspGraphRequest, requested_at_utc: &str) -> EspGraphOverlay {
    EspGraphOverlay {
        request_id: request.request_id.clone(),
        requested_at_utc: requested_at_utc.to_string(),
        device_match: skipped_section(MANAGED_DEVICES_SCOPE, GraphApiVersion::V1_0, "notRequested"),
        autopilot_identity: skipped_section(
            SERVICE_CONFIG_SCOPE,
            GraphApiVersion::V1_0,
            "notRequested",
        ),
        deployment_profile: skipped_section(
            SERVICE_CONFIG_SCOPE,
            GraphApiVersion::Beta,
            "notRequested",
        ),
        intended_deployment_profile: skipped_section(
            SERVICE_CONFIG_SCOPE,
            GraphApiVersion::Beta,
            "notRequested",
        ),
        profile_assignments: skipped_section(
            SERVICE_CONFIG_SCOPE,
            GraphApiVersion::Beta,
            "notRequested",
        ),
        autopilot_events: skipped_section(
            MANAGED_DEVICES_SCOPE,
            GraphApiVersion::Beta,
            "notRequested",
        ),
        enrollment_configuration: skipped_section(
            SERVICE_CONFIG_SCOPE,
            GraphApiVersion::V1_0,
            "notRequested",
        ),
        apps: skipped_section(APPS_SCOPE, GraphApiVersion::V1_0, "notRequested"),
        policies: skipped_section(CONFIGURATION_SCOPE, GraphApiVersion::V1_0, "notRequested"),
        scripts: skipped_section(SCRIPTS_SCOPE, GraphApiVersion::Beta, "notRequested"),
    }
}

fn skip_device_dependents(overlay: &mut EspGraphOverlay) {
    overlay.autopilot_identity =
        skipped_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0, "deviceMatch");
    overlay.deployment_profile =
        skipped_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta, "deviceMatch");
    overlay.intended_deployment_profile =
        skipped_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta, "deviceMatch");
    overlay.profile_assignments =
        skipped_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta, "deviceMatch");
    overlay.autopilot_events =
        skipped_section(MANAGED_DEVICES_SCOPE, GraphApiVersion::Beta, "deviceMatch");
    overlay.enrollment_configuration =
        skipped_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0, "deviceMatch");
    overlay.apps = skipped_section(APPS_SCOPE, GraphApiVersion::V1_0, "deviceMatch");
    overlay.policies = skipped_section(CONFIGURATION_SCOPE, GraphApiVersion::V1_0, "deviceMatch");
    overlay.scripts = skipped_section(SCRIPTS_SCOPE, GraphApiVersion::Beta, "deviceMatch");
}

fn cancel_device_dependents(overlay: &mut EspGraphOverlay) {
    overlay.autopilot_identity = cancelled_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0);
    overlay.deployment_profile = cancelled_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta);
    overlay.intended_deployment_profile =
        cancelled_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta);
    overlay.profile_assignments = cancelled_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta);
    overlay.autopilot_events = cancelled_section(MANAGED_DEVICES_SCOPE, GraphApiVersion::Beta);
    overlay.enrollment_configuration =
        cancelled_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0);
    overlay.apps = cancelled_section(APPS_SCOPE, GraphApiVersion::V1_0);
    overlay.policies = cancelled_section(CONFIGURATION_SCOPE, GraphApiVersion::V1_0);
    overlay.scripts = cancelled_section(SCRIPTS_SCOPE, GraphApiVersion::Beta);
}

fn managed_device_endpoint(request: &EspGraphRequest) -> (EspGraphEndpoint, bool) {
    let explicit = request
        .selected_managed_device_id
        .as_deref()
        .and_then(normalize_graph_guid)
        .or_else(|| {
            request
                .identity
                .managed_device_id
                .as_deref()
                .and_then(normalize_graph_guid)
        });
    let (path, is_collection) = if let Some(id) = explicit {
        (format!("/v1.0/deviceManagement/managedDevices/{id}"), false)
    } else if let Some(id) = request
        .identity
        .entra_device_id
        .as_deref()
        .and_then(normalize_graph_guid)
    {
        (
            format!(
                "/v1.0/deviceManagement/managedDevices?$filter=azureADDeviceId%20eq%20'{id}'&$top=25"
            ),
            true,
        )
    } else if let Some(serial) = request.identity.serial_number.as_ref() {
        (
            format!(
                "/v1.0/deviceManagement/managedDevices?$filter=serialNumber%20eq%20'{}'&$top=25",
                encode_odata_string(&serial.value)
            ),
            true,
        )
    } else if let Some(name) = request.identity.device_name.as_deref() {
        (
            format!(
                "/v1.0/deviceManagement/managedDevices?$filter=deviceName%20eq%20'{}'&$top=25",
                encode_odata_string(name)
            ),
            true,
        )
    } else {
        (
            "/v1.0/deviceManagement/managedDevices?$top=100".to_string(),
            true,
        )
    };
    (
        EspGraphEndpoint::new(path, MANAGED_DEVICES_SCOPE, GraphApiVersion::V1_0),
        is_collection,
    )
}

fn fetch_managed_candidates<P: EspGraphProvider>(
    provider: &P,
    request: &EspGraphRequest,
    cancellation: &dyn GraphCancellation,
) -> Result<Vec<EspGraphManagedDevice>, GraphClientError> {
    let selected = request
        .selected_managed_device_id
        .as_deref()
        .map(|value| {
            normalize_graph_guid(value).ok_or_else(|| invalid_response(MANAGED_DEVICES_SCOPE))
        })
        .transpose()?;
    let (primary, primary_is_collection) = managed_device_endpoint(request);
    let primary_result = if primary_is_collection {
        get_collection(provider, &primary, cancellation)
    } else {
        get(provider, &primary, cancellation)
    }
        .and_then(|value| parse_managed_devices(&value, MANAGED_DEVICES_SCOPE));
    if let Some(selected) = selected {
        return primary_result.and_then(|candidates| {
            if candidates.len() == 1 && candidates[0].managed_device_id == selected {
                Ok(candidates)
            } else {
                Err(invalid_response(MANAGED_DEVICES_SCOPE))
            }
        });
    }
    match primary_result {
        Ok(candidates) if !candidates.is_empty() => Ok(candidates),
        Err(error) if error.kind != GraphClientErrorKind::NotFound => Err(error),
        Ok(_) | Err(_) => {
            let fallback_path = "/v1.0/deviceManagement/managedDevices?$top=100";
            if primary.path == fallback_path {
                return Ok(Vec::new());
            }
            let fallback = EspGraphEndpoint::new(
                fallback_path.to_string(),
                MANAGED_DEVICES_SCOPE,
                GraphApiVersion::V1_0,
            );
            get_collection(provider, &fallback, cancellation)
                .and_then(|value| parse_managed_devices(&value, MANAGED_DEVICES_SCOPE))
        }
    }
}

fn parse_managed_devices(
    value: &Value,
    scope: &str,
) -> Result<Vec<EspGraphManagedDevice>, GraphClientError> {
    let values: Vec<&Value> = if let Some(items) = value.get("value").and_then(Value::as_array) {
        items.iter().collect()
    } else if value.is_object() {
        vec![value]
    } else {
        return Err(invalid_response(scope));
    };
    values
        .into_iter()
        .map(|item| {
            let id = required_guid(item, "id", scope)?;
            Ok(EspGraphManagedDevice {
                managed_device_id: id.clone(),
                entra_device_id: optional_guid(item, "azureADDeviceId", scope)?,
                serial_number: optional_classified(item, "serialNumber", scope)?,
                device_name: optional_string(item, "deviceName", scope)?,
                user_id: optional_guid(item, "userId", scope)?,
                user_principal_name: optional_classified(item, "userPrincipalName", scope)?,
                tenant_id: optional_classified(item, "tenantId", scope)?,
                evidence: vec![graph_evidence("managed-device", &id)],
            })
        })
        .collect()
}

fn fetch_autopilot_identity<P: EspGraphProvider>(
    provider: &P,
    device: &EspGraphManagedDevice,
    cancellation: &dyn GraphCancellation,
) -> GraphSection<EspGraphAutopilotIdentity> {
    let path = if let Some(entra) = device.entra_device_id.as_deref() {
        format!(
            "/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{entra}'&$top=25"
        )
    } else if let Some(serial) = device.serial_number.as_ref() {
        format!(
            "/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=serialNumber%20eq%20'{}'&$top=25",
            encode_odata_string(&serial.value)
        )
    } else {
        "/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$top=100".to_string()
    };
    let endpoint = EspGraphEndpoint::new(path, SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0);
    let result = get_collection(provider, &endpoint, cancellation).and_then(|value| {
        let items = page_items(&value, SERVICE_CONFIG_SCOPE)?;
        let mut matches = Vec::new();
        for item in items {
            let entra = optional_guid(item, "azureActiveDirectoryDeviceId", SERVICE_CONFIG_SCOPE)?;
            let serial = optional_classified(item, "serialNumber", SERVICE_CONFIG_SCOPE)?;
            let entra_match = device
                .entra_device_id
                .as_deref()
                .is_some_and(|expected| entra.as_deref() == Some(expected));
            let serial_match = device.serial_number.as_ref().is_some_and(|expected| {
                serial
                    .as_ref()
                    .is_some_and(|actual| text_eq(&actual.value, &expected.value))
            });
            if entra_match || serial_match {
                let id = required_guid(item, "id", SERVICE_CONFIG_SCOPE)?;
                matches.push(EspGraphAutopilotIdentity {
                    autopilot_device_id: id.clone(),
                    entra_device_id: entra,
                    serial_number: serial,
                    deployment_profile_id: optional_guid(
                        item,
                        "deploymentProfileId",
                        SERVICE_CONFIG_SCOPE,
                    )?,
                    group_tag: optional_string(item, "groupTag", SERVICE_CONFIG_SCOPE)?,
                    evidence: vec![graph_evidence("autopilot-identity", &id)],
                });
            }
        }
        matches.sort_by(|left, right| left.autopilot_device_id.cmp(&right.autopilot_device_id));
        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.pop()),
            _ => Err(invalid_response(SERVICE_CONFIG_SCOPE)),
        }
    });
    match result {
        Ok(Some(identity)) => {
            available_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0, identity)
        }
        Ok(None) => not_found_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0),
        Err(error) => error_section(error, SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0, None),
    }
}

fn fetch_profile<P: EspGraphProvider>(
    provider: &P,
    autopilot_id: &str,
    relation: &str,
    cancellation: &dyn GraphCancellation,
) -> GraphSection<EspGraphDeploymentProfile> {
    let endpoint = EspGraphEndpoint::new(
        format!(
            "/beta/deviceManagement/windowsAutopilotDeviceIdentities/{autopilot_id}/{relation}"
        ),
        SERVICE_CONFIG_SCOPE,
        GraphApiVersion::Beta,
    );
    match get(provider, &endpoint, cancellation)
        .and_then(|value| parse_profile(&value, SERVICE_CONFIG_SCOPE))
    {
        Ok(profile) => available_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta, profile),
        Err(error) => error_section(error, SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta, None),
    }
}

fn parse_profile(
    value: &Value,
    scope: &str,
) -> Result<EspGraphDeploymentProfile, GraphClientError> {
    let id = required_guid(value, "id", scope)?;
    let join_mode = if let Some(raw) = optional_string(value, "joinMode", scope)? {
        Some(serde_json::from_value(Value::String(raw)).map_err(|_| invalid_response(scope))?)
    } else {
        optional_string(value, "@odata.type", scope)?.and_then(|odata_type| {
            if odata_type.contains("azureADWindowsAutopilotDeploymentProfile") {
                Some(EspJoinMode::Entra)
            } else if odata_type.contains("activeDirectoryWindowsAutopilotDeploymentProfile") {
                Some(EspJoinMode::HybridEntra)
            } else {
                None
            }
        })
    };
    Ok(EspGraphDeploymentProfile {
        profile_id: id.clone(),
        display_name: optional_string(value, "displayName", scope)?,
        join_mode,
        selected_mobile_app_ids: guid_array(value, "selectedMobileAppIds", scope)?,
        evidence: vec![graph_evidence("deployment-profile", &id)],
    })
}

fn fetch_profile_assignments<P: EspGraphProvider>(
    provider: &P,
    profile_id: &str,
    cancellation: &dyn GraphCancellation,
) -> GraphSection<Vec<EspGraphAssignment>> {
    let endpoint = EspGraphEndpoint::new(
        format!(
            "/beta/deviceManagement/windowsAutopilotDeploymentProfiles/{profile_id}/assignments"
        ),
        SERVICE_CONFIG_SCOPE,
        GraphApiVersion::Beta,
    );
    match get_collection(provider, &endpoint, cancellation)
        .and_then(|value| parse_assignments(&value, SERVICE_CONFIG_SCOPE))
    {
        Ok(assignments) => {
            available_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta, assignments)
        }
        Err(error) => error_section(error, SERVICE_CONFIG_SCOPE, GraphApiVersion::Beta, None),
    }
}

fn fetch_autopilot_events<P: EspGraphProvider>(
    provider: &P,
    request: &EspGraphRequest,
    device: &EspGraphManagedDevice,
    cancellation: &dyn GraphCancellation,
) -> GraphSection<Vec<EspGraphAutopilotEvent>> {
    let window = match evidence_window(request) {
        Ok(Some(window)) => window,
        Ok(None) => {
            return skipped_section(
                MANAGED_DEVICES_SCOPE,
                GraphApiVersion::Beta,
                "localEvidenceWindow",
            )
        }
        Err(error) => {
            return error_section(error, MANAGED_DEVICES_SCOPE, GraphApiVersion::Beta, None)
        }
    };
    let managed_id = &device.managed_device_id;
    let event_device_id = device
        .entra_device_id
        .as_deref()
        .unwrap_or(managed_id.as_str());
    let endpoint = EspGraphEndpoint::new(
        format!(
            "/beta/deviceManagement/autopilotEvents?$filter=deviceId%20eq%20'{event_device_id}'&$orderby=eventDateTime%20desc&$top=25"
        ),
        MANAGED_DEVICES_SCOPE,
        GraphApiVersion::Beta,
    );
    let value = match get_collection(provider, &endpoint, cancellation) {
        Ok(value) => value,
        Err(error) => {
            return error_section(error, MANAGED_DEVICES_SCOPE, GraphApiVersion::Beta, None)
        }
    };
    let mut events = match (|| {
        let mut events = Vec::new();
        for item in page_items(&value, MANAGED_DEVICES_SCOPE)? {
            let item_device = optional_guid(item, "deviceId", MANAGED_DEVICES_SCOPE)?;
            if item_device.as_deref() != Some(event_device_id) {
                continue;
            }
            let id = required_guid(item, "id", MANAGED_DEVICES_SCOPE)?;
            let raw_state = required_string(item, "deploymentState", MANAGED_DEVICES_SCOPE)?;
            let event_time = required_string(item, "eventDateTime", MANAGED_DEVICES_SCOPE)?;
            let (event_time, instant) = graph_timestamp(&event_time, MANAGED_DEVICES_SCOPE)?;
            if instant < window.start || instant > window.end {
                continue;
            }
            events.push((
                instant,
                EspGraphAutopilotEvent {
                    event_id: id.clone(),
                    managed_device_id: Some(managed_id.clone()),
                    enrollment_configuration_id: optional_guid(
                        item,
                        "windows10EnrollmentCompletionPageConfigurationId",
                        MANAGED_DEVICES_SCOPE,
                    )?,
                    event_time: Some(event_time),
                    deployment_state: graph_status(&raw_state),
                    policy_status_details: Vec::new(),
                    evidence: vec![graph_evidence("autopilot-event", &id)],
                },
            ));
        }
        Ok::<_, GraphClientError>(events)
    })() {
        Ok(events) => events,
        Err(error) => {
            return error_section(error, MANAGED_DEVICES_SCOPE, GraphApiVersion::Beta, None)
        }
    };
    events.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.event_id.cmp(&right.1.event_id))
    });
    let mut events: Vec<EspGraphAutopilotEvent> =
        events.into_iter().map(|(_, event)| event).collect();
    if let Some(newest) = events.first_mut() {
        let detail_endpoint = EspGraphEndpoint::new(
            format!(
                "/beta/deviceManagement/autopilotEvents/{}/policyStatusDetails",
                newest.event_id
            ),
            MANAGED_DEVICES_SCOPE,
            GraphApiVersion::Beta,
        );
        match get_collection(provider, &detail_endpoint, cancellation)
            .and_then(|value| parse_policy_status_details(&value, MANAGED_DEVICES_SCOPE))
        {
            Ok(details) => newest.policy_status_details = details,
            Err(error) => {
                return error_section(
                    error,
                    MANAGED_DEVICES_SCOPE,
                    GraphApiVersion::Beta,
                    Some(events),
                )
            }
        }
    }
    available_section(MANAGED_DEVICES_SCOPE, GraphApiVersion::Beta, events)
}

fn parse_policy_status_details(
    value: &Value,
    scope: &str,
) -> Result<Vec<EspGraphPolicyStatusDetail>, GraphClientError> {
    page_items(value, scope)?
        .into_iter()
        .map(|item| {
            let id = required_guid(item, "id", scope)?;
            let kind_raw =
                optional_string(item, "policyType", scope)?.unwrap_or_else(|| "policy".to_string());
            let kind: EspGraphPolicyStatusDetailKind = serde_json::from_value(Value::String(
                if kind_raw.eq_ignore_ascii_case("app")
                    || kind_raw.eq_ignore_ascii_case("application")
                    || kind_raw.eq_ignore_ascii_case("appModel")
                {
                    "app".to_string()
                } else if kind_raw.eq_ignore_ascii_case("policy")
                    || kind_raw.eq_ignore_ascii_case("configurationPolicy")
                {
                    "policy".to_string()
                } else {
                    kind_raw
                },
            ))
            .map_err(|_| invalid_response(scope))?;
            let related_object_id = ["relatedObjectId", "appId", "policyId"]
                .into_iter()
                .find_map(|key| optional_guid(item, key, scope).transpose())
                .transpose()?;
            let raw_status = optional_string(item, "complianceStatus", scope)?
                .or(optional_string(item, "status", scope)?)
                .ok_or_else(|| invalid_response(scope))?;
            let mut status = graph_status(&raw_status);
            if let Some(error_code) = optional_i64(item, "errorCode", scope)? {
                status.detail = Some(EspStatusDetail {
                    raw: EspRawStatus::Number(error_code),
                    normalized: status.normalized.clone(),
                    display: format!("Graph error code {error_code}"),
                });
            }
            Ok(EspGraphPolicyStatusDetail {
                status_detail_id: id.clone(),
                related_object_id,
                display_name: optional_string(item, "displayName", scope)?,
                kind,
                status,
                tracked_on_enrollment_status: optional_bool(
                    item,
                    "trackedOnEnrollmentStatus",
                    scope,
                )?,
                correlation_confidence: EspCorrelationConfidence::Uncorrelated,
                evidence: vec![graph_evidence("policy-status-detail", &id)],
            })
        })
        .collect()
}

fn fetch_enrollment_configuration<P: EspGraphProvider>(
    provider: &P,
    request: &EspGraphRequest,
    events: Option<&[EspGraphAutopilotEvent]>,
    cancellation: &dyn GraphCancellation,
) -> GraphSection<EspGraphEnrollmentConfiguration> {
    if cancellation.is_cancelled() {
        return cancelled_section(SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0);
    }
    let mut configuration_ids = Vec::new();
    if let Some(events) = events {
        for id in events
            .iter()
            .filter_map(|event| event.enrollment_configuration_id.as_deref())
        {
            push_unique_guid(&mut configuration_ids, id);
        }
    }
    for id in &request.enrollment_configuration_ids {
        push_unique_guid(&mut configuration_ids, id);
    }
    let Some(configuration_id) = configuration_ids.into_iter().next() else {
        return skipped_section(
            SERVICE_CONFIG_SCOPE,
            GraphApiVersion::V1_0,
            "enrollmentConfigurationId",
        );
    };
    let endpoint = EspGraphEndpoint::new(
        format!("/v1.0/deviceManagement/deviceEnrollmentConfigurations/{configuration_id}"),
        SERVICE_CONFIG_SCOPE,
        GraphApiVersion::V1_0,
    );
    let value = match get(provider, &endpoint, cancellation) {
        Ok(value) => value,
        Err(error) => {
            return error_section(error, SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0, None)
        }
    };
    let id = match required_guid(&value, "id", SERVICE_CONFIG_SCOPE) {
        Ok(id) if id == configuration_id => id,
        _ => {
            return error_section(
                invalid_response(SERVICE_CONFIG_SCOPE),
                SERVICE_CONFIG_SCOPE,
                GraphApiVersion::V1_0,
                None,
            )
        }
    };
    let mut configuration = match parse_enrollment_configuration(&value, &id) {
        Ok(configuration) => configuration,
        Err(error) => {
            return error_section(error, SERVICE_CONFIG_SCOPE, GraphApiVersion::V1_0, None)
        }
    };
    let mut api_version = GraphApiVersion::V1_0;
    if !has_rich_enrollment_fields(&value) {
        let beta_endpoint = EspGraphEndpoint::new(
            format!("/beta/deviceManagement/deviceEnrollmentConfigurations/{id}"),
            SERVICE_CONFIG_SCOPE,
            GraphApiVersion::Beta,
        );
        let beta_value = match get(provider, &beta_endpoint, cancellation) {
            Ok(value) => value,
            Err(error) => {
                return error_section(
                    error,
                    SERVICE_CONFIG_SCOPE,
                    GraphApiVersion::Beta,
                    Some(configuration),
                )
            }
        };
        if required_guid(&beta_value, "id", SERVICE_CONFIG_SCOPE)
            .ok()
            .as_deref()
            != Some(id.as_str())
        {
            return error_section(
                invalid_response(SERVICE_CONFIG_SCOPE),
                SERVICE_CONFIG_SCOPE,
                GraphApiVersion::Beta,
                Some(configuration),
            );
        }
        configuration = match parse_enrollment_configuration(&beta_value, &id) {
            Ok(configuration) => configuration,
            Err(error) => {
                return error_section(
                    error,
                    SERVICE_CONFIG_SCOPE,
                    GraphApiVersion::Beta,
                    Some(configuration),
                )
            }
        };
        api_version = GraphApiVersion::Beta;
    }
    let assignments_endpoint = EspGraphEndpoint::new(
        format!("/v1.0/deviceManagement/deviceEnrollmentConfigurations/{id}/assignments"),
        SERVICE_CONFIG_SCOPE,
        GraphApiVersion::V1_0,
    );
    configuration.assignments = match get_collection(provider, &assignments_endpoint, cancellation)
        .and_then(|value| parse_assignments(&value, SERVICE_CONFIG_SCOPE))
    {
        Ok(assignments) => assignments,
        Err(error) => {
            return error_section(
                error,
                SERVICE_CONFIG_SCOPE,
                api_version,
                Some(configuration),
            )
        }
    };
    available_section(SERVICE_CONFIG_SCOPE, api_version, configuration)
}

fn parse_enrollment_configuration(
    value: &Value,
    id: &str,
) -> Result<EspGraphEnrollmentConfiguration, GraphClientError> {
    Ok(EspGraphEnrollmentConfiguration {
        configuration_id: id.to_string(),
        display_name: optional_string(value, "displayName", SERVICE_CONFIG_SCOPE)?,
        show_installation_progress: optional_bool(
            value,
            "showInstallationProgress",
            SERVICE_CONFIG_SCOPE,
        )?,
        device_esp_enabled: optional_bool(value, "deviceEspEnabled", SERVICE_CONFIG_SCOPE)?,
        user_esp_enabled: optional_bool(value, "userEspEnabled", SERVICE_CONFIG_SCOPE)?,
        disable_user_status_tracking_after_first_user: optional_bool(
            value,
            "disableUserStatusTrackingAfterFirstUser",
            SERVICE_CONFIG_SCOPE,
        )?,
        timeout_minutes: optional_u64(value, "timeoutInMinutes", SERVICE_CONFIG_SCOPE)?.or(
            optional_u64(
                value,
                "installProgressTimeoutInMinutes",
                SERVICE_CONFIG_SCOPE,
            )?,
        ),
        selected_mobile_app_ids: guid_array(value, "selectedMobileAppIds", SERVICE_CONFIG_SCOPE)?,
        assignments: Vec::new(),
        evidence: vec![graph_evidence("enrollment-configuration", id)],
    })
}

fn has_rich_enrollment_fields(value: &Value) -> bool {
    [
        "showInstallationProgress",
        "installProgressTimeoutInMinutes",
        "selectedMobileAppIds",
        "deviceEspEnabled",
        "userEspEnabled",
        "disableUserStatusTrackingAfterFirstUser",
    ]
    .into_iter()
    .any(|key| value.get(key).is_some())
}

fn fetch_apps<P: EspGraphProvider>(
    provider: &P,
    request: &EspGraphRequest,
    device: &EspGraphManagedDevice,
    overlay: &EspGraphOverlay,
    cancellation: &dyn GraphCancellation,
) -> GraphSection<Vec<EspGraphAppRecord>> {
    if cancellation.is_cancelled() {
        return cancelled_section(APPS_SCOPE, GraphApiVersion::V1_0);
    }
    let mut ids = normalized_ids(&request.workload_ids);
    ids.extend(normalized_ids(&request.app_ids));
    if let Some(profile) = overlay.deployment_profile.data.as_ref() {
        ids.extend(normalized_ids(&profile.selected_mobile_app_ids));
    }
    if let Some(configuration) = overlay.enrollment_configuration.data.as_ref() {
        ids.extend(normalized_ids(&configuration.selected_mobile_app_ids));
    }
    ids.sort();
    ids.dedup();
    let truncated = ids.len() > MAX_REFERENCED_OBJECTS;
    ids.truncate(MAX_REFERENCED_OBJECTS);
    if ids.is_empty() {
        return skipped_section(APPS_SCOPE, GraphApiVersion::V1_0, "referencedAppIds");
    }

    let selected_ids: BTreeSet<String> = overlay
        .deployment_profile
        .data
        .iter()
        .flat_map(|profile| profile.selected_mobile_app_ids.iter())
        .chain(
            overlay
                .enrollment_configuration
                .data
                .iter()
                .flat_map(|configuration| configuration.selected_mobile_app_ids.iter()),
        )
        .filter_map(|id| normalize_graph_guid(id))
        .collect();
    let mut records = Vec::new();
    for id in &ids {
        let endpoint = EspGraphEndpoint::new(
            format!("/v1.0/deviceAppManagement/mobileApps/{id}"),
            APPS_SCOPE,
            GraphApiVersion::V1_0,
        );
        let value = match get(provider, &endpoint, cancellation) {
            Ok(value) => value,
            Err(error) => {
                return error_section(error, APPS_SCOPE, GraphApiVersion::V1_0, Some(records))
            }
        };
        let response_id = match required_guid(&value, "id", APPS_SCOPE) {
            Ok(response_id) if response_id == *id => response_id,
            _ => {
                return error_section(
                    invalid_response(APPS_SCOPE),
                    APPS_SCOPE,
                    GraphApiVersion::V1_0,
                    Some(records),
                )
            }
        };
        let assignment_endpoint = EspGraphEndpoint::new(
            format!("/v1.0/deviceAppManagement/mobileApps/{id}/assignments"),
            APPS_SCOPE,
            GraphApiVersion::V1_0,
        );
        let assignments = match get_collection(provider, &assignment_endpoint, cancellation)
            .and_then(|value| parse_assignments(&value, APPS_SCOPE))
        {
            Ok(assignments) => assignments,
            Err(error) => {
                return error_section(error, APPS_SCOPE, GraphApiVersion::V1_0, Some(records))
            }
        };
        let (display_name, object_status, tracked) = match (|| -> Result<_, GraphClientError> {
            Ok((
                optional_string(&value, "displayName", APPS_SCOPE)?,
                optional_string(&value, "status", APPS_SCOPE)?.map(|raw| graph_status(&raw)),
                optional_bool(&value, "trackedOnEnrollmentStatus", APPS_SCOPE)?
                    .or_else(|| selected_ids.contains(id).then_some(true)),
            ))
        })() {
            Ok(fields) => fields,
            Err(error) => {
                return error_section(error, APPS_SCOPE, GraphApiVersion::V1_0, Some(records))
            }
        };
        records.push(EspGraphAppRecord {
            app_id: response_id.clone(),
            display_name,
            tracked_on_enrollment_status: tracked,
            status: object_status,
            intent_state: skipped_section(
                CONFIGURATION_SCOPE,
                GraphApiVersion::Beta,
                "mobileAppIntentAndStates",
            ),
            assignments,
            evidence: vec![graph_evidence("mobile-app", &response_id)],
        });
    }

    if let Some(user_id) = device.user_id.as_deref() {
        let endpoint = EspGraphEndpoint::new(
            format!("/beta/users/{user_id}/mobileAppIntentAndStates?$top=100"),
            CONFIGURATION_SCOPE,
            GraphApiVersion::Beta,
        );
        match get_collection(provider, &endpoint, cancellation) {
            Ok(value) => {
                if let Err(error) = apply_app_intent_states(&value, device, &mut records) {
                    set_app_intent_error(&mut records, error);
                }
            }
            Err(error) if error.kind == GraphClientErrorKind::NotFound => {
                for record in &mut records {
                    record.intent_state =
                        not_found_section(CONFIGURATION_SCOPE, GraphApiVersion::Beta);
                }
            }
            Err(error) => {
                set_app_intent_error(&mut records, error);
            }
        }
    }

    if truncated {
        error_section(
            item_limit_error(APPS_SCOPE),
            APPS_SCOPE,
            GraphApiVersion::V1_0,
            Some(records),
        )
    } else {
        available_section(APPS_SCOPE, GraphApiVersion::V1_0, records)
    }
}

fn apply_app_intent_states(
    value: &Value,
    device: &EspGraphManagedDevice,
    records: &mut [EspGraphAppRecord],
) -> Result<(), GraphClientError> {
    let mut states: BTreeMap<String, (EspStatus, Vec<EspEvidenceRef>)> = BTreeMap::new();
    for item in page_items(value, CONFIGURATION_SCOPE)? {
        let item_id = required_string(item, "id", CONFIGURATION_SCOPE)?;
        let item_device = required_string(item, "managedDeviceIdentifier", CONFIGURATION_SCOPE)?;
        if !device_identifier_matches(&item_device, device) {
            continue;
        }
        if let Some(item_user) = optional_guid(item, "userId", CONFIGURATION_SCOPE)? {
            if device.user_id.as_deref() != Some(item_user.as_str()) {
                continue;
            }
        }
        let app_items = item
            .get("mobileAppList")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_response(CONFIGURATION_SCOPE))?;
        for app_item in app_items {
            let app_id = required_guid(app_item, "applicationId", CONFIGURATION_SCOPE)?;
            let Some(raw) = optional_string(app_item, "installState", CONFIGURATION_SCOPE)? else {
                continue;
            };
            let state = graph_status(&raw);
            if states
                .get(&app_id)
                .is_some_and(|(existing, _)| existing != &state)
            {
                return Err(invalid_response(CONFIGURATION_SCOPE));
            }
            states.entry(app_id).or_insert_with(|| {
                (
                    state,
                    vec![graph_evidence("mobile-app-intent-state", &item_id)],
                )
            });
        }
    }

    for record in records {
        if let Some((state, evidence)) = states.remove(&record.app_id) {
            record.status = Some(state.clone());
            record.intent_state =
                available_section(CONFIGURATION_SCOPE, GraphApiVersion::Beta, state);
            extend_evidence(&mut record.evidence, &evidence);
        } else {
            record.intent_state = not_found_section(CONFIGURATION_SCOPE, GraphApiVersion::Beta);
        }
    }
    Ok(())
}

fn set_app_intent_error(records: &mut [EspGraphAppRecord], error: GraphClientError) {
    for record in records {
        record.intent_state = error_section(
            error.clone(),
            CONFIGURATION_SCOPE,
            GraphApiVersion::Beta,
            None,
        );
    }
}

fn fetch_policies<P: EspGraphProvider>(
    provider: &P,
    request: &EspGraphRequest,
    device: &EspGraphManagedDevice,
    cancellation: &dyn GraphCancellation,
) -> GraphSection<Vec<EspGraphPolicyRecord>> {
    if cancellation.is_cancelled() {
        return cancelled_section(CONFIGURATION_SCOPE, GraphApiVersion::V1_0);
    }
    let mut references: Vec<EspGraphPolicyReference> = request
        .policy_references
        .iter()
        .filter_map(|reference| {
            normalize_graph_guid(&reference.id).map(|id| EspGraphPolicyReference {
                id,
                kind: reference.kind.clone(),
            })
        })
        .collect();
    references.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| policy_kind_sort_key(&left.kind).cmp(&policy_kind_sort_key(&right.kind)))
    });
    references.dedup_by(|left, right| left.id == right.id && left.kind == right.kind);
    let truncated = references.len() > MAX_REFERENCED_OBJECTS;
    references.truncate(MAX_REFERENCED_OBJECTS);
    if references.is_empty() {
        return skipped_section(
            CONFIGURATION_SCOPE,
            GraphApiVersion::V1_0,
            "referencedPolicyIds",
        );
    }
    let mut records = Vec::new();
    let mut used_beta = false;
    for reference in references {
        let id = reference.id;
        let (base, version, has_statuses) = match reference.kind {
            EspGraphPolicyKind::Compliance => (
                format!("/v1.0/deviceManagement/deviceCompliancePolicies/{id}"),
                GraphApiVersion::V1_0,
                true,
            ),
            EspGraphPolicyKind::ConfigurationPolicy => (
                format!("/beta/deviceManagement/configurationPolicies/{id}"),
                GraphApiVersion::Beta,
                false,
            ),
            _ => (
                format!("/v1.0/deviceManagement/deviceConfigurations/{id}"),
                GraphApiVersion::V1_0,
                true,
            ),
        };
        used_beta |= version == GraphApiVersion::Beta;
        let endpoint = EspGraphEndpoint::new(base.clone(), CONFIGURATION_SCOPE, version.clone());
        let value = match get(provider, &endpoint, cancellation) {
            Ok(value) => value,
            Err(error) => return error_section(error, CONFIGURATION_SCOPE, version, Some(records)),
        };
        if required_guid(&value, "id", CONFIGURATION_SCOPE)
            .ok()
            .as_deref()
            != Some(id.as_str())
        {
            return error_section(
                invalid_response(CONFIGURATION_SCOPE),
                CONFIGURATION_SCOPE,
                version,
                Some(records),
            );
        }
        let assignment_endpoint = EspGraphEndpoint::new(
            format!("{base}/assignments"),
            CONFIGURATION_SCOPE,
            version.clone(),
        );
        let assignments = match get_collection(provider, &assignment_endpoint, cancellation)
            .and_then(|value| parse_assignments(&value, CONFIGURATION_SCOPE))
        {
            Ok(assignments) => assignments,
            Err(error) => return error_section(error, CONFIGURATION_SCOPE, version, Some(records)),
        };
        let status = if has_statuses {
            let status_endpoint = EspGraphEndpoint::new(
                format!("{base}/deviceStatuses?$top=100"),
                CONFIGURATION_SCOPE,
                version.clone(),
            );
            match get_collection(provider, &status_endpoint, cancellation)
                .and_then(|value| classic_device_status(&value, device, CONFIGURATION_SCOPE))
            {
                Ok(status) => status,
                Err(error) => {
                    return error_section(error, CONFIGURATION_SCOPE, version, Some(records))
                }
            }
        } else {
            None
        };
        let display_name = match optional_string(&value, "displayName", CONFIGURATION_SCOPE) {
            Ok(value) => value,
            Err(error) => return error_section(error, CONFIGURATION_SCOPE, version, Some(records)),
        };
        records.push(EspGraphPolicyRecord {
            policy_id: id.clone(),
            display_name,
            kind: reference.kind,
            status,
            assignments,
            evidence: vec![graph_evidence("policy", &id)],
        });
    }
    let api_version = if used_beta {
        GraphApiVersion::Beta
    } else {
        GraphApiVersion::V1_0
    };
    if truncated {
        error_section(
            item_limit_error(CONFIGURATION_SCOPE),
            CONFIGURATION_SCOPE,
            api_version,
            Some(records),
        )
    } else {
        available_section(CONFIGURATION_SCOPE, api_version, records)
    }
}

fn fetch_scripts<P: EspGraphProvider>(
    provider: &P,
    request: &EspGraphRequest,
    device: &EspGraphManagedDevice,
    cancellation: &dyn GraphCancellation,
) -> GraphSection<Vec<EspGraphScriptRecord>> {
    if cancellation.is_cancelled() {
        return cancelled_section(SCRIPTS_SCOPE, GraphApiVersion::Beta);
    }
    let mut references: Vec<EspGraphScriptReference> = request
        .script_references
        .iter()
        .filter_map(|reference| {
            normalize_graph_guid(&reference.id).map(|id| EspGraphScriptReference {
                id,
                kind: reference.kind.clone(),
            })
        })
        .collect();
    references.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| script_kind_sort_key(&left.kind).cmp(&script_kind_sort_key(&right.kind)))
    });
    references.dedup_by(|left, right| left.id == right.id && left.kind == right.kind);
    let truncated = references.len() > MAX_REFERENCED_OBJECTS;
    references.truncate(MAX_REFERENCED_OBJECTS);
    if references.is_empty() {
        return skipped_section(SCRIPTS_SCOPE, GraphApiVersion::Beta, "referencedScriptIds");
    }
    let mut records = Vec::new();
    for reference in references {
        let id = reference.id;
        let collection = match reference.kind {
            EspGraphScriptKind::Remediation => "deviceHealthScripts",
            _ => "deviceManagementScripts",
        };
        let base = format!("/beta/deviceManagement/{collection}/{id}");
        let endpoint = EspGraphEndpoint::new(base.clone(), SCRIPTS_SCOPE, GraphApiVersion::Beta);
        let value = match get(provider, &endpoint, cancellation) {
            Ok(value) => value,
            Err(error) => {
                return error_section(error, SCRIPTS_SCOPE, GraphApiVersion::Beta, Some(records))
            }
        };
        if required_guid(&value, "id", SCRIPTS_SCOPE).ok().as_deref() != Some(id.as_str()) {
            return error_section(
                invalid_response(SCRIPTS_SCOPE),
                SCRIPTS_SCOPE,
                GraphApiVersion::Beta,
                Some(records),
            );
        }
        let assignments_endpoint = EspGraphEndpoint::new(
            format!("{base}/assignments"),
            SCRIPTS_SCOPE,
            GraphApiVersion::Beta,
        );
        let assignments = match get_collection(provider, &assignments_endpoint, cancellation)
            .and_then(|value| parse_assignments(&value, SCRIPTS_SCOPE))
        {
            Ok(assignments) => assignments,
            Err(error) => {
                return error_section(error, SCRIPTS_SCOPE, GraphApiVersion::Beta, Some(records))
            }
        };
        let states_endpoint = EspGraphEndpoint::new(
            format!("{base}/deviceRunStates?$expand=managedDevice($select=id)&$top=100"),
            SCRIPTS_SCOPE,
            GraphApiVersion::Beta,
        );
        let status = match get_collection(provider, &states_endpoint, cancellation)
            .and_then(|value| script_device_status(&value, device, &reference.kind, SCRIPTS_SCOPE))
        {
            Ok(status) => status,
            Err(error) => {
                return error_section(error, SCRIPTS_SCOPE, GraphApiVersion::Beta, Some(records))
            }
        };
        let display_name = match optional_string(&value, "displayName", SCRIPTS_SCOPE) {
            Ok(value) => value,
            Err(error) => {
                return error_section(error, SCRIPTS_SCOPE, GraphApiVersion::Beta, Some(records))
            }
        };
        records.push(EspGraphScriptRecord {
            script_id: id.clone(),
            display_name,
            kind: reference.kind,
            status,
            assignments,
            evidence: vec![graph_evidence("script", &id)],
        });
    }
    if truncated {
        error_section(
            item_limit_error(SCRIPTS_SCOPE),
            SCRIPTS_SCOPE,
            GraphApiVersion::Beta,
            Some(records),
        )
    } else {
        available_section(SCRIPTS_SCOPE, GraphApiVersion::Beta, records)
    }
}

fn classic_device_status(
    value: &Value,
    device: &EspGraphManagedDevice,
    scope: &str,
) -> Result<Option<EspStatus>, GraphClientError> {
    let (Some(device_name), Some(user_principal_name)) = (
        device.device_name.as_deref(),
        device
            .user_principal_name
            .as_ref()
            .map(|value| value.value.as_str()),
    ) else {
        return Ok(None);
    };
    let mut matched = Vec::new();
    for item in page_items(value, scope)? {
        let item_name = optional_string(item, "deviceDisplayName", scope)?;
        let item_user = optional_string(item, "userPrincipalName", scope)?;
        if !item_name
            .as_deref()
            .is_some_and(|value| text_eq(value, device_name))
            || !item_user
                .as_deref()
                .is_some_and(|value| text_eq(value, user_principal_name))
        {
            continue;
        }
        if let Some(raw) = optional_string(item, "status", scope)? {
            matched.push(graph_status(&raw));
        }
    }
    Ok((matched.len() == 1).then(|| matched.remove(0)))
}

fn script_device_status(
    value: &Value,
    device: &EspGraphManagedDevice,
    kind: &EspGraphScriptKind,
    scope: &str,
) -> Result<Option<EspStatus>, GraphClientError> {
    let keys: &[&str] = match kind {
        EspGraphScriptKind::Remediation => &["remediationState", "detectionState"],
        _ => &["runState"],
    };
    let mut matched = Vec::new();
    for item in page_items(value, scope)? {
        let Some(relationship) = item.get("managedDevice") else {
            continue;
        };
        if !relationship.is_object() {
            return Err(invalid_response(scope));
        }
        if required_guid(relationship, "id", scope)? != device.managed_device_id {
            continue;
        }
        for key in keys {
            if let Some(raw) = optional_string(item, key, scope)? {
                matched.push(graph_status(&raw));
                break;
            }
        }
    }
    Ok((matched.len() == 1).then(|| matched.remove(0)))
}

fn correlate_policy_status_details(overlay: &mut EspGraphOverlay) {
    let Some(events) = overlay.autopilot_events.data.as_mut() else {
        return;
    };
    let mut apps = overlay.apps.data.as_mut();
    let mut policies = overlay.policies.data.as_mut();
    for event in events {
        for detail in &mut event.policy_status_details {
            match &detail.kind {
                EspGraphPolicyStatusDetailKind::App => {
                    let Some(records) = apps.as_deref_mut() else {
                        continue;
                    };
                    let matched = detail
                        .related_object_id
                        .as_deref()
                        .and_then(|id| records.iter().position(|record| record.app_id == id))
                        .map(|index| (index, EspCorrelationConfidence::Exact))
                        .or_else(|| {
                            unique_display_match(
                                detail.display_name.as_deref(),
                                records.iter().map(|record| record.display_name.as_deref()),
                            )
                            .map(|index| (index, EspCorrelationConfidence::Strong))
                        });
                    let Some((index, confidence)) = matched else {
                        continue;
                    };
                    let record = &mut records[index];
                    if record.status.is_none() {
                        record.status = Some(detail.status.clone());
                    }
                    if record.tracked_on_enrollment_status.is_none() {
                        record.tracked_on_enrollment_status = detail.tracked_on_enrollment_status;
                    }
                    extend_evidence(&mut record.evidence, &detail.evidence);
                    detail.correlation_confidence = confidence;
                }
                EspGraphPolicyStatusDetailKind::Policy => {
                    let Some(records) = policies.as_deref_mut() else {
                        continue;
                    };
                    let matched = detail
                        .related_object_id
                        .as_deref()
                        .and_then(|id| records.iter().position(|record| record.policy_id == id))
                        .map(|index| (index, EspCorrelationConfidence::Exact))
                        .or_else(|| {
                            unique_display_match(
                                detail.display_name.as_deref(),
                                records.iter().map(|record| record.display_name.as_deref()),
                            )
                            .map(|index| (index, EspCorrelationConfidence::Strong))
                        });
                    let Some((index, confidence)) = matched else {
                        continue;
                    };
                    let record = &mut records[index];
                    if record.status.is_none() {
                        record.status = Some(detail.status.clone());
                    }
                    extend_evidence(&mut record.evidence, &detail.evidence);
                    detail.correlation_confidence = confidence;
                }
                EspGraphPolicyStatusDetailKind::Unknown(_) => {}
            }
        }
    }
}

fn unique_display_match<'a>(
    expected: Option<&str>,
    candidates: impl Iterator<Item = Option<&'a str>>,
) -> Option<usize> {
    let expected = expected?.trim();
    if expected.is_empty() {
        return None;
    }
    let mut matches = candidates
        .enumerate()
        .filter(|(_, candidate)| candidate.is_some_and(|value| text_eq(value, expected)))
        .map(|(index, _)| index);
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn extend_evidence(target: &mut Vec<EspEvidenceRef>, additions: &[EspEvidenceRef]) {
    for addition in additions {
        if !target.iter().any(|existing| existing == addition) {
            target.push(addition.clone());
        }
    }
}

fn parse_assignments(
    value: &Value,
    scope: &str,
) -> Result<Vec<EspGraphAssignment>, GraphClientError> {
    page_items(value, scope)?
        .into_iter()
        .map(|item| {
            let id = required_string(item, "id", scope)?;
            let intent_raw =
                optional_string(item, "intent", scope)?.unwrap_or_else(|| "unknown".to_string());
            let intent: EspGraphAssignmentIntent =
                serde_json::from_value(Value::String(intent_raw))
                    .map_err(|_| invalid_response(scope))?;
            let target = item.get("target").filter(|value| value.is_object());
            let target_type = target
                .and_then(|value| value.get("@odata.type"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let target_kind_raw = if target_type.contains("allDevicesAssignmentTarget") {
                "allDevices"
            } else if target_type.contains("allLicensedUsersAssignmentTarget") {
                "allUsers"
            } else if target_type.contains("groupAssignmentTarget") {
                "group"
            } else {
                target_type
            };
            let target_kind: EspGraphTargetKind =
                serde_json::from_value(Value::String(target_kind_raw.to_string()))
                    .map_err(|_| invalid_response(scope))?;
            let target_id = target
                .map(|value| optional_guid(value, "groupId", scope))
                .transpose()?
                .flatten();
            let filter_id = target
                .map(|value| {
                    optional_guid(value, "deviceAndAppManagementAssignmentFilterId", scope)
                })
                .transpose()?
                .flatten();
            Ok(EspGraphAssignment {
                assignment_id: id.clone(),
                target_id,
                filter_id,
                intent,
                target_kind,
                targeting: EspGraphTargeting::Declared,
                evidence: vec![graph_evidence("assignment", &id)],
            })
        })
        .collect()
}

fn get<P: EspGraphProvider>(
    provider: &P,
    endpoint: &EspGraphEndpoint,
    cancellation: &dyn GraphCancellation,
) -> Result<Value, GraphClientError> {
    if cancellation.is_cancelled() {
        return Err(GraphClientError {
            kind: GraphClientErrorKind::Cancelled,
            status: None,
            request_id: None,
            required_scope: endpoint.required_scope.clone(),
        });
    }
    provider.get(endpoint, cancellation)
}

fn get_collection<P: EspGraphProvider>(
    provider: &P,
    endpoint: &EspGraphEndpoint,
    cancellation: &dyn GraphCancellation,
) -> Result<Value, GraphClientError> {
    if cancellation.is_cancelled() {
        return Err(GraphClientError {
            kind: GraphClientErrorKind::Cancelled,
            status: None,
            request_id: None,
            required_scope: endpoint.required_scope.clone(),
        });
    }
    provider.get_collection(endpoint, cancellation)
}

fn page_items<'a>(value: &'a Value, scope: &str) -> Result<Vec<&'a Value>, GraphClientError> {
    value
        .get("value")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .ok_or_else(|| invalid_response(scope))
}

fn required_string(value: &Value, key: &str, scope: &str) -> Result<String, GraphClientError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| invalid_response(scope))
}

fn optional_string(
    value: &Value,
    key: &str,
    scope: &str,
) -> Result<Option<String>, GraphClientError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid_response(scope)),
    }
}

fn optional_bool(value: &Value, key: &str, scope: &str) -> Result<Option<bool>, GraphClientError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid_response(scope)),
    }
}

fn optional_u64(value: &Value, key: &str, scope: &str) -> Result<Option<u64>, GraphClientError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| invalid_response(scope)),
        Some(_) => Err(invalid_response(scope)),
    }
}

fn optional_i64(value: &Value, key: &str, scope: &str) -> Result<Option<i64>, GraphClientError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| invalid_response(scope)),
        Some(_) => Err(invalid_response(scope)),
    }
}

fn required_guid(value: &Value, key: &str, scope: &str) -> Result<String, GraphClientError> {
    required_string(value, key, scope)
        .and_then(|raw| normalize_graph_guid(&raw).ok_or_else(|| invalid_response(scope)))
}

fn optional_guid(
    value: &Value,
    key: &str,
    scope: &str,
) -> Result<Option<String>, GraphClientError> {
    optional_string(value, key, scope)?
        .map(|raw| normalize_graph_guid(&raw).ok_or_else(|| invalid_response(scope)))
        .transpose()
}

fn optional_classified(
    value: &Value,
    key: &str,
    scope: &str,
) -> Result<Option<EspClassifiedString>, GraphClientError> {
    optional_string(value, key, scope).map(|value| {
        value.map(|value| EspClassifiedString {
            value,
            sensitivity: EspSensitivity::Sensitive,
        })
    })
}

fn guid_array(value: &Value, key: &str, scope: &str) -> Result<Vec<String>, GraphClientError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .and_then(normalize_graph_guid)
                    .ok_or_else(|| invalid_response(scope))
            })
            .collect(),
        Some(_) => Err(invalid_response(scope)),
    }
}

fn normalized_ids(values: &[String]) -> Vec<String> {
    let mut ids: Vec<String> = values
        .iter()
        .filter_map(|value| normalize_graph_guid(value))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

fn policy_kind_sort_key(kind: &EspGraphPolicyKind) -> (u8, &str) {
    match kind {
        EspGraphPolicyKind::DeviceConfiguration => (0, ""),
        EspGraphPolicyKind::Compliance => (1, ""),
        EspGraphPolicyKind::ConfigurationPolicy => (2, ""),
        EspGraphPolicyKind::ScepCertificate => (3, ""),
        EspGraphPolicyKind::Unknown(value) => (4, value.as_str()),
    }
}

fn script_kind_sort_key(kind: &EspGraphScriptKind) -> (u8, &str) {
    match kind {
        EspGraphScriptKind::PlatformScript => (0, ""),
        EspGraphScriptKind::Remediation => (1, ""),
        EspGraphScriptKind::Unknown(value) => (2, value.as_str()),
    }
}

fn graph_status(raw: &str) -> EspStatus {
    let normalized = match raw.trim().to_ascii_lowercase().as_str() {
        "success" | "succeeded" | "installed" | "compliant" => EspNormalizedStatus::Succeeded,
        "failure" | "failed" | "fail" | "error" | "scripterror" | "remediationfailed"
        | "noncompliant" => EspNormalizedStatus::Failed,
        "pending" | "notinstalled" => EspNormalizedStatus::Pending,
        "installing" | "inprogress" => EspNormalizedStatus::InProgress,
        "notapplicable" | "skipped" => EspNormalizedStatus::Skipped,
        "cancelled" | "canceled" => EspNormalizedStatus::Cancelled,
        _ => EspNormalizedStatus::Unknown,
    };
    EspStatus {
        raw: EspRawStatus::Text(raw.to_string()),
        normalized,
        display: raw.to_string(),
        detail: None,
    }
}

struct EvidenceWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

fn evidence_window(request: &EspGraphRequest) -> Result<Option<EvidenceWindow>, GraphClientError> {
    let (Some(start), Some(end)) = (
        request.evidence_window_start_utc.as_deref(),
        request.evidence_window_end_utc.as_deref(),
    ) else {
        if request.evidence_window_start_utc.is_some() || request.evidence_window_end_utc.is_some()
        {
            return Err(invalid_response(MANAGED_DEVICES_SCOPE));
        }
        return Ok(None);
    };
    let start = parse_rfc3339_instant(start, MANAGED_DEVICES_SCOPE)?;
    let end = parse_rfc3339_instant(end, MANAGED_DEVICES_SCOPE)?;
    if start > end {
        return Err(invalid_response(MANAGED_DEVICES_SCOPE));
    }
    Ok(Some(EvidenceWindow { start, end }))
}

fn graph_timestamp(
    raw: &str,
    scope: &str,
) -> Result<(EspTimestamp, DateTime<Utc>), GraphClientError> {
    let parsed = DateTime::parse_from_rfc3339(raw).map_err(|_| invalid_response(scope))?;
    let instant = parsed.with_timezone(&Utc);
    let is_utc = raw.ends_with('Z') || raw.ends_with('z');
    Ok((
        EspTimestamp {
            raw_text: raw.to_string(),
            original_offset: Some(if is_utc {
                "Z".to_string()
            } else {
                parsed.offset().to_string()
            }),
            normalized_utc: Some(instant.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
            kind: if is_utc {
                EspTimestampKind::Utc
            } else {
                EspTimestampKind::Offset
            },
        },
        instant,
    ))
}

fn parse_rfc3339_instant(raw: &str, scope: &str) -> Result<DateTime<Utc>, GraphClientError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| invalid_response(scope))
}

fn push_unique_guid(ids: &mut Vec<String>, value: &str) {
    let Some(id) = normalize_graph_guid(value) else {
        return;
    };
    if !ids.iter().any(|existing| existing == &id) {
        ids.push(id);
    }
}

fn graph_evidence(kind: &str, id: &str) -> EspEvidenceRef {
    EspEvidenceRef {
        evidence_id: format!("graph:{kind}:{id}"),
        source_artifact_id: GRAPH_ARTIFACT_ID.to_string(),
    }
}

fn available_section<T>(scope: &str, api_version: GraphApiVersion, data: T) -> GraphSection<T> {
    GraphSection {
        status: GraphSectionStatus::Available,
        required_scope: Some(scope.to_string()),
        api_version,
        data: Some(data),
        error: None,
    }
}

fn not_found_section<T>(scope: &str, api_version: GraphApiVersion) -> GraphSection<T> {
    GraphSection {
        status: GraphSectionStatus::NotFound,
        required_scope: Some(scope.to_string()),
        api_version,
        data: None,
        error: None,
    }
}

fn skipped_section<T>(
    scope: &str,
    api_version: GraphApiVersion,
    blocked_by: &str,
) -> GraphSection<T> {
    GraphSection {
        status: GraphSectionStatus::Skipped,
        required_scope: Some(scope.to_string()),
        api_version,
        data: None,
        error: Some(GraphSectionError {
            code: "skipped".to_string(),
            message: "Graph section was not requested because a dependency is unavailable."
                .to_string(),
            request_id: None,
            blocked_by: Some(blocked_by.to_string()),
            retry_after_seconds: None,
        }),
    }
}

fn cancelled_section<T>(scope: &str, api_version: GraphApiVersion) -> GraphSection<T> {
    GraphSection {
        status: GraphSectionStatus::Cancelled,
        required_scope: Some(scope.to_string()),
        api_version,
        data: None,
        error: Some(GraphSectionError {
            code: "Cancelled".to_string(),
            message: "Microsoft Graph enrichment was cancelled.".to_string(),
            request_id: None,
            blocked_by: None,
            retry_after_seconds: None,
        }),
    }
}

fn error_section<T>(
    error: GraphClientError,
    scope: &str,
    api_version: GraphApiVersion,
    data: Option<T>,
) -> GraphSection<T> {
    let status = match error.kind {
        GraphClientErrorKind::PermissionDenied => GraphSectionStatus::PermissionDenied,
        GraphClientErrorKind::NotFound => GraphSectionStatus::NotFound,
        GraphClientErrorKind::Cancelled => GraphSectionStatus::Cancelled,
        _ => GraphSectionStatus::Failed,
    };
    GraphSection {
        status,
        required_scope: Some(scope.to_string()),
        api_version,
        data,
        error: Some(GraphSectionError {
            code: format!("{:?}", error.kind),
            message: "Microsoft Graph could not provide this section.".to_string(),
            request_id: error.request_id,
            blocked_by: None,
            retry_after_seconds: None,
        }),
    }
}

fn invalid_response(scope: &str) -> GraphClientError {
    GraphClientError {
        kind: GraphClientErrorKind::InvalidResponse,
        status: None,
        request_id: None,
        required_scope: scope.to_string(),
    }
}

fn item_limit_error(scope: &str) -> GraphClientError {
    GraphClientError {
        kind: GraphClientErrorKind::ItemLimitExceeded,
        status: None,
        request_id: None,
        required_scope: scope.to_string(),
    }
}

fn encode_odata_string(value: &str) -> String {
    let escaped = value.replace('\'', "''");
    let mut encoded = String::new();
    for byte in escaped.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn text_eq(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    !left.is_empty() && left.eq_ignore_ascii_case(right)
}

fn device_identifier_matches(identifier: &str, device: &EspGraphManagedDevice) -> bool {
    text_eq(identifier, &device.managed_device_id)
        || device
            .entra_device_id
            .as_deref()
            .is_some_and(|value| text_eq(identifier, value))
        || device
            .device_name
            .as_deref()
            .is_some_and(|value| text_eq(identifier, value))
        || device
            .serial_number
            .as_ref()
            .is_some_and(|value| text_eq(identifier, &value.value))
}

#[cfg(test)]
mod tests {
    use super::graph_status;
    use cmtraceopen_parser::esp::EspNormalizedStatus;

    #[test]
    fn graph_script_status_covers_every_documented_run_state() {
        let cases = [
            ("unknown", EspNormalizedStatus::Unknown),
            ("success", EspNormalizedStatus::Succeeded),
            ("fail", EspNormalizedStatus::Failed),
            (" SCRIPTERROR ", EspNormalizedStatus::Failed),
            ("pending", EspNormalizedStatus::Pending),
            ("notApplicable", EspNormalizedStatus::Skipped),
            ("unknownFutureValue", EspNormalizedStatus::Unknown),
        ];

        for (raw, expected) in cases {
            assert_eq!(graph_status(raw).normalized, expected, "wire value {raw}");
        }
    }

    #[test]
    fn graph_script_status_covers_every_documented_remediation_state() {
        let cases = [
            ("unknown", EspNormalizedStatus::Unknown),
            ("skipped", EspNormalizedStatus::Skipped),
            ("success", EspNormalizedStatus::Succeeded),
            (" remediationFailed ", EspNormalizedStatus::Failed),
            ("scriptError", EspNormalizedStatus::Failed),
            ("unknownFutureValue", EspNormalizedStatus::Unknown),
        ];

        for (raw, expected) in cases {
            assert_eq!(graph_status(raw).normalized, expected, "wire value {raw}");
        }
    }
}
