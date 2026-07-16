use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use app_lib::graph_api::client::{
    GraphBatchItem, GraphCancellation, GraphClient, GraphClientError, GraphClientErrorKind,
    GraphTransport, GraphTransportFailure, GRAPH_REQUEST_TIMEOUT, MAX_GRAPH_ATTEMPTS,
    MAX_GRAPH_ITEMS, MAX_GRAPH_PAGES, MAX_GRAPH_RESPONSE_BYTES, MAX_GRAPH_RETRY_DELAY,
};
use app_lib::graph_api::models::{
    normalize_graph_guid, project_graph_auth_status, GraphAppInfo, GraphAuthCapabilities,
    GraphAuthStatus, GraphHttpMethod, GraphResolutionResult, GraphTransportRequest,
    GraphTransportResponse, GRAPH_DELEGATED_SCOPES, GRAPH_SCOPE_REQUEST,
};
use base64::Engine;
use serde::Deserialize;

fn unsigned_token(claims: serde_json::Value) -> String {
    let encode = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    format!(
        "{}.{}.signature",
        encode(br#"{"alg":"none"}"#),
        encode(
            serde_json::to_vec(&claims)
                .expect("claims serialize")
                .as_slice()
        )
    )
}

#[test]
fn platform_boundary_transport_dtos_round_trip_off_windows() {
    let request = GraphTransportRequest {
        method: GraphHttpMethod::Get,
        url: "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=25".to_string(),
        consistency_level: Some("eventual".to_string()),
        content_type: None,
        body: None,
        required_scope: "DeviceManagementManagedDevices.Read.All".to_string(),
    };
    let request_json = serde_json::to_string(&request).expect("request should serialize");
    let decoded_request: GraphTransportRequest =
        serde_json::from_str(&request_json).expect("request should deserialize");
    assert_eq!(decoded_request, request);
    assert!(!request_json.contains("Authorization"));
    assert!(!request_json.contains("Bearer"));
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains("managedDevices"));
    assert!(!request_debug.contains("Bearer"));

    let response = GraphTransportResponse {
        status: 429,
        headers: BTreeMap::from([
            ("retry-after".to_string(), "3".to_string()),
            ("request-id".to_string(), "request-a".to_string()),
        ]),
        body: br#"{"error":{"code":"TooManyRequests"}}"#.to_vec(),
    };
    let response_json = serde_json::to_string(&response).expect("response should serialize");
    let decoded_response: GraphTransportResponse =
        serde_json::from_str(&response_json).expect("response should deserialize");
    assert_eq!(decoded_response, response);
    assert!(!format!("{response:?}").contains("TooManyRequests"));

    let status = GraphAuthStatus {
        is_authenticated: true,
        user_principal_name: Some("user@contoso.example".to_string()),
        tenant_id: Some("tenant-a".to_string()),
        granted_scopes: GRAPH_DELEGATED_SCOPES
            .iter()
            .map(|scope| (*scope).to_string())
            .collect(),
        missing_scopes: Vec::new(),
        expires_at: Some(2_000_000_000),
        capabilities: GraphAuthCapabilities::all(),
        error: None,
    };
    let status_json = serde_json::to_string(&status).expect("status should serialize");
    let decoded_status: GraphAuthStatus =
        serde_json::from_str(&status_json).expect("status should deserialize");
    assert_eq!(decoded_status, status);

    let app = GraphAppInfo {
        id: "app-a".to_string(),
        display_name: "Contoso VPN".to_string(),
        publisher: Some("Contoso".to_string()),
        odata_type: Some("#microsoft.graph.win32LobApp".to_string()),
    };
    let resolution = GraphResolutionResult {
        resolved: [(app.id.clone(), app)].into_iter().collect(),
        not_found: vec!["app-b".to_string()],
        errors: Vec::new(),
    };
    let resolution_json = serde_json::to_string(&resolution).expect("resolution should serialize");
    let decoded_resolution: GraphResolutionResult =
        serde_json::from_str(&resolution_json).expect("resolution should deserialize");
    assert_eq!(decoded_resolution, resolution);
}

#[test]
fn graph_auth_status_reports_full_and_app_only_capabilities() {
    assert_eq!(
        GRAPH_SCOPE_REQUEST,
        "https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All \
https://graph.microsoft.com/DeviceManagementServiceConfig.Read.All \
https://graph.microsoft.com/DeviceManagementApps.Read.All \
https://graph.microsoft.com/DeviceManagementConfiguration.Read.All \
https://graph.microsoft.com/DeviceManagementScripts.Read.All"
    );

    let full = unsigned_token(serde_json::json!({
        "aud": "https://graph.microsoft.com",
        "tid": "tenant-a",
        "exp": 2_000_000_000_u64,
        "scp": GRAPH_DELEGATED_SCOPES.join(" "),
    }));
    let status = project_graph_auth_status(
        &full,
        Some("user@contoso.example"),
        Some("tenant-a"),
        1_900_000_000,
    );
    assert!(status.is_authenticated);
    assert_eq!(status.tenant_id.as_deref(), Some("tenant-a"));
    assert_eq!(status.expires_at, Some(2_000_000_000));
    assert_eq!(status.granted_scopes.len(), 5);
    assert!(status.missing_scopes.is_empty());
    assert_eq!(status.capabilities, GraphAuthCapabilities::all());
    assert_eq!(status.error, None);

    let app_only = unsigned_token(serde_json::json!({
        "aud": "00000003-0000-0000-c000-000000000000",
        "tid": "tenant-a",
        "exp": 2_000_000_000_u64,
        "scp": "DeviceManagementApps.Read.All User.Read",
    }));
    let status = project_graph_auth_status(
        &app_only,
        Some("user@contoso.example"),
        Some("tenant-a"),
        1_900_000_000,
    );
    assert!(status.is_authenticated);
    assert!(status.capabilities.apps);
    assert!(!status.capabilities.managed_devices);
    assert!(!status.capabilities.service_config);
    assert!(!status.capabilities.configuration);
    assert!(!status.capabilities.scripts);
    assert_eq!(status.granted_scopes, ["DeviceManagementApps.Read.All"]);
    assert_eq!(status.missing_scopes.len(), 4);
}

#[test]
fn graph_auth_status_rejects_expired_malformed_audience_and_tenant_claims() {
    let assert_rejected = |token: &str, wam_tenant: Option<&str>, expected: &str| {
        let status = project_graph_auth_status(
            token,
            Some("user@contoso.example"),
            wam_tenant,
            1_900_000_000,
        );
        assert!(!status.is_authenticated);
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|error| error.contains(expected)),
            "unexpected status: {status:?}"
        );
        assert!(status.granted_scopes.is_empty());
        assert_eq!(status.missing_scopes.len(), 5);
        assert_eq!(status.capabilities, GraphAuthCapabilities::default());
    };

    assert_rejected("not-a-jwt", Some("tenant-a"), "MalformedToken");
    assert_rejected(
        &unsigned_token(serde_json::json!({
            "aud": "api://not-graph",
            "tid": "tenant-a",
            "exp": 2_000_000_000_u64,
            "scp": GRAPH_DELEGATED_SCOPES.join(" "),
        })),
        Some("tenant-a"),
        "InvalidAudience",
    );
    assert_rejected(
        &unsigned_token(serde_json::json!({
            "aud": "https://graph.microsoft.com",
            "tid": "tenant-a",
            "exp": 1_800_000_000_u64,
            "scp": GRAPH_DELEGATED_SCOPES.join(" "),
        })),
        Some("tenant-a"),
        "ExpiredToken",
    );
    assert_rejected(
        &unsigned_token(serde_json::json!({
            "aud": "https://graph.microsoft.com",
            "tid": "tenant-b",
            "exp": 2_000_000_000_u64,
            "scp": GRAPH_DELEGATED_SCOPES.join(" "),
        })),
        Some("tenant-a"),
        "TenantMismatch",
    );
}

#[test]
fn graph_identifier_normalization_rejects_non_guid_paths_and_queries() {
    assert_eq!(
        normalize_graph_guid("{D85B3F4E-CB9C-4C40-93B4-407457A31A73}").as_deref(),
        Some("d85b3f4e-cb9c-4c40-93b4-407457a31a73")
    );
    for invalid in [
        "",
        "not-a-guid",
        "../../users",
        "d85b3f4e-cb9c-4c40-93b4-407457a31a73?$select=secret",
        "d85b3f4e-cb9c-4c40-93b4-407457a31a73/assignments",
    ] {
        assert_eq!(normalize_graph_guid(invalid), None, "accepted {invalid:?}");
    }
}

struct FakeGraphTransport {
    responses: Mutex<VecDeque<Result<GraphTransportResponse, GraphTransportFailure>>>,
    requests: Mutex<Vec<(GraphTransportRequest, Duration)>>,
    cancel_after_call: Option<(usize, Arc<AtomicBool>)>,
}

impl FakeGraphTransport {
    fn new(responses: Vec<Result<GraphTransportResponse, GraphTransportFailure>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
            cancel_after_call: None,
        }
    }

    fn cancelling_after(
        responses: Vec<Result<GraphTransportResponse, GraphTransportFailure>>,
        call: usize,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
            cancel_after_call: Some((call, cancelled)),
        }
    }

    fn requests(&self) -> Vec<(GraphTransportRequest, Duration)> {
        self.requests.lock().expect("requests lock").clone()
    }
}

impl GraphTransport for FakeGraphTransport {
    fn execute(
        &self,
        request: &GraphTransportRequest,
        timeout: Duration,
    ) -> Result<GraphTransportResponse, GraphTransportFailure> {
        let call = {
            let mut requests = self.requests.lock().expect("requests lock");
            requests.push((request.clone(), timeout));
            requests.len()
        };
        let response = self
            .responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .expect("fake response");
        if self
            .cancel_after_call
            .as_ref()
            .is_some_and(|(target, _)| call == *target)
        {
            self.cancel_after_call
                .as_ref()
                .expect("cancel target")
                .1
                .store(true, Ordering::SeqCst);
        }
        response
    }
}

#[derive(Default)]
struct FakeGraphCancellation {
    cancelled: Arc<AtomicBool>,
    waits: Mutex<Vec<Duration>>,
    cancel_on_wait: Option<usize>,
}

impl FakeGraphCancellation {
    fn cancelling_during_wait() -> Self {
        Self::cancelling_on_wait(1)
    }

    fn cancelling_on_wait(wait_number: usize) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            waits: Mutex::new(Vec::new()),
            cancel_on_wait: Some(wait_number),
        }
    }
}

impl GraphCancellation for FakeGraphCancellation {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn wait_for_retry(&self, duration: Duration) -> bool {
        let wait_number = {
            let mut waits = self.waits.lock().expect("waits lock");
            waits.push(duration);
            waits.len()
        };
        if self.cancel_on_wait == Some(wait_number) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        !self.is_cancelled()
    }
}

fn graph_response(
    status: u16,
    body: impl Into<Vec<u8>>,
    headers: &[(&str, &str)],
) -> GraphTransportResponse {
    GraphTransportResponse {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect(),
        body: body.into(),
    }
}

fn graph_page(value: serde_json::Value, next_link: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "value": value,
        "@odata.nextLink": next_link,
        "unknownPageField": { "preservedByWire": true },
    }))
    .expect("page JSON")
}

fn graph_batch_request(request_ids: &[&str]) -> GraphTransportRequest {
    let requests: Vec<serde_json::Value> = request_ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            serde_json::json!({
                "id": id,
                "method": "GET",
                "url": format!("/deviceAppManagement/mobileApps/app-{index}"),
            })
        })
        .collect();

    GraphTransportRequest {
        method: GraphHttpMethod::Post,
        url: "https://graph.microsoft.com/beta/$batch".to_string(),
        consistency_level: None,
        content_type: Some("application/json".to_string()),
        body: Some(
            serde_json::to_vec(&serde_json::json!({ "requests": requests }))
                .expect("batch request should serialize"),
        ),
        required_scope: "DeviceManagementApps.Read.All".to_string(),
    }
}

fn graph_batch_response(responses: serde_json::Value) -> GraphTransportResponse {
    graph_response(
        200,
        serde_json::to_vec(&serde_json::json!({ "responses": responses }))
            .expect("batch response should serialize"),
        &[],
    )
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct FakeWireItem {
    id: String,
    state: String,
}

#[test]
fn client_pins_get_contract_and_preserves_unknown_wire_values() {
    let url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,state&$top=100";
    let scope = "DeviceManagementManagedDevices.Read.All";
    let transport = FakeGraphTransport::new(vec![Ok(graph_response(
        200,
        graph_page(
            serde_json::json!([{
                "id": "device-a",
                "state": "futureState",
                "unknownItemField": [1, 2, 3],
            }]),
            None,
        ),
        &[],
    ))]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

    let items = client
        .get_paginated::<FakeWireItem>(url, scope)
        .expect("typed page should load");

    assert_eq!(
        items,
        [FakeWireItem {
            id: "device-a".to_string(),
            state: "futureState".to_string(),
        }]
    );
    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    let (request, timeout) = &requests[0];
    assert_eq!(request.method, GraphHttpMethod::Get);
    assert_eq!(request.url, url);
    assert_eq!(request.consistency_level.as_deref(), Some("eventual"));
    assert_eq!(request.content_type, None);
    assert_eq!(request.body, None);
    assert_eq!(request.required_scope, scope);
    assert_eq!(*timeout, GRAPH_REQUEST_TIMEOUT);
}

#[test]
fn client_maps_auth_http_errors_without_exposing_bodies_or_tokens() {
    let scope = "DeviceManagementApps.Read.All";
    for (status, expected_kind, invalidates_auth) in [
        (401, GraphClientErrorKind::Unauthorized, true),
        (403, GraphClientErrorKind::PermissionDenied, false),
        (404, GraphClientErrorKind::NotFound, false),
    ] {
        let transport = FakeGraphTransport::new(vec![Ok(graph_response(
            status,
            br#"{"error":{"message":"secret-access-token body"}}"#.to_vec(),
            &[("request-id", "request-safe-123")],
        ))]);
        let cancellation = FakeGraphCancellation::default();
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

        let error = client
            .get_paginated::<serde_json::Value>(
                "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps",
                scope,
            )
            .expect_err("status should fail");

        assert_eq!(error.kind, expected_kind);
        assert_eq!(error.status, Some(status));
        assert_eq!(error.request_id.as_deref(), Some("request-safe-123"));
        assert_eq!(error.required_scope, scope);
        assert_eq!(error.invalidates_auth(), invalidates_auth);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("secret-access-token"));
        assert!(!rendered.contains("mobileApps"));
        assert_eq!(transport.requests().len(), 1);
    }
}

#[test]
fn client_retries_429_503_504_with_capped_delay_and_four_attempt_limit() {
    let scope = "DeviceManagementManagedDevices.Read.All";
    let transport = FakeGraphTransport::new(vec![
        Ok(graph_response(429, Vec::new(), &[("Retry-After", "90")])),
        Ok(graph_response(503, Vec::new(), &[])),
        Ok(graph_response(504, Vec::new(), &[])),
        Ok(graph_response(
            200,
            graph_page(serde_json::json!([]), None),
            &[],
        )),
    ]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

    client
        .get_paginated::<serde_json::Value>(
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices",
            scope,
        )
        .expect("fourth attempt should succeed");

    assert_eq!(transport.requests().len(), MAX_GRAPH_ATTEMPTS);
    assert_eq!(
        *cancellation.waits.lock().expect("waits lock"),
        [
            MAX_GRAPH_RETRY_DELAY,
            Duration::from_secs(2),
            Duration::from_secs(4),
        ]
    );

    let exhausted = FakeGraphTransport::new(
        (0..MAX_GRAPH_ATTEMPTS)
            .map(|_| Ok(graph_response(503, Vec::new(), &[])))
            .collect(),
    );
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &exhausted, &cancellation);
    let error = client
        .get_paginated::<serde_json::Value>(
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices",
            scope,
        )
        .expect_err("four retryable responses should exhaust");
    assert_eq!(error.kind, GraphClientErrorKind::RetryExhausted);
    assert_eq!(error.status, Some(503));
    assert_eq!(exhausted.requests().len(), MAX_GRAPH_ATTEMPTS);
    assert_eq!(
        *cancellation.waits.lock().expect("waits lock"),
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
        ]
    );
}

#[test]
fn client_cancels_before_requests_during_retry_and_before_pagination() {
    let scope = "DeviceManagementApps.Read.All";
    let transport = FakeGraphTransport::new(vec![Ok(graph_response(
        200,
        graph_page(serde_json::json!([]), None),
        &[],
    ))]);
    let cancellation = FakeGraphCancellation::default();
    cancellation.cancelled.store(true, Ordering::SeqCst);
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .get_paginated::<serde_json::Value>(
            "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps",
            scope,
        )
        .expect_err("pre-cancelled request should stop");
    assert_eq!(error.kind, GraphClientErrorKind::Cancelled);
    assert!(transport.requests().is_empty());

    let transport = FakeGraphTransport::new(vec![
        Ok(graph_response(429, Vec::new(), &[("retry-after", "1")])),
        Ok(graph_response(
            200,
            graph_page(serde_json::json!([]), None),
            &[],
        )),
    ]);
    let cancellation = FakeGraphCancellation::cancelling_during_wait();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .get_paginated::<serde_json::Value>(
            "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps",
            scope,
        )
        .expect_err("retry wait cancellation should stop");
    assert_eq!(error.kind, GraphClientErrorKind::Cancelled);
    assert_eq!(transport.requests().len(), 1);

    let cancelled = Arc::new(AtomicBool::new(false));
    let transport = FakeGraphTransport::cancelling_after(
        vec![
            Ok(graph_response(
                200,
                graph_page(
                    serde_json::json!([{"id": "app-a"}]),
                    Some("https://graph.microsoft.com/v1.0/next?page=2"),
                ),
                &[],
            )),
            Ok(graph_response(
                200,
                graph_page(serde_json::json!([]), None),
                &[],
            )),
        ],
        1,
        Arc::clone(&cancelled),
    );
    let cancellation = FakeGraphCancellation {
        cancelled,
        ..Default::default()
    };
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .get_paginated::<serde_json::Value>(
            "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps",
            scope,
        )
        .expect_err("pagination cancellation should stop");
    assert_eq!(error.kind, GraphClientErrorKind::Cancelled);
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn client_rejects_untrusted_next_links_and_enforces_page_item_body_caps() {
    let scope = "DeviceManagementApps.Read.All";
    for next_link in [
        "http://graph.microsoft.com/v1.0/next",
        "https://graph.microsoft.com.evil.example/v1.0/next",
        "https://graph.microsoft.com@evil.example/v1.0/next",
    ] {
        let transport = FakeGraphTransport::new(vec![Ok(graph_response(
            200,
            graph_page(serde_json::json!([]), Some(next_link)),
            &[],
        ))]);
        let cancellation = FakeGraphCancellation::default();
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
        let error = client
            .get_paginated::<serde_json::Value>(
                "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps",
                scope,
            )
            .expect_err("untrusted nextLink should fail");
        assert_eq!(error.kind, GraphClientErrorKind::InvalidUrl);
        assert_eq!(transport.requests().len(), 1);
        assert!(!format!("{error:?} {error}").contains("evil.example"));
    }

    let transport = FakeGraphTransport::new(vec![Ok(graph_response(
        200,
        vec![b'x'; MAX_GRAPH_RESPONSE_BYTES + 1],
        &[],
    ))]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .get_paginated::<serde_json::Value>(
            "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps",
            scope,
        )
        .expect_err("oversized body should fail before parsing");
    assert_eq!(error.kind, GraphClientErrorKind::ResponseTooLarge);

    let items = vec![serde_json::json!({"id": "app"}); MAX_GRAPH_ITEMS + 1];
    let transport = FakeGraphTransport::new(vec![Ok(graph_response(
        200,
        graph_page(serde_json::Value::Array(items), None),
        &[],
    ))]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .get_paginated::<serde_json::Value>(
            "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps",
            scope,
        )
        .expect_err("item cap should fail");
    assert_eq!(error.kind, GraphClientErrorKind::ItemLimitExceeded);

    let pages = (0..MAX_GRAPH_PAGES)
        .map(|page| {
            Ok(graph_response(
                200,
                graph_page(
                    serde_json::json!([]),
                    Some(&format!(
                        "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?page={}",
                        page + 2
                    )),
                ),
                &[],
            ))
        })
        .collect();
    let transport = FakeGraphTransport::new(pages);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .get_paginated::<serde_json::Value>(
            "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?page=1",
            scope,
        )
        .expect_err("page cap should fail");
    assert_eq!(error.kind, GraphClientErrorKind::PageLimitExceeded);
    assert_eq!(transport.requests().len(), MAX_GRAPH_PAGES);
}

#[test]
fn client_passes_a_fixed_timeout_and_sanitizes_transport_failures() {
    let transport = FakeGraphTransport::new(vec![Err(GraphTransportFailure::Timeout)]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .get_paginated::<serde_json::Value>(
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?secret=token",
            "DeviceManagementManagedDevices.Read.All",
        )
        .expect_err("timeout should fail");

    assert_eq!(error.kind, GraphClientErrorKind::Timeout);
    assert_eq!(error.status, None);
    assert_eq!(transport.requests()[0].1, GRAPH_REQUEST_TIMEOUT);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("secret=token"));
}

#[test]
fn client_executes_bounded_single_json_requests() {
    let scope = "DeviceManagementApps.Read.All";
    let transport = FakeGraphTransport::new(vec![Ok(graph_response(
        200,
        serde_json::to_vec(&serde_json::json!({
            "id": "app-a",
            "displayName": "Contoso App"
        }))
        .expect("single response should serialize"),
        &[("request-id", "single-request")],
    ))]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

    let single: serde_json::Value = client
        .request_json(GraphTransportRequest {
            method: GraphHttpMethod::Get,
            url: "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/app-a?$select=id,displayName".to_string(),
            consistency_level: None,
            content_type: None,
            body: None,
            required_scope: scope.to_string(),
        })
        .expect("single-item request should use the bounded client");
    assert_eq!(single["id"], "app-a");

    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0.method, GraphHttpMethod::Get);
    assert_eq!(requests[0].1, GRAPH_REQUEST_TIMEOUT);
}

#[test]
fn client_rejects_non_read_request_shapes_before_transport() {
    let requests = [
        GraphTransportRequest {
            method: GraphHttpMethod::Post,
            url: "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps".to_string(),
            consistency_level: None,
            content_type: Some("application/json".to_string()),
            body: Some(b"{}".to_vec()),
            required_scope: "DeviceManagementApps.Read.All".to_string(),
        },
        GraphTransportRequest {
            method: GraphHttpMethod::Post,
            url: "https://graph.microsoft.com/beta/$batch".to_string(),
            consistency_level: None,
            content_type: Some("application/json".to_string()),
            body: Some(b"{}".to_vec()),
            required_scope: "DeviceManagementApps.Read.All".to_string(),
        },
        GraphTransportRequest {
            method: GraphHttpMethod::Get,
            url: "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps".to_string(),
            consistency_level: None,
            content_type: Some("application/json".to_string()),
            body: Some(b"{}".to_vec()),
            required_scope: "DeviceManagementApps.Read.All".to_string(),
        },
    ];

    for request in requests {
        let transport = FakeGraphTransport::new(vec![Ok(graph_response(200, b"{}".to_vec(), &[]))]);
        let cancellation = FakeGraphCancellation::default();
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

        let error = client
            .request_json::<serde_json::Value>(request)
            .expect_err("generic JSON reads must reject writes and request bodies");

        assert_eq!(error.kind, GraphClientErrorKind::InvalidResponse);
        assert!(transport.requests().is_empty());
    }
}

#[test]
fn client_batch_inner_401_marks_auth_for_invalidation_without_body_leakage() {
    let transport = FakeGraphTransport::new(vec![
        Ok(graph_batch_response(serde_json::json!([
            {
                "id": "0",
                "status": 429,
                "headers": { "retry-after": "1" },
            },
            {
                "id": "1",
                "status": 401,
                "headers": { "request-id": "inner-request-safe" },
                "body": { "error": { "message": "secret-access-token body" } },
            }
        ]))),
        Ok(graph_batch_response(serde_json::json!([{
            "id": "0",
            "status": 200,
            "body": { "id": "should-not-be-requested" },
        }]))),
    ]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

    let error = client
        .request_batch_json::<serde_json::Value>(graph_batch_request(&["0", "1"]))
        .expect_err("inner 401 should fail the batch");

    assert_eq!(error.kind, GraphClientErrorKind::Unauthorized);
    assert_eq!(error.status, Some(401));
    assert_eq!(error.request_id.as_deref(), Some("inner-request-safe"));
    assert_eq!(error.required_scope, "DeviceManagementApps.Read.All");
    assert!(error.invalidates_auth());
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("secret-access-token"));
    assert!(!rendered.contains("mobileApps"));
    assert_eq!(transport.requests().len(), 1);
    assert!(cancellation.waits.lock().expect("waits lock").is_empty());
}

#[test]
fn client_batch_inner_403_is_scope_aware_and_sanitizes_request_ids() {
    for (request_id, expected_request_id) in [
        ("safe.request-id_403", Some("safe.request-id_403")),
        ("unsafe request id secret", None),
    ] {
        let transport =
            FakeGraphTransport::new(vec![Ok(graph_batch_response(serde_json::json!([{
                "id": "0",
                "status": 403,
                "headers": { "request-id": request_id },
                "body": { "error": { "message": "secret-forbidden-body" } },
            }])))]);
        let cancellation = FakeGraphCancellation::default();
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

        let error = client
            .request_batch_json::<serde_json::Value>(graph_batch_request(&["0"]))
            .expect_err("inner 403 should fail the batch");

        assert_eq!(error.kind, GraphClientErrorKind::PermissionDenied);
        assert_eq!(error.status, Some(403));
        assert_eq!(error.request_id.as_deref(), expected_request_id);
        assert_eq!(error.required_scope, "DeviceManagementApps.Read.All");
        assert!(!error.invalidates_auth());
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("secret-forbidden-body"));
        if expected_request_id.is_none() {
            assert!(!rendered.contains("unsafe request id"));
        }
    }
}

#[test]
fn client_batch_allows_only_batch_post_with_nested_gets() {
    let transport = FakeGraphTransport::new(vec![Ok(graph_batch_response(serde_json::json!([{
        "id": "0",
        "status": 404,
    }])))]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let mut wrong_endpoint = graph_batch_request(&["0"]);
    wrong_endpoint.url =
        "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps".to_string();

    let error = client
        .request_batch_json::<serde_json::Value>(wrong_endpoint)
        .expect_err("batch-shaped POST must not target a non-batch Graph endpoint");
    assert_eq!(error.kind, GraphClientErrorKind::InvalidUrl);
    assert!(transport.requests().is_empty());

    let transport = FakeGraphTransport::new(Vec::new());
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let mut write_request = graph_batch_request(&["0"]);
    let mut body: serde_json::Value =
        serde_json::from_slice(write_request.body.as_deref().expect("batch request body"))
            .expect("batch request JSON");
    body["requests"][0]["method"] = serde_json::Value::String("DELETE".to_string());
    write_request.body = Some(serde_json::to_vec(&body).expect("write request should serialize"));

    let error = client
        .request_batch_json::<serde_json::Value>(write_request)
        .expect_err("nested Graph writes must be rejected before transport");
    assert_eq!(error.kind, GraphClientErrorKind::InvalidResponse);
    assert!(transport.requests().is_empty());
}

#[test]
fn client_batch_retries_only_the_throttled_item_with_bounded_retry_after() {
    let transport = FakeGraphTransport::new(vec![
        Ok(graph_batch_response(serde_json::json!([
            {
                "id": "0",
                "status": 200,
                "body": { "id": "app-a", "displayName": "App A" },
            },
            {
                "id": "1",
                "status": 429,
                "headers": { "Retry-After": "90" },
                "body": { "error": { "message": "throttled-secret" } },
            }
        ]))),
        Ok(graph_batch_response(serde_json::json!([{
            "id": "1",
            "status": 503,
            "body": { "error": { "message": "unavailable-secret" } },
        }]))),
        Ok(graph_batch_response(serde_json::json!([{
            "id": "1",
            "status": 504,
            "headers": { "retry-after": "3" },
            "body": { "error": { "message": "timeout-secret" } },
        }]))),
        Ok(graph_batch_response(serde_json::json!([{
            "id": "1",
            "status": 200,
            "body": { "id": "app-b", "displayName": "App B" },
        }]))),
    ]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

    let outcomes = client
        .request_batch_json::<serde_json::Value>(graph_batch_request(&["0", "1"]))
        .expect("fourth item attempt should succeed");

    assert_eq!(outcomes.len(), 2);
    assert!(matches!(
        &outcomes[0],
        GraphBatchItem::Success(body) if body["id"] == "app-a"
    ));
    assert!(matches!(
        &outcomes[1],
        GraphBatchItem::Success(body) if body["id"] == "app-b"
    ));
    let debug_body = format!(
        "{:?}",
        GraphBatchItem::Success(serde_json::json!({ "secret": "debug-secret-body" }))
    );
    assert!(!debug_body.contains("debug-secret-body"));
    assert_eq!(transport.requests().len(), MAX_GRAPH_ATTEMPTS);
    assert_eq!(
        *cancellation.waits.lock().expect("waits lock"),
        [
            MAX_GRAPH_RETRY_DELAY,
            Duration::from_secs(2),
            Duration::from_secs(3),
        ]
    );

    let requests = transport.requests();
    let initial_body: serde_json::Value =
        serde_json::from_slice(requests[0].0.body.as_deref().expect("initial batch body"))
            .expect("initial batch JSON");
    assert_eq!(initial_body["requests"].as_array().map(Vec::len), Some(2));
    for (request, timeout) in requests.iter().skip(1) {
        assert_eq!(request.method, GraphHttpMethod::Post);
        assert_eq!(*timeout, GRAPH_REQUEST_TIMEOUT);
        let body: serde_json::Value =
            serde_json::from_slice(request.body.as_deref().expect("retry batch body"))
                .expect("retry batch JSON");
        assert_eq!(body["requests"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["requests"][0]["id"], "1");
        assert_eq!(body["requests"][0]["method"], "GET");
    }
}

#[test]
fn client_batch_retry_exhaustion_and_wait_cancellation_are_bounded() {
    let exhausted = FakeGraphTransport::new(
        (0..MAX_GRAPH_ATTEMPTS)
            .map(|_| {
                Ok(graph_batch_response(serde_json::json!([{
                    "id": "0",
                    "status": 503,
                    "body": { "error": { "message": "retry-secret" } },
                }])))
            })
            .collect(),
    );
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &exhausted, &cancellation);
    let error = client
        .request_batch_json::<serde_json::Value>(graph_batch_request(&["0"]))
        .expect_err("four retryable item responses should exhaust");
    assert_eq!(error.kind, GraphClientErrorKind::RetryExhausted);
    assert_eq!(error.status, Some(503));
    assert_eq!(exhausted.requests().len(), MAX_GRAPH_ATTEMPTS);
    assert_eq!(
        *cancellation.waits.lock().expect("waits lock"),
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
        ]
    );
    assert!(!format!("{error:?} {error}").contains("retry-secret"));

    let cancelled_transport =
        FakeGraphTransport::new(vec![Ok(graph_batch_response(serde_json::json!([{
            "id": "0",
            "status": 429,
            "headers": { "retry-after": "5" },
            "body": { "error": { "message": "cancel-secret" } },
        }])))]);
    let cancellation = FakeGraphCancellation::cancelling_during_wait();
    let client = GraphClient::new("graph.microsoft.com", &cancelled_transport, &cancellation);
    let error = client
        .request_batch_json::<serde_json::Value>(graph_batch_request(&["0"]))
        .expect_err("cancelled item retry wait should stop");
    assert_eq!(error.kind, GraphClientErrorKind::Cancelled);
    assert_eq!(cancelled_transport.requests().len(), 1);
    assert_eq!(
        *cancellation.waits.lock().expect("waits lock"),
        [Duration::from_secs(5)]
    );
    assert!(!format!("{error:?} {error}").contains("cancel-secret"));
}

#[test]
fn client_batch_mixed_retry_sequence_that_previously_used_thirteen_calls_is_capped_at_four() {
    let mut responses = vec![Ok(graph_batch_response(serde_json::json!([{
        "id": "0",
        "status": 429,
    }])))];
    for _ in 0..3 {
        responses.extend([
            Ok(graph_response(503, Vec::new(), &[])),
            Ok(graph_response(503, Vec::new(), &[])),
            Ok(graph_response(503, Vec::new(), &[])),
            Ok(graph_batch_response(serde_json::json!([{
                "id": "0",
                "status": 429,
            }]))),
        ]);
    }
    assert_eq!(
        responses.len(),
        13,
        "fixture must model the old amplification"
    );

    let transport = FakeGraphTransport::new(responses);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .request_batch_json::<serde_json::Value>(graph_batch_request(&["0"]))
        .expect_err("one logical item must exhaust after four physical attempts");

    assert_eq!(error.kind, GraphClientErrorKind::RetryExhausted);
    assert_eq!(error.status, Some(503));
    assert_eq!(transport.requests().len(), MAX_GRAPH_ATTEMPTS);
    assert_eq!(
        *cancellation.waits.lock().expect("waits lock"),
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
        ]
    );
}

#[test]
fn client_batch_mixed_retry_sequence_that_previously_used_sixteen_calls_is_capped_at_four() {
    let mut responses = Vec::new();
    for _ in 0..4 {
        responses.extend([
            Ok(graph_response(503, Vec::new(), &[])),
            Ok(graph_response(503, Vec::new(), &[])),
            Ok(graph_response(503, Vec::new(), &[])),
            Ok(graph_batch_response(serde_json::json!([{
                "id": "0",
                "status": 429,
            }]))),
        ]);
    }
    assert_eq!(
        responses.len(),
        16,
        "fixture must model the old amplification"
    );

    let transport = FakeGraphTransport::new(responses);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .request_batch_json::<serde_json::Value>(graph_batch_request(&["0"]))
        .expect_err("initial outer retries must debit the item's shared budget");

    assert_eq!(error.kind, GraphClientErrorKind::RetryExhausted);
    assert_eq!(error.status, Some(429));
    assert_eq!(transport.requests().len(), MAX_GRAPH_ATTEMPTS);
    assert_eq!(
        *cancellation.waits.lock().expect("waits lock"),
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
        ]
    );
}

#[test]
fn client_batch_mixed_outer_retry_cancels_on_the_shared_second_wait() {
    let transport = FakeGraphTransport::new(vec![
        Ok(graph_batch_response(serde_json::json!([{
            "id": "0",
            "status": 429,
        }]))),
        Ok(graph_response(503, Vec::new(), &[])),
        Ok(graph_batch_response(serde_json::json!([{
            "id": "0",
            "status": 200,
            "body": { "id": "must-not-be-requested" },
        }]))),
    ]);
    let cancellation = FakeGraphCancellation::cancelling_on_wait(2);
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .request_batch_json::<serde_json::Value>(graph_batch_request(&["0"]))
        .expect_err("cancellation must interrupt the mixed-status retry boundary");

    assert_eq!(error.kind, GraphClientErrorKind::Cancelled);
    assert_eq!(transport.requests().len(), 2);
    assert_eq!(
        *cancellation.waits.lock().expect("waits lock"),
        [Duration::from_secs(1), Duration::from_secs(2)]
    );
}

#[test]
fn client_batch_inner_401_after_outer_retry_uses_shared_budget_and_stops() {
    let transport = FakeGraphTransport::new(vec![
        Ok(graph_batch_response(serde_json::json!([{
            "id": "0",
            "status": 429,
        }]))),
        Ok(graph_response(503, Vec::new(), &[])),
        Ok(graph_batch_response(serde_json::json!([{
            "id": "0",
            "status": 401,
            "headers": { "request-id": "mixed-auth-request" },
            "body": { "error": { "message": "mixed-auth-secret" } },
        }]))),
        Ok(graph_batch_response(serde_json::json!([{
            "id": "0",
            "status": 200,
            "body": { "id": "must-not-be-requested" },
        }]))),
    ]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .request_batch_json::<serde_json::Value>(graph_batch_request(&["0"]))
        .expect_err("inner 401 must terminate the mixed retry sequence");

    assert_eq!(error.kind, GraphClientErrorKind::Unauthorized);
    assert_eq!(error.status, Some(401));
    assert_eq!(error.request_id.as_deref(), Some("mixed-auth-request"));
    assert!(error.invalidates_auth());
    assert_eq!(transport.requests().len(), 3);
    assert_eq!(
        *cancellation.waits.lock().expect("waits lock"),
        [Duration::from_secs(1), Duration::from_secs(2)]
    );
    assert!(!format!("{error:?} {error}").contains("mixed-auth-secret"));
}

#[test]
fn client_batch_inner_401_preempts_exhausted_sibling_after_initial_outer_retries() {
    let transport = FakeGraphTransport::new(vec![
        Ok(graph_response(503, Vec::new(), &[])),
        Ok(graph_response(503, Vec::new(), &[])),
        Ok(graph_response(503, Vec::new(), &[])),
        Ok(graph_batch_response(serde_json::json!([
            {
                "id": "0",
                "status": 429,
                "body": { "error": { "message": "exhausted-secret" } },
            },
            {
                "id": "1",
                "status": 401,
                "headers": { "request-id": "preempted-auth-request" },
                "body": { "error": { "message": "auth-secret" } },
            }
        ]))),
    ]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let error = client
        .request_batch_json::<serde_json::Value>(graph_batch_request(&["0", "1"]))
        .expect_err("inner 401 must remain authoritative after outer retries");

    assert_eq!(error.kind, GraphClientErrorKind::Unauthorized);
    assert_eq!(error.status, Some(401));
    assert_eq!(error.request_id.as_deref(), Some("preempted-auth-request"));
    assert!(error.invalidates_auth());
    assert_eq!(transport.requests().len(), MAX_GRAPH_ATTEMPTS);
    assert_eq!(
        *cancellation.waits.lock().expect("waits lock"),
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
        ]
    );
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("exhausted-secret"));
    assert!(!rendered.contains("auth-secret"));
}

#[test]
fn client_batch_rejects_malformed_duplicate_and_missing_response_ids_body_free() {
    let cases = vec![
        (
            "malformed",
            vec!["0"],
            serde_json::json!([{
                "id": 0,
                "status": 500,
                "body": { "error": { "message": "malformed-secret" } },
            }]),
        ),
        (
            "duplicate",
            vec!["0", "1"],
            serde_json::json!([
                {
                    "id": "0",
                    "status": 200,
                    "body": { "id": "duplicate-secret-a" },
                },
                {
                    "id": "0",
                    "status": 200,
                    "body": { "id": "duplicate-secret-b" },
                }
            ]),
        ),
        (
            "missing",
            vec!["0", "1"],
            serde_json::json!([{
                "id": "0",
                "status": 200,
                "body": { "id": "missing-secret" },
            }]),
        ),
    ];

    for (label, request_ids, responses) in cases {
        let transport = FakeGraphTransport::new(vec![Ok(graph_batch_response(responses))]);
        let cancellation = FakeGraphCancellation::default();
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

        let error = client
            .request_batch_json::<serde_json::Value>(graph_batch_request(&request_ids))
            .expect_err(label);

        assert_eq!(error.kind, GraphClientErrorKind::InvalidResponse, "{label}");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("secret"), "{label}: {rendered}");
        assert_eq!(transport.requests().len(), 1, "{label}");
    }
}

#[test]
fn oversized_outer_401_still_invalidates_auth_without_weakening_body_cap() {
    let mut oversized_body = b"secret-outer-401-body".to_vec();
    oversized_body.resize(MAX_GRAPH_RESPONSE_BYTES + 1, b'x');
    let transport = FakeGraphTransport::new(vec![Ok(graph_response(
        401,
        oversized_body,
        &[("request-id", "oversized-401-request")],
    ))]);
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

    let error = client
        .request_json::<serde_json::Value>(GraphTransportRequest {
            method: GraphHttpMethod::Get,
            url: "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/app-a"
                .to_string(),
            consistency_level: None,
            content_type: None,
            body: None,
            required_scope: "DeviceManagementApps.Read.All".to_string(),
        })
        .expect_err("oversized outer 401 should fail before parsing");

    assert_eq!(error.kind, GraphClientErrorKind::ResponseTooLarge);
    assert_eq!(error.status, Some(401));
    assert!(error.invalidates_auth());
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("secret-outer-401-body"));
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn client_error_controls_single_item_fallback_without_restarting_retryable_work() {
    fn request_error(
        responses: Vec<Result<GraphTransportResponse, GraphTransportFailure>>,
    ) -> GraphClientError {
        let transport = FakeGraphTransport::new(responses);
        let cancellation = FakeGraphCancellation::default();
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
        client
            .request_json::<serde_json::Value>(GraphTransportRequest {
                method: GraphHttpMethod::Get,
                url: "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/app-a"
                    .to_string(),
                consistency_level: None,
                content_type: None,
                body: None,
                required_scope: "DeviceManagementApps.Read.All".to_string(),
            })
            .expect_err("fixture must return an error")
    }

    let retry_exhausted = request_error(
        (0..MAX_GRAPH_ATTEMPTS)
            .map(|_| Ok(graph_response(503, Vec::new(), &[])))
            .collect(),
    );
    assert_eq!(retry_exhausted.kind, GraphClientErrorKind::RetryExhausted);
    assert!(!retry_exhausted.allows_single_item_fallback());

    let permission_denied = request_error(vec![Ok(graph_response(403, Vec::new(), &[]))]);
    assert_eq!(
        permission_denied.kind,
        GraphClientErrorKind::PermissionDenied
    );
    assert!(!permission_denied.allows_single_item_fallback());

    let mut oversized_forbidden = vec![b'x'; MAX_GRAPH_RESPONSE_BYTES + 1];
    oversized_forbidden[..3].copy_from_slice(b"403");
    let oversized_forbidden =
        request_error(vec![Ok(graph_response(403, oversized_forbidden, &[]))]);
    assert_eq!(
        oversized_forbidden.kind,
        GraphClientErrorKind::ResponseTooLarge
    );
    assert!(!oversized_forbidden.allows_single_item_fallback());

    let transport_failure = request_error(vec![Err(GraphTransportFailure::Network)]);
    assert_eq!(transport_failure.kind, GraphClientErrorKind::Transport);
    assert!(!transport_failure.allows_single_item_fallback());

    let invalid_response = request_error(vec![Ok(graph_response(200, b"{".to_vec(), &[]))]);
    assert_eq!(invalid_response.kind, GraphClientErrorKind::InvalidResponse);
    assert!(invalid_response.allows_single_item_fallback());

    let missing_batch_endpoint = request_error(vec![Ok(graph_response(404, Vec::new(), &[]))]);
    assert_eq!(missing_batch_endpoint.kind, GraphClientErrorKind::NotFound);
    assert!(missing_batch_endpoint.allows_single_item_fallback());

    let batch_specific_http_failure = request_error(vec![Ok(graph_response(500, Vec::new(), &[]))]);
    assert_eq!(
        batch_specific_http_failure.kind,
        GraphClientErrorKind::HttpStatus
    );
    assert!(batch_specific_http_failure.allows_single_item_fallback());
}
