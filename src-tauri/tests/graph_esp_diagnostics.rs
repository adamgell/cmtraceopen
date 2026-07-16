use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use app_lib::graph_api::client::{
    resolve_app_chunk_with_fallback, GraphBatchItem, GraphCancellation, GraphClient,
    GraphClientError, GraphClientErrorKind, GraphTransport, GraphTransportFailure,
    GRAPH_REQUEST_TIMEOUT, MAX_GRAPH_ATTEMPTS, MAX_GRAPH_ITEMS, MAX_GRAPH_PAGES,
    MAX_GRAPH_RESPONSE_BYTES, MAX_GRAPH_RETRY_DELAY,
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
fn client_cancels_after_final_in_flight_response() {
    let scope = "DeviceManagementApps.Read.All";
    let cancelled = Arc::new(AtomicBool::new(false));
    let transport = FakeGraphTransport::cancelling_after(
        vec![Ok(graph_response(
            200,
            graph_page(serde_json::json!([]), None),
            &[],
        ))],
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
        .expect_err("final in-flight cancellation should stop");

    assert_eq!(error.kind, GraphClientErrorKind::Cancelled);
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn client_cancellation_wins_after_in_flight_network_failure() {
    let scope = "DeviceManagementApps.Read.All";
    let cancelled = Arc::new(AtomicBool::new(false));
    let transport = FakeGraphTransport::cancelling_after(
        vec![Err(GraphTransportFailure::Network)],
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
        .expect_err("in-flight cancellation must win over a network failure");

    assert_eq!(error.kind, GraphClientErrorKind::Cancelled);
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn client_cancellation_wins_after_in_flight_timeout() {
    let scope = "DeviceManagementApps.Read.All";
    let cancelled = Arc::new(AtomicBool::new(false));
    let transport = FakeGraphTransport::cancelling_after(
        vec![Err(GraphTransportFailure::Timeout)],
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
        .expect_err("in-flight cancellation must win over a timeout");

    assert_eq!(error.kind, GraphClientErrorKind::Cancelled);
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn client_post_transport_cancellation_suppresses_retries_but_preserves_401_invalidation() {
    let scope = "DeviceManagementApps.Read.All";
    let cases = vec![
        (
            "200",
            Ok(graph_response(
                200,
                graph_page(serde_json::json!([]), None),
                &[],
            )),
            false,
        ),
        (
            "401",
            Ok(graph_response(
                401,
                br#"{"error":{"message":"secret-response-body"}}"#.to_vec(),
                &[("request-id", "request-safe-401")],
            )),
            true,
        ),
        (
            "403",
            Ok(graph_response(
                403,
                br#"{"error":{"message":"secret-response-body"}}"#.to_vec(),
                &[],
            )),
            false,
        ),
        (
            "429",
            Ok(graph_response(
                429,
                br#"{"error":{"message":"secret-response-body"}}"#.to_vec(),
                &[("retry-after", "1")],
            )),
            false,
        ),
        (
            "503",
            Ok(graph_response(
                503,
                br#"{"error":{"message":"secret-response-body"}}"#.to_vec(),
                &[],
            )),
            false,
        ),
        ("network", Err(GraphTransportFailure::Network), false),
        ("timeout", Err(GraphTransportFailure::Timeout), false),
    ];

    for (label, response, invalidates_auth) in cases {
        let cancelled = Arc::new(AtomicBool::new(false));
        let transport =
            FakeGraphTransport::cancelling_after(vec![response], 1, Arc::clone(&cancelled));
        let cancellation = FakeGraphCancellation {
            cancelled,
            ..Default::default()
        };
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);

        let error = client
            .get_paginated::<serde_json::Value>(
                "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?secret=query",
                scope,
            )
            .expect_err("post-transport cancellation must win");

        assert_eq!(error.kind, GraphClientErrorKind::Cancelled, "{label}");
        assert_eq!(error.invalidates_auth(), invalidates_auth, "{label}");
        assert_eq!(error.status, invalidates_auth.then_some(401), "{label}");
        assert_eq!(
            error.request_id.as_deref(),
            invalidates_auth.then_some("request-safe-401"),
            "{label}"
        );
        assert_eq!(transport.requests().len(), 1, "{label} retried");
        assert!(
            cancellation.waits.lock().expect("waits lock").is_empty(),
            "{label} entered retry wait"
        );
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("secret-response-body"), "{label}");
        assert!(!rendered.contains("secret=query"), "{label}");
    }
}

#[test]
fn client_rejects_untrusted_next_links_and_enforces_page_item_body_caps() {
    let scope = "DeviceManagementApps.Read.All";
    for next_link in [
        "http://graph.microsoft.com/v1.0/next",
        "https://graph.microsoft.com.evil.example/v1.0/next",
        "https://graph.microsoft.com@evil.example/v1.0/next",
        "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$skiptoken=version-switch",
        "https://graph.microsoft.com/v1.0/users?$skiptoken=resource-switch",
        "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/../users?$skiptoken=traversal",
        "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/%2e%2e/users?$skiptoken=encoded",
    ] {
        let transport = FakeGraphTransport::new(vec![
            Ok(graph_response(
                200,
                graph_page(serde_json::json!([]), Some(next_link)),
                &[],
            )),
            Ok(graph_response(
                200,
                graph_page(serde_json::json!([]), None),
                &[],
            )),
        ]);
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

#[test]
fn resolver_caller_does_not_restart_exhausted_batch_work_as_single_reads() {
    let transport = FakeGraphTransport::new(
        (0..MAX_GRAPH_ATTEMPTS)
            .map(|_| Ok(graph_response(503, Vec::new(), &[])))
            .collect(),
    );
    let cancellation = FakeGraphCancellation::default();
    let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
    let guids = vec!["d85b3f4e-cb9c-4c40-93b4-407457a31a73".to_string()];
    let single_calls = Cell::new(0);

    let result = resolve_app_chunk_with_fallback(
        &guids,
        |_| {
            client
                .request_batch_json::<serde_json::Value>(graph_batch_request(&["0"]))
                .map(|_| GraphResolutionResult {
                    resolved: Default::default(),
                    not_found: Vec::new(),
                    errors: Vec::new(),
                })
        },
        |_| {
            single_calls.set(single_calls.get() + 1);
            Ok(None)
        },
    )
    .expect("retry exhaustion should remain a non-auth resolution error");

    assert_eq!(transport.requests().len(), MAX_GRAPH_ATTEMPTS);
    assert_eq!(single_calls.get(), 0);
    assert!(result.resolved.is_empty());
    assert!(result.not_found.is_empty());
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].contains("RetryExhausted"));
}

#[test]
fn resolver_caller_falls_back_for_malformed_batches_and_preserves_results() {
    let first_guid = "d85b3f4e-cb9c-4c40-93b4-407457a31a73".to_string();
    let second_guid = "97b7a3e5-f25b-4ba0-9c25-702e1e845dc7".to_string();
    let guids = vec![first_guid.clone(), second_guid.clone()];
    let single_calls = Cell::new(0);

    let result = resolve_app_chunk_with_fallback(
        &guids,
        |_| {
            Err(GraphClientError {
                kind: GraphClientErrorKind::InvalidResponse,
                status: Some(200),
                request_id: None,
                required_scope: "DeviceManagementApps.Read.All".to_string(),
            })
        },
        |guid| {
            single_calls.set(single_calls.get() + 1);
            if guid == first_guid {
                Ok(Some(GraphAppInfo {
                    id: guid.to_string(),
                    display_name: "Contoso App".to_string(),
                    publisher: None,
                    odata_type: Some("#microsoft.graph.win32LobApp".to_string()),
                }))
            } else {
                Ok(None)
            }
        },
    )
    .expect("malformed batches should use bounded single-item fallback");

    assert_eq!(single_calls.get(), 2);
    assert_eq!(result.resolved[&first_guid].display_name, "Contoso App");
    assert_eq!(result.not_found, vec![second_guid]);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].contains("InvalidResponse"));
}

#[cfg(feature = "esp-diagnostics")]
mod esp_correlation_tests {
    use app_lib::graph_api::correlation::correlate_managed_device;
    use cmtraceopen_parser::esp::{
        EspClassifiedString, EspCorrelationConfidence, EspEvidenceRef, EspGraphManagedDevice,
        EspIdentityEvidence, EspSensitivity,
    };

    const LOCAL_MANAGED: &str = "8c5a1ea3-bd82-454c-a19c-45dffcb10ef8";
    const LOCAL_ENTRA: &str = "cf016a06-56ea-4f34-a7a7-8d744fa14b87";
    const OTHER_MANAGED: &str = "6122aaff-6736-4ccf-b0fe-82932dd076f0";
    const OTHER_ENTRA: &str = "c7fde315-1d29-489f-a880-3d781f54c6e3";

    fn classified(value: &str) -> EspClassifiedString {
        EspClassifiedString {
            value: value.to_string(),
            sensitivity: EspSensitivity::Sensitive,
        }
    }

    fn evidence(id: &str) -> EspEvidenceRef {
        EspEvidenceRef {
            evidence_id: id.to_string(),
            source_artifact_id: "graph".to_string(),
        }
    }

    fn identity() -> EspIdentityEvidence {
        EspIdentityEvidence {
            device_name: Some("DEVICE-01".to_string()),
            managed_device_id: Some(LOCAL_MANAGED.to_uppercase()),
            entra_device_id: Some(LOCAL_ENTRA.to_uppercase()),
            entdm_id: None,
            tenant_id: Some(classified("tenant-a")),
            tenant_domain: None,
            user_principal_name: Some(classified("User@Contoso.example")),
            serial_number: Some(classified("SERIAL-001")),
            evidence: vec![evidence("local-identity")],
        }
    }

    fn candidate(
        managed_id: &str,
        entra_id: &str,
        serial: &str,
        name: &str,
        tenant: Option<&str>,
        upn: Option<&str>,
    ) -> EspGraphManagedDevice {
        EspGraphManagedDevice {
            managed_device_id: managed_id.to_string(),
            entra_device_id: Some(entra_id.to_string()),
            serial_number: Some(classified(serial)),
            device_name: Some(name.to_string()),
            user_id: Some("b63ca3f8-cd07-4ef5-824f-1f923df54ea7".to_string()),
            user_principal_name: upn.map(classified),
            tenant_id: tenant.map(classified),
            evidence: vec![evidence(managed_id)],
        }
    }

    #[test]
    fn correlation_explicit_managed_device_selection_has_highest_priority() {
        let by_local_managed = candidate(
            LOCAL_MANAGED,
            OTHER_ENTRA,
            "OTHER-SERIAL",
            "OTHER",
            None,
            None,
        );
        let explicitly_selected = candidate(
            OTHER_MANAGED,
            LOCAL_ENTRA,
            "SERIAL-001",
            "DEVICE-01",
            Some("tenant-a"),
            Some("user@contoso.example"),
        );

        let matched = correlate_managed_device(
            &identity(),
            Some(OTHER_MANAGED),
            vec![by_local_managed, explicitly_selected],
        );

        assert_eq!(
            matched
                .selected
                .as_ref()
                .map(|item| item.managed_device_id.as_str()),
            Some(OTHER_MANAGED)
        );
        assert_eq!(
            matched.match_basis.as_deref(),
            Some("selectedManagedDeviceId")
        );
        assert_eq!(matched.confidence, EspCorrelationConfidence::Exact);
    }

    #[test]
    fn correlation_unmatched_explicit_selection_never_falls_through_to_local_identity() {
        let locally_matching = candidate(
            LOCAL_MANAGED,
            LOCAL_ENTRA,
            "SERIAL-001",
            "DEVICE-01",
            Some("tenant-a"),
            Some("user@contoso.example"),
        );

        let matched =
            correlate_managed_device(&identity(), Some(OTHER_MANAGED), vec![locally_matching]);

        assert!(matched.selected.is_none());
        assert_eq!(matched.candidates.len(), 1);
        assert_eq!(
            matched.match_basis.as_deref(),
            Some("selectedManagedDeviceId")
        );
        assert_eq!(matched.confidence, EspCorrelationConfidence::Uncorrelated);
    }

    #[test]
    fn correlation_priority_is_managed_then_entra_then_serial() {
        let local_managed = candidate(
            LOCAL_MANAGED,
            OTHER_ENTRA,
            "OTHER-SERIAL",
            "OTHER",
            None,
            None,
        );
        let entra = candidate(
            OTHER_MANAGED,
            LOCAL_ENTRA,
            "SERIAL-001",
            "DEVICE-01",
            Some("tenant-a"),
            Some("user@contoso.example"),
        );
        let matched = correlate_managed_device(&identity(), None, vec![entra, local_managed]);
        assert_eq!(
            matched
                .selected
                .as_ref()
                .map(|item| item.managed_device_id.as_str()),
            Some(LOCAL_MANAGED)
        );
        assert_eq!(matched.match_basis.as_deref(), Some("managedDeviceId"));

        let mut without_managed = identity();
        without_managed.managed_device_id = None;
        let entra = candidate(
            OTHER_MANAGED,
            LOCAL_ENTRA,
            "OTHER-SERIAL",
            "OTHER",
            None,
            None,
        );
        let serial = candidate(
            LOCAL_MANAGED,
            OTHER_ENTRA,
            "SERIAL-001",
            "DEVICE-01",
            Some("tenant-a"),
            Some("user@contoso.example"),
        );
        let matched = correlate_managed_device(&without_managed, None, vec![serial, entra]);
        assert_eq!(
            matched
                .selected
                .as_ref()
                .map(|item| item.managed_device_id.as_str()),
            Some(OTHER_MANAGED)
        );
        assert_eq!(matched.match_basis.as_deref(), Some("entraDeviceId"));
    }

    #[test]
    fn correlation_never_accepts_hostname_without_matching_tenant_or_user_evidence() {
        let mut weak_identity = identity();
        weak_identity.managed_device_id = None;
        weak_identity.entra_device_id = None;
        weak_identity.serial_number = None;
        let name_only = candidate(
            OTHER_MANAGED,
            OTHER_ENTRA,
            "OTHER",
            "device-01",
            Some("tenant-b"),
            Some("other@contoso.example"),
        );

        let matched = correlate_managed_device(&weak_identity, None, vec![name_only]);
        assert!(matched.selected.is_none());
        assert!(matched.candidates.is_empty());
        assert_eq!(matched.match_basis, None);
        assert_eq!(matched.confidence, EspCorrelationConfidence::Uncorrelated);
    }

    #[test]
    fn correlation_multiple_weak_candidates_are_ambiguous_and_stop_selection() {
        let mut weak_identity = identity();
        weak_identity.managed_device_id = None;
        weak_identity.entra_device_id = None;
        weak_identity.serial_number = None;
        let first = candidate(
            LOCAL_MANAGED,
            LOCAL_ENTRA,
            "FIRST",
            "device-01",
            None,
            Some("user@contoso.example"),
        );
        let second = candidate(
            OTHER_MANAGED,
            OTHER_ENTRA,
            "SECOND",
            "DEVICE-01",
            Some("TENANT-A"),
            None,
        );

        let matched = correlate_managed_device(&weak_identity, None, vec![second, first]);
        assert!(matched.selected.is_none());
        assert_eq!(matched.candidates.len(), 2);
        assert_eq!(
            matched.match_basis.as_deref(),
            Some("hostnameWithTenantOrUser")
        );
        assert_eq!(matched.confidence, EspCorrelationConfidence::Uncorrelated);
        assert_eq!(
            matched
                .candidates
                .iter()
                .map(|item| item.managed_device_id.as_str())
                .collect::<Vec<_>>(),
            vec![OTHER_MANAGED, LOCAL_MANAGED],
            "ambiguous candidates must be deterministic"
        );
    }
}

#[cfg(feature = "esp-diagnostics")]
mod esp_orchestration_tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::{Duration, Instant};

    use app_lib::graph_api::client::{
        GraphCancellation, GraphClientError, GraphClientErrorKind, GraphTransport,
        GraphTransportFailure,
    };
    use app_lib::graph_api::esp::{
        fetch_esp_graph_overlay, EspGraphClientProvider, EspGraphEndpoint, EspGraphOperationError,
        EspGraphOperationRegistry, EspGraphPolicyReference, EspGraphProvider, EspGraphRequest,
        EspGraphScriptReference, APPS_SCOPE, CONFIGURATION_SCOPE, MANAGED_DEVICES_SCOPE,
    };
    use app_lib::graph_api::models::{GraphTransportRequest, GraphTransportResponse};
    use cmtraceopen_parser::esp::{
        EspClassifiedString, EspCorrelationConfidence, EspGraphPolicyKind,
        EspGraphPolicyStatusDetailKind, EspGraphScriptKind, EspGraphTargeting, EspIdentityEvidence,
        EspJoinMode, EspSensitivity, GraphApiVersion, GraphSectionStatus,
    };

    const MANAGED: &str = "8c5a1ea3-bd82-454c-a19c-45dffcb10ef8";
    const ENTRA: &str = "cf016a06-56ea-4f34-a7a7-8d744fa14b87";
    const AUTOPILOT: &str = "3d44df13-3098-4aed-a138-a7f965666f84";
    const PROFILE: &str = "943414e8-5674-41d3-b107-ff932c9cd2ea";
    const INTENDED_PROFILE: &str = "b9f52a9b-06b1-480f-9f03-838b81e96ca0";
    const EVENT: &str = "44c09b28-edb7-4983-ad29-3b12b6b003a7";
    const ENROLLMENT: &str = "8dc9a8ca-0b02-4c87-9562-390807e808db";
    const APP: &str = "f0a66d99-5eeb-4abc-8cac-5a96b70293ae";
    const LOCAL_APP: &str = "08ff8202-b8f2-49b0-85a2-f2a64c720dc2";
    const POLICY: &str = "d329d4b4-5acc-4ff2-a5b5-8457cadf2a7f";
    const SCRIPT: &str = "c2d8ffcb-b328-40c0-b87c-5cb862337d01";
    const COMPLIANCE: &str = "10d25055-b5a0-4f6c-863a-059c745b3543";
    const CONFIG_POLICY: &str = "afdc0879-e75d-42ef-8aee-50f5dc67cb8f";
    const REMEDIATION: &str = "79efc4f2-a93f-48e4-9b45-88da3a4628cb";
    const USER: &str = "b63ca3f8-cd07-4ef5-824f-1f923df54ea7";
    const REQUEST: &str = "10000000-0000-4000-8000-000000000001";
    const REQUEST_FIRST: &str = "10000000-0000-4000-8000-000000000002";
    const REQUEST_SECOND: &str = "10000000-0000-4000-8000-000000000003";
    const REQUEST_MISSING: &str = "10000000-0000-4000-8000-000000000004";
    const REQUEST_REUSED: &str = "10000000-0000-4000-8000-000000000005";
    const REQUEST_OVER_LIMIT: &str = "10000000-0000-4000-8000-000000000006";
    const REQUEST_WAIT: &str = "10000000-0000-4000-8000-000000000007";
    const REQUEST_NEW_GENERATION: &str = "10000000-0000-4000-8000-000000000008";
    const REQUEST_OLD_GENERATION: &str = "10000000-0000-4000-8000-000000000009";
    const REQUEST_STALE_GENERATION: &str = "10000000-0000-4000-8000-00000000000a";
    const REQUEST_CURRENT_GENERATION: &str = "10000000-0000-4000-8000-00000000000b";

    fn classified(value: &str) -> EspClassifiedString {
        EspClassifiedString {
            value: value.to_string(),
            sensitivity: EspSensitivity::Sensitive,
        }
    }

    fn identity() -> EspIdentityEvidence {
        EspIdentityEvidence {
            device_name: Some("DEVICE-01".to_string()),
            managed_device_id: Some(MANAGED.to_string()),
            entra_device_id: Some(ENTRA.to_string()),
            entdm_id: None,
            tenant_id: Some(classified("tenant-a")),
            tenant_domain: None,
            user_principal_name: Some(classified("user@contoso.example")),
            serial_number: Some(classified("SERIAL-001")),
            evidence: Vec::new(),
        }
    }

    fn request() -> EspGraphRequest {
        EspGraphRequest {
            request_id: REQUEST.to_string(),
            identity: identity(),
            workload_ids: vec![APP.to_string()],
            selected_managed_device_id: None,
            evidence_window_start_utc: Some("2026-07-15T09:00:00Z".to_string()),
            evidence_window_end_utc: Some("2026-07-15T13:00:00Z".to_string()),
            enrollment_configuration_ids: Vec::new(),
            app_ids: vec![APP.to_string()],
            policy_references: vec![EspGraphPolicyReference {
                id: POLICY.to_string(),
                kind: EspGraphPolicyKind::DeviceConfiguration,
            }],
            script_references: vec![EspGraphScriptReference {
                id: SCRIPT.to_string(),
                kind: EspGraphScriptKind::PlatformScript,
            }],
        }
    }

    #[derive(Default)]
    struct FakeEspGraphProvider {
        responses: HashMap<String, Result<serde_json::Value, GraphClientError>>,
        requests: Mutex<Vec<EspGraphEndpoint>>,
        cancel_after_call: Option<(usize, Arc<AtomicBool>)>,
    }

    impl FakeEspGraphProvider {
        fn with(mut self, path: &str, body: serde_json::Value) -> Self {
            self.responses.insert(path.to_string(), Ok(body));
            self
        }

        fn with_error(mut self, path: &str, kind: GraphClientErrorKind) -> Self {
            self.responses.insert(
                path.to_string(),
                Err(GraphClientError {
                    kind,
                    status: (kind == GraphClientErrorKind::PermissionDenied).then_some(403),
                    request_id: Some("graph-request-error".to_string()),
                    required_scope: "fixture".to_string(),
                }),
            );
            self
        }

        fn paths(&self) -> Vec<String> {
            self.requests
                .lock()
                .expect("requests lock")
                .iter()
                .map(|request| request.path.clone())
                .collect()
        }

        fn cancelling_after(mut self, call: usize, cancelled: Arc<AtomicBool>) -> Self {
            self.cancel_after_call = Some((call, cancelled));
            self
        }

        fn response_for(
            &self,
            endpoint: &EspGraphEndpoint,
        ) -> Result<serde_json::Value, GraphClientError> {
            let call = {
                let mut requests = self.requests.lock().expect("requests lock");
                requests.push(endpoint.clone());
                requests.len()
            };
            let response = self
                .responses
                .get(&endpoint.path)
                .cloned()
                .unwrap_or_else(|| panic!("unexpected Graph endpoint: {}", endpoint.path));
            if self
                .cancel_after_call
                .as_ref()
                .is_some_and(|(cancel_after, _)| *cancel_after == call)
            {
                self.cancel_after_call
                    .as_ref()
                    .expect("cancel tuple")
                    .1
                    .store(true, Ordering::SeqCst);
            }
            response
        }
    }

    struct FakeEspGraphTransport<'a> {
        provider: &'a FakeEspGraphProvider,
    }

    impl GraphTransport for FakeEspGraphTransport<'_> {
        fn execute(
            &self,
            request: &GraphTransportRequest,
            _timeout: Duration,
        ) -> Result<GraphTransportResponse, GraphTransportFailure> {
            let path = request
                .url
                .strip_prefix("https://graph.microsoft.com")
                .expect("bounded client must pin the Graph host");
            let endpoint = EspGraphEndpoint {
                path: path.to_string(),
                required_scope: request.required_scope.clone(),
                api_version: if path.starts_with("/beta/") {
                    GraphApiVersion::Beta
                } else {
                    GraphApiVersion::V1_0
                },
            };
            match self.provider.response_for(&endpoint) {
                Ok(value) => Ok(GraphTransportResponse {
                    status: 200,
                    headers: std::collections::BTreeMap::new(),
                    body: serde_json::to_vec(&value).expect("fixture response should serialize"),
                }),
                Err(error) => match error.kind {
                    GraphClientErrorKind::Cancelled => Err(GraphTransportFailure::Cancelled),
                    GraphClientErrorKind::Timeout => Err(GraphTransportFailure::Timeout),
                    GraphClientErrorKind::Transport => Err(GraphTransportFailure::Network),
                    kind => {
                        let status = error.status.unwrap_or(match kind {
                            GraphClientErrorKind::Unauthorized => 401,
                            GraphClientErrorKind::PermissionDenied => 403,
                            GraphClientErrorKind::NotFound => 404,
                            GraphClientErrorKind::RetryExhausted => 503,
                            GraphClientErrorKind::InvalidResponse => 200,
                            _ => 500,
                        });
                        let mut headers = std::collections::BTreeMap::new();
                        if let Some(request_id) = error.request_id {
                            headers.insert("request-id".to_string(), request_id);
                        }
                        Ok(GraphTransportResponse {
                            status,
                            headers,
                            body: Vec::new(),
                        })
                    }
                },
            }
        }
    }

    impl EspGraphProvider for FakeEspGraphProvider {
        fn get(
            &self,
            endpoint: &EspGraphEndpoint,
            cancellation: &dyn GraphCancellation,
        ) -> Result<serde_json::Value, GraphClientError> {
            EspGraphClientProvider::new(&FakeEspGraphTransport { provider: self })
                .get(endpoint, cancellation)
        }

        fn get_collection(
            &self,
            endpoint: &EspGraphEndpoint,
            cancellation: &dyn GraphCancellation,
        ) -> Result<serde_json::Value, GraphClientError> {
            EspGraphClientProvider::new(&FakeEspGraphTransport { provider: self })
                .get_collection(endpoint, cancellation)
        }
    }

    #[test]
    fn esp_provider_rejects_mismatched_or_unapproved_endpoints_before_transport() {
        let cases = vec![
            (
                "version mismatch",
                EspGraphEndpoint {
                    path: "/v1.0/deviceManagement/managedDevices?$top=25".to_string(),
                    required_scope: MANAGED_DEVICES_SCOPE.to_string(),
                    api_version: GraphApiVersion::Beta,
                },
                true,
            ),
            (
                "scope mismatch",
                EspGraphEndpoint {
                    path: "/v1.0/deviceManagement/managedDevices?$top=25".to_string(),
                    required_scope: APPS_SCOPE.to_string(),
                    api_version: GraphApiVersion::V1_0,
                },
                true,
            ),
            (
                "path traversal",
                EspGraphEndpoint {
                    path: "/v1.0/deviceManagement/managedDevices/../users".to_string(),
                    required_scope: MANAGED_DEVICES_SCOPE.to_string(),
                    api_version: GraphApiVersion::V1_0,
                },
                false,
            ),
            (
                "unapproved resource",
                EspGraphEndpoint {
                    path: format!("/v1.0/users/{USER}/messages"),
                    required_scope: CONFIGURATION_SCOPE.to_string(),
                    api_version: GraphApiVersion::V1_0,
                },
                true,
            ),
            (
                "object used as collection",
                EspGraphEndpoint {
                    path: format!("/v1.0/deviceManagement/managedDevices/{MANAGED}"),
                    required_scope: MANAGED_DEVICES_SCOPE.to_string(),
                    api_version: GraphApiVersion::V1_0,
                },
                true,
            ),
        ];

        for (label, endpoint, collection) in cases {
            let transport = super::FakeGraphTransport::new(vec![Ok(super::graph_response(
                200,
                super::graph_page(serde_json::json!([]), None),
                &[],
            ))]);
            let cancellation = super::FakeGraphCancellation::default();
            let provider = EspGraphClientProvider::new(&transport);

            let error = if collection {
                provider.get_collection(&endpoint, &cancellation)
            } else {
                provider.get(&endpoint, &cancellation)
            }
            .expect_err("invalid ESP endpoint must be rejected");

            assert_eq!(error.kind, GraphClientErrorKind::InvalidUrl, "{label}");
            assert!(transport.requests().is_empty(), "{label} reached transport");
        }
    }

    #[test]
    fn esp_provider_binds_continuations_to_the_original_version_and_collection_path() {
        let endpoint = EspGraphEndpoint {
            path: "/v1.0/deviceManagement/managedDevices?$top=25".to_string(),
            required_scope: MANAGED_DEVICES_SCOPE.to_string(),
            api_version: GraphApiVersion::V1_0,
        };
        for next_link in [
            format!(
                "https://graph.microsoft.com/beta/users/{USER}/mobileAppIntentAndStates?$top=100"
            ),
            format!("https://graph.microsoft.com/v1.0/users/{USER}/messages?$top=100"),
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/../users?secret=traversal"
                .to_string(),
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/%2e%2e/users?secret=encoded"
                .to_string(),
        ] {
            let transport = super::FakeGraphTransport::new(vec![
                Ok(super::graph_response(
                    200,
                    super::graph_page(serde_json::json!([]), Some(&next_link)),
                    &[],
                )),
                Ok(super::graph_response(
                    200,
                    super::graph_page(serde_json::json!([]), None),
                    &[],
                )),
            ]);
            let cancellation = super::FakeGraphCancellation::default();
            let provider = EspGraphClientProvider::new(&transport);

            let error = provider
                .get_collection(&endpoint, &cancellation)
                .expect_err("collection continuation escaped its approved resource");

            assert_eq!(error.kind, GraphClientErrorKind::InvalidUrl);
            assert_eq!(transport.requests().len(), 1, "followed {next_link}");
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("users"));
            assert!(!rendered.contains("secret"));
        }
    }

    fn full_provider() -> FakeEspGraphProvider {
        FakeEspGraphProvider::default()
            .with(
                &format!("/v1.0/deviceManagement/managedDevices/{MANAGED}"),
                serde_json::json!({
                    "id": MANAGED,
                    "azureADDeviceId": ENTRA,
                    "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01",
                    "userId": USER,
                    "userPrincipalName": "user@contoso.example",
                    "tenantId": "tenant-a"
                }),
            )
            .with(
                &format!("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{ENTRA}'&$top=25"),
                serde_json::json!({"value": [{
                    "id": AUTOPILOT,
                    "azureActiveDirectoryDeviceId": ENTRA,
                    "serialNumber": "SERIAL-001",
                    "deploymentProfileId": PROFILE,
                    "groupTag": "HQ"
                }]}),
            )
            .with(
                &format!("/beta/deviceManagement/windowsAutopilotDeviceIdentities/{AUTOPILOT}/deploymentProfile"),
                serde_json::json!({
                    "id": PROFILE,
                    "displayName": "Production Autopilot",
                    "joinMode": "entra",
                    "selectedMobileAppIds": [APP]
                }),
            )
            .with(
                &format!("/beta/deviceManagement/windowsAutopilotDeviceIdentities/{AUTOPILOT}/intendedDeploymentProfile"),
                serde_json::json!({
                    "id": INTENDED_PROFILE,
                    "displayName": "Intended Autopilot",
                    "joinMode": "futureJoinMode",
                    "selectedMobileAppIds": []
                }),
            )
            .with(
                &format!("/beta/deviceManagement/windowsAutopilotDeploymentProfiles/{PROFILE}/assignments"),
                serde_json::json!({"value": [{
                    "id": "405ba5b8-b63f-4600-9f70-e379d9b802b1",
                    "intent": "required",
                    "target": {
                        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                        "groupId": "7d86dd6b-20b3-4c88-a312-615fb96fa275",
                        "deviceAndAppManagementAssignmentFilterId": "3372d2a4-91a4-45b6-b59b-13d74e493915"
                    }
                }]}),
            )
            .with(
                &format!("/beta/deviceManagement/autopilotEvents?$filter=deviceId%20eq%20'{ENTRA}'&$orderby=eventDateTime%20desc&$top=25"),
                serde_json::json!({"value": [
                    {"id": "26a7aa94-bf93-44ca-87fc-270a8a241857", "deviceId": ENTRA, "eventDateTime": "2026-07-15T10:00:00Z", "deploymentState": "success"},
                    {"id": EVENT, "deviceId": ENTRA, "eventDateTime": "2026-07-15T12:00:00Z", "deploymentState": "failure",
                     "windows10EnrollmentCompletionPageConfigurationId": ENROLLMENT}
                ]}),
            )
            .with(
                &format!("/beta/deviceManagement/autopilotEvents/{EVENT}/policyStatusDetails"),
                serde_json::json!({"value": [{
                    "id": "f3b25704-c28a-4bc6-b7e1-10410f0f3958",
                    "displayName": "Contoso VPN",
                    "policyType": "application",
                    "complianceStatus": "error",
                    "trackedOnEnrollmentStatus": true
                }]}),
            )
            .with(
                &format!("/v1.0/deviceManagement/deviceEnrollmentConfigurations/{ENROLLMENT}"),
                serde_json::json!({
                    "id": ENROLLMENT,
                    "displayName": "Default ESP",
                    "showInstallationProgress": true,
                    "installProgressTimeoutInMinutes": 60,
                    "selectedMobileAppIds": [APP]
                }),
            )
            .with(
                &format!("/v1.0/deviceManagement/deviceEnrollmentConfigurations/{ENROLLMENT}/assignments"),
                serde_json::json!({"value": []}),
            )
            .with(
                &format!("/v1.0/deviceAppManagement/mobileApps/{APP}"),
                serde_json::json!({"id": APP, "displayName": "Contoso VPN", "trackedOnEnrollmentStatus": true}),
            )
            .with(
                &format!("/v1.0/deviceAppManagement/mobileApps/{APP}/assignments"),
                serde_json::json!({"value": []}),
            )
            .with(
                &format!("/beta/users/{USER}/mobileAppIntentAndStates?$top=100"),
                serde_json::json!({"value": [
                    {"id": "7388bfd3-cdce-4788-b516-6eae7dcb38fe", "managedDeviceIdentifier": MANAGED, "userId": USER,
                     "mobileAppList": [{"applicationId": APP, "installState": "failed", "mobileAppIntent": "requiredInstall"}]},
                    {"id": "b0ca7427-eaef-489c-9fca-294e197893f7", "managedDeviceIdentifier": "5eb3db17-64cf-4b17-b00c-d93d9ec8c31c", "userId": USER,
                     "mobileAppList": [{"applicationId": APP, "installState": "installed", "mobileAppIntent": "requiredInstall"}]}
                ]}),
            )
            .with(
                &format!("/v1.0/deviceManagement/deviceConfigurations/{POLICY}"),
                serde_json::json!({"id": POLICY, "displayName": "Security Baseline"}),
            )
            .with(
                &format!("/v1.0/deviceManagement/deviceConfigurations/{POLICY}/assignments"),
                serde_json::json!({"value": []}),
            )
            .with(
                &format!("/v1.0/deviceManagement/deviceConfigurations/{POLICY}/deviceStatuses?$top=100"),
                serde_json::json!({"value": [
                    {"id": "status-elsewhere", "deviceDisplayName": "OTHER", "userPrincipalName": "other@contoso.example", "status": "compliant"},
                    {"id": "status-local", "deviceDisplayName": "DEVICE-01", "userPrincipalName": "user@contoso.example", "status": "error"}
                ]}),
            )
            .with(
                &format!("/beta/deviceManagement/deviceManagementScripts/{SCRIPT}"),
                serde_json::json!({"id": SCRIPT, "displayName": "Configure Device"}),
            )
            .with(
                &format!("/beta/deviceManagement/deviceManagementScripts/{SCRIPT}/assignments"),
                serde_json::json!({"value": []}),
            )
            .with(
                &format!("/beta/deviceManagement/deviceManagementScripts/{SCRIPT}/deviceRunStates?$expand=managedDevice($select=id)&$top=100"),
                serde_json::json!({"value": [
                    {"id": "run-local", "managedDevice": {"id": MANAGED}, "runState": "success"}
                ]}),
            )
    }

    #[test]
    fn orchestration_full_path_is_bounded_ordered_and_referenced_only() {
        let provider = full_provider();
        let cancellation = super::FakeGraphCancellation::default();
        let overlay =
            fetch_esp_graph_overlay(&provider, &request(), &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(overlay.request_id, REQUEST);
        assert_eq!(overlay.device_match.status, GraphSectionStatus::Available);
        assert_eq!(
            overlay.autopilot_identity.status,
            GraphSectionStatus::Available
        );
        assert_eq!(
            overlay.deployment_profile.status,
            GraphSectionStatus::Available
        );
        assert_eq!(
            overlay.intended_deployment_profile.status,
            GraphSectionStatus::Available
        );
        assert_eq!(
            overlay
                .intended_deployment_profile
                .data
                .as_ref()
                .and_then(|profile| profile.join_mode.as_ref()),
            Some(&EspJoinMode::Unknown("futureJoinMode".to_string()))
        );
        assert_eq!(
            overlay.profile_assignments.status,
            GraphSectionStatus::Available
        );
        assert_eq!(
            overlay.autopilot_events.status,
            GraphSectionStatus::Available
        );
        assert_eq!(
            overlay.enrollment_configuration.status,
            GraphSectionStatus::Available
        );
        assert_eq!(overlay.apps.status, GraphSectionStatus::Available);
        assert_eq!(overlay.policies.status, GraphSectionStatus::Available);
        assert_eq!(overlay.scripts.status, GraphSectionStatus::Available);

        let detail = &overlay.autopilot_events.data.as_ref().unwrap()[0].policy_status_details[0];
        assert_eq!(
            detail.status_detail_id,
            "f3b25704-c28a-4bc6-b7e1-10410f0f3958"
        );
        assert_eq!(
            detail.related_object_id, None,
            "policyStatusDetails.id is not an app/policy object id"
        );
        assert_eq!(detail.kind, EspGraphPolicyStatusDetailKind::App);
        assert_eq!(detail.status.display, "error");
        assert_eq!(detail.tracked_on_enrollment_status, Some(true));
        assert_eq!(
            detail.correlation_confidence,
            EspCorrelationConfidence::Strong,
            "bounded unique display-name/type correlation is strong, not exact"
        );
        let assignment = &overlay.profile_assignments.data.as_ref().unwrap()[0];
        assert_eq!(assignment.targeting, EspGraphTargeting::Declared);
        assert_eq!(
            assignment.target_id.as_deref(),
            Some("7d86dd6b-20b3-4c88-a312-615fb96fa275")
        );
        assert_eq!(
            overlay.apps.data.as_ref().unwrap()[0]
                .status
                .as_ref()
                .unwrap()
                .display,
            "failed",
            "user intent must be filtered to the matched device"
        );
        let intent_state = &overlay.apps.data.as_ref().unwrap()[0].intent_state;
        assert_eq!(intent_state.status, GraphSectionStatus::Available);
        assert_eq!(intent_state.api_version, GraphApiVersion::Beta);
        assert_eq!(
            intent_state.required_scope.as_deref(),
            Some("DeviceManagementConfiguration.Read.All")
        );
        assert_eq!(
            overlay.policies.data.as_ref().unwrap()[0]
                .status
                .as_ref()
                .unwrap()
                .display,
            "error"
        );
        assert_eq!(
            overlay.scripts.data.as_ref().unwrap()[0]
                .status
                .as_ref()
                .unwrap()
                .display,
            "success"
        );

        let paths = provider.paths();
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/graph/esp/orchestration-cases.json"))
                .expect("orchestration fixture should parse");
        let expected_paths: Vec<String> = fixture["fullExpectedPaths"]
            .as_array()
            .expect("expected paths array")
            .iter()
            .map(|value| value.as_str().expect("path string").to_string())
            .collect();
        assert_eq!(
            paths, expected_paths,
            "Graph reads must keep dependency order"
        );
        for forbidden in fixture["forbiddenPathFragments"]
            .as_array()
            .expect("forbidden path fragments")
        {
            let forbidden = forbidden.as_str().expect("forbidden fragment string");
            assert!(
                paths.iter().all(|path| !path.contains(forbidden)),
                "forbidden Graph path fragment requested: {forbidden}"
            );
        }
    }

    #[test]
    fn orchestration_autopilot_events_use_instant_order_and_local_evidence_window() {
        let older_event = "0f8105d6-955b-4d55-a8de-6a1786dc0135";
        let outside_event = "6e8b56ec-e722-4d2c-916b-6fa55f8b6693";
        let older_configuration = "00000000-0000-4000-8000-000000000001";
        let managed_path = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let autopilot_path = format!("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{ENTRA}'&$top=25");
        let event_path = format!("/beta/deviceManagement/autopilotEvents?$filter=deviceId%20eq%20'{ENTRA}'&$orderby=eventDateTime%20desc&$top=25");
        let detail_path =
            format!("/beta/deviceManagement/autopilotEvents/{EVENT}/policyStatusDetails");
        let configuration_path =
            format!("/v1.0/deviceManagement/deviceEnrollmentConfigurations/{ENROLLMENT}");
        let provider = FakeEspGraphProvider::default()
            .with(
                &managed_path,
                serde_json::json!({
                    "id": MANAGED,
                    "azureADDeviceId": ENTRA,
                    "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01"
                }),
            )
            .with_error(&autopilot_path, GraphClientErrorKind::PermissionDenied)
            .with(
                &event_path,
                serde_json::json!({"value": [
                    {
                        "id": outside_event,
                        "deviceId": ENTRA,
                        "eventDateTime": "2026-07-15T17:00:00Z",
                        "deploymentState": "failure",
                        "windows10EnrollmentCompletionPageConfigurationId": older_configuration
                    },
                    {
                        "id": older_event,
                        "deviceId": ENTRA,
                        "eventDateTime": "2026-07-15T15:00:00+01:00",
                        "deploymentState": "success",
                        "windows10EnrollmentCompletionPageConfigurationId": older_configuration
                    },
                    {
                        "id": EVENT,
                        "deviceId": ENTRA,
                        "eventDateTime": "2026-07-15T10:30:00-04:00",
                        "deploymentState": "failure",
                        "windows10EnrollmentCompletionPageConfigurationId": ENROLLMENT
                    }
                ]}),
            )
            .with(&detail_path, serde_json::json!({"value": []}))
            .with(
                &configuration_path,
                serde_json::json!({
                    "id": ENROLLMENT,
                    "displayName": "Current ESP",
                    "deviceEspEnabled": true
                }),
            )
            .with(
                &format!("{configuration_path}/assignments"),
                serde_json::json!({"value": []}),
            );
        let cancellation = super::FakeGraphCancellation::default();
        let mut request = request();
        request.evidence_window_start_utc = Some("2026-07-15T13:00:00Z".to_string());
        request.evidence_window_end_utc = Some("2026-07-15T15:00:00Z".to_string());
        request.workload_ids.clear();
        request.app_ids.clear();
        request.enrollment_configuration_ids = vec![older_configuration.to_string()];
        request.policy_references.clear();
        request.script_references.clear();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        let events = overlay.autopilot_events.data.as_ref().expect("events");
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec![EVENT, older_event]
        );
        assert_eq!(
            events[0]
                .event_time
                .as_ref()
                .and_then(|timestamp| timestamp.normalized_utc.as_deref()),
            Some("2026-07-15T14:30:00Z")
        );
        assert!(provider.paths().contains(&configuration_path));
        assert!(!provider.paths().iter().any(|path| {
            path.ends_with(&format!(
                "deviceEnrollmentConfigurations/{older_configuration}"
            ))
        }));
    }

    #[test]
    fn orchestration_includes_assignment_and_device_statuses_from_later_pages() {
        let assignment_path =
            format!("/v1.0/deviceManagement/deviceConfigurations/{POLICY}/assignments");
        let assignment_next_path = format!("{assignment_path}?$skiptoken=page-2");
        let assignment_next_url = format!("https://graph.microsoft.com{assignment_next_path}");
        let status_path =
            format!("/v1.0/deviceManagement/deviceConfigurations/{POLICY}/deviceStatuses?$top=100");
        let status_next_path = format!("{status_path}&$skiptoken=page-2");
        let status_next_url = format!("https://graph.microsoft.com{status_next_path}");
        let script_status_path = format!(
            "/beta/deviceManagement/deviceManagementScripts/{SCRIPT}/deviceRunStates?$expand=managedDevice($select=id)&$top=100"
        );
        let script_status_next_path = format!("{script_status_path}&$skiptoken=page-2");
        let script_status_next_url =
            format!("https://graph.microsoft.com{script_status_next_path}");
        let later_group = "3273fc57-ff9a-41d2-9bd4-1ceeb1825906";
        let provider = full_provider()
            .with(
                &assignment_path,
                serde_json::json!({
                    "value": [],
                    "@odata.nextLink": assignment_next_url
                }),
            )
            .with(
                &assignment_next_path,
                serde_json::json!({"value": [{
                    "id": "later-assignment",
                    "intent": "required",
                    "target": {
                        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                        "groupId": later_group
                    }
                }]}),
            )
            .with(
                &status_path,
                serde_json::json!({
                    "value": [{
                        "id": "status-elsewhere",
                        "deviceDisplayName": "OTHER-DEVICE",
                        "userPrincipalName": "other@contoso.example",
                        "status": "compliant"
                    }],
                    "@odata.nextLink": status_next_url
                }),
            )
            .with(
                &status_next_path,
                serde_json::json!({"value": [{
                    "id": "status-local",
                    "deviceDisplayName": "DEVICE-01",
                    "userPrincipalName": "user@contoso.example",
                    "status": "error"
                }]}),
            )
            .with(
                &script_status_path,
                serde_json::json!({
                    "value": [{
                        "id": "run-elsewhere",
                        "managedDevice": {"id": "5eb3db17-64cf-4b17-b00c-d93d9ec8c31c"},
                        "runState": "fail"
                    }],
                    "@odata.nextLink": script_status_next_url
                }),
            )
            .with(
                &script_status_next_path,
                serde_json::json!({"value": [{
                    "id": "run-local",
                    "managedDevice": {"id": MANAGED},
                    "runState": "success"
                }]}),
            );
        let cancellation = super::FakeGraphCancellation::default();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request(), &cancellation, "2026-07-16T12:00:00Z");

        let policy = &overlay.policies.data.as_ref().expect("policies")[0];
        assert_eq!(
            policy.assignments[0].target_id.as_deref(),
            Some(later_group),
            "a later-page assignment target must not be silently dropped"
        );
        assert_eq!(
            policy.status.as_ref().map(|status| status.display.as_str()),
            Some("error"),
            "the matched device status on a later page must be included"
        );
        assert_eq!(
            overlay.scripts.data.as_ref().expect("scripts")[0]
                .status
                .as_ref()
                .map(|status| status.display.as_str()),
            Some("success"),
            "the matched device run state on a later page must be included"
        );
        let paths = provider.paths();
        assert!(paths.contains(&assignment_next_path));
        assert!(paths.contains(&status_next_path));
        assert!(paths.contains(&script_status_next_path));
    }

    #[test]
    fn orchestration_rejects_an_untrusted_collection_next_link() {
        let status_path =
            format!("/v1.0/deviceManagement/deviceConfigurations/{POLICY}/deviceStatuses?$top=100");
        let provider = full_provider().with(
            &status_path,
            serde_json::json!({
                "value": [],
                "@odata.nextLink": "https://graph.microsoft.com.evil.example/steal?token=secret"
            }),
        );
        let cancellation = super::FakeGraphCancellation::default();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request(), &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(overlay.policies.status, GraphSectionStatus::Failed);
        let error = overlay.policies.error.as_ref().expect("policy error");
        assert_eq!(error.code, "InvalidUrl");
        assert!(!format!("{error:?}").contains("evil.example"));
        assert!(!format!("{error:?}").contains("secret"));
    }

    #[test]
    fn orchestration_rejects_a_collection_that_exceeds_the_page_limit() {
        let status_path =
            format!("/v1.0/deviceManagement/deviceConfigurations/{POLICY}/deviceStatuses?$top=100");
        let mut provider = full_provider();
        for page_index in 0..super::MAX_GRAPH_PAGES {
            let path = if page_index == 0 {
                status_path.clone()
            } else {
                format!("{status_path}&$skiptoken=page-{}", page_index + 1)
            };
            let next_path = format!("{status_path}&$skiptoken=page-{}", page_index + 2);
            provider = provider.with(
                &path,
                serde_json::json!({
                    "value": [],
                    "@odata.nextLink": format!("https://graph.microsoft.com{next_path}")
                }),
            );
        }
        let cancellation = super::FakeGraphCancellation::default();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request(), &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(overlay.policies.status, GraphSectionStatus::Failed);
        let error = overlay.policies.error.as_ref().expect("policy error");
        assert_eq!(error.code, "PageLimitExceeded");
        assert_eq!(
            provider
                .paths()
                .iter()
                .filter(|path| path.starts_with(&status_path))
                .count(),
            super::MAX_GRAPH_PAGES
        );
    }

    #[test]
    fn orchestration_ambiguous_weak_device_match_skips_all_dependent_sections() {
        let mut request = request();
        request.identity.managed_device_id = None;
        request.identity.entra_device_id = None;
        request.identity.serial_number = None;
        request.selected_managed_device_id = None;
        let path =
            "/v1.0/deviceManagement/managedDevices?$filter=deviceName%20eq%20'DEVICE-01'&$top=25";
        let provider = FakeEspGraphProvider::default().with(
            path,
            serde_json::json!({"value": [
                {"id": MANAGED, "azureADDeviceId": ENTRA, "deviceName": "DEVICE-01", "userPrincipalName": "user@contoso.example"},
                {"id": "6122aaff-6736-4ccf-b0fe-82932dd076f0", "azureADDeviceId": "c7fde315-1d29-489f-a880-3d781f54c6e3", "deviceName": "DEVICE-01", "tenantId": "tenant-a"}
            ]}),
        );
        let cancellation = super::FakeGraphCancellation::default();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(provider.paths(), [path]);
        assert!(overlay
            .device_match
            .data
            .as_ref()
            .unwrap()
            .selected
            .is_none());
        assert_eq!(
            overlay.device_match.data.as_ref().unwrap().candidates.len(),
            2
        );
        assert_eq!(
            overlay.autopilot_identity.status,
            GraphSectionStatus::Skipped
        );
        assert_eq!(
            overlay.deployment_profile.status,
            GraphSectionStatus::Skipped
        );
        assert_eq!(
            overlay.intended_deployment_profile.status,
            GraphSectionStatus::Skipped
        );
        assert_eq!(
            overlay
                .autopilot_identity
                .error
                .as_ref()
                .and_then(|error| error.blocked_by.as_deref()),
            Some("deviceMatch")
        );
        assert_eq!(
            overlay
                .deployment_profile
                .error
                .as_ref()
                .and_then(|error| error.blocked_by.as_deref()),
            Some("deviceMatch")
        );
        assert_eq!(
            overlay
                .intended_deployment_profile
                .error
                .as_ref()
                .and_then(|error| error.blocked_by.as_deref()),
            Some("deviceMatch")
        );
        for status in [
            &overlay.profile_assignments.status,
            &overlay.autopilot_events.status,
            &overlay.enrollment_configuration.status,
            &overlay.apps.status,
            &overlay.policies.status,
            &overlay.scripts.status,
        ] {
            assert_eq!(*status, GraphSectionStatus::Skipped);
        }
    }

    #[test]
    fn orchestration_permission_denial_isolated_to_autopilot_section() {
        let managed_path = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let autopilot_path = format!("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{ENTRA}'&$top=25");
        let app_path = format!("/v1.0/deviceAppManagement/mobileApps/{APP}");
        let assignments_path = format!("{app_path}/assignments");
        let user_path = format!("/beta/users/{USER}/mobileAppIntentAndStates?$top=100");
        let event_path = format!("/beta/deviceManagement/autopilotEvents?$filter=deviceId%20eq%20'{ENTRA}'&$orderby=eventDateTime%20desc&$top=25");
        let provider = FakeEspGraphProvider::default()
            .with(
                &managed_path,
                serde_json::json!({
                    "id": MANAGED, "azureADDeviceId": ENTRA, "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01", "userId": USER,
                    "userPrincipalName": "user@contoso.example"
                }),
            )
            .with_error(&autopilot_path, GraphClientErrorKind::PermissionDenied)
            .with(&event_path, serde_json::json!({"value": []}))
            .with(
                &app_path,
                serde_json::json!({"id": APP, "displayName": "Contoso VPN"}),
            )
            .with(&assignments_path, serde_json::json!({"value": []}))
            .with(&user_path, serde_json::json!({"value": []}));
        let cancellation = super::FakeGraphCancellation::default();
        let mut request = request();
        request.enrollment_configuration_ids.clear();
        request.policy_references.clear();
        request.script_references.clear();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(overlay.device_match.status, GraphSectionStatus::Available);
        assert_eq!(
            overlay.autopilot_identity.status,
            GraphSectionStatus::PermissionDenied
        );
        assert_eq!(
            overlay.deployment_profile.status,
            GraphSectionStatus::Skipped
        );
        assert_eq!(overlay.apps.status, GraphSectionStatus::Available);
        assert_eq!(
            overlay.enrollment_configuration.status,
            GraphSectionStatus::Skipped
        );
        assert_eq!(overlay.policies.status, GraphSectionStatus::Skipped);
        assert_eq!(overlay.scripts.status, GraphSectionStatus::Skipped);
    }

    #[test]
    fn orchestration_optional_app_intent_failure_preserves_primary_app_section() {
        let user_path = format!("/beta/users/{USER}/mobileAppIntentAndStates?$top=100");
        let provider =
            full_provider().with_error(&user_path, GraphClientErrorKind::PermissionDenied);
        let cancellation = super::FakeGraphCancellation::default();
        let mut request = request();
        request.policy_references.clear();
        request.script_references.clear();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(overlay.apps.status, GraphSectionStatus::Available);
        assert_eq!(overlay.apps.api_version, GraphApiVersion::V1_0);
        assert_eq!(
            overlay.apps.required_scope.as_deref(),
            Some("DeviceManagementApps.Read.All")
        );
        let apps = overlay.apps.data.as_ref().expect("primary app records");
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].app_id, APP);
        assert_eq!(
            apps[0].intent_state.status,
            GraphSectionStatus::PermissionDenied
        );
        assert_eq!(apps[0].intent_state.api_version, GraphApiVersion::Beta);
        assert_eq!(
            apps[0].intent_state.required_scope.as_deref(),
            Some("DeviceManagementConfiguration.Read.All")
        );
    }

    #[test]
    fn orchestration_managed_device_not_found_uses_one_bounded_fallback() {
        let primary = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let fallback = "/v1.0/deviceManagement/managedDevices?$top=100";
        let autopilot_path = format!("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{ENTRA}'&$top=25");
        let event_path = format!("/beta/deviceManagement/autopilotEvents?$filter=deviceId%20eq%20'{ENTRA}'&$orderby=eventDateTime%20desc&$top=25");
        let cancellation = super::FakeGraphCancellation::default();
        let provider = FakeEspGraphProvider::default()
            .with_error(&primary, GraphClientErrorKind::NotFound)
            .with(
                fallback,
                serde_json::json!({"value": [{
                    "id": MANAGED,
                    "azureADDeviceId": ENTRA,
                    "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01",
                    "userId": USER,
                    "userPrincipalName": "user@contoso.example"
                }]}),
            )
            .with_error(&autopilot_path, GraphClientErrorKind::NotFound)
            .with(&event_path, serde_json::json!({"value": []}));
        let mut request = request();
        request.workload_ids.clear();
        request.enrollment_configuration_ids.clear();
        request.app_ids.clear();
        request.policy_references.clear();
        request.script_references.clear();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        let paths = provider.paths();
        assert_eq!(paths[0..2], [primary, fallback.to_string()]);
        assert_eq!(
            paths
                .iter()
                .filter(|path| path.as_str() == fallback)
                .count(),
            1
        );
        assert_eq!(overlay.device_match.status, GraphSectionStatus::Available);
        assert_eq!(
            overlay
                .device_match
                .data
                .as_ref()
                .and_then(|matched| matched.selected.as_ref())
                .map(|device| device.managed_device_id.as_str()),
            Some(MANAGED)
        );
        assert_eq!(
            overlay.autopilot_identity.status,
            GraphSectionStatus::NotFound
        );
        assert_eq!(
            overlay.autopilot_events.status,
            GraphSectionStatus::Available
        );
        assert_eq!(overlay.apps.status, GraphSectionStatus::Skipped);
    }

    #[test]
    fn orchestration_explicit_managed_device_not_found_is_authoritative() {
        let primary = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let provider =
            FakeEspGraphProvider::default().with_error(&primary, GraphClientErrorKind::NotFound);
        let cancellation = super::FakeGraphCancellation::default();
        let mut request = request();
        request.selected_managed_device_id = Some(MANAGED.to_string());

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(provider.paths(), [primary]);
        assert_eq!(overlay.device_match.status, GraphSectionStatus::NotFound);
        assert!(overlay.device_match.data.is_none());
        assert_eq!(
            overlay
                .autopilot_identity
                .error
                .as_ref()
                .and_then(|error| error.blocked_by.as_deref()),
            Some("deviceMatch")
        );
    }

    #[test]
    fn orchestration_explicit_managed_device_payload_mismatch_is_rejected() {
        let other_managed = "6122aaff-6736-4ccf-b0fe-82932dd076f0";
        let primary = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let provider = FakeEspGraphProvider::default().with(
            &primary,
            serde_json::json!({
                "id": other_managed,
                "azureADDeviceId": "c7fde315-1d29-489f-a880-3d781f54c6e3",
                "serialNumber": "OTHER",
                "deviceName": "OTHER"
            }),
        );
        let cancellation = super::FakeGraphCancellation::default();
        let mut request = request();
        request.selected_managed_device_id = Some(MANAGED.to_string());

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(provider.paths(), [primary]);
        assert_eq!(overlay.device_match.status, GraphSectionStatus::Failed);
        assert_eq!(
            overlay
                .device_match
                .error
                .as_ref()
                .map(|error| error.code.as_str()),
            Some("InvalidResponse")
        );
        assert_eq!(overlay.autopilot_events.status, GraphSectionStatus::Skipped);
    }

    #[test]
    fn orchestration_cancellation_after_device_transport_cancels_every_section() {
        let managed_path = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let cancellation = super::FakeGraphCancellation::default();
        let provider = FakeEspGraphProvider::default()
            .with(
                &managed_path,
                serde_json::json!({
                    "id": MANAGED,
                    "azureADDeviceId": ENTRA,
                    "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01",
                    "userId": USER
                }),
            )
            .cancelling_after(1, cancellation.cancelled.clone());

        let overlay =
            fetch_esp_graph_overlay(&provider, &request(), &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(provider.paths(), [managed_path]);
        assert_eq!(overlay.device_match.status, GraphSectionStatus::Cancelled);
        for status in [
            &overlay.autopilot_identity.status,
            &overlay.deployment_profile.status,
            &overlay.intended_deployment_profile.status,
            &overlay.profile_assignments.status,
            &overlay.autopilot_events.status,
            &overlay.enrollment_configuration.status,
            &overlay.apps.status,
            &overlay.policies.status,
            &overlay.scripts.status,
        ] {
            assert_eq!(*status, GraphSectionStatus::Cancelled);
        }
    }

    #[test]
    fn orchestration_cancellation_after_autopilot_transport_cancels_that_section_and_dependents() {
        let managed_path = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let autopilot_path = format!("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{ENTRA}'&$top=25");
        let cancellation = super::FakeGraphCancellation::default();
        let provider = FakeEspGraphProvider::default()
            .with(
                &managed_path,
                serde_json::json!({
                    "id": MANAGED,
                    "azureADDeviceId": ENTRA,
                    "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01"
                }),
            )
            .with(
                &autopilot_path,
                serde_json::json!({"value": [{
                    "id": AUTOPILOT,
                    "azureActiveDirectoryDeviceId": ENTRA,
                    "serialNumber": "SERIAL-001"
                }]}),
            )
            .cancelling_after(2, cancellation.cancelled.clone());

        let overlay =
            fetch_esp_graph_overlay(&provider, &request(), &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(provider.paths(), [managed_path, autopilot_path]);
        assert_eq!(overlay.device_match.status, GraphSectionStatus::Available);
        assert_eq!(
            overlay.autopilot_identity.status,
            GraphSectionStatus::Cancelled
        );
        assert_eq!(
            overlay.deployment_profile.status,
            GraphSectionStatus::Cancelled
        );
        assert_eq!(
            overlay.intended_deployment_profile.status,
            GraphSectionStatus::Cancelled
        );
        assert_eq!(
            overlay.profile_assignments.status,
            GraphSectionStatus::Cancelled
        );
    }

    #[test]
    fn orchestration_unions_local_and_remote_app_references() {
        let provider = full_provider()
            .with(
                &format!("/v1.0/deviceAppManagement/mobileApps/{LOCAL_APP}"),
                serde_json::json!({"id": LOCAL_APP, "displayName": "Local Evidence App"}),
            )
            .with(
                &format!("/v1.0/deviceAppManagement/mobileApps/{LOCAL_APP}/assignments"),
                serde_json::json!({"value": []}),
            );
        let cancellation = super::FakeGraphCancellation::default();
        let mut request = request();
        request.workload_ids = vec![LOCAL_APP.to_string()];

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(overlay.apps.status, GraphSectionStatus::Available);
        assert_eq!(
            overlay
                .apps
                .data
                .as_ref()
                .expect("apps")
                .iter()
                .map(|app| app.app_id.as_str())
                .collect::<Vec<_>>(),
            vec![LOCAL_APP, APP]
        );
        let paths = provider.paths();
        assert!(paths.contains(&format!("/v1.0/deviceAppManagement/mobileApps/{LOCAL_APP}")));
        assert!(paths.contains(&format!("/v1.0/deviceAppManagement/mobileApps/{APP}")));
    }

    #[test]
    fn orchestration_deduplicates_referenced_policy_and_script_reads() {
        let provider = full_provider();
        let cancellation = super::FakeGraphCancellation::default();
        let mut request = request();
        request.policy_references.push(EspGraphPolicyReference {
            id: POLICY.to_uppercase(),
            kind: EspGraphPolicyKind::DeviceConfiguration,
        });
        request.script_references.push(EspGraphScriptReference {
            id: SCRIPT.to_uppercase(),
            kind: EspGraphScriptKind::PlatformScript,
        });

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(overlay.policies.status, GraphSectionStatus::Available);
        assert_eq!(overlay.scripts.status, GraphSectionStatus::Available);
        let paths = provider.paths();
        let policy_path = format!("/v1.0/deviceManagement/deviceConfigurations/{POLICY}");
        let script_path = format!("/beta/deviceManagement/deviceManagementScripts/{SCRIPT}");
        assert_eq!(paths.iter().filter(|path| **path == policy_path).count(), 1);
        assert_eq!(paths.iter().filter(|path| **path == script_path).count(), 1);
    }

    #[test]
    fn orchestration_beta_enrollment_failure_preserves_v1_configuration() {
        let managed_path = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let autopilot_path = format!("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{ENTRA}'&$top=25");
        let event_path = format!("/beta/deviceManagement/autopilotEvents?$filter=deviceId%20eq%20'{ENTRA}'&$orderby=eventDateTime%20desc&$top=25");
        let enrollment_path =
            format!("/v1.0/deviceManagement/deviceEnrollmentConfigurations/{ENROLLMENT}");
        let beta_path =
            format!("/beta/deviceManagement/deviceEnrollmentConfigurations/{ENROLLMENT}");
        let provider = FakeEspGraphProvider::default()
            .with(
                &managed_path,
                serde_json::json!({
                    "id": MANAGED,
                    "azureADDeviceId": ENTRA,
                    "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01"
                }),
            )
            .with_error(&autopilot_path, GraphClientErrorKind::NotFound)
            .with(&event_path, serde_json::json!({"value": []}))
            .with(
                &enrollment_path,
                serde_json::json!({
                    "id": ENROLLMENT,
                    "displayName": "Default ESP"
                }),
            )
            .with_error(&beta_path, GraphClientErrorKind::PermissionDenied);
        let cancellation = super::FakeGraphCancellation::default();
        let mut request = request();
        request.enrollment_configuration_ids = vec![ENROLLMENT.to_string()];
        request.app_ids.clear();
        request.workload_ids.clear();
        request.policy_references.clear();
        request.script_references.clear();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(
            overlay.enrollment_configuration.status,
            GraphSectionStatus::PermissionDenied
        );
        assert_eq!(
            overlay.enrollment_configuration.api_version,
            GraphApiVersion::Beta
        );
        let partial = overlay
            .enrollment_configuration
            .data
            .as_ref()
            .expect("v1 configuration must survive beta enrichment failure");
        assert_eq!(partial.configuration_id, ENROLLMENT);
        assert_eq!(partial.display_name.as_deref(), Some("Default ESP"));
        assert_eq!(partial.device_esp_enabled, None);
        assert!(partial.assignments.is_empty());
    }

    #[test]
    fn orchestration_uses_exact_compliance_configuration_policy_and_remediation_paths() {
        let managed_path = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let autopilot_path = format!("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{ENTRA}'&$top=25");
        let event_path = format!("/beta/deviceManagement/autopilotEvents?$filter=deviceId%20eq%20'{ENTRA}'&$orderby=eventDateTime%20desc&$top=25");
        let compliance_base =
            format!("/v1.0/deviceManagement/deviceCompliancePolicies/{COMPLIANCE}");
        let configuration_base =
            format!("/beta/deviceManagement/configurationPolicies/{CONFIG_POLICY}");
        let remediation_base = format!("/beta/deviceManagement/deviceHealthScripts/{REMEDIATION}");
        let provider = FakeEspGraphProvider::default()
            .with(
                &managed_path,
                serde_json::json!({
                    "id": MANAGED, "azureADDeviceId": ENTRA, "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01", "userId": USER,
                    "userPrincipalName": "user@contoso.example"
                }),
            )
            .with_error(&autopilot_path, GraphClientErrorKind::PermissionDenied)
            .with(&event_path, serde_json::json!({"value": []}))
            .with(
                &compliance_base,
                serde_json::json!({"id": COMPLIANCE, "displayName": "Compliance"}),
            )
            .with(
                &format!("{compliance_base}/assignments"),
                serde_json::json!({"value": []}),
            )
            .with(
                &format!("{compliance_base}/deviceStatuses?$top=100"),
                serde_json::json!({"value": [{
                    "id": "status",
                    "deviceDisplayName": "DEVICE-01",
                    "userPrincipalName": "user@contoso.example",
                    "status": "error"
                }]}),
            )
            .with(
                &configuration_base,
                serde_json::json!({"id": CONFIG_POLICY, "displayName": "Settings Catalog"}),
            )
            .with(
                &format!("{configuration_base}/assignments"),
                serde_json::json!({"value": []}),
            )
            .with(
                &remediation_base,
                serde_json::json!({"id": REMEDIATION, "displayName": "Repair Device"}),
            )
            .with(
                &format!("{remediation_base}/assignments"),
                serde_json::json!({"value": []}),
            )
            .with(
                &format!(
                    "{remediation_base}/deviceRunStates?$expand=managedDevice($select=id)&$top=100"
                ),
                serde_json::json!({"value": [{
                    "id": "run",
                    "managedDevice": {"id": MANAGED},
                    "detectionState": "success",
                    "remediationState": "success"
                }]}),
            );
        let mut request = request();
        request.workload_ids.clear();
        request.app_ids.clear();
        request.enrollment_configuration_ids.clear();
        request.policy_references = vec![
            EspGraphPolicyReference {
                id: CONFIG_POLICY.to_string(),
                kind: EspGraphPolicyKind::ConfigurationPolicy,
            },
            EspGraphPolicyReference {
                id: COMPLIANCE.to_string(),
                kind: EspGraphPolicyKind::Compliance,
            },
        ];
        request.script_references = vec![EspGraphScriptReference {
            id: REMEDIATION.to_string(),
            kind: EspGraphScriptKind::Remediation,
        }];
        let cancellation = super::FakeGraphCancellation::default();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(overlay.policies.status, GraphSectionStatus::Available);
        assert_eq!(overlay.policies.api_version, GraphApiVersion::Beta);
        assert_eq!(overlay.policies.data.as_ref().unwrap().len(), 2);
        let compliance = overlay
            .policies
            .data
            .as_ref()
            .unwrap()
            .iter()
            .find(|policy| policy.policy_id == COMPLIANCE)
            .expect("compliance policy");
        assert_eq!(
            compliance
                .status
                .as_ref()
                .map(|status| status.display.as_str()),
            Some("error")
        );
        assert_eq!(overlay.scripts.status, GraphSectionStatus::Available);
        assert_eq!(
            overlay.scripts.data.as_ref().unwrap()[0]
                .status
                .as_ref()
                .map(|status| status.display.as_str()),
            Some("success")
        );
        let paths = provider.paths();
        assert!(paths.contains(&format!("{compliance_base}/deviceStatuses?$top=100")));
        assert!(paths.contains(&format!("{configuration_base}/assignments")));
        assert!(
            !paths.contains(&format!("{configuration_base}/deviceStatuses?$top=100")),
            "configurationPolicies must not use the classic status path"
        );
        assert!(paths.contains(&format!(
            "{remediation_base}/deviceRunStates?$expand=managedDevice($select=id)&$top=100"
        )));
    }

    #[test]
    fn orchestration_malformed_success_fails_only_the_app_section_with_sanitized_error() {
        let managed_path = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let autopilot_path = format!("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{ENTRA}'&$top=25");
        let event_path = format!("/beta/deviceManagement/autopilotEvents?$filter=deviceId%20eq%20'{ENTRA}'&$orderby=eventDateTime%20desc&$top=25");
        let app_path = format!("/v1.0/deviceAppManagement/mobileApps/{APP}");
        let provider = FakeEspGraphProvider::default()
            .with(
                &managed_path,
                serde_json::json!({
                    "id": MANAGED, "azureADDeviceId": ENTRA, "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01", "userId": USER
                }),
            )
            .with_error(&autopilot_path, GraphClientErrorKind::PermissionDenied)
            .with(&event_path, serde_json::json!({"value": []}))
            .with(
                &app_path,
                serde_json::json!({"id": APP, "displayName": {"secret": "must-not-surface"}}),
            )
            .with(
                &format!("{app_path}/assignments"),
                serde_json::json!({"value": []}),
            );
        let mut request = request();
        request.enrollment_configuration_ids.clear();
        request.policy_references.clear();
        request.script_references.clear();
        let cancellation = super::FakeGraphCancellation::default();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(overlay.device_match.status, GraphSectionStatus::Available);
        assert_eq!(
            overlay.autopilot_events.status,
            GraphSectionStatus::Available
        );
        assert_eq!(overlay.apps.status, GraphSectionStatus::Failed);
        assert!(overlay.apps.data.as_ref().is_some_and(Vec::is_empty));
        let error = overlay.apps.error.as_ref().unwrap();
        assert_eq!(error.code, "InvalidResponse");
        assert!(!error.message.contains("secret"));
        assert_eq!(overlay.policies.status, GraphSectionStatus::Skipped);
        assert_eq!(overlay.scripts.status, GraphSectionStatus::Skipped);
    }

    #[test]
    fn orchestration_uses_beta_only_to_fill_rich_esp_fields_missing_from_v1() {
        let managed_path = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let autopilot_path = format!("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{ENTRA}'&$top=25");
        let event_path = format!("/beta/deviceManagement/autopilotEvents?$filter=deviceId%20eq%20'{ENTRA}'&$orderby=eventDateTime%20desc&$top=25");
        let detail_path =
            format!("/beta/deviceManagement/autopilotEvents/{EVENT}/policyStatusDetails");
        let v1_configuration =
            format!("/v1.0/deviceManagement/deviceEnrollmentConfigurations/{ENROLLMENT}");
        let beta_configuration =
            format!("/beta/deviceManagement/deviceEnrollmentConfigurations/{ENROLLMENT}");
        let assignment_path = format!("{v1_configuration}/assignments");
        let provider = FakeEspGraphProvider::default()
            .with(
                &managed_path,
                serde_json::json!({
                    "id": MANAGED, "azureADDeviceId": ENTRA, "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01", "userId": USER
                }),
            )
            .with_error(&autopilot_path, GraphClientErrorKind::PermissionDenied)
            .with(
                &event_path,
                serde_json::json!({"value": [{
                    "id": EVENT, "deviceId": ENTRA, "eventDateTime": "2026-07-15T12:00:00Z",
                    "deploymentState": "success",
                    "windows10EnrollmentCompletionPageConfigurationId": ENROLLMENT
                }]}),
            )
            .with(&detail_path, serde_json::json!({"value": []}))
            .with(
                &v1_configuration,
                serde_json::json!({
                    "id": ENROLLMENT, "displayName": "Default ESP",
                    "allowNonBlockingAppInstallation": false
                }),
            )
            .with(
                &beta_configuration,
                serde_json::json!({
                    "id": ENROLLMENT, "displayName": "Default ESP",
                    "showInstallationProgress": true,
                    "disableUserStatusTrackingAfterFirstUser": true,
                    "installProgressTimeoutInMinutes": 45,
                    "selectedMobileAppIds": []
                }),
            )
            .with(&assignment_path, serde_json::json!({"value": []}));
        let mut request = request();
        request.workload_ids.clear();
        request.app_ids.clear();
        request.policy_references.clear();
        request.script_references.clear();
        let cancellation = super::FakeGraphCancellation::default();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(
            overlay.enrollment_configuration.status,
            GraphSectionStatus::Available
        );
        assert_eq!(
            overlay.enrollment_configuration.api_version,
            GraphApiVersion::Beta
        );
        let configuration = overlay.enrollment_configuration.data.as_ref().unwrap();
        assert_eq!(configuration.show_installation_progress, Some(true));
        assert_eq!(configuration.device_esp_enabled, None);
        assert_eq!(configuration.user_esp_enabled, None);
        assert_eq!(
            configuration.disable_user_status_tracking_after_first_user,
            Some(true)
        );
        assert_eq!(configuration.timeout_minutes, Some(45));
        let paths = provider.paths();
        let v1_index = paths
            .iter()
            .position(|path| path == &v1_configuration)
            .unwrap();
        assert_eq!(paths[v1_index + 1], beta_configuration);
        assert_eq!(paths[v1_index + 2], assignment_path);
    }

    #[test]
    fn orchestration_marks_all_referenced_object_caps_as_partial() {
        let managed_path = format!("/v1.0/deviceManagement/managedDevices/{MANAGED}");
        let autopilot_path = format!("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=azureActiveDirectoryDeviceId%20eq%20'{ENTRA}'&$top=25");
        let event_path = format!("/beta/deviceManagement/autopilotEvents?$filter=deviceId%20eq%20'{ENTRA}'&$orderby=eventDateTime%20desc&$top=25");
        let mut provider = FakeEspGraphProvider::default()
            .with(
                &managed_path,
                serde_json::json!({
                    "id": MANAGED,
                    "azureADDeviceId": ENTRA,
                    "serialNumber": "SERIAL-001",
                    "deviceName": "DEVICE-01",
                    "userPrincipalName": "user@contoso.example"
                }),
            )
            .with_error(&autopilot_path, GraphClientErrorKind::NotFound)
            .with(&event_path, serde_json::json!({"value": []}));
        let mut app_ids = Vec::new();
        let mut policy_references = Vec::new();
        let mut script_references = Vec::new();
        for index in 1..=101_u64 {
            let app_id = format!("10000000-0000-4000-8000-{index:012x}");
            let policy_id = format!("20000000-0000-4000-8000-{index:012x}");
            let script_id = format!("30000000-0000-4000-8000-{index:012x}");
            let app_base = format!("/v1.0/deviceAppManagement/mobileApps/{app_id}");
            let policy_base = format!("/v1.0/deviceManagement/deviceConfigurations/{policy_id}");
            let script_base = format!("/beta/deviceManagement/deviceManagementScripts/{script_id}");
            provider = provider
                .with(
                    &app_base,
                    serde_json::json!({"id": app_id, "displayName": "Bounded App"}),
                )
                .with(
                    &format!("{app_base}/assignments"),
                    serde_json::json!({"value": []}),
                )
                .with(
                    &policy_base,
                    serde_json::json!({"id": policy_id, "displayName": "Bounded Policy"}),
                )
                .with(
                    &format!("{policy_base}/assignments"),
                    serde_json::json!({"value": []}),
                )
                .with(
                    &format!("{policy_base}/deviceStatuses?$top=100"),
                    serde_json::json!({"value": []}),
                )
                .with(
                    &script_base,
                    serde_json::json!({"id": script_id, "displayName": "Bounded Script"}),
                )
                .with(
                    &format!("{script_base}/assignments"),
                    serde_json::json!({"value": []}),
                )
                .with(
                    &format!(
                        "{script_base}/deviceRunStates?$expand=managedDevice($select=id)&$top=100"
                    ),
                    serde_json::json!({"value": []}),
                );
            app_ids.push(app_id);
            policy_references.push(EspGraphPolicyReference {
                id: policy_id,
                kind: EspGraphPolicyKind::DeviceConfiguration,
            });
            script_references.push(EspGraphScriptReference {
                id: script_id,
                kind: EspGraphScriptKind::PlatformScript,
            });
        }
        let mut request = request();
        request.workload_ids.clear();
        request.app_ids = app_ids;
        request.enrollment_configuration_ids.clear();
        request.policy_references = policy_references;
        request.script_references = script_references;
        let cancellation = super::FakeGraphCancellation::default();

        let overlay =
            fetch_esp_graph_overlay(&provider, &request, &cancellation, "2026-07-16T12:00:00Z");

        assert_eq!(overlay.apps.status, GraphSectionStatus::Failed);
        assert_eq!(overlay.apps.data.as_ref().map(Vec::len), Some(100));
        assert_eq!(
            overlay.apps.error.as_ref().map(|error| error.code.as_str()),
            Some("ItemLimitExceeded")
        );
        assert_eq!(overlay.policies.status, GraphSectionStatus::Failed);
        assert_eq!(overlay.policies.data.as_ref().map(Vec::len), Some(100));
        assert_eq!(
            overlay
                .policies
                .error
                .as_ref()
                .map(|error| error.code.as_str()),
            Some("ItemLimitExceeded")
        );
        assert_eq!(overlay.scripts.status, GraphSectionStatus::Failed);
        assert_eq!(overlay.scripts.data.as_ref().map(Vec::len), Some(100));
        assert_eq!(
            overlay
                .scripts
                .error
                .as_ref()
                .map(|error| error.code.as_str()),
            Some("ItemLimitExceeded")
        );
    }

    #[test]
    fn ipc_request_contract_round_trips_every_reference_class_without_credentials() {
        let request = request();
        let value = serde_json::to_value(&request).expect("serialize ESP Graph request");

        assert_eq!(value["requestId"], REQUEST);
        assert_eq!(value["workloadIds"], serde_json::json!([APP]));
        assert_eq!(value["appIds"], serde_json::json!([APP]));
        assert_eq!(
            value["policyReferences"],
            serde_json::json!([{"id": POLICY, "kind": "deviceConfiguration"}])
        );
        assert_eq!(
            value["scriptReferences"],
            serde_json::json!([{"id": SCRIPT, "kind": "platformScript"}])
        );
        let serialized = serde_json::to_string(&value).expect("request JSON");
        assert!(!serialized.contains("accessToken"));
        assert!(!serialized.contains("Authorization"));
        assert_eq!(
            serde_json::from_value::<EspGraphRequest>(value).expect("deserialize request"),
            request
        );
    }

    #[test]
    fn ipc_operation_registry_cancels_only_the_owned_id_and_releases_on_drop() {
        let registry = EspGraphOperationRegistry::default();
        let first = registry.begin(REQUEST_FIRST, 0).expect("first operation");
        let second = registry.begin(REQUEST_SECOND, 0).expect("second operation");

        assert!(matches!(
            registry.begin(REQUEST_FIRST, 0),
            Err(EspGraphOperationError::DuplicateRequest)
        ));
        assert!(!registry.cancel(REQUEST_MISSING));
        assert!(registry.cancel(REQUEST_FIRST));
        assert!(first.is_cancelled());
        assert!(!second.is_cancelled());

        drop(first);
        assert!(registry.begin(REQUEST_FIRST, 0).is_ok());
        assert!(!second.is_cancelled());
    }

    #[test]
    fn ipc_operation_registry_rejects_invalid_ids_and_bounds_active_ownership() {
        let registry = EspGraphOperationRegistry::default();
        for invalid in [
            "",
            "caller-controlled-request-name",
            " leading",
            "trailing ",
            "line\nbreak",
        ] {
            assert!(matches!(
                registry.begin(invalid, 0),
                Err(EspGraphOperationError::InvalidRequestId)
            ));
        }
        assert!(matches!(
            registry.begin(&"x".repeat(129), 0),
            Err(EspGraphOperationError::InvalidRequestId)
        ));
        assert!(registry.begin(REQUEST_REUSED, 0).is_ok());
        drop(registry);

        let registry = EspGraphOperationRegistry::default();

        let operations: Vec<_> = (0..32)
            .map(|index| {
                registry
                    .begin(&format!("20000000-0000-4000-8000-{index:012x}"), 0)
                    .expect("bounded active operation")
            })
            .collect();
        assert!(matches!(
            registry.begin(REQUEST_OVER_LIMIT, 0),
            Err(EspGraphOperationError::ResourceLimit)
        ));

        drop(operations);
        assert!(registry.begin(REQUEST_REUSED, 0).is_ok());
    }

    #[test]
    fn ipc_operation_new_generation_survives_delayed_prior_generation_cleanup() {
        let registry = EspGraphOperationRegistry::default();
        registry.advance_generation(7);
        let operation = registry
            .begin(REQUEST_NEW_GENERATION, 7)
            .expect("new-generation operation");

        registry.advance_generation(7);

        assert!(!operation.is_cancelled());
    }

    #[test]
    fn ipc_operation_old_generation_cannot_begin_or_survive_after_transition() {
        let registry = EspGraphOperationRegistry::default();
        registry.advance_generation(11);
        let old_operation = registry
            .begin(REQUEST_OLD_GENERATION, 11)
            .expect("old-generation operation");
        let captured_generation = 11;

        registry.advance_generation(12);

        assert!(old_operation.is_cancelled());
        assert!(matches!(
            registry.begin(REQUEST_STALE_GENERATION, captured_generation),
            Err(EspGraphOperationError::StaleGeneration)
        ));
        let current_operation = registry
            .begin(REQUEST_CURRENT_GENERATION, 12)
            .expect("current-generation operation");
        assert!(!current_operation.is_cancelled());
    }

    #[test]
    fn ipc_operation_cancellation_interrupts_a_retry_wait() {
        let registry = EspGraphOperationRegistry::default();
        let operation = Arc::new(registry.begin(REQUEST_WAIT, 0).expect("wait operation"));
        let worker_operation = Arc::clone(&operation);
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            worker_barrier.wait();
            worker_operation.wait_for_retry(Duration::from_secs(10))
        });

        barrier.wait();
        assert!(registry.cancel(REQUEST_WAIT));
        assert!(!worker.join().expect("wait worker"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
