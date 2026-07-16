use std::collections::BTreeMap;

use app_lib::graph_api::models::{
    project_graph_auth_status, GraphAppInfo, GraphAuthCapabilities, GraphAuthStatus,
    GraphHttpMethod, GraphResolutionResult, GraphTransportRequest, GraphTransportResponse,
    GRAPH_DELEGATED_SCOPES, GRAPH_SCOPE_REQUEST,
};
use base64::Engine;

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
