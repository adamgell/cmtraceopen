use std::collections::BTreeMap;

use app_lib::graph_api::models::{
    GraphAppInfo, GraphAuthStatus, GraphHttpMethod, GraphResolutionResult, GraphTransportRequest,
    GraphTransportResponse,
};

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
