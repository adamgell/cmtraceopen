//! Microsoft Graph API integration.
//!
//! Portable models compile on every platform. The existing WAM token cache and
//! concrete HTTP implementation remain Windows-only and user-opt-in.

pub mod client;
pub mod models;

pub use models::{
    project_graph_auth_status, GraphAppInfo, GraphAuthCapabilities, GraphAuthStatus,
    GraphHttpMethod, GraphResolutionResult, GraphTransportRequest, GraphTransportResponse,
    GRAPH_DELEGATED_SCOPES, GRAPH_SCOPE_REQUEST,
};

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::collections::{BTreeMap, HashMap};
    use std::io::Read;
    use std::sync::Mutex;

    use super::client::{
        GraphCancellation, GraphClient, GraphTransport, GraphTransportFailure,
        MAX_GRAPH_RESPONSE_BYTES,
    };
    use super::{
        project_graph_auth_status, GraphAppInfo, GraphAuthStatus, GraphHttpMethod,
        GraphResolutionResult, GraphTransportRequest, GraphTransportResponse, GRAPH_SCOPE_REQUEST,
    };
    use crate::error::AppError;

    // ── Public types ────────────────────────────────────────────────────────────

    // ── Token cache ─────────────────────────────────────────────────────────────

    #[derive(Default)]
    pub struct GraphAuthState {
        access_token: Mutex<Option<CachedToken>>,
        guid_cache: Mutex<HashMap<String, GraphAppInfo>>,
    }

    #[derive(Clone)]
    struct CachedToken {
        token: String,
        status: GraphAuthStatus,
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    impl GraphAuthState {
        pub fn new() -> Self {
            Self::default()
        }

        fn get_valid_token(&self) -> Option<CachedToken> {
            let mut guard = self.access_token.lock().unwrap();
            let is_valid = guard
                .as_ref()
                .and_then(|token| token.status.expires_at)
                .is_some_and(|expires_at| expires_at > unix_now());
            if is_valid {
                guard.clone()
            } else {
                *guard = None;
                None
            }
        }

        fn set_token(&self, token: CachedToken) {
            *self.access_token.lock().unwrap() = Some(token);
        }

        fn clear_token(&self) {
            *self.access_token.lock().unwrap() = None;
        }

        fn get_cached_app(&self, guid: &str) -> Option<GraphAppInfo> {
            self.guid_cache.lock().unwrap().get(guid).cloned()
        }

        fn cache_apps(&self, apps: &HashMap<String, GraphAppInfo>) {
            let mut cache = self.guid_cache.lock().unwrap();
            for (k, v) in apps {
                cache.insert(k.clone(), v.clone());
            }
        }
    }

    // ── WAM token acquisition (Windows only) ────────────────────────────────────

    /// Well-known Microsoft Graph PowerShell client ID (public client, no app reg needed).
    const GRAPH_POWERSHELL_CLIENT_ID: &str = "14d82eec-204b-4c2f-b7e8-296a70dab67e";

    mod wam {
        use super::*;

        use windows::core::{factory, HSTRING};
        use windows::Security::Authentication::Web::Core::{
            WebAuthenticationCoreManager, WebTokenRequest, WebTokenRequestResult,
            WebTokenRequestStatus,
        };
        use windows::Win32::Foundation::HWND;
        use windows::Win32::System::WinRT::IWebAuthenticationCoreManagerInterop;
        use windows_future::IAsyncOperation;

        /// Acquire a token via WAM using the Win32 interop path.
        ///
        /// Desktop (Win32) apps don't have a CoreWindow, so we must use
        /// `IWebAuthenticationCoreManagerInterop::RequestTokenForWindowAsync`
        /// with an explicit HWND instead of the UWP `RequestTokenAsync`.
        pub fn acquire_token(hwnd_raw: isize) -> Result<CachedToken, AppError> {
            let hwnd = HWND(hwnd_raw as *mut _);

            // Provider lookup doesn't need a window
            let authority = HSTRING::from("organizations");
            let provider = WebAuthenticationCoreManager::FindAccountProviderWithAuthorityAsync(
                &HSTRING::from("https://login.microsoft.com"),
                &authority,
            )
            .map_err(|e| AppError::Internal(format!("WAM provider lookup failed: {e}")))?
            .join()
            .map_err(|e| AppError::Internal(format!("WAM provider await failed: {e}")))?;

            // WAM v2 scope model: request only the five delegated Intune read
            // capabilities and do not attach a v1 `resource` property.
            let scope = HSTRING::from(GRAPH_SCOPE_REQUEST);
            let client_id = HSTRING::from(GRAPH_POWERSHELL_CLIENT_ID);
            let request = WebTokenRequest::Create(&provider, &scope, &client_id)
                .map_err(|e| AppError::Internal(format!("WAM request creation failed: {e}")))?;

            // Use the COM interop interface to pass our HWND
            let interop: IWebAuthenticationCoreManagerInterop =
                factory::<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerInterop>()
                    .map_err(|e| AppError::Internal(format!("WAM interop factory failed: {e}")))?;

            let operation: IAsyncOperation<WebTokenRequestResult> =
                unsafe { interop.RequestTokenForWindowAsync(hwnd, &request) }
                    .map_err(|e| AppError::Internal(format!("WAM token request failed: {e}")))?;

            let result = operation
                .join()
                .map_err(|e| AppError::Internal(format!("WAM token await failed: {e}")))?;

            let status = result
                .ResponseStatus()
                .map_err(|e| AppError::Internal(format!("WAM status check failed: {e}")))?;

            match status {
                WebTokenRequestStatus::Success => {
                    let responses = result
                        .ResponseData()
                        .map_err(|e| AppError::Internal(format!("WAM response data: {e}")))?;
                    let response = responses
                        .GetAt(0)
                        .map_err(|e| AppError::Internal(format!("WAM response index: {e}")))?;

                    let token = response
                        .Token()
                        .map_err(|e| AppError::Internal(format!("WAM token extract: {e}")))?
                        .to_string();

                    if token.is_empty() {
                        return Err(AppError::Internal(
                            "WAM returned Success but the access token is empty. \
                             The delegated scope request did not return usable credentials."
                                .into(),
                        ));
                    }

                    let upn = response
                        .WebAccount()
                        .ok()
                        .and_then(|acct| acct.UserName().ok())
                        .map(|s| s.to_string());

                    let tenant = response
                        .Properties()
                        .ok()
                        .and_then(|props| props.Lookup(&HSTRING::from("TenantId")).ok())
                        .map(|s| s.to_string());

                    let status = project_graph_auth_status(
                        &token,
                        upn.as_deref(),
                        tenant.as_deref(),
                        unix_now(),
                    );
                    if !status.is_authenticated {
                        return Err(AppError::Internal(
                            status
                                .error
                                .clone()
                                .unwrap_or_else(|| "InvalidWamToken".to_string()),
                        ));
                    }

                    Ok(CachedToken { token, status })
                }
                WebTokenRequestStatus::UserCancel => Err(AppError::Internal(
                    "Authentication was cancelled by user.".into(),
                )),
                WebTokenRequestStatus::UserInteractionRequired => Err(AppError::Internal(
                    "Interactive authentication required. Please sign in to Windows with your Entra ID account first.".into(),
                )),
                _ => {
                    let error_msg = result
                        .ResponseError()
                        .ok()
                        .and_then(|e| e.ErrorMessage().ok())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "Unknown WAM error".to_string());
                    Err(AppError::Internal(format!(
                        "WAM authentication failed: {error_msg}"
                    )))
                }
            }
        }
    }

    // ── Graph API calls ─────────────────────────────────────────────────────────

    const GRAPH_BETA_BASE: &str = "https://graph.microsoft.com/beta";

    struct UreqGraphTransport<'a> {
        access_token: &'a str,
    }

    impl GraphTransport for UreqGraphTransport<'_> {
        fn execute(
            &self,
            request: &GraphTransportRequest,
            timeout: std::time::Duration,
        ) -> Result<GraphTransportResponse, GraphTransportFailure> {
            let agent = ureq::Agent::config_builder()
                .https_only(true)
                .http_status_as_error(false)
                .max_redirects(0)
                .timeout_global(Some(timeout))
                .build()
                .new_agent();
            let authorization = format!("Bearer {}", self.access_token);

            let response = match request.method {
                GraphHttpMethod::Get => {
                    let mut builder = agent
                        .get(&request.url)
                        .header("Authorization", &authorization);
                    if let Some(consistency) = &request.consistency_level {
                        builder = builder.header("ConsistencyLevel", consistency);
                    }
                    builder.call()
                }
                GraphHttpMethod::Post => {
                    let mut builder = agent
                        .post(&request.url)
                        .header("Authorization", &authorization);
                    if let Some(consistency) = &request.consistency_level {
                        builder = builder.header("ConsistencyLevel", consistency);
                    }
                    if let Some(content_type) = &request.content_type {
                        builder = builder.header("Content-Type", content_type);
                    }
                    match &request.body {
                        Some(body) => builder.send(body.as_slice()),
                        None => builder.send_empty(),
                    }
                }
            }
            .map_err(map_ureq_transport_error)?;

            bounded_transport_response(response)
        }
    }

    struct NoGraphCancellation;

    impl GraphCancellation for NoGraphCancellation {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn wait_for_retry(&self, duration: std::time::Duration) -> bool {
            std::thread::sleep(duration);
            true
        }
    }

    fn map_ureq_transport_error(error: ureq::Error) -> GraphTransportFailure {
        match error {
            ureq::Error::Timeout(_) => GraphTransportFailure::Timeout,
            _ => GraphTransportFailure::Network,
        }
    }

    fn bounded_transport_response(
        response: ureq::http::Response<ureq::Body>,
    ) -> Result<GraphTransportResponse, GraphTransportFailure> {
        let (parts, body) = response.into_parts();
        let headers: BTreeMap<String, String> = parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect();
        let mut bytes = Vec::new();
        body.into_reader()
            .take((MAX_GRAPH_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) {
                    GraphTransportFailure::Timeout
                } else {
                    GraphTransportFailure::Network
                }
            })?;

        Ok(GraphTransportResponse {
            status: parts.status.as_u16(),
            headers,
            body: bytes,
        })
    }

    /// Helper: parse a ureq response body as JSON.
    fn read_json(
        response: ureq::http::Response<ureq::Body>,
    ) -> Result<serde_json::Value, AppError> {
        let body = response
            .into_body()
            .read_to_string()
            .map_err(|e| AppError::Internal(format!("Failed to read response body: {e}")))?;
        serde_json::from_str(&body)
            .map_err(|e| AppError::Internal(format!("Failed to parse JSON: {e}")))
    }

    /// Helper: extract a GraphAppInfo from a JSON object.
    fn parse_app_json(item: &serde_json::Value) -> Option<GraphAppInfo> {
        let id = item.get("id").and_then(|v| v.as_str())?;
        let name = item.get("displayName").and_then(|v| v.as_str())?;
        Some(GraphAppInfo {
            id: id.to_lowercase(),
            display_name: name.to_string(),
            publisher: item
                .get("publisher")
                .and_then(|v| v.as_str())
                .map(String::from),
            odata_type: item
                .get("@odata.type")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    }

    fn make_agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_recv_body(Some(std::time::Duration::from_secs(30)))
            .timeout_send_body(Some(std::time::Duration::from_secs(10)))
            .build()
            .new_agent()
    }

    /// Authenticate with Graph API via WAM. Returns current auth status.
    /// `hwnd_raw` is the native window handle for the WAM dialog.
    pub fn authenticate(
        state: &GraphAuthState,
        hwnd_raw: isize,
    ) -> Result<GraphAuthStatus, AppError> {
        if let Some(cached) = state.get_valid_token() {
            return Ok(cached.status);
        }

        match wam::acquire_token(hwnd_raw) {
            Ok(token) => {
                let status = token.status.clone();
                state.set_token(token);
                Ok(status)
            }
            Err(e) => {
                state.clear_token();
                Ok(GraphAuthStatus::disconnected(Some(e.to_string())))
            }
        }
    }

    /// Get current auth status without triggering a new auth flow.
    pub fn get_auth_status(state: &GraphAuthState) -> GraphAuthStatus {
        match state.get_valid_token() {
            Some(cached) => cached.status,
            None => GraphAuthStatus::disconnected(None),
        }
    }

    /// Sign out — clear cached token and GUID cache.
    pub fn sign_out(state: &GraphAuthState) {
        state.clear_token();
        *state.guid_cache.lock().unwrap() = HashMap::new();
    }

    /// Resolve a batch of GUIDs to app display names via Graph API.
    pub fn resolve_guids(
        state: &GraphAuthState,
        guids: &[String],
    ) -> Result<GraphResolutionResult, AppError> {
        let token = state
            .get_valid_token()
            .ok_or_else(|| AppError::Internal("Not authenticated. Please sign in first.".into()))?;

        let mut resolved: HashMap<String, GraphAppInfo> = HashMap::new();
        let mut to_fetch: Vec<String> = Vec::new();

        for guid in guids {
            let normalized = guid.to_lowercase();
            if let Some(cached) = state.get_cached_app(&normalized) {
                resolved.insert(normalized, cached);
            } else {
                to_fetch.push(normalized);
            }
        }

        if to_fetch.is_empty() {
            return Ok(GraphResolutionResult {
                resolved,
                not_found: vec![],
                errors: vec![],
            });
        }

        let mut not_found = Vec::new();
        let mut errors = Vec::new();

        // Graph $batch supports max 20 requests per batch
        for chunk in to_fetch.chunks(20) {
            match fetch_apps_batch(&token.token, chunk) {
                Ok(batch_result) => {
                    for (guid, info) in &batch_result.resolved {
                        resolved.insert(guid.clone(), info.clone());
                    }
                    not_found.extend(batch_result.not_found);
                    errors.extend(batch_result.errors);
                }
                Err(e) => {
                    errors.push(format!("Batch request failed: {e}"));
                    for guid in chunk {
                        match fetch_single_app(&token.token, guid) {
                            Ok(Some(info)) => {
                                resolved.insert(guid.clone(), info);
                            }
                            Ok(None) => not_found.push(guid.clone()),
                            Err(e) => errors.push(format!("{guid}: {e}")),
                        }
                    }
                }
            }
        }

        state.cache_apps(&resolved);

        Ok(GraphResolutionResult {
            resolved,
            not_found,
            errors,
        })
    }

    /// Fetch all Intune apps, scripts, and remediations for pre-populating the cache.
    pub fn fetch_all_apps(state: &GraphAuthState) -> Result<Vec<GraphAppInfo>, AppError> {
        let token = state
            .get_valid_token()
            .ok_or_else(|| AppError::Internal("Not authenticated. Please sign in first.".into()))?;

        let mut all: Vec<GraphAppInfo> = Vec::new();

        // Win32/LOB/Store apps
        all.extend(fetch_paginated(
            &token.token,
            &format!(
                "{GRAPH_BETA_BASE}/deviceAppManagement/mobileApps?$select=id,displayName,publisher"
            ),
            None,
            "DeviceManagementApps.Read.All",
        )?);

        // Proactive Remediations (Health Scripts)
        match fetch_paginated(
        &token.token,
        &format!("{GRAPH_BETA_BASE}/deviceManagement/deviceHealthScripts?$select=id,displayName,publisher"),
        Some("#microsoft.graph.deviceHealthScript"),
        "DeviceManagementScripts.Read.All",
    ) {
        Ok(items) => all.extend(items),
        Err(e) => log::warn!("event=graph_skip_health_scripts error=\"{e}\""),
    }

        // Platform scripts (PowerShell scripts deployed via Intune)
        match fetch_paginated(
            &token.token,
            &format!(
                "{GRAPH_BETA_BASE}/deviceManagement/deviceManagementScripts?$select=id,displayName"
            ),
            Some("#microsoft.graph.deviceManagementScript"),
            "DeviceManagementScripts.Read.All",
        ) {
            Ok(items) => all.extend(items),
            Err(e) => log::warn!("event=graph_skip_device_scripts error=\"{e}\""),
        }

        // Shell scripts (macOS)
        match fetch_paginated(
            &token.token,
            &format!(
                "{GRAPH_BETA_BASE}/deviceManagement/deviceShellScripts?$select=id,displayName"
            ),
            Some("#microsoft.graph.deviceShellScript"),
            "DeviceManagementScripts.Read.All",
        ) {
            Ok(items) => all.extend(items),
            Err(e) => log::warn!("event=graph_skip_shell_scripts error=\"{e}\""),
        }

        let cache_map: HashMap<String, GraphAppInfo> =
            all.iter().map(|a| (a.id.clone(), a.clone())).collect();
        state.cache_apps(&cache_map);

        Ok(all)
    }

    /// Fetch all items from a paginated Graph API endpoint.
    /// `default_type` is used when the response items don't include `@odata.type`.
    fn fetch_paginated(
        token: &str,
        initial_url: &str,
        default_type: Option<&str>,
        required_scope: &str,
    ) -> Result<Vec<GraphAppInfo>, AppError> {
        let transport = UreqGraphTransport {
            access_token: token,
        };
        let cancellation = NoGraphCancellation;
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
        let values = client
            .get_paginated::<serde_json::Value>(initial_url, required_scope)
            .map_err(|error| AppError::Internal(error.to_string()))?;

        Ok(values
            .iter()
            .filter_map(|item| {
                let mut app = parse_app_json(item)?;
                if app.odata_type.is_none() {
                    app.odata_type = default_type.map(String::from);
                }
                Some(app)
            })
            .collect())
    }

    // ── Internal helpers ────────────────────────────────────────────────────────

    fn fetch_apps_batch(token: &str, guids: &[String]) -> Result<GraphResolutionResult, AppError> {
        let requests: Vec<serde_json::Value> = guids
        .iter()
        .enumerate()
        .map(|(i, guid)| {
            serde_json::json!({
                "id": i.to_string(),
                "method": "GET",
                "url": format!("/deviceAppManagement/mobileApps/{guid}?$select=id,displayName,publisher")
            })
        })
        .collect();

        let batch_body = serde_json::json!({ "requests": requests });
        let body_str = serde_json::to_string(&batch_body)
            .map_err(|e| AppError::Internal(format!("JSON serialize failed: {e}")))?;

        let agent = make_agent();
        let response = agent
            .post(&format!("{GRAPH_BETA_BASE}/$batch"))
            .header("Authorization", &format!("Bearer {token}"))
            .content_type("application/json")
            .send(&body_str)
            .map_err(|e| AppError::Internal(format!("Graph batch request failed: {e}")))?;

        let body = read_json(response)?;

        let mut resolved = HashMap::new();
        let mut not_found = Vec::new();
        let mut errors = Vec::new();

        if let Some(responses) = body.get("responses").and_then(|v| v.as_array()) {
            for resp in responses {
                let id_str = resp.get("id").and_then(|v| v.as_str()).unwrap_or("0");
                let idx: usize = id_str.parse().unwrap_or(0);
                let status = resp.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
                let guid = guids.get(idx).cloned().unwrap_or_default();

                if status == 200 {
                    if let Some(resp_body) = resp.get("body") {
                        if let Some(app) = parse_app_json(resp_body) {
                            resolved.insert(app.id.clone(), app);
                        }
                    }
                } else if status == 404 {
                    not_found.push(guid);
                } else {
                    let msg = resp
                        .get("body")
                        .and_then(|b| b.get("error"))
                        .and_then(|e| e.get("message"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("Unknown error");
                    errors.push(format!("{guid}: HTTP {status} - {msg}"));
                }
            }
        }

        Ok(GraphResolutionResult {
            resolved,
            not_found,
            errors,
        })
    }

    fn fetch_single_app(token: &str, guid: &str) -> Result<Option<GraphAppInfo>, AppError> {
        let agent = make_agent();
        let url = format!(
        "{GRAPH_BETA_BASE}/deviceAppManagement/mobileApps/{guid}?$select=id,displayName,publisher"
    );

        match agent
            .get(&url)
            .header("Authorization", &format!("Bearer {token}"))
            .call()
        {
            Ok(response) => {
                let body = read_json(response)?;
                Ok(parse_app_json(&body))
            }
            Err(ureq::Error::StatusCode(404)) => Ok(None),
            Err(e) => Err(AppError::Internal(format!("Graph request failed: {e}"))),
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::*;
