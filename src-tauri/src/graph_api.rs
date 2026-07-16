//! Microsoft Graph API integration.
//!
//! Portable models compile on every platform. The existing WAM token cache and
//! concrete HTTP implementation remain Windows-only and user-opt-in.

pub mod client;
pub mod models;

pub use models::{
    normalize_graph_guid, project_graph_auth_status, GraphAppInfo, GraphAuthCapabilities,
    GraphAuthStatus, GraphHttpMethod, GraphResolutionResult, GraphTransportRequest,
    GraphTransportResponse, GRAPH_DELEGATED_SCOPES, GRAPH_SCOPE_REQUEST,
};

#[cfg(any(target_os = "windows", test))]
#[derive(Default)]
struct VersionedGuidCache {
    generation: u64,
    apps: std::collections::HashMap<String, GraphAppInfo>,
}

#[cfg(any(target_os = "windows", test))]
impl VersionedGuidCache {
    fn get(&self, generation: u64, guid: &str) -> Option<GraphAppInfo> {
        (self.generation == generation)
            .then(|| self.apps.get(guid).cloned())
            .flatten()
    }

    fn insert_all(
        &mut self,
        generation: u64,
        apps: &std::collections::HashMap<String, GraphAppInfo>,
    ) {
        if self.generation != generation {
            return;
        }
        for (key, app) in apps {
            self.apps.insert(key.clone(), app.clone());
        }
    }

    fn replace_all(
        &mut self,
        generation: u64,
        apps: std::collections::HashMap<String, GraphAppInfo>,
    ) {
        if self.generation == generation {
            self.apps = apps;
        }
    }

    fn reset_to(&mut self, generation: u64) {
        if generation <= self.generation {
            return;
        }
        self.generation = generation;
        self.apps.clear();
    }
}

#[cfg(any(target_os = "windows", test))]
struct VersionedAuthSlot<T> {
    generation: u64,
    value: Option<T>,
}

#[cfg(any(target_os = "windows", test))]
impl<T> Default for VersionedAuthSlot<T> {
    fn default() -> Self {
        Self {
            generation: 0,
            value: None,
        }
    }
}

#[cfg(any(target_os = "windows", test))]
impl<T> VersionedAuthSlot<T> {
    fn replace(&mut self, value: Option<T>) -> u64 {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("Graph auth generation exhausted");
        self.value = value;
        self.generation
    }

    fn replace_if_generation(&mut self, expected: u64, value: Option<T>) -> Option<u64> {
        if self.generation != expected {
            return None;
        }
        Some(self.replace(value))
    }
}

#[cfg(any(target_os = "windows", test))]
fn invalid_graph_app_response(required_scope: &str) -> client::GraphClientError {
    client::GraphClientError::new(
        client::GraphClientErrorKind::InvalidResponse,
        required_scope,
    )
}

#[cfg(any(target_os = "windows", test))]
fn optional_graph_string(
    item: &serde_json::Value,
    key: &str,
    required_scope: &str,
) -> Result<Option<String>, client::GraphClientError> {
    match item.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid_graph_app_response(required_scope)),
    }
}

#[cfg(any(target_os = "windows", test))]
fn parse_graph_app_json(
    item: &serde_json::Value,
    default_type: Option<&str>,
    expected_id: Option<&str>,
    required_scope: &str,
) -> Result<GraphAppInfo, client::GraphClientError> {
    let id = item
        .get("id")
        .and_then(serde_json::Value::as_str)
        .and_then(normalize_graph_guid)
        .ok_or_else(|| invalid_graph_app_response(required_scope))?;
    if expected_id.is_some_and(|expected| id != expected) {
        return Err(invalid_graph_app_response(required_scope));
    }
    let display_name = item
        .get("displayName")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_graph_app_response(required_scope))?
        .to_string();
    let publisher = optional_graph_string(item, "publisher", required_scope)?;
    let odata_type = optional_graph_string(item, "@odata.type", required_scope)?
        .or_else(|| default_type.map(String::from));

    Ok(GraphAppInfo {
        id,
        display_name,
        publisher,
        odata_type,
    })
}

#[cfg(any(target_os = "windows", test))]
fn parse_graph_app_values(
    values: &[serde_json::Value],
    default_type: Option<&str>,
    required_scope: &str,
) -> Result<Vec<GraphAppInfo>, client::GraphClientError> {
    values
        .iter()
        .map(|item| parse_graph_app_json(item, default_type, None, required_scope))
        .collect()
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::io::Read;
    use std::sync::Mutex;

    use super::client::{
        resolve_app_chunk_with_fallback, GraphBatchItem, GraphCancellation, GraphClient,
        GraphClientError, GraphClientErrorKind, GraphTransport, GraphTransportFailure,
        MAX_GRAPH_RESPONSE_BYTES,
    };
    use super::{
        normalize_graph_guid, parse_graph_app_json, parse_graph_app_values,
        project_graph_auth_status, GraphAppInfo, GraphAuthStatus, GraphHttpMethod,
        GraphResolutionResult, GraphTransportRequest, GraphTransportResponse, VersionedAuthSlot,
        VersionedGuidCache, GRAPH_SCOPE_REQUEST,
    };
    use crate::error::AppError;

    // ── Public types ────────────────────────────────────────────────────────────

    // ── Token cache ─────────────────────────────────────────────────────────────

    #[derive(Default)]
    pub struct GraphAuthState {
        access_token: Mutex<VersionedAuthSlot<CachedToken>>,
        guid_cache: Mutex<VersionedGuidCache>,
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

        fn get_valid_token_snapshot(&self) -> (Option<CachedToken>, u64) {
            let mut guard = self.access_token.lock().unwrap();
            let is_valid = guard
                .value
                .as_ref()
                .and_then(|token| token.status.expires_at)
                .is_some_and(|expires_at| expires_at > unix_now());
            if is_valid {
                return (guard.value.clone(), guard.generation);
            }

            if guard.value.is_none() {
                return (None, guard.generation);
            }

            let generation = guard.replace(None);
            drop(guard);
            self.guid_cache.lock().unwrap().reset_to(generation);
            (None, generation)
        }

        fn get_valid_token(&self) -> Option<(CachedToken, u64)> {
            let (token, generation) = self.get_valid_token_snapshot();
            token.map(|token| (token, generation))
        }

        fn claim_authentication(&self) -> Result<CachedToken, u64> {
            let mut guard = self.access_token.lock().unwrap();
            let is_valid = guard
                .value
                .as_ref()
                .and_then(|token| token.status.expires_at)
                .is_some_and(|expires_at| expires_at > unix_now());
            if is_valid {
                return Ok(guard
                    .value
                    .clone()
                    .expect("validated Graph token must remain present"));
            }

            let generation = guard.replace(None);
            drop(guard);
            self.guid_cache.lock().unwrap().reset_to(generation);
            Err(generation)
        }

        fn set_token_if_generation(&self, expected: u64, token: CachedToken) -> bool {
            let mut guard = self.access_token.lock().unwrap();
            let Some(generation) = guard.replace_if_generation(expected, Some(token)) else {
                return false;
            };
            drop(guard);
            self.guid_cache.lock().unwrap().reset_to(generation);
            true
        }

        fn clear_token_if_generation(&self, expected: u64) -> bool {
            let mut guard = self.access_token.lock().unwrap();
            let Some(generation) = guard.replace_if_generation(expected, None) else {
                return false;
            };
            drop(guard);
            self.guid_cache.lock().unwrap().reset_to(generation);
            true
        }

        fn clear_token(&self) {
            let mut guard = self.access_token.lock().unwrap();
            let generation = guard.replace(None);
            drop(guard);
            self.guid_cache.lock().unwrap().reset_to(generation);
        }

        fn get_cached_app(&self, generation: u64, guid: &str) -> Option<GraphAppInfo> {
            self.guid_cache.lock().unwrap().get(generation, guid)
        }

        fn cache_apps(&self, generation: u64, apps: &HashMap<String, GraphAppInfo>) {
            self.guid_cache.lock().unwrap().insert_all(generation, apps);
        }

        fn replace_apps(&self, generation: u64, apps: HashMap<String, GraphAppInfo>) {
            self.guid_cache
                .lock()
                .unwrap()
                .replace_all(generation, apps);
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
    const MAX_GRAPH_RESOLUTION_IDS: usize = 5_000;

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

    fn graph_request_error(
        state: &GraphAuthState,
        generation: u64,
        error: GraphClientError,
    ) -> AppError {
        if error.invalidates_auth() {
            state.clear_token_if_generation(generation);
        }
        AppError::Internal(error.to_string())
    }

    fn current_auth_status(state: &GraphAuthState) -> GraphAuthStatus {
        state
            .get_valid_token()
            .map(|(cached, _)| cached.status)
            .unwrap_or_else(|| GraphAuthStatus::disconnected(None))
    }

    /// Authenticate with Graph API via WAM. Returns current auth status.
    /// `hwnd_raw` is the native window handle for the WAM dialog.
    pub fn authenticate(
        state: &GraphAuthState,
        hwnd_raw: isize,
    ) -> Result<GraphAuthStatus, AppError> {
        let expected_generation = match state.claim_authentication() {
            Ok(cached) => return Ok(cached.status),
            Err(generation) => generation,
        };

        match wam::acquire_token(hwnd_raw) {
            Ok(token) => {
                let status = token.status.clone();
                if state.set_token_if_generation(expected_generation, token) {
                    Ok(status)
                } else {
                    Ok(current_auth_status(state))
                }
            }
            Err(e) => {
                if state.clear_token_if_generation(expected_generation) {
                    Ok(GraphAuthStatus::disconnected(Some(e.to_string())))
                } else {
                    Ok(current_auth_status(state))
                }
            }
        }
    }

    /// Get current auth status without triggering a new auth flow.
    pub fn get_auth_status(state: &GraphAuthState) -> GraphAuthStatus {
        current_auth_status(state)
    }

    /// Sign out — clear cached token and GUID cache.
    pub fn sign_out(state: &GraphAuthState) {
        state.clear_token();
    }

    /// Resolve a batch of GUIDs to app display names via Graph API.
    pub fn resolve_guids(
        state: &GraphAuthState,
        guids: &[String],
    ) -> Result<GraphResolutionResult, AppError> {
        if guids.len() > MAX_GRAPH_RESOLUTION_IDS {
            return Err(AppError::Internal(format!(
                "Graph app resolution is limited to {MAX_GRAPH_RESOLUTION_IDS} identifiers."
            )));
        }
        let (token, generation) = state
            .get_valid_token()
            .ok_or_else(|| AppError::Internal("Not authenticated. Please sign in first.".into()))?;

        let mut resolved: HashMap<String, GraphAppInfo> = HashMap::new();
        let mut to_fetch: Vec<String> = Vec::new();
        let mut queued = HashSet::new();
        let mut invalid_identifiers = 0_usize;

        for guid in guids {
            let Some(normalized) = normalize_graph_guid(guid) else {
                invalid_identifiers += 1;
                continue;
            };
            if let Some(cached) = state.get_cached_app(generation, &normalized) {
                resolved.insert(normalized, cached);
            } else if queued.insert(normalized.clone()) {
                to_fetch.push(normalized);
            }
        }

        let mut errors = Vec::new();
        if invalid_identifiers > 0 {
            errors.push(format!(
                "Skipped {invalid_identifiers} invalid app identifier(s)."
            ));
        }

        if to_fetch.is_empty() {
            return Ok(GraphResolutionResult {
                resolved,
                not_found: vec![],
                errors,
            });
        }

        let mut not_found = Vec::new();

        // Graph $batch supports max 20 requests per batch
        for chunk in to_fetch.chunks(20) {
            let chunk_result = resolve_app_chunk_with_fallback(
                chunk,
                |guids| fetch_apps_batch(&token.token, guids),
                |guid| fetch_single_app(&token.token, guid),
            )
            .map_err(|error| graph_request_error(state, generation, error))?;

            for (guid, info) in chunk_result.resolved {
                resolved.insert(guid, info);
            }
            not_found.extend(chunk_result.not_found);
            errors.extend(chunk_result.errors);
        }

        state.cache_apps(generation, &resolved);

        Ok(GraphResolutionResult {
            resolved,
            not_found,
            errors,
        })
    }

    /// Fetch all Intune apps, scripts, and remediations for pre-populating the cache.
    pub fn fetch_all_apps(state: &GraphAuthState) -> Result<Vec<GraphAppInfo>, AppError> {
        let (token, generation) = state
            .get_valid_token()
            .ok_or_else(|| AppError::Internal("Not authenticated. Please sign in first.".into()))?;

        let mut all: Vec<GraphAppInfo> = Vec::new();

        // Win32/LOB/Store apps
        all.extend(
            fetch_paginated(
                &token.token,
                &format!(
                    "{GRAPH_BETA_BASE}/deviceAppManagement/mobileApps?$select=id,displayName,publisher"
                ),
                None,
                "DeviceManagementApps.Read.All",
            )
            .map_err(|error| graph_request_error(state, generation, error))?,
        );

        // Proactive Remediations (Health Scripts)
        match fetch_paginated(
        &token.token,
        &format!("{GRAPH_BETA_BASE}/deviceManagement/deviceHealthScripts?$select=id,displayName,publisher"),
        Some("#microsoft.graph.deviceHealthScript"),
        "DeviceManagementScripts.Read.All",
    ) {
        Ok(items) => all.extend(items),
        Err(error) if error.invalidates_auth() => {
            return Err(graph_request_error(state, generation, error));
        }
        Err(error) => log::warn!("event=graph_skip_health_scripts error=\"{error}\""),
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
            Err(error) if error.invalidates_auth() => {
                return Err(graph_request_error(state, generation, error));
            }
            Err(error) => {
                log::warn!("event=graph_skip_device_scripts error=\"{error}\"");
            }
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
            Err(error) if error.invalidates_auth() => {
                return Err(graph_request_error(state, generation, error));
            }
            Err(error) => log::warn!("event=graph_skip_shell_scripts error=\"{error}\""),
        }

        let cache_map: HashMap<String, GraphAppInfo> =
            all.iter().map(|a| (a.id.clone(), a.clone())).collect();
        state.replace_apps(generation, cache_map);

        Ok(all)
    }

    /// Fetch all items from a paginated Graph API endpoint.
    /// `default_type` is used when the response items don't include `@odata.type`.
    fn fetch_paginated(
        token: &str,
        initial_url: &str,
        default_type: Option<&str>,
        required_scope: &str,
    ) -> Result<Vec<GraphAppInfo>, GraphClientError> {
        let transport = UreqGraphTransport {
            access_token: token,
        };
        let cancellation = NoGraphCancellation;
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
        let values = client.get_paginated::<serde_json::Value>(initial_url, required_scope)?;
        parse_graph_app_values(&values, default_type, required_scope)
    }

    // ── Internal helpers ────────────────────────────────────────────────────────

    fn fetch_apps_batch(
        token: &str,
        guids: &[String],
    ) -> Result<GraphResolutionResult, GraphClientError> {
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
        let body_bytes = serde_json::to_vec(&batch_body).map_err(|_| {
            GraphClientError::new(
                GraphClientErrorKind::InvalidResponse,
                "DeviceManagementApps.Read.All",
            )
        })?;
        let transport = UreqGraphTransport {
            access_token: token,
        };
        let cancellation = NoGraphCancellation;
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
        let outcomes = client.request_batch_json::<serde_json::Value>(GraphTransportRequest {
            method: GraphHttpMethod::Post,
            url: format!("{GRAPH_BETA_BASE}/$batch"),
            consistency_level: None,
            content_type: Some("application/json".to_string()),
            body: Some(body_bytes),
            required_scope: "DeviceManagementApps.Read.All".to_string(),
        })?;

        let mut resolved = HashMap::new();
        let mut not_found = Vec::new();

        for (guid, outcome) in guids.iter().zip(outcomes) {
            match outcome {
                GraphBatchItem::Success(body) => {
                    let app = parse_graph_app_json(
                        &body,
                        None,
                        Some(guid),
                        "DeviceManagementApps.Read.All",
                    )?;
                    resolved.insert(app.id.clone(), app);
                }
                GraphBatchItem::NotFound => not_found.push(guid.clone()),
            }
        }

        Ok(GraphResolutionResult {
            resolved,
            not_found,
            errors: Vec::new(),
        })
    }

    fn fetch_single_app(token: &str, guid: &str) -> Result<Option<GraphAppInfo>, GraphClientError> {
        let url = format!(
        "{GRAPH_BETA_BASE}/deviceAppManagement/mobileApps/{guid}?$select=id,displayName,publisher"
    );
        let transport = UreqGraphTransport {
            access_token: token,
        };
        let cancellation = NoGraphCancellation;
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
        let request = GraphTransportRequest {
            method: GraphHttpMethod::Get,
            url,
            consistency_level: None,
            content_type: None,
            body: None,
            required_scope: "DeviceManagementApps.Read.All".to_string(),
        };

        match client.request_json::<serde_json::Value>(request) {
            Ok(body) => {
                parse_graph_app_json(&body, None, Some(guid), "DeviceManagementApps.Read.All")
                    .map(Some)
            }
            Err(error) if error.kind == GraphClientErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::client::GraphClientErrorKind;
    use super::{
        parse_graph_app_json, parse_graph_app_values, GraphAppInfo, VersionedAuthSlot,
        VersionedGuidCache,
    };

    const APP_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const APP_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const APP_SCOPE: &str = "DeviceManagementApps.Read.All";

    fn app(id: &str, name: &str) -> GraphAppInfo {
        GraphAppInfo {
            id: id.to_string(),
            display_name: name.to_string(),
            publisher: None,
            odata_type: None,
        }
    }

    #[test]
    fn graph_guid_cache_rejects_stale_results_across_auth_generations() {
        let mut cache = VersionedGuidCache::default();
        cache.reset_to(7);
        cache.insert_all(
            7,
            &HashMap::from([("app-a".to_string(), app("app-a", "Tenant A"))]),
        );
        assert_eq!(
            cache.get(7, "app-a").map(|app| app.display_name),
            Some("Tenant A".to_string())
        );

        cache.reset_to(8);
        assert!(cache.get(8, "app-a").is_none());

        cache.insert_all(
            7,
            &HashMap::from([("app-stale".to_string(), app("app-stale", "Stale tenant"))]),
        );
        assert!(cache.get(8, "app-stale").is_none());

        cache.insert_all(
            8,
            &HashMap::from([("app-b".to_string(), app("app-b", "Tenant B"))]),
        );
        cache.reset_to(7);
        assert_eq!(
            cache.get(8, "app-b").map(|app| app.display_name),
            Some("Tenant B".to_string())
        );
    }

    #[test]
    fn graph_guid_cache_full_snapshot_replaces_same_generation_entries() {
        let mut cache = VersionedGuidCache::default();
        cache.reset_to(7);
        cache.insert_all(
            7,
            &HashMap::from([("app-stale".to_string(), app("app-stale", "Old name"))]),
        );

        cache.replace_all(
            7,
            HashMap::from([("app-current".to_string(), app("app-current", "Current"))]),
        );

        assert!(cache.get(7, "app-stale").is_none());
        assert_eq!(
            cache.get(7, "app-current").map(|app| app.display_name),
            Some("Current".to_string())
        );

        cache.replace_all(
            6,
            HashMap::from([("app-wrong".to_string(), app("app-wrong", "Wrong tenant"))]),
        );
        assert!(cache.get(7, "app-wrong").is_none());
        assert!(cache.get(7, "app-current").is_some());
    }

    #[test]
    fn graph_auth_slot_rejects_stale_token_set_and_clear_mutations() {
        let mut slot = VersionedAuthSlot::default();
        let first_attempt = slot.replace(None);
        let newer_attempt = slot.replace(None);
        assert_eq!(
            slot.replace_if_generation(first_attempt, Some("token-stale")),
            None
        );
        assert_eq!(
            slot.replace_if_generation(newer_attempt, Some("token-a")),
            Some(3)
        );

        let stale_request = newer_attempt;
        let newer_generation = slot.replace(Some("token-b"));
        assert_eq!(newer_generation, 4);
        assert_eq!(slot.replace_if_generation(stale_request, None), None);
        assert_eq!(slot.value, Some("token-b"));

        assert_eq!(slot.replace_if_generation(newer_generation, None), Some(5));
        assert_eq!(slot.value, None);
    }

    #[test]
    fn successful_graph_app_payloads_require_canonical_matching_guids() {
        let canonical = parse_graph_app_json(
            &serde_json::json!({
                "id": "{AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA}",
                "displayName": "App A",
                "publisher": "Contoso"
            }),
            Some("#microsoft.graph.win32LobApp"),
            Some(APP_A),
            APP_SCOPE,
        )
        .expect("canonical response");
        assert_eq!(canonical.id, APP_A);
        assert_eq!(
            canonical.odata_type.as_deref(),
            Some("#microsoft.graph.win32LobApp")
        );

        for payload in [
            serde_json::json!({"id": "not-a-guid", "displayName": "Bad"}),
            serde_json::json!({"id": APP_A}),
            serde_json::json!({"id": APP_A, "displayName": 42}),
            serde_json::json!({"id": APP_A, "displayName": "Bad", "publisher": 42}),
            serde_json::json!({"id": APP_B, "displayName": "Wrong app"}),
        ] {
            let error = parse_graph_app_json(&payload, None, Some(APP_A), APP_SCOPE)
                .expect_err("malformed or mismatched 2xx payload must fail");
            assert_eq!(error.kind, GraphClientErrorKind::InvalidResponse);
        }
    }

    #[test]
    fn paginated_graph_app_payloads_fail_instead_of_dropping_malformed_items() {
        let values = vec![
            serde_json::json!({"id": APP_A, "displayName": "App A"}),
            serde_json::json!({"id": "bad", "displayName": "Discarded before fix"}),
        ];

        let error = parse_graph_app_values(&values, None, APP_SCOPE)
            .expect_err("one malformed successful item invalidates the page");
        assert_eq!(error.kind, GraphClientErrorKind::InvalidResponse);
    }
}
