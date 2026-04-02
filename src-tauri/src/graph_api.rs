//! Microsoft Graph API integration for GUID resolution.
//!
//! Uses WAM (Web Account Manager) for silent token acquisition on Entra-joined
//! devices. This module is Windows-only and gated behind user opt-in.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::AppError;

// ── Public types ────────────────────────────────────────────────────────────

/// Status of the Graph API connection, returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphAuthStatus {
    pub is_authenticated: bool,
    pub user_principal_name: Option<String>,
    pub tenant_id: Option<String>,
    pub error: Option<String>,
}

/// A resolved app from Graph API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphAppInfo {
    pub id: String,
    pub display_name: String,
    pub publisher: Option<String>,
    pub odata_type: Option<String>,
}

/// Batch resolution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphResolutionResult {
    pub resolved: HashMap<String, GraphAppInfo>,
    pub not_found: Vec<String>,
    pub errors: Vec<String>,
}

// ── Token cache ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct GraphAuthState {
    access_token: Mutex<Option<CachedToken>>,
    guid_cache: Mutex<HashMap<String, GraphAppInfo>>,
}

#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    user_principal_name: Option<String>,
    tenant_id: Option<String>,
    expires_at: std::time::Instant,
}

impl GraphAuthState {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_valid_token(&self) -> Option<CachedToken> {
        let guard = self.access_token.lock().unwrap();
        guard.as_ref().and_then(|t| {
            if t.expires_at > std::time::Instant::now() {
                Some(t.clone())
            } else {
                None
            }
        })
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
const GRAPH_RESOURCE: &str = "https://graph.microsoft.com";

#[cfg(target_os = "windows")]
mod wam {
    use super::*;

    use windows::core::{factory, HSTRING};
    use windows::Foundation::IAsyncOperation;
    use windows::Security::Authentication::Web::Core::{
        WebAuthenticationCoreManager, WebTokenRequest, WebTokenRequestResult,
        WebTokenRequestStatus,
    };
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::WinRT::IWebAuthenticationCoreManagerInterop;

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
        .get()
        .map_err(|e| AppError::Internal(format!("WAM provider await failed: {e}")))?;

        // WAM v1 resource model: pass empty scope, set resource via properties
        let scope = HSTRING::from("");
        let client_id = HSTRING::from(GRAPH_POWERSHELL_CLIENT_ID);
        let request = WebTokenRequest::Create(&provider, &scope, &client_id)
            .map_err(|e| AppError::Internal(format!("WAM request creation failed: {e}")))?;

        request.Properties()
            .map_err(|e| AppError::Internal(format!("WAM properties failed: {e}")))?
            .Insert(&HSTRING::from("resource"), &HSTRING::from(GRAPH_RESOURCE))
            .map_err(|e| AppError::Internal(format!("WAM set resource failed: {e}")))?;

        // Use the COM interop interface to pass our HWND
        let interop: IWebAuthenticationCoreManagerInterop =
            factory::<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerInterop>()
                .map_err(|e| AppError::Internal(format!("WAM interop factory failed: {e}")))?;

        let operation: IAsyncOperation<WebTokenRequestResult> = unsafe {
            interop.RequestTokenForWindowAsync(hwnd, &request)
        }
        .map_err(|e| AppError::Internal(format!("WAM token request failed: {e}")))?;

        let result = operation
            .get()
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
                         Ensure the resource property is set correctly.".into()
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

                Ok(CachedToken {
                    token,
                    user_principal_name: upn,
                    tenant_id: tenant,
                    expires_at: std::time::Instant::now()
                        + std::time::Duration::from_secs(50 * 60),
                })
            }
            WebTokenRequestStatus::UserCancel => {
                Err(AppError::Internal("Authentication was cancelled by user.".into()))
            }
            WebTokenRequestStatus::UserInteractionRequired => {
                Err(AppError::Internal(
                    "Interactive authentication required. Please sign in to Windows with your Entra ID account first.".into()
                ))
            }
            _ => {
                let error_msg = result
                    .ResponseError()
                    .ok()
                    .and_then(|e| e.ErrorMessage().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown WAM error".to_string());
                Err(AppError::Internal(format!("WAM authentication failed: {error_msg}")))
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod wam {
    use super::*;

    pub fn acquire_token(_hwnd_raw: isize) -> Result<CachedToken, AppError> {
        Err(AppError::PlatformUnsupported(
            "Graph API authentication via WAM is only available on Windows.".into(),
        ))
    }
}

// ── Graph API calls ─────────────────────────────────────────────────────────

const GRAPH_BETA_BASE: &str = "https://graph.microsoft.com/beta";

/// Helper: parse a ureq response body as JSON.
fn read_json(response: ureq::Response) -> Result<serde_json::Value, AppError> {
    let body = response
        .into_string()
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
        publisher: item.get("publisher").and_then(|v| v.as_str()).map(String::from),
        odata_type: item.get("@odata.type").and_then(|v| v.as_str()).map(String::from),
    })
}

fn make_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_read(std::time::Duration::from_secs(30))
        .timeout_write(std::time::Duration::from_secs(10))
        .build()
}

/// Authenticate with Graph API via WAM. Returns current auth status.
/// `hwnd_raw` is the native window handle for the WAM dialog.
pub fn authenticate(state: &GraphAuthState, hwnd_raw: isize) -> Result<GraphAuthStatus, AppError> {
    if let Some(cached) = state.get_valid_token() {
        return Ok(GraphAuthStatus {
            is_authenticated: true,
            user_principal_name: cached.user_principal_name,
            tenant_id: cached.tenant_id,
            error: None,
        });
    }

    match wam::acquire_token(hwnd_raw) {
        Ok(token) => {
            let status = GraphAuthStatus {
                is_authenticated: true,
                user_principal_name: token.user_principal_name.clone(),
                tenant_id: token.tenant_id.clone(),
                error: None,
            };
            state.set_token(token);
            Ok(status)
        }
        Err(e) => {
            state.clear_token();
            Ok(GraphAuthStatus {
                is_authenticated: false,
                user_principal_name: None,
                tenant_id: None,
                error: Some(e.to_string()),
            })
        }
    }
}

/// Get current auth status without triggering a new auth flow.
pub fn get_auth_status(state: &GraphAuthState) -> GraphAuthStatus {
    match state.get_valid_token() {
        Some(cached) => GraphAuthStatus {
            is_authenticated: true,
            user_principal_name: cached.user_principal_name,
            tenant_id: cached.tenant_id,
            error: None,
        },
        None => GraphAuthStatus {
            is_authenticated: false,
            user_principal_name: None,
            tenant_id: None,
            error: None,
        },
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
        &format!("{GRAPH_BETA_BASE}/deviceAppManagement/mobileApps?$select=id,displayName,publisher"),
        None,
    )?);

    // Proactive Remediations (Health Scripts)
    match fetch_paginated(
        &token.token,
        &format!("{GRAPH_BETA_BASE}/deviceManagement/deviceHealthScripts?$select=id,displayName,publisher"),
        Some("#microsoft.graph.deviceHealthScript"),
    ) {
        Ok(items) => all.extend(items),
        Err(e) => log::warn!("event=graph_skip_health_scripts error=\"{e}\""),
    }

    // Platform scripts (PowerShell scripts deployed via Intune)
    match fetch_paginated(
        &token.token,
        &format!("{GRAPH_BETA_BASE}/deviceManagement/deviceManagementScripts?$select=id,displayName"),
        Some("#microsoft.graph.deviceManagementScript"),
    ) {
        Ok(items) => all.extend(items),
        Err(e) => log::warn!("event=graph_skip_device_scripts error=\"{e}\""),
    }

    // Shell scripts (macOS)
    match fetch_paginated(
        &token.token,
        &format!("{GRAPH_BETA_BASE}/deviceManagement/deviceShellScripts?$select=id,displayName"),
        Some("#microsoft.graph.deviceShellScript"),
    ) {
        Ok(items) => all.extend(items),
        Err(e) => log::warn!("event=graph_skip_shell_scripts error=\"{e}\""),
    }

    let cache_map: HashMap<String, GraphAppInfo> = all
        .iter()
        .map(|a| (a.id.clone(), a.clone()))
        .collect();
    state.cache_apps(&cache_map);

    Ok(all)
}

/// Fetch all items from a paginated Graph API endpoint.
/// `default_type` is used when the response items don't include `@odata.type`.
fn fetch_paginated(
    token: &str,
    initial_url: &str,
    default_type: Option<&str>,
) -> Result<Vec<GraphAppInfo>, AppError> {
    let agent = make_agent();
    let mut items: Vec<GraphAppInfo> = Vec::new();
    let mut next_url: Option<String> = Some(initial_url.to_string());

    while let Some(url) = next_url.take() {
        let response = agent
            .get(&url)
            .set("Authorization", &format!("Bearer {token}"))
            .set("ConsistencyLevel", "eventual")
            .call()
            .map_err(|e| {
                if let ureq::Error::Status(code, resp) = e {
                    let body = resp.into_string().unwrap_or_default();
                    log::warn!("Graph API HTTP {code} for {url}: {body}");
                    AppError::Internal(format!("Graph API HTTP {code}: {body}"))
                } else {
                    AppError::Internal(format!("Graph API request failed: {e}"))
                }
            })?;

        let body = read_json(response)?;

        if let Some(value) = body.get("value").and_then(|v| v.as_array()) {
            for item in value {
                if let Some(mut app) = parse_app_json(item) {
                    if app.odata_type.is_none() {
                        app.odata_type = default_type.map(String::from);
                    }
                    items.push(app);
                }
            }
        }

        next_url = body
            .get("@odata.nextLink")
            .and_then(|v| v.as_str())
            .map(String::from);
    }

    Ok(items)
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn fetch_apps_batch(
    token: &str,
    guids: &[String],
) -> Result<GraphResolutionResult, AppError> {
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
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/json")
        .send_string(&body_str)
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
        .set("Authorization", &format!("Bearer {token}"))
        .call()
    {
        Ok(response) => {
            let body = read_json(response)?;
            Ok(parse_app_json(&body))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(AppError::Internal(format!("Graph request failed: {e}"))),
    }
}
